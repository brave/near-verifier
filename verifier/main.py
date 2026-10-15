# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Check NEAR AI Cloud attestation - Main entry point."""

import argparse
import asyncio
import json
import logging
import os
import secrets
import sys
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import (
    _INFERENCE_EXPECTED_COMMITS,
    ACCEPTED_EXTRA_PROXY_IMAGES,
    BASE_URL,
    CERT_REPOSITORIES,
    INFERENCE_REPOSITORIES,
    MODEL_NAME,
    NEAR_ENV,
    SIGNING_ALGOS,
)
from .keccak import derive_ecdsa_address
from .models import create_verification_policy
from .pin_drift import MISMATCH_RE
from .s3_cache import save_serving_compose, save_serving_log, save_signing_key
from .s3_upload import persist_results
from .validation import validate_report_values
from .verification_steps import (
    capture_gateway_signing_key,
    capture_inference_signing_key,
    fetch_attestation_report,
    verify_cloud_api,
    verify_inference_models,
    verify_models,
    verify_tls_certificate,
)
from .verifications import cvm_state
from .verifications.compose_manager import unapproved_weights
from .verifications.tdx import _extract_app_compose

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def _persistence_enabled(no_persist: bool) -> bool:
    """S3 persistence is on only when NEAR_BUCKET_NAME is set and not --no-persist."""
    if no_persist:
        return False
    return bool(os.environ.get("NEAR_BUCKET_NAME"))


def _signing_key_binds_address(
    signing_public_key: str, signing_address: str | None, signing_algo: str | None
) -> bool:
    """Confirm the public key matches the hardware-bound signing address.

    Only ``signing_address`` is in the TDX report data; the public key is
    unbound until checked here. A missing or unknown algo is refused.
    """
    algo = (signing_algo or "").lower()
    expected = (signing_address or "").lower().removeprefix("0x")
    pubkey = signing_public_key.lower().removeprefix("0x")

    if algo == "ed25519":
        is_hex32 = len(pubkey) == 64 and all(c in "0123456789abcdef" for c in pubkey)
        if not is_hex32:
            logger.error(
                "⚠️ ed25519 signing_public_key is not 32 bytes of hex; not recording"
            )
            return False
        if not expected or pubkey != expected:
            logger.error(
                "⚠️ ed25519 signing_public_key does not match bound signing_address "
                "(pubkey=%s, bound=%s); not recording",
                pubkey,
                expected,
            )
            return False
        return True

    if algo == "ecdsa":
        derived = derive_ecdsa_address(signing_public_key)
        if derived is None:
            logger.error(
                "⚠️ signing_public_key is not a valid secp256k1 key; not recording"
            )
            return False
        if not expected or derived != expected:
            logger.error(
                "⚠️ signing_public_key does not derive to bound signing_address "
                "(derived=%s, bound=%s); not recording",
                derived,
                expected,
            )
            return False
        return True

    logger.warning(
        "⚠️ Cannot verify signing-key correspondence for algo %r; not recording",
        signing_algo,
    )
    return False


def _record_signing_key(
    signing_public_key: str | None,
    *,
    signing_address: str | None,
    tdx_verified: bool,
    report_data_valid: bool,
    component: str,
    signing_algo: str | None,
) -> None:
    """Persist a signing public key once its TDX quote is verified and binds it.

    Best-effort: failures never affect the verification result.
    """
    if not (tdx_verified and report_data_valid):
        return
    if not signing_public_key:
        logger.warning(f"⚠️ No signing_public_key for {component}; not recorded")
        return
    if not _signing_key_binds_address(
        signing_public_key, signing_address, signing_algo
    ):
        return
    try:
        save_signing_key(
            signing_public_key,
            {
                "component": component,
                "signing_algo": signing_algo,
                "signing_address": signing_address,
                "verification_timestamp": datetime.now(UTC).isoformat(),
            },
        )
    except Exception as e:  # noqa: BLE001 - best-effort, must not break verification
        logger.warning(f"⚠️ Failed to record signing public key for {component}: {e}")


def record_gateway_signing_key(
    report: dict[str, Any], gateway_summary: Mapping[str, Any]
) -> None:
    """Record the gateway's signing public key.

    Read from ``gateway_attestation``, not the report's top level, which nothing
    ties to the gateway quote.
    """
    gateway = report.get("gateway_attestation") or {}
    _record_signing_key(
        gateway.get("signing_public_key"),
        signing_address=gateway.get("signing_address"),
        tdx_verified=bool(gateway_summary.get("tdx_verified")),
        report_data_valid=bool(gateway_summary.get("report_data_valid")),
        component="Gateway",
        signing_algo=gateway.get("signing_algo"),
    )


def record_inference_signing_keys(
    inference_summaries: list[dict[str, Any]],
) -> None:
    """Record each verified inference CVM's signing public key."""
    for summary in inference_summaries:
        _record_signing_key(
            summary.get("signing_public_key"),
            signing_address=summary.get("signing_address"),
            tdx_verified=bool(summary.get("tdx_verified")),
            report_data_valid=bool(summary.get("proxy_report_data_valid")),
            component=summary.get("type", "Inference"),
            signing_algo=summary.get("signing_algo"),
        )


# What the weights markers rest on: a genuine inference CVM, an actions log
# bound to it and written by verified compose-manager code, and approved
# weights in every running server. The proxy image and gateway verdicts are
# not among them, so a failure there does not hold back the weights markers.
_WEIGHTS_CHAIN = (
    "model_name_matches",
    "tdx_verified",
    "os_measurements_valid",
    "mrconfig_valid",
    "compose_hash_valid",
    "report_data_valid",
    "compose_manager_verified",
    "serving_yaml_verified",
    "model_weights_approved",
)


def record_serving_composes(inference_summaries: list[dict[str, Any]]) -> None:
    """Record what the relay needs from each CVM whose weights chain verified:
    its compose history, and each compose file it runs whose every model is
    approved. The history head marker is written only when every named file
    was approved, so it cannot bless history that includes an unapproved one.
    Called even when the overall run fails.
    """
    for summary in inference_summaries:
        head = summary.get("compose_log")
        if not (head and all(summary.get(k) is True for k in _WEIGHTS_CHAIN)):
            continue
        model = str(summary["model_name"])
        now = datetime.now(UTC).isoformat()
        try:
            composes = summary.get("serving_composes") or []
            for compose in composes:
                if compose.get("approved"):
                    save_serving_compose(
                        model,
                        compose["file_sha256"],
                        {
                            "file": compose["file"],
                            "commit": compose["commit"],
                            "verification_timestamp": now,
                        },
                    )
            unapproved = [str(c["file"]) for c in composes if not c.get("approved")]
            if unapproved:
                logger.warning(
                    "⚠️ Serving-log marker for %s withheld: %s not approved",
                    model,
                    ", ".join(unapproved),
                )
            else:
                save_serving_log(
                    model,
                    head,
                    {
                        "serving_composes": composes,
                        "serving_weights": summary.get("serving_weights") or [],
                        "verification_timestamp": now,
                    },
                )
        except Exception as e:  # noqa: BLE001 - best-effort, must not break verification
            logger.warning(f"⚠️ Failed to record serving composes: {e}")


async def _record_other_schemes(
    covered: set[str],
    capture: Callable[[str], Awaitable[dict[str, str] | None]],
    component: Callable[[dict[str, str]], str],
    label: str,
) -> None:
    """Capture and record a signing key for each scheme not in ``covered``.

    Best-effort: a failed capture is logged and never breaks the run.
    """
    for algo in SIGNING_ALGOS:
        if algo in covered:
            continue
        try:
            key = await capture(algo)
        except Exception as e:  # noqa: BLE001 - best-effort, must not break run
            logger.warning("%s signing-key capture errored (%s): %s", label, algo, e)
            continue
        if key is None:
            continue
        _record_signing_key(
            key["signing_public_key"],
            signing_address=key["signing_address"],
            tdx_verified=True,
            report_data_valid=True,
            component=component(key),
            signing_algo=key["signing_algo"],
        )


async def record_other_scheme_gateway_key(model: str, report: dict[str, Any]) -> None:
    """Record the gateway signing key for schemes the main pass did not cover."""
    gateway = report.get("gateway_attestation") or {}
    app_compose = _extract_app_compose(gateway)
    await _record_other_schemes(
        {str(gateway.get("signing_algo") or "").lower()},
        lambda algo: capture_gateway_signing_key(
            model, secrets.token_hex(32), algo, app_compose
        ),
        lambda _key: "Gateway",
        "Gateway",
    )


async def record_other_scheme_inference_keys(
    model: str, inference_summaries: list[dict[str, Any]], report: dict[str, Any]
) -> None:
    """Record inference signing keys for schemes the main pass did not cover."""
    attestations = report.get("model_attestations") or [{}]
    expected = cvm_state(attestations[0])
    await _record_other_schemes(
        {str(s.get("signing_algo") or "").lower() for s in inference_summaries},
        lambda algo: capture_inference_signing_key(
            model, secrets.token_hex(32), algo, expected
        ),
        lambda key: f"Inference: {key['model_name']}",
        f"Inference {model}",
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify NEAR AI Cloud TEE attestation")
    parser.add_argument(
        "--model",
        default=MODEL_NAME,
        help="Marketplace model id to verify (default: $MODEL_NAME, currently "
        f"{MODEL_NAME!r}). The vllm-proxy-rs pin is selected from MODEL_NAME at "
        "import, so override this only together with MODEL_NAME",
    )
    parser.add_argument(
        "--no-persist",
        action="store_true",
        help="Do not write the report / markers to S3, even if NEAR_BUCKET_NAME is set",
    )
    parser.add_argument(
        "--skip-reproducibility",
        action="store_true",
        help="Skip the Docker reproducibility rebuild (provenance-only, a WEAKER "
        "guarantee. Use only when Docker is unavailable or for a quick check)",
    )
    parser.add_argument(
        "--output", metavar="FILE", help="Write the JSON verification report to FILE"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the JSON report to stdout (logs go to stderr)",
    )
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("--quiet", action="store_true", help="Only warnings/errors")
    verbosity.add_argument("--verbose", action="store_true", help="Debug logging")
    return parser.parse_args()


def _emit_report(summaries: list[dict[str, Any]], args: argparse.Namespace) -> None:
    """Write/print the JSON report per the output flags."""
    report_json = json.dumps(summaries, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(report_json)
        logger.info("Report written to %s", args.output)
    if args.json:
        sys.stdout.write(report_json + "\n")  # machine-readable; logs stay on stderr
    else:
        logger.info("Summary:\n%s", report_json)


async def main() -> None:
    """Main entry point for attestation verification."""
    args = _parse_args()
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    elif args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # The proxy pin is resolved from MODEL_NAME at import.
    if args.model != MODEL_NAME:
        logger.error(
            "--model=%r disagrees with MODEL_NAME=%r. The vllm-proxy-rs pin is "
            "selected from MODEL_NAME, so set MODEL_NAME=%s (or drop --model) "
            "and re-run.",
            args.model,
            MODEL_NAME,
            args.model,
        )
        sys.exit(1)

    persist = _persistence_enabled(args.no_persist)
    require_reproducible = not args.skip_reproducibility
    if not require_reproducible:
        logger.warning(
            "⚠️ --skip-reproducibility: images are checked for provenance only, NOT "
            "reproducibly rebuilt. This is a weaker guarantee."
        )
        # Clients read S3 objects as full approval.
        if persist:
            logger.warning("⚠️ --skip-reproducibility: S3 persistence disabled")
            persist = False

    nonce = secrets.token_hex(32)
    gateway_policy = create_verification_policy(
        CERT_REPOSITORIES, require_reproducible_build=require_reproducible
    )
    report = await asyncio.to_thread(fetch_attestation_report, args.model, nonce)

    summaries: list[dict[str, Any]] = []

    cloud_api_verification = await verify_cloud_api(report, gateway_policy, nonce)
    summaries.append(cloud_api_verification)  # type: ignore[arg-type]

    model_summaries = await verify_models(report.get("model_attestations", []), nonce)
    summaries.extend(model_summaries)

    inference_policy = create_verification_policy(
        INFERENCE_REPOSITORIES, require_reproducible_build=require_reproducible
    )
    inference_summaries = await verify_inference_models(
        report.get("model_attestations", []), nonce, inference_policy, args.model
    )
    summaries.extend(inference_summaries)  # type: ignore[arg-type]

    tls_summary = await verify_tls_certificate(BASE_URL, report)
    summaries.append(tls_summary)  # type: ignore[arg-type]

    _emit_report(summaries, args)

    validation_passed = validate_report_values(summaries)

    # The weights markers have their own gate (_WEIGHTS_CHAIN), so an
    # unrelated failure, such as a stale proxy image, does not block them.
    if persist:
        record_serving_composes(inference_summaries)  # type: ignore[arg-type]

    # Gated on the full verdict: a key from unaudited code must never get a marker.
    if persist and validation_passed:
        record_gateway_signing_key(report, cloud_api_verification)
        record_inference_signing_keys(inference_summaries)  # type: ignore[arg-type]
        await record_other_scheme_gateway_key(args.model, report)
        await record_other_scheme_inference_keys(
            args.model,
            inference_summaries,  # type: ignore[arg-type]
            report,
        )
        if persist_results(summaries):
            logger.info("✅ All verifications passed. Report persisted to S3")
        else:
            logger.error("❌ Verifications passed but S3 persistence FAILED")
            sys.exit(1)
    elif validation_passed:
        logger.info("✅ All verifications passed (persistence disabled)")
    else:
        logger.error("❌ Verification FAILED")

    _report_pin_drift(summaries)
    if not validation_passed:
        sys.exit(1)


def _report_pin_drift(summaries: list[dict[str, Any]]) -> None:
    """Print every image whose deployed commit no longer matches its pin, and
    how to update it."""
    seen: dict[str, tuple[str, str]] = {}
    extra = ACCEPTED_EXTRA_PROXY_IMAGES.get(MODEL_NAME, frozenset())
    for summary in summaries:
        image_verification = summary.get("image_verification") or {}
        for ref, image in image_verification.get("images", {}).items():
            if ref in extra:
                continue
            for message in image.get("messages", []):
                match = MISMATCH_RE.search(message)
                if match:
                    seen[match.group("img")] = (
                        match.group("have"),
                        match.group("need"),
                    )
    weights = sorted(
        {
            w
            for summary in summaries
            for w in unapproved_weights(
                summary.get("serving_weights") or [], MODEL_NAME
            )
        }
    )
    if not seen and not weights:
        return

    lines = [
        "",
        "═══════════════════════════════════════════════════════════════",
        "🔑 PIN UPDATE REQUIRED",
        "═══════════════════════════════════════════════════════════════",
        "These image or model-weight pins no longer match what NEAR",
        f"deploys to the '{NEAR_ENV}' environment (the",
        "deployed commit may be newer, older after a rollback, or a different",
        "build). Pins are a manually-audited allow-list, so each change must be",
        "reviewed and updated by hand. To fix:",
        "",
        "  File to edit:  verifier/config.py",
        "",
    ]
    for registry, (have, need) in sorted(seen.items()):
        edit_key = registry
        if registry == "nearaidev/vllm-proxy-rs":
            location = (
                "dict `_PROXY_EXPECTED_COMMITS` (per-model, keyed by the"
                f" marketplace model id, here {MODEL_NAME!r})"
            )
            edit_key = MODEL_NAME
        elif registry in _INFERENCE_EXPECTED_COMMITS:
            location = "dict `_INFERENCE_EXPECTED_COMMITS` (shared, all environments)"
        else:
            location = f'dict `_GATEWAY_EXPECTED_COMMITS["{NEAR_ENV}"]`'
        source_repo = {**CERT_REPOSITORIES, **INFERENCE_REPOSITORIES}.get(registry)
        review = (
            f"https://github.com/{source_repo}/commit/{need}"
            if source_repo
            else "(source repo unknown, see CERT_REPOSITORIES in config.py)"
        )
        lines += [
            f"  ▸ {registry}",
            f"      have (pinned):   {have}",
            f"      need (deployed): {need}",
            f"      edit:   in {location},",
            f'              set "{edit_key}" to "{need}"',
            f"      review: {review}",
            "",
        ]
    for w in weights:
        repo, _, rev = w.partition("@")
        lines += [
            f"  ▸ model weights for {MODEL_NAME!r}",
            f"      deployed: {w}",
            f"      edit:   add it to `APPROVED_MODEL_WEIGHTS[{MODEL_NAME!r}]`",
            f"      review: https://huggingface.co/{repo}/tree/{rev}"
            if rev
            else "      review: not a pinned snapshot; NEAR must pin a revision",
            "",
        ]
    lines += [
        "Before changing a pin, open the review link and confirm the diff from the",
        "old commit is a legitimate NEAR change. The 'deployed' commit above is",
        "already Sigstore-verified from the image's SLSA provenance, so it is the",
        "real source commit for the running image. You are auditing, not trusting.",
        "═══════════════════════════════════════════════════════════════",
    ]
    print("\n".join(lines), file=sys.stderr)  # noqa: T201


def cli() -> None:
    """Console entry point (``verify-near-tee``); RuntimeError exits 1 cleanly."""
    try:
        asyncio.run(main())
    except RuntimeError as e:
        logger.error("❌ %s", e)
        sys.exit(1)


if __name__ == "__main__":
    cli()
