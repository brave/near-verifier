# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""TDX attestation verification."""

import json
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256 as _sha256
from io import StringIO
from typing import Any, TypedDict

import dcap_qvl

from ..config import (
    ACCEPTED_OUTOFDATE_ADVISORIES,
    EXPECTED_OS_MEASUREMENTS,
    PCCS_URL,
)
from ..models import SourceVerificationResult, VerificationPolicy
from ..utils import get_logger
from .image import (
    ANY_VAR,
    all_images_fully_verified,
    compose_images,
    verify_compose_images_full,
)

logger = get_logger(__name__)

# "OutOfDate" is excluded: the host's TCB has unpatched published CVEs. The
# one exception is tdx_status_acceptable's allow-list of reviewed advisories.
ACCEPTABLE_TDX_STATUSES = {"UpToDate", "SWHardeningNeeded"}


def tdx_status_acceptable(status: str, advisory_ids: list[str] | None) -> bool:
    """An acceptable status, or "OutOfDate" with only reviewed advisories."""
    if status in ACCEPTABLE_TDX_STATUSES:
        return True
    advisories = set(advisory_ids or [])
    return (
        status == "OutOfDate"
        and bool(advisories)
        and advisories <= ACCEPTED_OUTOFDATE_ADVISORIES
    )


class ReportDataResult(TypedDict, total=False):
    binds_address: bool
    embeds_nonce: bool
    binds_tls_cert: bool


class IntelQuoteBody(TypedDict):
    reportdata: str
    mrconfig: str
    mrtd: str
    rtmrs: list[str]


class IntelQuote(TypedDict):
    body: IntelQuoteBody


class IntelResult(TypedDict):
    quote: IntelQuote
    verified: bool


class GatewayAttestationSummary(TypedDict):
    type: str
    tdx_verified: bool
    os_measurements_valid: bool
    mrconfig_valid: bool
    report_data_valid: bool
    compose_verified: bool
    image_provenance_verified: bool
    image_verification: SourceVerificationResult | None


def _extract_app_compose(attestation: dict[str, Any]) -> str:
    """Return the raw app_compose JSON string from tcb_info, or '' if absent."""
    tcb_info: dict[str, Any] = attestation.get("info", {}).get("tcb_info", {})
    if isinstance(tcb_info, str):
        tcb_info = json.loads(tcb_info)
    return str(tcb_info.get("app_compose") or "")


def overridable_envs(app_compose: str) -> frozenset[str]:
    """Variables a compose value may be interpolated from without being fixed
    by the measured compose.

    The app_compose ``allowed_envs`` are set by the operator at deploy time.
    A non-empty ``pre_launch_script`` can export any variable (including from
    names it reads at runtime), so it adds ``ANY_VAR``: every variable counts.
    Unparseable input means every variable counts too.
    """
    try:
        data = json.loads(app_compose)
        envs = {str(env) for env in data.get("allowed_envs") or []}
        if str(data.get("pre_launch_script") or "").strip():
            envs.add(ANY_VAR)
    except (json.JSONDecodeError, AttributeError):
        return frozenset({ANY_VAR})
    return frozenset(envs)


def _validate_mrconfig(app_compose: str, mrconfig: str) -> bool:
    """Validate that mrconfig is exactly 0x01 || SHA256(app_compose) || 0x00*15.

    The padding is compared too: a prefix match would leave 15 host-chosen bytes
    unchecked.
    """
    if not app_compose or not mrconfig:
        reason = (
            "mrconfig is empty" if not mrconfig else "app_compose missing from tcb_info"
        )
        logger.warning("⚠️ Cannot validate mrconfig: %s", reason)
        return False
    compose_hash = _sha256(app_compose.encode()).hexdigest()
    expected = ("01" + compose_hash).ljust(96, "0")
    return mrconfig.lower().removeprefix("0x") == expected


def os_measurements(intel_result: IntelResult) -> tuple[str, str, str, str]:
    """(MRTD, RTMR0, RTMR1, RTMR2) of a verified quote, lowercased."""
    body = intel_result["quote"]["body"]
    rtmrs = (list(body.get("rtmrs", [])) + ["", "", ""])[:3]
    mrtd = body.get("mrtd", "")
    return (mrtd.lower(), rtmrs[0].lower(), rtmrs[1].lower(), rtmrs[2].lower())


def check_os_measurements(intel_result: IntelResult, component: str) -> bool:
    """True only if the quote's OS measurements are a pinned dstack release."""
    observed = os_measurements(intel_result)
    if all(observed) and observed in EXPECTED_OS_MEASUREMENTS:
        return True
    logger.error(
        "❌ %s OS measurements are not a pinned dstack release. To audit and"
        " pin, add this tuple to EXPECTED_OS_MEASUREMENTS in verifier/config.py"
        " (MRTD, RTMR0, RTMR1, RTMR2): %s",
        component,
        observed,
    )
    return False


def check_report_data(
    attestation: dict[str, Any],
    request_nonce: str,
    intel_result: IntelResult,
) -> ReportDataResult:
    """Verify that TDX report data binds the signing address and request nonce."""
    report_data_hex = intel_result["quote"]["body"]["reportdata"]
    report_data = bytes.fromhex(report_data_hex.removeprefix("0x"))
    signing_addr: str = attestation["signing_address"]
    # Same binding for ecdsa (20-byte address) and ed25519 (32-byte key).
    signing_address_bytes = bytes.fromhex(signing_addr.removeprefix("0x"))
    embedded_address = report_data[:32]
    embedded_nonce = report_data[32:]

    expected_address_binding = signing_address_bytes.ljust(32, b"\x00")
    binds_address = embedded_address == expected_address_binding

    fingerprint_hex = attestation.get("tls_cert_fingerprint", "")
    binds_tls_cert = False
    if fingerprint_hex:
        normalized = fingerprint_hex.replace(":", "").strip().lower()
        try:
            fingerprint_bytes = bytes.fromhex(normalized)
        except ValueError:
            logger.error(
                "TLS cert fingerprint from attestation is not valid hex: %s",
                fingerprint_hex,
            )
            fingerprint_bytes = b""
        if fingerprint_bytes:
            hashed_binding = _sha256(signing_address_bytes + fingerprint_bytes).digest()
            binds_tls_cert = embedded_address == hashed_binding
            if binds_tls_cert:
                logger.info("Report data binds TLS certificate fingerprint ✅")

    embeds_nonce = embedded_nonce.hex() == request_nonce

    if not (binds_address or binds_tls_cert):
        logger.error(
            "Report data binds signing address or TLS fingerprint: "
            "expected address=%s TLS hash available=%s actual=%s",
            expected_address_binding.hex(),
            bool(fingerprint_hex),
            embedded_address.hex(),
        )
    if not embeds_nonce:
        logger.error(
            "Report data embeds request nonce: expected: %s, actual: %s",
            request_nonce,
            embedded_nonce.hex(),
        )

    return {
        "binds_address": binds_address,
        "binds_tls_cert": binds_tls_cert,
        "embeds_nonce": embeds_nonce,
    }


async def verify_tdx_quote(attestation: dict[str, Any]) -> IntelResult:
    """Verify an Intel TDX quote via dcap-qvl and return the decoded result."""
    intel_quote: str = attestation["intel_quote"]
    try:
        intel_quote_bytes = bytes.fromhex(intel_quote)
        # Process-global redirect spanning an await: unsafe if quote
        # verifications ever run concurrently.
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            result = await dcap_qvl.get_collateral_and_verify(
                intel_quote_bytes, PCCS_URL
            )
        result_json = json.loads(result.to_json())
        if hasattr(result, "advisory_ids") and result.advisory_ids:
            logger.info(f"   Advisory IDs: {result.advisory_ids}")
    except ValueError as e:
        logger.error(f"❌ Verification failed: {e}")
        raise e
    except RuntimeError as e:
        logger.error(f"❌ Failed to verify TDX quote: {e}")
        raise e
    report_data = ""
    mr_config = ""
    mr_td = ""
    rtmrs: list[str] = []
    if "report" in result_json and "TD10" in result_json["report"]:
        td10 = result_json["report"]["TD10"]
        report_data = td10.get("report_data", "")
        mr_config = td10.get("mr_config_id", "")
        mr_td = td10.get("mr_td", "")
        rtmrs = [td10.get(f"rt_mr{i}", "") for i in range(4)]
    else:
        # Measurements stay empty, so every check that needs them fails.
        logger.error(
            "Unsupported TD report variant %s; only TD10 is parsed",
            list((result_json.get("report") or {}).keys()),
        )
    status = result.status if hasattr(result, "status") else "Unknown"
    advisory_ids = list(getattr(result, "advisory_ids", None) or [])
    verified = tdx_status_acceptable(status, advisory_ids)
    if verified and status not in ACCEPTABLE_TDX_STATUSES:
        logger.warning(
            f"⚠️ TDX quote status {status!r} accepted: advisories {advisory_ids} "
            "are all in ACCEPTED_OUTOFDATE_ADVISORIES"
        )
    elif verified:
        logger.info(f"   TDX quote status: {status} ✅")
    else:
        acceptable = sorted(ACCEPTABLE_TDX_STATUSES)
        advisories = sorted(ACCEPTED_OUTOFDATE_ADVISORIES)
        logger.warning(
            f"⚠️ TDX quote status not acceptable: {status!r} (acceptable: "
            f"{acceptable}, or OutOfDate with only {advisories}; "
            f"reported advisories: {advisory_ids})"
        )
    intel_result: IntelResult = {
        "quote": {
            "body": {
                "reportdata": report_data,
                "mrconfig": mr_config,
                "mrtd": mr_td,
                "rtmrs": rtmrs,
            }
        },
        "verified": verified,
    }
    return intel_result


def verify_source(
    attestation: dict[str, Any], policy: VerificationPolicy
) -> SourceVerificationResult:
    compose = _extract_app_compose(attestation)
    if not compose:
        logger.error("\n⚠️  No compose file found in attestation")
        return {"images": {}}
    compose_data = json.loads(compose)
    docker_compose = compose_data.get("docker_compose_file", "")
    if not docker_compose:
        logger.error("\n⚠️  No docker_compose_file found")
        return {"images": {}}
    result: SourceVerificationResult = verify_compose_images_full(
        compose_images(docker_compose), policy, overridable_envs(compose)
    )
    return result


async def verify_gateway_attestation(
    attestation: dict[str, Any], request_nonce: str, policy: VerificationPolicy
) -> GatewayAttestationSummary:
    """Verify the attestation and return summary."""
    summary: GatewayAttestationSummary = {
        "type": "Gateway",
        "tdx_verified": False,
        "os_measurements_valid": False,
        "mrconfig_valid": False,
        "report_data_valid": False,
        "compose_verified": False,
        "image_provenance_verified": False,
        "image_verification": None,
    }
    intel_result = await verify_tdx_quote(attestation)

    summary["tdx_verified"] = intel_result["verified"]
    summary["os_measurements_valid"] = check_os_measurements(intel_result, "Gateway")

    app_compose = _extract_app_compose(attestation)
    mrconfig_valid = _validate_mrconfig(
        app_compose, intel_result["quote"]["body"]["mrconfig"]
    )
    summary["mrconfig_valid"] = mrconfig_valid
    if mrconfig_valid:
        logger.info("   MR_CONFIG_ID matches app_compose ✅")
    else:
        logger.warning(
            "⚠️ MR_CONFIG_ID does not match app_compose"
            ". Served tcb_info may differ from attested compose"
        )

    report_data_result = check_report_data(
        attestation,
        request_nonce,
        intel_result,
    )
    # binds_address is not enough here: no response signature is checked
    # against that address, so a gateway could proxy a genuine backend's quote
    # onto its own certificate. Only binds_tls_cert anchors the TLS channel.
    binds_identity = report_data_result.get("binds_tls_cert", False)
    report_data_valid = binds_identity and report_data_result["embeds_nonce"]
    summary["report_data_valid"] = report_data_valid
    image_verification_report = verify_source(attestation, policy)
    summary["image_verification"] = image_verification_report

    images = image_verification_report["images"]
    summary["compose_verified"] = all_images_fully_verified(
        image_verification_report, policy
    )
    # NEAR publishes SLSA provenance, not separate cosign signatures.
    summary["image_provenance_verified"] = bool(images) and all(
        value["provenance_verified"] for value in images.values()
    )

    return summary
