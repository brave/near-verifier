# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Individual verification steps for the attestation process."""

import asyncio
import logging
from typing import Any
from urllib.parse import urlparse

from .config import API_KEY, BASE_URL
from .models import VerificationPolicy
from .utils import get_http_session
from .verifications import (
    CvmState,
    GatewayAttestationSummary,
    InferenceAttestationSummary,
    TLSVerificationResult,
    model_names_match,
    signing_key_from_inference_attestation,
    verify_certificate,
    verify_gateway_attestation,
    verify_inference_attestation,
    verify_model_attestation,
)
from .verifications.compose_manager import blank_inference_summary
from .verifications.tdx import (
    _validate_mrconfig,
    check_os_measurements,
    check_report_data,
    verify_tdx_quote,
)

logger = logging.getLogger(__name__)


async def verify_cloud_api(
    report: dict[str, Any], policy: VerificationPolicy, nonce: str
) -> GatewayAttestationSummary:
    """Verify cloud API gateway attestation."""
    report_gateway_attestation = report.get("gateway_attestation")
    if report_gateway_attestation is None:
        raise ValueError("Gateway attestation required")
    return await verify_gateway_attestation(report_gateway_attestation, nonce, policy)


async def verify_models(
    model_attestations: list[dict[str, Any]], nonce: str
) -> list[dict[str, Any]]:
    """Verify all model attestations."""
    logger.info(f"🎯 Found {len(model_attestations)} model attestation(s)")
    results: list[dict[str, Any]] = []

    for index, model_attestation in enumerate(model_attestations, 1):
        logger.debug(f"🔍 Model #{index} fields: {list(model_attestation.keys())}")

        if "error" in model_attestation:
            logger.warning(f"⚠️ Error in model attestation: {model_attestation}")

        if "nvidia_payload" not in model_attestation:
            logger.warning(
                f"⚠️ Model #{index} missing nvidia_payload, skipping GPU verification"
            )
            results.append(
                {
                    "type": f"Model #{index}",
                    "gpu_verified": False,
                    "error": "Missing nvidia_payload - may not be a GPU model",
                }
            )
            continue

        model_summary = await verify_model_attestation(
            model_attestation, nonce, attestation_type=f"Model #{index}"
        )
        results.append(model_summary)  # type: ignore[arg-type]

    return results


def _failed_inference_summary(model: str, error: str) -> InferenceAttestationSummary:
    """Build a fully-failed inference summary when a model cannot be verified."""
    logger.error("Inference attestation unusable for %s: %s", model, error)
    return blank_inference_summary(model, model)


async def verify_inference_models(
    model_attestations: list[dict[str, Any]],
    nonce: str,
    policy: VerificationPolicy,
    requested_model: str,
) -> list[InferenceAttestationSummary]:
    """Verify the inference CVM behind each attestation via the compose-manager chain.

    An empty ``model_attestations`` yields one failed summary: silence must not
    read as success.
    """
    if not model_attestations:
        return [
            _failed_inference_summary(
                requested_model,
                "gateway report carried no model_attestations; the gateway may "
                "not serve this model (check MODEL_NAME against /v1/models)",
            )
        ]
    logger.info(f"🧠 Verifying {len(model_attestations)} inference model(s)")
    results: list[InferenceAttestationSummary] = []
    for attestation in model_attestations:
        label = str(attestation.get("model_name") or requested_model)
        try:
            results.append(
                await verify_inference_attestation(
                    attestation, nonce, policy, requested_model
                )
            )
        except Exception as e:  # noqa: BLE001
            logger.error("Inference verification errored for %s: %s", label, e)
            results.append(_failed_inference_summary(label, str(e)))
    return results


async def verify_tls_certificate(
    base_url: str, report: dict[str, Any]
) -> TLSVerificationResult:
    """Verify the TLS certificate carried in ``report.tls_certificate``."""
    domain = urlparse(base_url).hostname
    if not domain:
        raise ValueError(f"Invalid BASE_URL: {base_url}")

    gateway_attestation = report.get("gateway_attestation", {})
    cert_pem = report.get("tls_certificate")
    attestation_fingerprint = gateway_attestation.get("tls_cert_fingerprint")

    if not cert_pem:
        logger.error(
            "❌ TLS certificate not found in attestation report"
            ". Request include_tls_fingerprint=true"
        )
        return {
            "type": "Domain TLS Certificate",
            "domain": domain,
            "certificate_verified": False,
            "fingerprint_matches": False,
            "attestation_fingerprint_matches": False,
            "dns_caa_verified": False,
        }

    return await verify_certificate(domain, cert_pem, attestation_fingerprint)


def fetch_attestation_report(
    model: str, nonce: str, signing_algo: str = "ecdsa"
) -> dict[str, Any]:
    """Fetch the attestation report from the API, signed with ``signing_algo``."""
    report_url = (
        f"{BASE_URL}/v1/attestation/report"
        f"?model={model}&nonce={nonce}&signing_algo={signing_algo}"
        f"&include_tls=true&include_tls_fingerprint=true"
    )
    headers = {"Authorization": f"Bearer {API_KEY}"} if API_KEY else {}
    response = get_http_session().get(report_url, timeout=30, headers=headers)
    if not response.ok:
        hint = ""
        if response.status_code in (401, 403):
            hint = (
                ". An API key is required (prod and staging). Set NEAR_API_KEY"
                " or the per-env NEAR_API_KEY_PROD / NEAR_API_KEY_STAGING."
                " If a key was set, it was rejected: check it is valid for"
                " this environment and is a raw key, not a JSON blob"
            )
        raise RuntimeError(
            f"Attestation report fetch failed: HTTP {response.status_code} "
            f"from {report_url}{hint}"
        )
    result = response.json()
    if not isinstance(result, dict):
        raise RuntimeError(
            f"Unexpected attestation report response type: {type(result)}"
        )
    return result


async def capture_inference_signing_key(
    model: str, nonce: str, signing_algo: str, expected: CvmState
) -> dict[str, str] | None:
    """Capture a model CVM's signing key under one signature scheme, or None."""
    report = await asyncio.to_thread(
        fetch_attestation_report, model, nonce, signing_algo
    )
    model_attestations = report.get("model_attestations") or []
    if not model_attestations:
        return None
    attestation = model_attestations[0]
    attested = str(attestation.get("model_name") or "")
    if not model_names_match(attested, model):
        logger.warning(
            "Signing-key capture: gateway attested %r, not the requested %r; skipping",
            attested,
            model,
        )
        return None
    return await signing_key_from_inference_attestation(
        attestation, nonce, signing_algo, model, expected
    )


async def capture_gateway_signing_key(
    model: str, nonce: str, signing_algo: str, expected_app_compose: str
) -> dict[str, str] | None:
    """Capture the gateway's signing key under one signature scheme, or None.

    Only ed25519 is captured: an ecdsa gateway exposes only its address, not a
    recordable public key. MR_CONFIG_ID must be ``expected_app_compose`` so a
    replica running another compose cannot get its key recorded.
    """
    if signing_algo != "ed25519":
        return None
    report = await asyncio.to_thread(
        fetch_attestation_report, model, nonce, signing_algo
    )
    gateway_attestation = report.get("gateway_attestation")
    if not isinstance(gateway_attestation, dict):
        return None
    if str(gateway_attestation.get("signing_algo") or "").lower() != signing_algo:
        return None
    signing_address = str(gateway_attestation.get("signing_address") or "")
    try:
        intel_result = await verify_tdx_quote(gateway_attestation)
    except (ValueError, RuntimeError) as e:
        logger.warning("Gateway signing-key capture: quote verify failed: %s", e)
        return None
    if not intel_result.get("verified"):
        return None
    if not (
        check_os_measurements(intel_result, "Gateway signing-key capture")
        and _validate_mrconfig(
            expected_app_compose, intel_result["quote"]["body"]["mrconfig"]
        )
    ):
        logger.warning("Gateway signing-key capture: not the verified CVM image")
        return None
    report_data = check_report_data(gateway_attestation, nonce, intel_result)
    # Only the TLS binding anchors a gateway quote (see verify_gateway_attestation).
    if not (report_data.get("binds_tls_cert") and report_data.get("embeds_nonce")):
        logger.warning("Gateway signing-key capture: report_data binding failed")
        return None
    # ed25519: the bound signing_address is itself the public key.
    return {
        "signing_public_key": signing_address,
        "signing_address": signing_address,
        "signing_algo": signing_algo,
    }
