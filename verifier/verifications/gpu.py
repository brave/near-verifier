# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""GPU attestation verification."""

import json
from functools import lru_cache
from typing import Any, TypedDict

import jwt
from jwt import PyJWKClient, PyJWKClientError

from ..config import GPU_VERIFIER_API, NVIDIA_JWKS_URL
from ..utils import get_http_session, get_logger

logger = get_logger(__name__)

# Asymmetric only; HS* and "none" are excluded.
_ALLOWED_JWT_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}


class GpuCheckResult(TypedDict):
    nonce_matches: bool
    verdict: bool


class ModelAttestationSummary(TypedDict):
    type: str
    gpu_verified: bool | None


@lru_cache(maxsize=1)
def _jwks_client() -> PyJWKClient:
    """One client per process, so its key cache spans GPU checks."""
    return PyJWKClient(NVIDIA_JWKS_URL)


def _verify_and_decode_gpu_jwt(jwt_token: str) -> dict[str, Any]:
    """Verify the NVIDIA NRAS JWT against NVIDIA's JWKS and return the payload."""
    header = jwt.get_unverified_header(jwt_token)
    alg = header.get("alg", "")
    if alg not in _ALLOWED_JWT_ALGORITHMS:
        raise jwt.exceptions.InvalidAlgorithmError(
            f"JWT algorithm {alg!r} is not in the allowed set {_ALLOWED_JWT_ALGORITHMS}"
        )
    signing_key = _jwks_client().get_signing_key_from_jwt(jwt_token)
    return jwt.decode(  # type: ignore[return-value]
        jwt_token, signing_key.key, algorithms=[alg], options={"require": ["exp"]}
    )


def _signed_jwt_nonce_matches(
    decoded: dict[str, Any], request_nonce: str
) -> bool | None:
    """Compare the request nonce against a nonce claim inside the NVIDIA-signed JWT.

    The unsigned ``nvidia_payload['nonce']`` can be swapped onto replayed
    evidence. Returns None if no claim is found; callers must fail closed.
    """
    want = request_nonce.lower().removeprefix("0x")
    for key in ("eat_nonce", "x-nvidia-eat-nonce", "nonce"):
        value = decoded.get(key)
        if isinstance(value, list):
            value = value[0] if value and isinstance(value[0], str) else None
        if isinstance(value, str):
            candidate = value.lower().removeprefix("0x")
            if len(candidate) == len(want) and all(
                c in "0123456789abcdef" for c in candidate
            ):
                return candidate == want
    return None


def check_gpu(attestation: dict[str, Any], request_nonce: str) -> GpuCheckResult:
    """Verify GPU attestation evidence via NVIDIA NRAS."""
    payload = json.loads(attestation["nvidia_payload"])
    response = get_http_session().post(GPU_VERIFIER_API, json=payload, timeout=30)
    if not response.ok:
        raise RuntimeError(f"NVIDIA NRAS request failed: HTTP {response.status_code}")
    body = response.json()
    if (
        not isinstance(body, list)
        or not body
        or not isinstance(body[0], list)
        or len(body[0]) < 2
    ):
        raise RuntimeError(f"Unexpected NVIDIA NRAS response structure: {body!r}")
    jwt_token = body[0][1]
    try:
        decoded = _verify_and_decode_gpu_jwt(jwt_token)
    except PyJWKClientError as e:
        raise RuntimeError(
            f"Failed to fetch NVIDIA JWKS for JWT verification: {e}"
        ) from e
    except jwt.exceptions.ExpiredSignatureError as e:
        raise RuntimeError("NVIDIA GPU attestation JWT has expired") from e
    except jwt.exceptions.PyJWTError as e:
        raise RuntimeError(
            f"NVIDIA GPU attestation JWT verification failed: {e}"
        ) from e
    signed_match = _signed_jwt_nonce_matches(decoded, request_nonce)
    if signed_match is None:
        logger.error(
            "NVIDIA GPU JWT carried no recognizable hex nonce claim; cannot "
            "prove freshness from the signed token. Failing closed (replay "
            "cannot be excluded)."
        )
        nonce_matches = False
    else:
        nonce_matches = signed_match
    verdict = decoded.get("x-nvidia-overall-att-result") is True
    if "x-nvidia-overall-att-result" not in decoded:
        logger.error(
            "NVIDIA GPU JWT carried no x-nvidia-overall-att-result claim;"
            " cannot establish a GPU verdict. Failing closed."
        )
    return {
        "nonce_matches": nonce_matches,
        "verdict": verdict,
    }


async def verify_model_attestation(
    attestation: dict[str, Any], request_nonce: str, attestation_type: str
) -> ModelAttestationSummary:
    """Verify the model attestation and return summary."""
    summary: ModelAttestationSummary = {
        "type": attestation_type,
        "gpu_verified": None,
    }
    gpu_result = check_gpu(attestation, request_nonce)
    summary["gpu_verified"] = gpu_result["nonce_matches"] and gpu_result["verdict"]
    return summary
