# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tests for the compose_verified logic in both TDX verification paths.

Covers all four combinations of (provenance_verified, build_reproducible).
"""

import asyncio
import hashlib
from unittest.mock import AsyncMock, patch

import pytest

from verifier.models import VerificationPolicy
from verifier.verifications.image import compose_images, verify_compose_images_full
from verifier.verifications.tdx import verify_gateway_attestation

# Minimal policy; the values under test don't touch policy fields.
POLICY = VerificationPolicy(
    allowed_repos=[],
    allowed_builders=[],
    required_images=[],
    require_reproducible_build=True,
    skip_reproducibility_images=set(),
)

MOCK_INTEL_RESULT = {
    "quote": {"body": {"reportdata": "00" * 64, "mrconfig": "00" * 48}},
    "verified": True,
}

# (provenance_verified, build_reproducible, expected_compose_verified)
COMPOSE_CASES = [
    pytest.param(True, True, True, id="both_pass"),
    pytest.param(True, False, False, id="build_not_reproducible"),
    pytest.param(False, True, False, id="provenance_not_verified"),
    pytest.param(False, False, False, id="both_fail_regression_case"),
]


def _source_result(provenance_verified: bool, build_reproducible: bool) -> dict:
    """Build a minimal SourceVerificationResult for a single image."""
    return {
        "images": {
            "img@sha256:abc": {
                "image": "img@sha256:abc",
                "provenance_found": True,
                "provenance_verified": provenance_verified,
                "build_reproducible": build_reproducible,
                "messages": [],
            }
        }
    }


@pytest.mark.parametrize(
    "provenance_verified,build_reproducible,expected", COMPOSE_CASES
)
def test_gateway_compose_verified(
    provenance_verified: bool, build_reproducible: bool, expected: bool
) -> None:
    with (
        patch(
            "verifier.verifications.tdx.verify_tdx_quote",
            new=AsyncMock(return_value=MOCK_INTEL_RESULT),
        ),
        patch(
            "verifier.verifications.tdx.check_report_data",
            return_value={"binds_address": True, "embeds_nonce": True},
        ),
        patch(
            "verifier.verifications.tdx.verify_source",
            return_value=_source_result(provenance_verified, build_reproducible),
        ),
    ):
        result = asyncio.run(verify_gateway_attestation({}, "nonce", POLICY))

    assert result["compose_verified"] == expected


def test_gateway_compose_verified_fails_closed_on_empty_images() -> None:
    # An empty image-verification result (no required image checked at all) must
    # NOT vacuously satisfy compose_verified. Fail closed.
    with (
        patch(
            "verifier.verifications.tdx.verify_tdx_quote",
            new=AsyncMock(return_value=MOCK_INTEL_RESULT),
        ),
        patch(
            "verifier.verifications.tdx.check_report_data",
            return_value={"binds_address": True, "embeds_nonce": True},
        ),
        patch(
            "verifier.verifications.tdx.verify_source",
            return_value={"images": {}},
        ),
    ):
        result = asyncio.run(verify_gateway_attestation({}, "nonce", POLICY))

    assert result["compose_verified"] is False
    # Empty images: no image's provenance could verify, so this is False.
    assert result["image_provenance_verified"] is False


def test_gateway_image_provenance_verified_tracks_provenance() -> None:
    with (
        patch(
            "verifier.verifications.tdx.verify_tdx_quote",
            new=AsyncMock(return_value=MOCK_INTEL_RESULT),
        ),
        patch(
            "verifier.verifications.tdx.check_report_data",
            return_value={"binds_address": True, "embeds_nonce": True},
        ),
        patch(
            "verifier.verifications.tdx.verify_source",
            return_value=_source_result(
                provenance_verified=True, build_reproducible=True
            ),
        ),
    ):
        ok = asyncio.run(verify_gateway_attestation({}, "nonce", POLICY))
    assert ok["image_provenance_verified"] is True

    with (
        patch(
            "verifier.verifications.tdx.verify_tdx_quote",
            new=AsyncMock(return_value=MOCK_INTEL_RESULT),
        ),
        patch(
            "verifier.verifications.tdx.check_report_data",
            return_value={"binds_address": True, "embeds_nonce": True},
        ),
        patch(
            "verifier.verifications.tdx.verify_source",
            return_value=_source_result(
                provenance_verified=False, build_reproducible=True
            ),
        ),
    ):
        bad = asyncio.run(verify_gateway_attestation({}, "nonce", POLICY))
    assert bad["image_provenance_verified"] is False


def test_verify_compose_images_full_missing_required_image() -> None:
    """A required image absent from the compose yields a failing entry."""
    compose = "services:\n  x:\n    image: other/image@sha256:" + "a" * 64
    policy = VerificationPolicy(
        allowed_repos=[],
        allowed_builders=[],
        required_images=["nearaidev/cloud-api"],
        require_reproducible_build=True,
        skip_reproducibility_images=set(),
    )
    result = verify_compose_images_full(compose_images(compose), policy)
    images = result["images"]

    assert any("not-found" in key for key in images), (
        "Expected a 'not-found' sentinel key for the missing required image"
    )
    for img in images.values():
        assert img["provenance_verified"] is False
        assert img["build_reproducible"] is False


def test_verify_compose_images_full_all_required_images_found() -> None:
    """A present required image adds no sentinel and is verified."""
    digest = "a" * 64
    compose = f"services:\n  api:\n    image: nearaidev/cloud-api@sha256:{digest}"
    policy = VerificationPolicy(
        allowed_repos=[],
        allowed_builders=[],
        required_images=["nearaidev/cloud-api"],
        require_reproducible_build=True,
        skip_reproducibility_images=set(),
    )
    fake_result = {
        "image": f"nearaidev/cloud-api@sha256:{digest}",
        "provenance_found": True,
        "provenance_verified": True,
        "build_reproducible": True,
        "messages": [],
    }
    with patch(
        "verifier.verifications.image.verify_image_full",
        return_value=fake_result,
    ):
        result = verify_compose_images_full(compose_images(compose), policy)

    images = result["images"]
    assert not any("not-found" in key for key in images), (
        "No sentinel entry expected when required image is present"
    )
    assert len(images) == 1


def test_verify_compose_images_full_compose_variable_default_form() -> None:
    """The registry is extracted from inside `image: ${VAR:-registry@sha256:...}`."""
    digest = "a" * 64
    compose = (
        "services:\n  cm:\n    image: ${COMPOSE_MANAGER_IMAGE:-"
        f"nearaidev/compose-manager@sha256:{digest}}}"
    )
    policy = VerificationPolicy(
        allowed_repos=[],
        allowed_builders=[],
        required_images=["nearaidev/compose-manager"],
        require_reproducible_build=True,
        skip_reproducibility_images=set(),
    )
    fake_result = {
        "image": f"nearaidev/compose-manager@sha256:{digest}",
        "provenance_found": True,
        "provenance_verified": True,
        "build_reproducible": True,
        "messages": [],
    }
    with patch(
        "verifier.verifications.image.verify_image_full",
        return_value=fake_result,
    ):
        result = verify_compose_images_full(compose_images(compose), policy)

    images = result["images"]
    assert not any("not-found" in key for key in images)
    assert f"nearaidev/compose-manager@sha256:{digest}" in images


def test_verify_compose_images_full_records_provenance_failure() -> None:
    """Unverifiable provenance is recorded as a failed entry, not raised."""
    digest = "a" * 64
    compose = f"services:\n  api:\n    image: nearaidev/cloud-api@sha256:{digest}"
    policy = VerificationPolicy(
        allowed_repos=[],
        allowed_builders=[],
        required_images=["nearaidev/cloud-api"],
        require_reproducible_build=True,
        skip_reproducibility_images=set(),
    )
    failed = {
        "image": f"nearaidev/cloud-api@sha256:{digest}",
        "provenance_found": False,
        "provenance_verified": False,
        "build_reproducible": False,
        "messages": ["❌ Provenance check failed: Commit SHA mismatch"],
    }
    with patch("verifier.verifications.image.verify_image_full", return_value=failed):
        result = verify_compose_images_full(compose_images(compose), policy)
    entry = result["images"][f"nearaidev/cloud-api@sha256:{digest}"]
    assert entry["provenance_verified"] is False
    assert len(result["images"]) == 1


# --- MR_CONFIG_ID must match app_compose -----------------------------------


def _make_mrconfig(app_compose: str) -> str:
    """Compute the expected 48-byte (96-hex-char) mrconfig for an app_compose."""
    compose_hash = hashlib.sha256(app_compose.encode()).hexdigest()
    return ("01" + compose_hash).ljust(96, "0")


def test_gateway_mrconfig_valid() -> None:
    """mrconfig that matches app_compose → mrconfig_valid=True."""
    app_compose = '{"docker_compose_file": ""}'
    mrconfig = _make_mrconfig(app_compose)
    mock_intel = {
        "quote": {"body": {"reportdata": "00" * 64, "mrconfig": mrconfig}},
        "verified": True,
    }
    attestation = {"info": {"tcb_info": {"app_compose": app_compose}}}

    with (
        patch(
            "verifier.verifications.tdx.verify_tdx_quote",
            new=AsyncMock(return_value=mock_intel),
        ),
        patch(
            "verifier.verifications.tdx.check_report_data",
            return_value={"binds_address": True, "embeds_nonce": True},
        ),
        patch(
            "verifier.verifications.tdx.verify_source",
            return_value={"images": {}},
        ),
    ):
        result = asyncio.run(verify_gateway_attestation(attestation, "nonce", POLICY))

    assert result["mrconfig_valid"] is True


def test_gateway_mrconfig_mismatch() -> None:
    """mrconfig that does NOT match app_compose → mrconfig_valid=False."""
    app_compose = '{"docker_compose_file": ""}'
    mock_intel = {
        "quote": {"body": {"reportdata": "00" * 64, "mrconfig": "00" * 96}},
        "verified": True,
    }
    attestation = {"info": {"tcb_info": {"app_compose": app_compose}}}

    with (
        patch(
            "verifier.verifications.tdx.verify_tdx_quote",
            new=AsyncMock(return_value=mock_intel),
        ),
        patch(
            "verifier.verifications.tdx.check_report_data",
            return_value={"binds_address": True, "embeds_nonce": True},
        ),
        patch(
            "verifier.verifications.tdx.verify_source",
            return_value={"images": {}},
        ),
    ):
        result = asyncio.run(verify_gateway_attestation(attestation, "nonce", POLICY))

    assert result["mrconfig_valid"] is False
