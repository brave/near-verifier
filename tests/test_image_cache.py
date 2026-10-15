# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tests for pre-verified cache trust hardening in verify_image_full."""

from typing import Any
from unittest.mock import patch

import pytest

from verifier.models import VerificationPolicy
from verifier.verifications.image import (
    _cached_result_is_trustworthy,
    verify_image_full,
)

DIGEST = "sha256:" + "a" * 64
REGISTRY = "nearaidev/cloud-api"
OTHER_DIGEST = "sha256:" + "b" * 64
PINNED_COMMIT = "c" * 40
OTHER_COMMIT = "d" * 40


@pytest.fixture(autouse=True)
def _pin_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    # Cache hits are trusted only for the pinned commit; pin REGISTRY hermetically.
    monkeypatch.setattr(
        "verifier.verifications.image.CERT_EXPECTED_COMMITS",
        {REGISTRY: PINNED_COMMIT},
    )


POLICY = VerificationPolicy(
    allowed_repos=[],
    allowed_builders=[],
    required_images=[REGISTRY],
    require_reproducible_build=True,
    skip_reproducibility_images=set(),
)


def _valid_entry(**overrides: Any) -> dict[str, Any]:
    entry = {
        "image": f"{REGISTRY}@{DIGEST}",
        "provenance_found": True,
        "provenance_verified": True,
        "build_reproducible": True,
        "build_result": {"status": "✅ passed", "digest": DIGEST, "expected": DIGEST},
        "provenance": {"commit_sha": PINNED_COMMIT},
        "messages": [],
    }
    entry.update(overrides)
    return entry


class TestCachedResultIsTrustworthy:
    def test_accepts_valid_reproducible_entry(self) -> None:
        assert _cached_result_is_trustworthy(DIGEST, REGISTRY, _valid_entry()) is True

    def test_accepts_provenance_only_entry(self) -> None:
        # Reproducibility skipped/not-claimed is fine as long as it's well-formed.
        entry = _valid_entry(build_reproducible=False, build_result=None)
        assert _cached_result_is_trustworthy(DIGEST, REGISTRY, entry) is True

    def test_accepts_legacy_entry_with_signature_field(self) -> None:
        # The obsolete image_signature_verified key is ignored, not rejected.
        entry = _valid_entry(image_signature_verified=False)
        assert _cached_result_is_trustworthy(DIGEST, REGISTRY, entry) is True

    def test_rejects_non_dict(self) -> None:
        assert _cached_result_is_trustworthy(DIGEST, REGISTRY, "nope") is False

    def test_rejects_wrong_digest(self) -> None:
        entry = _valid_entry(image=f"{REGISTRY}@{OTHER_DIGEST}")
        assert _cached_result_is_trustworthy(DIGEST, REGISTRY, entry) is False

    def test_rejects_wrong_registry(self) -> None:
        entry = _valid_entry(image=f"evil/img@{DIGEST}")
        assert _cached_result_is_trustworthy(DIGEST, REGISTRY, entry) is False

    def test_rejects_missing_boolean_field(self) -> None:
        entry = _valid_entry()
        del entry["provenance_verified"]
        assert _cached_result_is_trustworthy(DIGEST, REGISTRY, entry) is False

    def test_rejects_reproducible_claim_not_bound_to_digest(self) -> None:
        # Claims reproducible, but build_result is for a different digest -> reject
        # (prevents replaying image A's reproducibility pass onto image B).
        entry = _valid_entry(
            build_result={
                "status": "✅ passed",
                "digest": OTHER_DIGEST,
                "expected": OTHER_DIGEST,
            }
        )
        assert _cached_result_is_trustworthy(DIGEST, REGISTRY, entry) is False

    def test_rejects_reproducible_claim_without_build_result(self) -> None:
        entry = _valid_entry(build_result=None)
        assert _cached_result_is_trustworthy(DIGEST, REGISTRY, entry) is False

    def test_rejects_entry_for_stale_pin(self) -> None:
        entry = _valid_entry(provenance={"commit_sha": OTHER_COMMIT})
        assert _cached_result_is_trustworthy(DIGEST, REGISTRY, entry) is False

    def test_rejects_entry_with_failed_provenance(self) -> None:
        entry = _valid_entry(provenance_verified=False)
        assert _cached_result_is_trustworthy(DIGEST, REGISTRY, entry) is False

    def test_rejects_entry_with_no_pin_configured(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # An unpinned (empty) commit fails closed, matching full verification.
        monkeypatch.setattr(
            "verifier.verifications.image.CERT_EXPECTED_COMMITS", {REGISTRY: ""}
        )
        assert _cached_result_is_trustworthy(DIGEST, REGISTRY, _valid_entry()) is False

    def test_reviewed_set_replaces_single_pin(self) -> None:
        entry = _valid_entry(provenance={"commit_sha": OTHER_COMMIT})
        reviewed = frozenset({OTHER_COMMIT})
        assert _cached_result_is_trustworthy(DIGEST, REGISTRY, entry, reviewed) is True
        # The single pin is not implicitly in the reviewed set.
        assert (
            _cached_result_is_trustworthy(DIGEST, REGISTRY, _valid_entry(), reviewed)
            is False
        )


class TestVerifyImageFullCacheGate:
    def test_uses_valid_cache_entry_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PRE_VERIFY_DISABLED", raising=False)
        entry = _valid_entry()
        with patch("verifier.s3_cache.load_pre_verification", return_value=entry):
            result = verify_image_full(DIGEST, REGISTRY, POLICY)
        assert result == entry

    def test_disabled_skips_cache(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRE_VERIFY_DISABLED", "1")
        with (
            patch("verifier.s3_cache.load_pre_verification") as mock_load,
            patch(
                "verifier.verifications.image.extract_provenance_attestation",
                return_value=None,
            ),
        ):
            verify_image_full(DIGEST, REGISTRY, POLICY)
        mock_load.assert_not_called()

    def test_commit_mismatch_fails_closed_without_crashing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Recorded as provenance_found=False, never raised.
        monkeypatch.setenv("PRE_VERIFY_DISABLED", "1")
        with patch(
            "verifier.verifications.image.extract_provenance_attestation",
            side_effect=ValueError("Commit SHA mismatch for 'nearaidev/cloud-api'"),
        ):
            result = verify_image_full(DIGEST, REGISTRY, POLICY)
        assert result["provenance_found"] is False
        assert any("Provenance check failed" in m for m in result["messages"])

    def test_ignores_tampered_cache_entry_and_reverifies(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PRE_VERIFY_DISABLED", raising=False)
        # Tampered: claims a pass but for a different digest.
        tampered = _valid_entry(image=f"{REGISTRY}@{OTHER_DIGEST}")
        with (
            patch("verifier.s3_cache.load_pre_verification", return_value=tampered),
            # Force the fresh path to terminate quickly without network/docker.
            patch(
                "verifier.verifications.image.extract_provenance_attestation",
                return_value=None,
            ),
        ):
            result = verify_image_full(DIGEST, REGISTRY, POLICY)
        # We must NOT have returned the tampered entry; the fresh run finds no
        # provenance and fails closed.
        assert result != tampered
        assert result["provenance_found"] is False
