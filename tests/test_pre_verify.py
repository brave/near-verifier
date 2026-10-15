# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tests for verifier.pre_verify and the cache-lookup path in verify_image_full."""

from textwrap import dedent
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from verifier.pre_verify import _images_from_compose, _pre_verify_image

DIGEST = "sha256:" + "b" * 64
REGISTRY = "nearaidev/cloud-api"
PINNED_COMMIT = "c" * 40

SAMPLE_COMPOSE = dedent(f"""\
    services:
      api:
        image: {REGISTRY}@{DIGEST}
      ingress:
        image: nearaidev/cvm-ingress@sha256:{"c" * 64}
      unpinned:
        image: someimage:latest
""")

_FAKE_RESULT = {
    "image": f"{REGISTRY}@{DIGEST}",
    "provenance_found": True,
    "provenance_verified": True,
    "build_reproducible": True,
    "build_result": {"status": "✅ passed", "digest": DIGEST, "expected": DIGEST},
    "provenance": {"commit_sha": PINNED_COMMIT},
    "messages": [],
}


class TestImagesFromCompose:
    def test_finds_all_pinned_images(self) -> None:
        results = _images_from_compose(SAMPLE_COMPOSE)
        assert len(results) == 2

    def test_returns_registry_and_digest_tuples(self) -> None:
        results = _images_from_compose(SAMPLE_COMPOSE)
        registries, digests = zip(*results, strict=False)
        assert REGISTRY in registries
        assert DIGEST in digests

    def test_skips_unpinned_tags(self) -> None:
        results = _images_from_compose(SAMPLE_COMPOSE)
        for _, digest in results:
            assert digest.startswith("sha256:")

    def test_empty_compose_returns_empty_list(self) -> None:
        assert _images_from_compose("") == []

    def test_single_image(self) -> None:
        compose = f"services:\n  api:\n    image: {REGISTRY}@{DIGEST}\n"
        results = _images_from_compose(compose)
        assert results == [(REGISTRY, DIGEST)]


class TestPreVerifyImage:
    def test_saves_result_to_s3_cache(self) -> None:
        with (
            patch("verifier.pre_verify.verify_image_full", return_value=_FAKE_RESULT),
            patch("verifier.pre_verify.save_pre_verification") as mock_save,
        ):
            _pre_verify_image(REGISTRY, DIGEST)
        mock_save.assert_called_once_with(DIGEST, _FAKE_RESULT)

    def test_returns_true_when_provenance_verified(self) -> None:
        with (
            patch("verifier.pre_verify.verify_image_full", return_value=_FAKE_RESULT),
            patch("verifier.pre_verify.save_pre_verification"),
        ):
            assert _pre_verify_image(REGISTRY, DIGEST) is True

    def test_returns_false_when_provenance_fails(self) -> None:
        failed = {**_FAKE_RESULT, "provenance_verified": False}
        with (
            patch("verifier.pre_verify.verify_image_full", return_value=failed),
            patch("verifier.pre_verify.save_pre_verification"),
        ):
            assert _pre_verify_image(REGISTRY, DIGEST) is False

    def test_still_saves_on_failure(self) -> None:
        failed = {**_FAKE_RESULT, "provenance_verified": False}
        with (
            patch("verifier.pre_verify.verify_image_full", return_value=failed),
            patch("verifier.pre_verify.save_pre_verification") as mock_save,
        ):
            _pre_verify_image(REGISTRY, DIGEST)
        mock_save.assert_called_once()


class TestVerifyImageFullCacheLookup:
    """Verify that a cache hit bypasses the expensive cosign/build path."""

    _CACHED = {**_FAKE_RESULT, "messages": ["from cache"]}

    @pytest.fixture(autouse=True)
    def _pin_registry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Cache hits are trusted only for the pinned commit; pin REGISTRY hermetically.
        monkeypatch.setattr(
            "verifier.verifications.image.CERT_EXPECTED_COMMITS",
            {REGISTRY: PINNED_COMMIT},
        )

    def _call_verify_image_full(self) -> Any:
        from verifier.verifications.image import verify_image_full

        return verify_image_full(
            image_digest=DIGEST,
            registry=REGISTRY,
            policy=MagicMock(
                require_reproducible_build=True,
                skip_reproducibility_images=set(),
            ),
        )

    def test_returns_cached_result_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PRE_VERIFY_DISABLED", raising=False)
        with patch(
            "verifier.s3_cache.load_pre_verification", return_value=self._CACHED
        ):
            result = self._call_verify_image_full()
        assert result["messages"] == ["from cache"]

    def test_cache_hit_skips_cosign(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PRE_VERIFY_DISABLED", raising=False)
        with (
            patch("verifier.s3_cache.load_pre_verification", return_value=self._CACHED),
            patch(
                "verifier.verifications.image.extract_provenance_attestation"
            ) as mock_prov,
        ):
            self._call_verify_image_full()
        mock_prov.assert_not_called()

    def test_cache_miss_falls_through_to_full_verification(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PRE_VERIFY_DISABLED", raising=False)
        with (
            patch("verifier.s3_cache.load_pre_verification", return_value=None),
            patch(
                "verifier.verifications.image.extract_provenance_attestation",
                return_value=None,
            ) as mock_prov,
        ):
            result = self._call_verify_image_full()
        mock_prov.assert_called_once()
        assert result["provenance_found"] is False

    def test_cache_not_consulted_when_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PRE_VERIFY_DISABLED", "1")
        with (
            patch("verifier.s3_cache.load_pre_verification") as mock_load,
            patch(
                "verifier.verifications.image.extract_provenance_attestation",
                return_value=None,
            ),
        ):
            self._call_verify_image_full()
        mock_load.assert_not_called()
