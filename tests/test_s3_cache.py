# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tests for verifier.s3_cache."""

import json
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest

from verifier.s3_cache import (
    _s3_client,
    load_pre_verification,
    save_pre_verification,
    save_serving_compose,
    save_signing_key,
)


@pytest.fixture(autouse=True)
def _clear_s3_client_cache() -> Iterator[None]:
    """The S3 client is cached, so a mock from one test would leak into the next."""
    _s3_client.cache_clear()
    yield
    _s3_client.cache_clear()


DIGEST = "sha256:" + "a" * 64
HEX = "a" * 64
RESULT = {
    "image": f"nearaidev/cloud-api@{DIGEST}",
    "provenance_verified": True,
    "build_reproducible": True,
}

SIGNING_KEY = "0x" + "c" * 64
SIGNING_META = {"component": "Gateway", "signing_algo": "ecdsa"}


def _client_error(code: str) -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": code}}, "GetObject"
    )


class TestSavePreVerification:
    def test_writes_to_correct_bucket_and_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("NEAR_BUCKET_NAME", "test-bucket")
        mock_s3 = MagicMock()
        with patch("verifier.s3_cache.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_s3
            save_pre_verification(DIGEST, RESULT)
        call_kwargs = mock_s3.put_object.call_args.kwargs
        assert call_kwargs["Bucket"] == "test-bucket"
        assert call_kwargs["Key"] == f"pre-verified/{HEX}.json"

    def test_body_is_json_serialised_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("NEAR_BUCKET_NAME", "bucket")
        mock_s3 = MagicMock()
        with patch("verifier.s3_cache.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_s3
            save_pre_verification(DIGEST, RESULT)
        body = mock_s3.put_object.call_args.kwargs["Body"]
        assert json.loads(body) == RESULT

    def test_strips_sha256_prefix_from_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("NEAR_BUCKET_NAME", "bucket")
        mock_s3 = MagicMock()
        with patch("verifier.s3_cache.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_s3
            save_pre_verification(
                "sha256:deadbeef",
                {
                    "image": "x",
                    "provenance_verified": True,
                    "build_reproducible": True,
                },
            )
        key = mock_s3.put_object.call_args.kwargs["Key"]
        assert key == "pre-verified/deadbeef.json"

    def test_refuses_to_write_non_full_pass(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A failed or provenance-only result must never seed the access gate.
        monkeypatch.setenv("NEAR_BUCKET_NAME", "bucket")
        mock_s3 = MagicMock()
        with patch("verifier.s3_cache.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_s3
            save_pre_verification(
                DIGEST,
                {
                    "image": f"nearaidev/cloud-api@{DIGEST}",
                    "provenance_verified": True,
                    "build_reproducible": False,
                },
            )
        mock_s3.put_object.assert_not_called()

    def test_raises_without_bucket_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NEAR_BUCKET_NAME", raising=False)
        with pytest.raises(ValueError, match="NEAR_BUCKET_NAME"):
            save_pre_verification(DIGEST, RESULT)


class TestLoadPreVerification:
    def test_returns_cached_result_on_hit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("NEAR_BUCKET_NAME", "test-bucket")
        mock_s3 = MagicMock()
        mock_s3.get_object.return_value = {
            "Body": MagicMock(read=lambda: json.dumps(RESULT).encode())
        }
        with patch("verifier.s3_cache.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_s3
            result = load_pre_verification(DIGEST)
        assert result == RESULT

    def test_reads_correct_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEAR_BUCKET_NAME", "test-bucket")
        mock_s3 = MagicMock()
        mock_s3.get_object.return_value = {"Body": MagicMock(read=lambda: b"{}")}
        with patch("verifier.s3_cache.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_s3
            load_pre_verification(DIGEST)
        call_kwargs = mock_s3.get_object.call_args.kwargs
        assert call_kwargs["Bucket"] == "test-bucket"
        assert call_kwargs["Key"] == f"pre-verified/{HEX}.json"

    def test_returns_none_on_cache_miss(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEAR_BUCKET_NAME", "test-bucket")
        mock_s3 = MagicMock()
        mock_s3.get_object.side_effect = _client_error("NoSuchKey")
        with patch("verifier.s3_cache.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_s3
            result = load_pre_verification(DIGEST)
        assert result is None

    def test_returns_none_on_other_client_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("NEAR_BUCKET_NAME", "test-bucket")
        mock_s3 = MagicMock()
        mock_s3.get_object.side_effect = _client_error("AccessDenied")
        with patch("verifier.s3_cache.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_s3
            result = load_pre_verification(DIGEST)
        assert result is None

    def test_returns_none_without_bucket_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("NEAR_BUCKET_NAME", raising=False)
        result = load_pre_verification(DIGEST)
        assert result is None

    def test_returns_none_on_unexpected_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("NEAR_BUCKET_NAME", "test-bucket")
        mock_s3 = MagicMock()
        mock_s3.get_object.side_effect = RuntimeError("unexpected")
        with patch("verifier.s3_cache.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_s3
            result = load_pre_verification(DIGEST)
        assert result is None


class TestSaveSigningKey:
    def test_writes_when_marker_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEAR_BUCKET_NAME", "test-bucket")
        mock_s3 = MagicMock()
        mock_s3.head_object.side_effect = _client_error("404")
        with patch("verifier.s3_cache.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_s3
            save_signing_key(SIGNING_KEY, SIGNING_META)
        call_kwargs = mock_s3.put_object.call_args.kwargs
        assert call_kwargs["Bucket"] == "test-bucket"
        # 0x prefix stripped; key is the public key itself.
        assert call_kwargs["Key"] == f"signing-keys/{'c' * 64}.json"
        body = json.loads(call_kwargs["Body"])
        assert body["signing_public_key"] == SIGNING_KEY
        assert body["component"] == "Gateway"

    def test_rewrites_existing_marker(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The bucket expires objects, so a still-valid marker is rewritten."""
        monkeypatch.setenv("NEAR_BUCKET_NAME", "test-bucket")
        mock_s3 = MagicMock()
        mock_s3.head_object.return_value = {"ContentLength": 123}
        with patch("verifier.s3_cache.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_s3
            save_signing_key(SIGNING_KEY, SIGNING_META)
        mock_s3.put_object.assert_called_once()

    def test_skips_silently_without_bucket(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("NEAR_BUCKET_NAME", raising=False)
        with patch("verifier.s3_cache.boto3") as mock_boto3:
            save_signing_key(SIGNING_KEY, SIGNING_META)
        mock_boto3.client.assert_not_called()

    def test_swallows_put_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEAR_BUCKET_NAME", "test-bucket")
        mock_s3 = MagicMock()
        mock_s3.head_object.side_effect = _client_error("NoSuchKey")
        mock_s3.put_object.side_effect = _client_error("AccessDenied")
        with patch("verifier.s3_cache.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_s3
            # Must not raise.
            save_signing_key(SIGNING_KEY, SIGNING_META)


class TestSaveServingCompose:
    def test_writes_model_scoped_marker(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEAR_BUCKET_NAME", "test-bucket")
        mock_s3 = MagicMock()
        mock_s3.head_object.side_effect = _client_error("404")
        with patch("verifier.s3_cache.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_s3
            save_serving_compose("z-ai/glm-5.3-flash", "AB" * 32, {"file": "f.yaml"})
        call_kwargs = mock_s3.put_object.call_args.kwargs
        assert (
            call_kwargs["Key"] == f"serving-compose/z-ai/glm-5.3-flash/{'ab' * 32}.json"
        )
        body = json.loads(call_kwargs["Body"])
        assert body["model"] == "z-ai/glm-5.3-flash"
        assert body["file"] == "f.yaml"
