# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tests for verifier.s3_upload per-image approval objects."""

from typing import Any
from unittest.mock import MagicMock, patch

import boto3
import botocore.exceptions
import pytest

from verifier.s3_upload import (
    _digest_from_ref,
    persist_results,
    upload_per_image_objects,
    upload_to_s3,
)

HEX_A = "a" * 64
HEX_B = "b" * 64

SUMMARIES: list[dict[str, Any]] = [
    {
        "type": "Gateway",
        "image_verification": {
            "images": {
                f"nearaidev/cloud-api@sha256:{HEX_A}": {"provenance_verified": True},
                f"nearaidev/cvm-ingress@sha256:{HEX_B}": {"provenance_verified": True},
            }
        },
    },
    {"type": "Model #1", "gpu_verified": True},
    {"type": "Domain TLS Certificate", "certificate_verified": True},
]


class TestDigestFromRef:
    def test_extracts_digest_from_full_ref(self) -> None:
        assert _digest_from_ref(f"nearaidev/cloud-api@sha256:{HEX_A}") == (
            f"sha256:{HEX_A}"
        )

    def test_passes_through_bare_digest(self) -> None:
        assert _digest_from_ref(f"sha256:{HEX_A}") == f"sha256:{HEX_A}"

    def test_returns_empty_for_non_digest_ref(self) -> None:
        assert _digest_from_ref("nearaidev/cloud-api@not-found") == ""


class TestUploadPerImageObjects:
    def test_writes_one_object_per_digest(self) -> None:
        with patch("verifier.s3_upload.save_pre_verification") as mock_save:
            upload_per_image_objects(SUMMARIES)
        saved_digests = sorted(call.args[0] for call in mock_save.call_args_list)
        assert saved_digests == sorted([f"sha256:{HEX_A}", f"sha256:{HEX_B}"])

    def test_passes_per_image_result_as_body(self) -> None:
        with patch("verifier.s3_upload.save_pre_verification") as mock_save:
            upload_per_image_objects(SUMMARIES)
        for call in mock_save.call_args_list:
            assert call.args[1] == {"provenance_verified": True}

    def test_skips_entries_without_digest(self) -> None:
        summaries: list[dict[str, Any]] = [
            {"image_verification": {"images": {"nearaidev/x@not-found": {}}}},
        ]
        with patch("verifier.s3_upload.save_pre_verification") as mock_save:
            upload_per_image_objects(summaries)
        mock_save.assert_not_called()

    def test_handles_summaries_without_image_verification(self) -> None:
        with patch("verifier.s3_upload.save_pre_verification") as mock_save:
            upload_per_image_objects([{"type": "Model #1", "gpu_verified": True}])
        mock_save.assert_not_called()

    def test_writes_markers_for_validated_inference_near_images(self) -> None:
        # Inference NEAR images are carried in image_verification (fully
        # validated), so they get markers via the same path as the gateway.
        # The third-party model image is NOT in image_verification -> no marker.
        summaries: list[dict[str, Any]] = [
            {
                "type": "Inference: gpt-oss-120b",
                "image_verification": {
                    "images": {
                        f"nearaidev/compose-manager@sha256:{HEX_A}": {
                            "provenance_verified": True,
                            "build_reproducible": True,
                        }
                    }
                },
            }
        ]
        with patch("verifier.s3_upload.save_pre_verification") as mock_save:
            upload_per_image_objects(summaries)
        saved = sorted(call.args[0] for call in mock_save.call_args_list)
        assert saved == [f"sha256:{HEX_A}"]


class TestUploadToS3:
    def test_writes_concat_hash_object_and_per_image_objects(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("NEAR_BUCKET_NAME", "test-bucket")
        mock_s3 = MagicMock()
        with (
            patch("verifier.s3_upload._s3_client", return_value=mock_s3),
            patch("verifier.s3_upload.save_pre_verification") as mock_save,
        ):
            upload_to_s3(SUMMARIES)

        # One concat-hash object...
        assert mock_s3.put_object.call_count == 1
        # ...plus one per-image object per digest.
        assert mock_save.call_count == 2


class TestPersistResults:
    def test_returns_true_on_success(self) -> None:
        with patch("verifier.s3_upload.upload_to_s3") as mock_up:
            assert persist_results(SUMMARIES) is True
        mock_up.assert_called_once()

    def test_returns_false_on_missing_bucket(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # upload_to_s3 raises ValueError when NEAR_BUCKET_NAME is unset; that must
        # be caught and reported as a persistence failure, not propagated.
        monkeypatch.delenv("NEAR_BUCKET_NAME", raising=False)
        assert persist_results(SUMMARIES) is False

    @pytest.mark.parametrize(
        "error",
        [
            boto3.exceptions.Boto3Error("boom"),
            botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "no"}}, "PutObject"
            ),
            botocore.exceptions.NoCredentialsError(),
        ],
        ids=["boto3", "client-error", "no-credentials"],
    )
    def test_returns_false_on_boto_error(self, error: Exception) -> None:
        with patch("verifier.s3_upload.upload_to_s3", side_effect=error):
            assert persist_results(SUMMARIES) is False
