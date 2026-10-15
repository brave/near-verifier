# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""S3 upload functionality for verification reports."""

import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

import boto3
import botocore.exceptions

from .s3_cache import _s3_client, save_pre_verification
from .utils import hash_digests

logger = logging.getLogger(__name__)


def _digest_from_ref(image_ref: str) -> str:
    """Return the ``sha256:...`` digest from an image reference, or '' if none."""
    if "@sha256:" in image_ref:
        return "sha256:" + image_ref.split("@sha256:")[1]
    if image_ref.startswith("sha256:"):
        return image_ref
    return ""


def upload_per_image_objects(summaries: list[dict[str, Any]]) -> None:
    """Write one approval object per image digest; call only after validation passes."""
    for item in summaries:
        image_verification = item.get("image_verification") or {}
        for image_ref, result in image_verification.get("images", {}).items():
            digest = _digest_from_ref(image_ref)
            if digest:
                save_pre_verification(digest, result)


def upload_to_s3(summaries: list[dict[str, Any]]) -> None:
    """Upload verification summaries to S3."""
    logger.info("Validation passed. Preparing to upload to S3...")

    summary_json = json.dumps(summaries, indent=2, ensure_ascii=False)
    logger.debug(f"JSON serialized successfully. Length: {len(summary_json)} bytes")

    s3_client = _s3_client()
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d_%H-%M-%S")
    report_s3_key = hash_digests(summaries)

    bucket_name = os.environ.get("NEAR_BUCKET_NAME")
    if not bucket_name:
        raise ValueError("NEAR_BUCKET_NAME environment variable not set")

    logger.info(f"Uploading to S3: bucket={bucket_name}, key={report_s3_key}")

    s3_client.put_object(
        Bucket=bucket_name,
        Key=report_s3_key,
        Body=summary_json,
        ContentType="text/plain",
        Metadata={"verification-timestamp": timestamp},
    )

    logger.info(
        {
            "success": True,
            "message": "Report successfully saved to S3",
            "report_s3_key": report_s3_key,
            "bucket": bucket_name,
            "validation_passed": True,
        }
    )

    upload_per_image_objects(summaries)


def persist_results(summaries: list[dict[str, Any]]) -> bool:
    """Persist the report and per-image markers to S3; False on any error."""
    try:
        upload_to_s3(summaries)
        return True
    except (
        ValueError,
        OSError,
        boto3.exceptions.Boto3Error,
        botocore.exceptions.BotoCoreError,
        botocore.exceptions.ClientError,
    ) as e:
        logger.error("❌ S3 persistence failed: %s", e)
        return False
