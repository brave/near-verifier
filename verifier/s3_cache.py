# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""S3 objects shared with the gateway relay: pre-verified image results, and
the signing-key and serving-compose markers it trusts."""

import json
import logging
import os
from collections.abc import Mapping
from functools import lru_cache
from typing import Any

import boto3
import botocore.exceptions

from .config import (
    CERT_SKIP_REPRODUCIBILITY,
    PRE_VERIFY_KEY_PREFIX,
    SERVING_COMPOSE_KEY_PREFIX,
    SERVING_LOG_KEY_PREFIX,
    SIGNING_KEY_KEY_PREFIX,
)

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _s3_client() -> Any:
    """Shared S3 client."""
    return boto3.client("s3")


def _key(image_digest: str) -> str:
    return PRE_VERIFY_KEY_PREFIX + image_digest.removeprefix("sha256:") + ".json"


def _signing_key_key(signing_public_key: str) -> str:
    return SIGNING_KEY_KEY_PREFIX + signing_public_key.removeprefix("0x") + ".json"


def _put_marker(key: str, record: dict[str, Any], label: str) -> None:
    """Write an approval marker. Best-effort.

    Always rewritten, even when it exists: the bucket expires objects after
    120 days, so each passing run restarts the clock on what it still approves.
    """
    bucket_name = os.environ.get("NEAR_BUCKET_NAME")
    if not bucket_name:
        logger.info(f"NEAR_BUCKET_NAME not set; skipping {label} record")
        return
    client = _s3_client()
    body = json.dumps(record, indent=2, ensure_ascii=False)
    try:
        client.put_object(
            Bucket=bucket_name,
            Key=key,
            Body=body,
            ContentType="application/json",
        )
        logger.info(f"{label} recorded: s3://{bucket_name}/{key}")
    except botocore.exceptions.ClientError as e:
        logger.warning(f"Failed to record {label} ({key}): {e}")


def save_signing_key(signing_public_key: str, metadata: dict[str, Any]) -> None:
    """Record a signing public key seen in a TDX-verified attestation."""
    _put_marker(
        _signing_key_key(signing_public_key),
        {**metadata, "signing_public_key": signing_public_key},
        "Signing key",
    )


def serving_compose_key(model: str, file_sha256: str) -> str:
    return f"{SERVING_COMPOSE_KEY_PREFIX}{model}/{file_sha256.lower()}.json"


def save_serving_compose(
    model: str, file_sha256: str, metadata: dict[str, Any]
) -> None:
    """Record a serving compose (and so its model weights) as approved for
    ``model``."""
    _put_marker(
        serving_compose_key(model, file_sha256),
        {**metadata, "model": model, "file_sha256": file_sha256},
        "Serving compose",
    )


def serving_log_key(model: str, head: str) -> str:
    return f"{SERVING_LOG_KEY_PREFIX}{model}/{head}.json"


def save_serving_log(model: str, head: str, metadata: dict[str, Any]) -> None:
    """Record the compose history ending at ``head`` as verified for ``model``."""
    _put_marker(
        serving_log_key(model, head),
        {**metadata, "model": model, "compose_log": head},
        "Serving log",
    )


def is_full_pass(result: Mapping[str, Any]) -> bool:
    """True only for provenance verified AND reproduced (or exempt): presence
    in the pre-verified keyspace is treated as approval."""
    if result.get("provenance_verified") is not True:
        return False
    if result.get("build_reproducible") is True:
        return True
    registry = str(result.get("image", "")).split("@")[0].split(":")[0]
    return registry in CERT_SKIP_REPRODUCIBILITY


def save_pre_verification(image_digest: str, result: Mapping[str, Any]) -> None:
    """Write a pre-verification result to S3 if it is a full pass."""
    bucket_name = os.environ.get("NEAR_BUCKET_NAME")
    if not bucket_name:
        raise ValueError("NEAR_BUCKET_NAME environment variable not set")
    if not is_full_pass(result):
        logger.warning(
            "Refusing to cache %s in the pre-verified access gate: not a full "
            "pass (provenance_verified=%s, build_reproducible=%s)",
            result.get("image", image_digest),
            result.get("provenance_verified"),
            result.get("build_reproducible"),
        )
        return
    key = _key(image_digest)
    _s3_client().put_object(
        Bucket=bucket_name,
        Key=key,
        Body=json.dumps(result, indent=2, ensure_ascii=False),
        ContentType="application/json",
    )
    logger.info(f"Pre-verification saved: s3://{bucket_name}/{key}")


def load_pre_verification(image_digest: str) -> dict[str, Any] | None:
    """Load a pre-verification result from S3. Returns None on miss or error."""
    bucket_name = os.environ.get("NEAR_BUCKET_NAME")
    if not bucket_name:
        return None
    key = _key(image_digest)
    try:
        response = _s3_client().get_object(Bucket=bucket_name, Key=key)
        result: dict[str, Any] = json.loads(response["Body"].read())
        logger.info(f"Pre-verification cache hit: {key}")
        return result
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            logger.info(f"Pre-verification cache miss: {key}")
        else:
            logger.warning(f"S3 error loading pre-verification cache ({key}): {e}")
        return None
    except Exception as e:
        logger.warning(f"Failed to load pre-verification cache ({key}): {e}")
        return None
