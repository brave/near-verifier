# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Utility functions for attestation verification."""

import hashlib
import logging
import re
import threading
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Thread-local: requests.Session is not thread-safe and HTTP runs via to_thread.
_thread_local = threading.local()


# A full git commit SHA, lowercase; use with fullmatch.
COMMIT_SHA_RE = re.compile(r"[0-9a-f]{40}")


def get_http_session() -> requests.Session:
    """Return this thread's requests Session, with retry on transient errors."""
    existing: requests.Session | None = getattr(_thread_local, "session", None)
    if existing is not None:
        return existing

    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    _thread_local.session = session
    return session


def get_logger(name: str | None = None) -> logging.Logger:
    """Get a logger instance."""
    return logging.getLogger(name or __name__)


def extract_image_digests(report: list[dict[str, Any]]) -> list[str]:
    """Return the sorted ``sha256:...`` digests of every verified image."""
    digests: list[str] = []
    for item in report:
        if "image_verification" in item:
            images: dict[str, Any] = item.get("image_verification", {}).get(
                "images", {}
            )
            for image_key in images.keys():
                if "@sha256:" in image_key:
                    digest = image_key.split("@sha256:")[1]
                    digests.append(f"sha256:{digest}")
                elif "sha256:" in image_key:
                    digests.append(image_key)
    return sorted(digests)


def hash_digests(report: list[dict[str, Any]]) -> str:
    sorted_digests: list[str] = extract_image_digests(report)
    logger = logging.getLogger(__name__)
    logger.info(f"Sorted digests for S3 key: {sorted_digests}")
    concatenated: str = "".join(sorted_digests)
    logger.info(f"Concatenated digests for S3 key: {concatenated}")
    sha256_hash: str = hashlib.sha256(concatenated.encode()).hexdigest()
    logger.info(f"Hashed digests for S3 key: {sha256_hash}")
    return sha256_hash
