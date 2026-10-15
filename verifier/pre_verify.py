# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Pre-verify container images ahead of release to eliminate image-check latency."""

import argparse
import logging
import sys
from dataclasses import replace
from pathlib import Path

from .config import CERT_REPOSITORIES
from .models import create_verification_policy
from .s3_cache import is_full_pass, save_pre_verification
from .verifications.image import compose_images, pinned_images, verify_image_full

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def _images_from_compose(compose_content: str) -> list[tuple[str, str]]:
    """Return (registry, digest) pairs for all pinned images in a compose file."""
    return pinned_images(compose_images(compose_content))


def _pre_verify_image(registry: str, digest: str) -> bool:
    """Verify image fully and cache the result in S3. Returns True on success."""
    policy = replace(
        create_verification_policy(CERT_REPOSITORIES), required_images=[registry]
    )
    logger.info(f"Pre-verifying {registry}@{digest[:19]}...")
    result = verify_image_full(image_digest=digest, registry=registry, policy=policy)
    save_pre_verification(digest, result)
    passed = is_full_pass(result)
    status = "✅" if passed else "❌"
    logger.info(
        f"{status} {registry}: "
        f"provenance_verified={result.get('provenance_verified', False)}, "
        f"build_reproducible={result.get('build_reproducible', False)}"
    )
    return passed


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Pre-verify container images so release-time verification skips "
            "the slow cosign and reproducibility steps."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--compose",
        type=Path,
        metavar="FILE",
        help="Docker Compose file to extract images from",
    )
    source.add_argument(
        "--image",
        nargs="+",
        metavar="REGISTRY@DIGEST",
        help="One or more image references (registry@sha256:...)",
    )
    args = parser.parse_args()

    images: list[tuple[str, str]] = []

    if args.compose:
        content = args.compose.read_text()
        images = _images_from_compose(content)
        if not images:
            logger.error(
                f"No pinned images (registry@sha256:...) found in {args.compose}"
            )
            sys.exit(1)
        logger.info(f"Found {len(images)} pinned image(s) in {args.compose}")
    else:
        for ref in args.image:
            if "@sha256:" not in ref:
                logger.error(f"Image reference must include digest: {ref!r}")
                sys.exit(1)
            registry, digest = ref.split("@", 1)
            images.append((registry, digest))

    failed = 0
    for registry, digest in images:
        if not _pre_verify_image(registry, digest):
            failed += 1

    total = len(images)
    passed = total - failed
    logger.info(f"\nPre-verification complete: {passed}/{total} passed")

    if failed:
        logger.error(f"❌ {failed} image(s) failed pre-verification")
        sys.exit(1)

    logger.info("✅ All images pre-verified and cached in S3")


if __name__ == "__main__":
    main()
