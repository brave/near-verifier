# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

from dataclasses import dataclass
from typing import Any, TypedDict

from .config import CERT_SKIP_REPRODUCIBILITY


@dataclass
class ProvenanceInfo:
    """Structured provenance information from SLSA attestation."""

    source_repo: str
    commit_sha: str
    builder_id: str
    build_type: str


@dataclass
class VerificationPolicy:
    """Policy defining what's acceptable for verification."""

    allowed_repos: list[str]  # e.g., ["https://github.com/nearai/*"]
    allowed_builders: list[str]
    required_images: list[str]
    require_reproducible_build: bool
    skip_reproducibility_images: set[str]  # image prefixes exempt from the above


class SourceVerificationResult(TypedDict, total=False):
    images: dict[str, Any]
    # Images present in the compose that this tool does not verify at all.
    unverified_images: list[str]
    error: str


def create_verification_policy(
    repositories: dict[str, str],
    require_reproducible_build: bool = True,
) -> VerificationPolicy:
    """Verification policy requiring every image in the image-to-repo map."""
    repos = list(repositories.values())
    return VerificationPolicy(
        allowed_repos=[f"https://github.com/{repo}" for repo in repos],
        allowed_builders=[f"https://github.com/{repo}/*" for repo in repos],
        required_images=list(repositories.keys()),
        require_reproducible_build=require_reproducible_build,
        skip_reproducibility_images=CERT_SKIP_REPRODUCIBILITY,
    )
