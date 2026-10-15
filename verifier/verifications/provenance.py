# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""SLSA provenance extraction and verification."""

import base64
import json
import subprocess
from typing import Any

from ..config import CERT_EXPECTED_COMMITS, CERT_IDENTITY_REGEXP, CERT_OIDC_ISSUER
from ..models import ProvenanceInfo, VerificationPolicy
from ..utils import COMMIT_SHA_RE, get_logger

logger = get_logger(__name__)


def extract_provenance_attestation(
    image_ref: str, allowed_commits: frozenset[str] | None = None
) -> ProvenanceInfo | None:
    """Sigstore-verify an image's SLSA provenance and check its commit pin.

    ``allowed_commits`` replaces the single ``CERT_EXPECTED_COMMITS`` pin with
    a set of reviewed commits. Raises ValueError if no pin is configured or the
    commit does not match.
    """
    image_ref_trunc = image_ref.split("@")[0].strip().split(":")[0].strip()

    expected_commit = CERT_EXPECTED_COMMITS.get(image_ref_trunc, "")
    if allowed_commits is not None:
        expected_commit = ", ".join(sorted(allowed_commits))
    commands = _get_cosign_commands(image_ref)

    for cmd, version in commands:
        try:
            result = _run_cosign_verification(cmd)
            if not result:
                logger.debug(
                    "Returning early from provenance extraction: Missing result"
                )
                continue

            payload = _extract_payload(result)
            if not payload:
                logger.debug(
                    "Returning early from provenance extraction: Extraction failed"
                )
                continue

            predicate = payload.get("predicate", {})
            provenance_info = _parse_provenance(predicate)

            if provenance_info is None:
                logger.error(f"Error in provenance response: {result}")
                continue

            if not expected_commit:
                raise ValueError(
                    f"No expected commit SHA configured for image "
                    f"{image_ref_trunc!r}; deployed commit is "
                    f"{provenance_info.commit_sha}. Audit it, then set "
                    f"CERT_EXPECTED_COMMITS[{image_ref_trunc!r}] in config.py "
                    "to that commit."
                )

            if allowed_commits is not None:
                if provenance_info.commit_sha not in allowed_commits:
                    raise ValueError(
                        f"Commit SHA mismatch for {image_ref_trunc!r}:\n"
                        f"\texpected one of: {expected_commit}\n"
                        f"\tgot:      {provenance_info.commit_sha}"
                    )
            elif provenance_info.commit_sha != expected_commit:
                raise ValueError(
                    f"Commit SHA mismatch for {image_ref_trunc!r}:\n"
                    f"\texpected: {expected_commit}\n"
                    f"\tgot:      {provenance_info.commit_sha}"
                )

            return provenance_info

        except subprocess.CalledProcessError as e:
            logger.debug("cosign %s failed for %s: %s", version, image_ref, e.stderr)
            continue
        except subprocess.TimeoutExpired:
            logger.warning(
                "cosign %s timed out for %s; trying the next command",
                version,
                image_ref,
            )
            continue
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"⚠️ Failed to parse {version} provenance: {e}")
            continue

    if not expected_commit:
        raise ValueError(
            f"No expected commit SHA configured for image {image_ref_trunc!r}, "
            "and no SLSA provenance attestation was found to extract a deployed "
            f"commit from. Set CERT_EXPECTED_COMMITS[{image_ref_trunc!r}] in "
            "config.py once the image's provenance is available and audited."
        )
    return None


def _get_cosign_commands(image_ref: str) -> list:
    """Generate cosign commands for different SLSA versions."""
    image_ref_without_sha256 = image_ref.split("@")[0].strip()
    image_ref_trunc = image_ref_without_sha256.split(":")[0].strip()

    cert_identity_regexp = CERT_IDENTITY_REGEXP.get(image_ref_trunc)
    if cert_identity_regexp is None:
        raise ValueError(
            f"No certificate identity regexp configured for image {image_ref_trunc!r}."
            " Add an entry to CERT_IDENTITY_REGEXP in config.py."
        )

    base_flags = [
        "--certificate-identity-regexp",
        cert_identity_regexp,
        "--certificate-oidc-issuer",
        CERT_OIDC_ISSUER,
    ]

    cmd_v1 = [
        "cosign",
        "verify-attestation",
        image_ref,
        "--type",
        "https://slsa.dev/provenance/v1",
        *base_flags,
    ]

    cmd_v02 = [
        "cosign",
        "verify-attestation",
        image_ref,
        "--type",
        "slsaprovenance",
        *base_flags,
    ]

    return [(cmd_v1, "v1"), (cmd_v02, "v0.2")]


def _run_cosign_verification(cmd: list[str]) -> str | None:
    """Run cosign verification command and return stdout."""
    result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)  # nosec B603
    return result.stdout.strip()


def _extract_payload(output: str) -> dict[str, Any] | None:
    """Extract and decode the payload from cosign output."""
    json_output = _find_json_line(output)
    if not json_output:
        logger.error(f"Unexpected cosign response: {output}")
        return None
    attestation_wrapper: dict[str, Any] = json.loads(json_output)
    payload_b64 = attestation_wrapper.get("payload")
    if not payload_b64:
        logger.error(f"Unexpected cosign response: {output}")
        return None
    payload_data: dict[str, Any] = json.loads(base64.b64decode(payload_b64).decode())
    return payload_data


def _find_json_line(output: str) -> str | None:
    """Find the first line that starts with '{' in the output."""
    return next((line for line in output.split("\n") if line.startswith("{")), None)


def _parse_provenance(predicate: dict) -> ProvenanceInfo | None:
    """Parse provenance data based on SLSA version."""
    if "buildDefinition" in predicate:
        return _parse_slsa_v1(predicate)
    elif "materials" in predicate:
        return _parse_slsa_v02(predicate)
    return None


def _parse_slsa_v1(predicate: dict) -> ProvenanceInfo:
    """Parse SLSA v1.0 format provenance."""
    build_def = predicate["buildDefinition"]
    resolved_deps = build_def.get("resolvedDependencies", [])

    repo, commit = _extract_git_source(resolved_deps)

    builder_id = predicate.get("runDetails", {}).get("builder", {}).get("id", "unknown")
    build_type = build_def.get("buildType", "unknown")

    return ProvenanceInfo(
        source_repo=repo,
        commit_sha=commit,
        builder_id=builder_id,
        build_type=build_type,
    )


def _parse_slsa_v02(predicate: dict) -> ProvenanceInfo:
    """Parse SLSA v0.2 format provenance."""
    materials = predicate.get("materials", [])
    repo, commit = _extract_git_source_v02(materials)

    return ProvenanceInfo(
        source_repo=repo,
        commit_sha=commit,
        builder_id=predicate.get("builder", {}).get("id", "unknown"),
        build_type=predicate.get("buildType", "unknown"),
    )


def _extract_git_source(resolved_deps: list) -> tuple[str, str]:
    """Extract git repo and commit from SLSA v1 resolved dependencies."""
    source_dep = next(
        (d for d in resolved_deps if d.get("uri", "").startswith("git+")), None
    )

    if not source_dep:
        return "unknown", "unknown"

    uri = source_dep["uri"]
    repo = (
        uri.replace("git+", "").split("@")[0] if "@" in uri else uri.replace("git+", "")
    )
    commit = source_dep.get("digest", {}).get("gitCommit", "unknown")

    return repo, commit


def _extract_git_source_v02(materials: list) -> tuple[str, str]:
    """Extract git repo and commit from SLSA v0.2 materials."""
    source_material = next(
        (m for m in materials if m.get("uri", "").startswith("git+")), None
    )

    if not source_material:
        return "unknown", "unknown"

    uri = source_material["uri"]

    if "@" in uri:
        repo, commit = uri.split("@")
        repo = repo.replace("git+", "")
    else:
        repo = uri.replace("git+", "")
        commit = "unknown"

    return repo, commit


def verify_provenance_against_policy(
    provenance: ProvenanceInfo, policy: VerificationPolicy
) -> tuple[bool, list[str]]:
    """Verify provenance against policy; returns (success, messages)."""
    messages = []
    success = True

    repo_success, repo_message = _verify_repository(
        provenance.source_repo, policy.allowed_repos
    )
    success &= repo_success
    messages.append(repo_message)

    builder_success, builder_message = _verify_builder(
        provenance.builder_id, policy.allowed_builders
    )
    success &= builder_success
    messages.append(builder_message)

    sha_success, sha_message = _validate_commit_sha(provenance.commit_sha)
    success &= sha_success
    messages.append(sha_message)

    return success, messages


def _verify_repository(source_repo: str, allowed_repos: list[str]) -> tuple[bool, str]:
    """Check if source repository matches allowed patterns."""
    if _matches_any_pattern(source_repo, allowed_repos):
        return True, f"✅ Source repository allowed: {source_repo}"
    else:
        return False, f"❌ Repo '{source_repo}' not in {allowed_repos}"


def _verify_builder(builder_id: str, allowed_builders: list[str]) -> tuple[bool, str]:
    """Check if builder matches allowed patterns."""
    if _matches_any_pattern(builder_id, allowed_builders):
        return True, f"✅ Builder allowed: {builder_id}"
    else:
        return False, f"❌ Builder '{builder_id}' not in allowed list"


def _matches_any_pattern(value: str, patterns: list[str]) -> bool:
    """Check if value matches any of the allowed patterns."""
    return any(_matches_pattern(value, pattern) for pattern in patterns)


def _matches_pattern(value: str, pattern: str) -> bool:
    """Check if value matches a pattern (a trailing * is a prefix wildcard).

    ``repo/*`` keeps its slash, so it does not match a sibling ``repo-evil``.
    """
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return value == pattern


def _validate_commit_sha(commit_sha: str) -> tuple[bool, str]:
    """A provenance commit must be a full 40-hex SHA."""
    if COMMIT_SHA_RE.fullmatch(commit_sha):
        return True, f"✅ Valid commit SHA: {commit_sha}"
    return False, f"❌ Provenance commit is not a full SHA: {commit_sha!r}"
