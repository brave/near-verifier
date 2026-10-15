# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""SLSA provenance and reproducible-build verification of container images."""

import hashlib
import json
import os
import re
import subprocess
import tarfile
import tempfile
from contextlib import nullcontext
from pathlib import Path
from typing import Any, TypedDict

import yaml

from ..config import CERT_BUILD_ENV, CERT_EXPECTED_COMMITS
from ..models import SourceVerificationResult, VerificationPolicy
from ..utils import COMMIT_SHA_RE, get_logger
from .provenance import extract_provenance_attestation, verify_provenance_against_policy

logger = get_logger(__name__)


_GITHUB_URL_RE = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?$"
)

# A digest-pinned reference: group 1 the registry path, group 2 the digest.
_PINNED_IMAGE_RE = re.compile(r"([^@\s${}]+)@(sha256:[0-9a-f]{64})")
# A whole-value `${VAR}`, `${VAR-ref}` or `${VAR:-ref}`: group 1 the variable,
# group 2 the default reference.
_INTERPOLATED_IMAGE_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}")
# Docker Hub spellings of the same repository as the bare `owner/name`.
_DOCKER_HUB_PREFIXES = ("docker.io/", "index.docker.io/", "registry-1.docker.io/")


# In ``overridable_envs``: every variable is operator-controlled.
ANY_VAR = "*"


def compose_images(compose: str) -> list[str]:
    """The ``image`` value of every service in a docker-compose file.

    Parsed as YAML so only a service's own ``image`` key counts: an
    ``image:`` string in a label, env value or comment is not an image. A
    service with no ``image`` (e.g. ``build:``) is listed by name so it shows
    up as unverified. Unparseable input yields [], so required images go
    missing and verification fails closed.
    """
    try:
        doc = yaml.safe_load(compose)
    except yaml.YAMLError as e:
        logger.error("Compose file is not valid YAML: %s", e)
        return []
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict):
        logger.error("Compose file has no services mapping")
        return []
    images: list[str] = []
    for name, service in services.items():
        image = service.get("image") if isinstance(service, dict) else None
        images.append(str(image) if image else f"<service {name}: no image>")
    return images


def _split_image(value: str) -> tuple[str | None, str]:
    """``(variable, reference)`` of an image value, reference normalised."""
    var = None
    match = _INTERPOLATED_IMAGE_RE.fullmatch(value.strip())
    if match:
        var, value = match.group(1), match.group(2) or ""
    ref = value.strip()
    for prefix in _DOCKER_HUB_PREFIXES:
        if ref.startswith(prefix):
            ref = ref.removeprefix(prefix)
            break
    return var, ref


def image_path(value: str) -> str:
    """Registry path of an image value, e.g. ``nearaidev/cloud-api``."""
    return _repo_path(_split_image(value)[1])


def pinned_images(images: list[str]) -> list[tuple[str, str]]:
    """``(registry_path, digest)`` for every digest-pinned image value."""
    pinned = []
    for value in images:
        match = _PINNED_IMAGE_RE.fullmatch(_split_image(value)[1])
        if match:
            pinned.append((_repo_path(match.group(1)), match.group(2)))
    return pinned


def _repo_path(ref: str) -> str:
    """`registry/path` of an image reference, without digest or tag."""
    base = ref.split("@", 1)[0]
    name, _, tag = base.rpartition(":")
    return name if name and "/" not in tag else base


def compose_image_problems(
    images: list[str], required: list[str], overridable_envs: frozenset[str]
) -> tuple[list[str], list[str]]:
    """Find image values (from :func:`compose_images`) the digest check alone
    would let through.

    Returns ``(problems, unverified)``.  A problem fails compose verification:
    a required image not referenced by exactly ``path@sha256:<digest>`` (it
    would run unverified next to a pinned decoy), or one whose value comes from
    a variable in ``overridable_envs`` (the operator or a pre_launch_script can
    override the default; ``ANY_VAR`` there means every variable).
    ``unverified`` lists every other image in the compose, which this tool
    does not verify at all; it is reported so it is visible.
    """
    problems: list[str] = []
    unverified: list[str] = []
    for value in images:
        var, ref = _split_image(value)
        path = _repo_path(ref)
        if path not in required:
            unverified.append(f"${{{var}}}" if var and not ref else ref)
        elif var and (var in overridable_envs or ANY_VAR in overridable_envs):
            problems.append(
                f"Required image {path!r} is set from ${{{var}}}, which"
                " allowed_envs or the pre_launch_script can override"
            )
        elif not _PINNED_IMAGE_RE.fullmatch(ref):
            problems.append(f"Required image {path!r} is not pinned by digest: {ref}")
    return problems, unverified


def fetch_source_at_commit(repo_url: str, commit_sha: str, dest_dir: Path) -> bool:
    """Clone a specific commit from a git repository; True on success."""
    if not _GITHUB_URL_RE.match(repo_url):
        raise ValueError(f"Invalid or non-GitHub repo URL: {repo_url!r}")
    if not COMMIT_SHA_RE.fullmatch(commit_sha):
        raise ValueError(f"Invalid commit SHA: {commit_sha!r}")
    try:
        subprocess.run(  # nosec B603 B607
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--branch",
                commit_sha,
                repo_url,
                str(dest_dir),
            ],
            capture_output=True,
            check=True,
            timeout=300,
        )
        return _checked_out(dest_dir, commit_sha)
    except subprocess.CalledProcessError:
        try:
            subprocess.run(  # nosec B603 B607
                ["git", "clone", repo_url, str(dest_dir)],
                capture_output=True,
                check=True,
                timeout=300,
            )
            subprocess.run(  # nosec B603 B607
                ["git", "checkout", commit_sha],
                cwd=dest_dir,
                capture_output=True,
                check=True,
                timeout=30,
            )
            return _checked_out(dest_dir, commit_sha)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to fetch source: {e.stderr.decode()}")
            return False
    except FileNotFoundError:
        logger.error("git not found - please install git")
        return False


def _checked_out(repo_dir: Path, commit_sha: str) -> bool:
    """Whether HEAD is ``commit_sha``. A branch or tag named like a SHA would
    otherwise win over the commit in ``clone --branch`` and ``checkout``."""
    try:
        head = subprocess.run(  # nosec B603 B607
            ["git", "rev-parse", "HEAD"],
            cwd=repo_dir,
            capture_output=True,
            check=True,
            text=True,
            timeout=30,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return False
    if head != commit_sha.lower():
        logger.error("Checked-out HEAD %s is not commit %s", head, commit_sha)
        return False
    return True


def _reset_clone(repo_dir: Path, commit_sha: str) -> bool:
    """Put a cached clone back to exactly ``commit_sha``: a matching HEAD says
    nothing about modified, untracked or ignored files left in the tree."""
    try:
        for args in (
            ["reset", "--quiet", "--hard", commit_sha],
            ["clean", "--quiet", "-ffdx"],
        ):
            subprocess.run(  # nosec B603 B607
                ["git", *args],
                cwd=repo_dir,
                capture_output=True,
                check=True,
                timeout=120,
            )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        logger.error("Could not reset cached clone %s: %s", repo_dir, e)
        return False
    return _checked_out(repo_dir, commit_sha)


def verify_commit_signature(build_dir: Path, commit_sha: str) -> tuple[bool, str]:
    """Verify the GPG signature on a git commit; returns (verified, signer_info)."""
    if not COMMIT_SHA_RE.fullmatch(commit_sha):
        raise ValueError(f"Invalid commit SHA: {commit_sha!r}")
    try:
        result = subprocess.run(  # nosec B603 B607
            ["git", "verify-commit", commit_sha],
            cwd=build_dir,
            capture_output=True,
            text=True,
            timeout=10,
        )
        logger.debug(f"Git commit verify output: {result}")

        return result.returncode == 0, result.stderr
    except subprocess.TimeoutExpired:
        return False, (
            f"git verify-commit timed out after 10s for {commit_sha}"
            " (gpg-agent or pinentry may be waiting for input)"
        )
    except FileNotFoundError:
        return False, "git not found"


def rebuild_and_compare(
    source_dir: str | Path,
    original_digest: str,
    build_script: str = "docker-build.sh",
    build_env: dict[str, str] | None = None,
) -> tuple[bool, str]:
    """Reproducibly rebuild from source; returns (matches, rebuilt_digest)."""
    source_dir = Path(source_dir)
    script_path = source_dir / build_script
    if not script_path.exists():
        script_path = source_dir / "build-image.sh"
        if not script_path.exists():
            logger.debug("Directory contents: %s", os.listdir(source_dir))
            return False, f"Build script not found: {script_path.name}"
    try:
        if not _run_build_script(script_path, source_dir, build_env):
            return False, "Build script did not create oci.tar"
        rebuilt_digest = _extract_digest_from_oci(source_dir / "oci.tar")
        if not rebuilt_digest:
            return False, "Could not extract digest from OCI archive"
        return _compare_digests(source_dir, original_digest, rebuilt_digest)
    except (subprocess.TimeoutExpired, RuntimeError) as e:
        return False, f"Build failed: {e}"


# The build script is third-party code, so it must not inherit the verifier's
# secrets (API keys, AWS credentials, bucket names).
_BUILD_ENV_ALLOWLIST: frozenset[str] = frozenset(
    {
        "PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "TMPDIR",
        "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_BUILDKIT",
        "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "BUILDX_BUILDER",
        "BUILDKIT_PROGRESS", "XDG_RUNTIME_DIR", "SSL_CERT_FILE",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    }
)  # fmt: skip


def _run_build_script(
    script_path: Path, source_dir: Path, build_env: dict[str, str] | None = None
) -> bool:
    """Run the source repo's own build script; True if it produced oci.tar.

    The script still has Docker access, which is host-equivalent.
    """
    env = {k: v for k, v in os.environ.items() if k in _BUILD_ENV_ALLOWLIST}
    env["SOURCE_DATE_EPOCH"] = "0"
    if build_env:
        env.update(build_env)

    build_script = script_path
    override = os.environ.get("BUILD_WRAPPER_SCRIPT", "")
    if override and Path(override).exists():
        build_script = Path(override)
        logger.debug(f"Using BUILD_WRAPPER_SCRIPT override: {build_script}")

    (source_dir / "oci.tar").unlink(missing_ok=True)
    logger.debug(f"Running build command: bash {build_script}")
    logger.debug(f"Working directory: {source_dir}")

    try:
        result = subprocess.run(  # nosec B603 B607
            ["bash", str(build_script)],
            cwd=source_dir,
            capture_output=True,
            text=True,
            check=False,
            timeout=3600,
            env=env,
        )
        logger.debug(f"Build process completed with return code: {result.returncode}")

    except subprocess.TimeoutExpired as e:
        logger.error("❌ Build timed out after 3600 seconds")
        raise RuntimeError("Build timed out after 3600 seconds") from e

    oci_path = source_dir / "oci.tar"

    stdout = result.stdout if isinstance(result.stdout, str) else ""
    stderr = result.stderr if isinstance(result.stderr, str) else ""

    if result.returncode != 0:
        error_msg = (
            f"Build failed with return code {result.returncode}\n"
            f"Stdout: {stdout}\n"
            f"Stderr: {stderr}"
        )
        logger.error(f"❌ {error_msg}")
        raise RuntimeError(error_msg)

    if not oci_path.exists():
        error_msg = (
            f"Build succeeded but oci.tar not found at {oci_path}\n"
            f"Return code: {result.returncode}\n"
            f"Stdout: {stdout}\n"
            f"Stderr: {stderr}"
        )
        logger.error(f"❌ {error_msg}")
        raise RuntimeError(error_msg)

    logger.debug("  ✅ Build completed - oci.tar created")
    return True


def _extract_digest_from_oci(oci_path: Path) -> str:
    """Return the first manifest digest from an OCI archive's ``index.json``,
    or "" on any failure."""
    logger.debug("  Extracting digest from OCI archive...")
    try:
        with tarfile.open(oci_path) as archive:
            member = archive.extractfile("index.json")
            if member is None:
                logger.error("index.json is not a regular file in %s", oci_path)
                return ""
            index_data: dict[str, Any] = json.loads(member.read())
    except (OSError, tarfile.TarError, KeyError, json.JSONDecodeError) as e:
        logger.error("Failed to read index.json from %s: %s", oci_path, e)
        return ""

    manifests: list[Any] = index_data.get("manifests", [])
    if not manifests:
        logger.error("index.json in %s lists no manifests", oci_path)
        return ""
    digest: str = manifests[0].get("digest", "")
    if not _blobs_match(oci_path, digest):
        return ""
    logger.debug("  ✅ Extracted digest: %s", digest)
    return digest


def _blobs_match(oci_path: Path, digest: str) -> bool:
    """Whether the manifest ``digest`` names, and every blob it references,
    is in the archive with that sha256, so ``index.json`` alone cannot claim a
    digest the build did not produce."""
    try:
        with tarfile.open(oci_path) as archive:
            pending, seen = [(digest, True)], set()
            while pending:
                current, is_manifest = pending.pop()
                if current in seen:
                    continue
                seen.add(current)
                algo, _, hexdigest = current.partition(":")
                member = archive.extractfile(f"blobs/{algo}/{hexdigest}")
                if algo != "sha256" or member is None:
                    raise KeyError(current)
                h, body = hashlib.sha256(), b""
                while chunk := member.read(1 << 20):
                    h.update(chunk)
                    if is_manifest:
                        body += chunk
                if h.hexdigest() != hexdigest:
                    logger.error("OCI blob %s does not match its digest", current)
                    return False
                if not is_manifest:
                    continue
                doc = json.loads(body)
                refs = [(doc.get("config"), False)]
                refs += [(r, False) for r in doc.get("layers") or []]
                refs += [(r, True) for r in doc.get("manifests") or []]
                pending += [(r["digest"], m) for r, m in refs if isinstance(r, dict)]
    except (OSError, tarfile.TarError, KeyError, ValueError, AttributeError) as e:
        logger.error("OCI archive %s fails its blob check: %s", oci_path, e)
        return False
    return True


def _compare_digests(
    source_dir: Path, original_digest: str, rebuilt_digest: str
) -> tuple[bool, str]:
    """Compare original and rebuilt digests; returns (matches, rebuilt_digest)."""
    original_hash = original_digest.split(":")[-1]
    rebuilt_hash = rebuilt_digest.split(":")[-1]

    matches = original_hash == rebuilt_hash

    logger.debug(f"\n  📊 Comparison {source_dir}:")
    logger.debug(f"     Original: {original_hash}")
    logger.debug(f"     Rebuilt:  {rebuilt_hash}")
    logger.debug(f"     Result:   {'✅ MATCH' if matches else '❌ MISMATCH'}")

    return matches, rebuilt_digest


class ProvenanceData(TypedDict):
    source_repo: str
    commit_sha: str
    builder_id: str
    build_type: str


class BuildResult(TypedDict):
    status: str
    digest: str
    expected: str


class VerificationResults(TypedDict, total=False):
    image: str
    provenance_found: bool
    provenance_verified: bool
    build_reproducible: bool
    messages: list[str]
    provenance: ProvenanceData
    build_result: BuildResult


def _cached_result_is_trustworthy(
    image_digest: str,
    registry: str,
    cached: Any,
    allowed_commits: frozenset[str] | None = None,
) -> bool:
    """Validate a pre-verified S3 cache entry before trusting it.

    The entry must be well-formed and bound to the exact image requested, so
    the cache can never turn a failure into a pass or apply one image's verdict
    to another digest.
    """
    if not isinstance(cached, dict):
        return False
    if cached.get("image") != f"{registry}@{image_digest}":
        logger.warning(
            "Cache entry image %r does not match requested %s@%s",
            cached.get("image"),
            registry,
            image_digest,
        )
        return False
    for key in (
        "provenance_found",
        "provenance_verified",
        "build_reproducible",
    ):
        if not isinstance(cached.get(key), bool):
            logger.warning("Cache entry missing/invalid boolean field %r", key)
            return False
    if cached.get("build_reproducible") is True:
        build_result = cached.get("build_result")
        if (
            not isinstance(build_result, dict)
            or build_result.get("expected") != image_digest
        ):
            logger.warning(
                "Cache entry claims reproducible build but is not bound to %s",
                image_digest,
            )
            return False
    # A hit skips the pin check, so the entry must match the current pin or a
    # stale entry would defeat a pin bump.
    if cached.get("provenance_verified") is not True:
        return False
    expected_commit = CERT_EXPECTED_COMMITS.get(registry, "")
    allowed = (
        allowed_commits if allowed_commits is not None else {expected_commit} - {""}
    )
    cached_commit = ""
    provenance = cached.get("provenance")
    if isinstance(provenance, dict):
        cached_commit = str(provenance.get("commit_sha", ""))
    if cached_commit not in allowed:
        logger.warning(
            "Cache entry for %s is pinned to %r but the current expected commit "
            "is %r; ignoring it and running full verification",
            registry,
            cached_commit,
            sorted(allowed),
        )
        return False
    return True


def _failed_result(image: str, *messages: str) -> VerificationResults:
    """A result for ``image`` that verified nothing (yet)."""
    return {
        "image": image,
        "provenance_found": False,
        "provenance_verified": False,
        "build_reproducible": False,
        "messages": list(messages),
    }


def verify_image_full(
    image_digest: str,
    registry: str,
    policy: VerificationPolicy,
    allowed_commits: frozenset[str] | None = None,
) -> VerificationResults:
    """Perform complete source code verification for a container image.

    ``allowed_commits`` replaces the image's single commit pin with a set of
    reviewed commits (see ``extract_provenance_attestation``).
    """
    if not os.environ.get("PRE_VERIFY_DISABLED"):
        from ..s3_cache import load_pre_verification

        cached = load_pre_verification(image_digest)
        if cached is not None and _cached_result_is_trustworthy(
            image_digest, registry, cached, allowed_commits
        ):
            logger.info(
                f"Using pre-verified result for {registry}@{image_digest[:19]}..."
            )
            return cached  # type: ignore[return-value]
        if cached is not None:
            logger.warning(
                "Pre-verified cache entry for %s@%s failed integrity checks;"
                " ignoring it and running full verification",
                registry,
                image_digest[:19],
            )

    image_ref = f"{registry}@{image_digest}"
    results = _failed_result(image_ref)

    try:
        provenance = extract_provenance_attestation(image_ref, allowed_commits)
    except ValueError as e:
        # e.g. pin mismatch: a verification failure, not a crash.
        logger.error("❌ Provenance check failed for %s: %s", image_ref, e)
        results["messages"].append(f"❌ Provenance check failed: {e}")
        return results

    if provenance is None:
        logger.error(
            f"\nProvenance not found:\n\tImage: {image_ref}\n\tProvenance: {provenance}"
        )
        results["messages"].append("❌ No SLSA provenance attestation found")
        return results

    results["provenance_found"] = True
    results["provenance"] = {
        "source_repo": provenance.source_repo,
        "commit_sha": provenance.commit_sha,
        "builder_id": provenance.builder_id,
        "build_type": provenance.build_type,
    }

    prov_result = verify_provenance_against_policy(provenance, policy)
    results["provenance_verified"] = prov_result[0]
    results["messages"].extend(prov_result[1])

    if not results["provenance_verified"]:
        results["messages"].append("❌ Provenance verification failed - stopping")
        return results

    if (
        not policy.require_reproducible_build
        or registry in policy.skip_reproducibility_images
    ):
        results["messages"].append("⚠️ Reproducibility check skipped for this image")
        return results

    build_env = CERT_BUILD_ENV.get(registry, {})

    # BUILD_CACHE_DIR persists the clone between runs, keyed by digest.
    cache_base = os.environ.get("BUILD_CACHE_DIR", "")
    if cache_base:
        clone_dir = Path(cache_base) / image_digest.replace("sha256:", "") / "clone"
        clone_dir.mkdir(parents=True, exist_ok=True)
        ctx: Any = nullcontext(clone_dir)
    else:
        ctx = tempfile.TemporaryDirectory()

    with ctx as tmpdir:
        clone_dir = Path(tmpdir) if cache_base else Path(tmpdir) / "clone"

        already_cloned = (clone_dir / ".git").exists()
        if (
            _reset_clone(clone_dir, provenance.commit_sha)
            if already_cloned
            else fetch_source_at_commit(
                provenance.source_repo, provenance.commit_sha, clone_dir
            )
        ):
            if not already_cloned:
                results["messages"].append(
                    f"✅ Source code fetched at commit {provenance.commit_sha}"
                )
            else:
                results["messages"].append(
                    f"✅ Using cached clone at commit {provenance.commit_sha}"
                )

            commit_sig_verified, signer_info = verify_commit_signature(
                clone_dir, provenance.commit_sha
            )
            if commit_sig_verified:
                results["messages"].append("✅ Commit signature verified")
            else:
                results["messages"].append(
                    "⚠️  Commit signature not verified (may not be signed)"
                )

            matched, digest = rebuild_and_compare(
                clone_dir, image_digest, build_env=build_env
            )
            results["build_reproducible"] = matched

            results["build_result"] = {
                "status": "✅ passed" if matched else "❌ mismatch",
                "digest": digest,
                "expected": image_digest,
            }
        else:
            results["messages"].append("❌ Failed to fetch source code")

    return results


def verify_compose_images_full(
    images: list[str],
    policy: VerificationPolicy,
    overridable_envs: frozenset[str] = frozenset(),
) -> SourceVerificationResult:
    """Verify the image values of a compose file (see :func:`compose_images`).

    ``overridable_envs`` is :func:`tdx.overridable_envs` of the app_compose.
    """

    matches = pinned_images(images)
    results: dict[str, Any] = {}
    problems, unverified = compose_image_problems(
        images, policy.required_images, overridable_envs
    )
    for index, problem in enumerate(problems):
        logger.error("❌ %s", problem)
        ref = f"rejected-{index}@invalid"
        results[ref] = _failed_result(ref, f"❌ {problem}")
    if unverified:
        logger.warning(
            "⚠️ Images in the compose that are NOT verified (no provenance or"
            " rebuild): %s",
            unverified,
        )
    found_required: set[str] = set()
    for registry_path, digest in dict.fromkeys(matches):
        if registry_path in policy.required_images:
            logger.info(f"Verifying image: {registry_path}")
            image_ref = f"{registry_path}@{digest}"
            verification = verify_image_full(
                image_digest=digest,
                registry=registry_path,
                policy=policy,
            )
            if not verification["provenance_found"]:
                logger.error(
                    "Provenance information was not found for %s", registry_path
                )
            results[image_ref] = verification
            found_required.add(registry_path)

    # A missing required image must fail, not pass vacuously.
    for required in policy.required_images:
        if required not in found_required:
            logger.error(
                "Required image %r absent from compose file"
                ". Compose verification fails",
                required,
            )
            ref = f"{required}@not-found"
            results[ref] = _failed_result(
                ref, f"❌ Required image {required!r} not found in compose file"
            )

    return {"images": results, "unverified_images": unverified}


def all_images_fully_verified(
    image_verification: SourceVerificationResult, policy: VerificationPolicy
) -> bool:
    """Every image in the compose must pass provenance and reproducible rebuild.

    Fails closed on an empty result.
    """
    images = image_verification.get("images", {})
    if not images:
        logger.error("No images were verified; failing compose verification closed")
        return False
    verified = True
    for image_ref, value in images.items():
        prefix = image_ref.split("@")[0]
        skipped = prefix in policy.skip_reproducibility_images
        reproducible_ok = (
            skipped
            or not policy.require_reproducible_build
            or value.get("build_reproducible")
        )
        if not value.get("provenance_verified") or not reproducible_ok:
            logger.error(
                "Image failed full validation: %s"
                " (provenance_verified=%s, build_reproducible=%s,"
                " reproducibility_skipped=%s)",
                image_ref,
                value.get("provenance_verified"),
                value.get("build_reproducible"),
                skipped,
            )
            verified = False
    return verified
