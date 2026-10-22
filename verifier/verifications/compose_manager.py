# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Inference-CVM verification via the compose-manager actions log.

The gateway ``compose_hash`` does not reflect runtime model swaps: NEAR inference
CVMs run a ``compose-manager`` service (baked into the boot compose) that pulls
new docker-compose YAMLs from the ``cvm-compose-files`` repo and runs
``docker compose up`` to swap models.  So the running model containers diverge
from what is pinned in ``tcb_info.app_compose.docker_compose_file``.

The per-model attestation arrives in the gateway report's
``model_attestations[]``. Verifying which model image is serving requires:

1. Verify the inference-proxy TDX quote and confirm ``mrconfig == "01" ||
   compose_hash`` and ``compose_hash == sha256(app_compose)``.
2. Fully verify the boot compose-manager (reviewed commit, reproducible
   rebuild) and the running one named in the actions log (pinned commit),
   plus the launcher that chooses between them (pinned provenance), so the
   actions log comes from code we reviewed.
3. Verify the embedded compose-manager TDX quote and its report-data binding:
   ``report_data[0:32] == sha256(canonical(actions))`` and
   ``report_data[32:64] == nonce`` (byte offsets).  The first binds the
   *actual* actions log content to the hardware quote (see below).
4. Replay the actions log into the services now running and the compose file
   each came from (see :func:`serving_state`), fetching each pinned YAML from
   the cvm-compose-files repo (verified by sha256) to recover the serving
   images and model weights.

Actions-log binding: compose-manager hashes the actions into report_data using
a canonical serialization (alphabetical keys, compact, omit null/empty-array,
UTF-8). We recompute it from the emitted ``actions``, so a forged actions list
cannot pass.
"""

import asyncio
import json
import os
import posixpath
import re
import shlex
import subprocess  # nosec B404
import tempfile
from collections.abc import Mapping
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
from typing import Any, NamedTuple, TypedDict

import yaml

from ..config import (
    ACCEPTED_EXTRA_PROXY_IMAGES,
    APPROVED_MAINTENANCE_COMPOSES,
    APPROVED_MODEL_WEIGHTS,
    BOOT_COMPOSE_MANAGER_COMMITS,
    COMPOSE_COMMAND,
    COMPOSE_VERSION,
    CVM_COMPOSE_FILES_RAW_BASE,
    CVM_COMPOSE_FILES_REPO,
)
from ..models import SourceVerificationResult, VerificationPolicy
from ..utils import COMMIT_SHA_RE, get_http_session, get_logger
from .gpu import check_gpu
from .image import (
    ANY_VAR,
    all_images_fully_verified,
    compose_image_problems,
    compose_images,
    image_path,
    pinned_images,
    verify_compose_images_full,
    verify_image_full,
)
from .tdx import (
    IntelResult,
    _extract_app_compose,
    _validate_mrconfig,
    check_os_measurements,
    check_report_data,
    overridable_envs,
    verify_tdx_quote,
)

logger = get_logger(__name__)


class InferenceAttestationSummary(TypedDict):
    type: str
    model_name: str
    # cloud-api can alias a retired model id onto a different live model's CVM,
    # which would otherwise verify cleanly while attesting the wrong deployment.
    model_name_matches: bool
    tdx_verified: bool
    os_measurements_valid: bool
    mrconfig_valid: bool
    compose_hash_valid: bool
    near_images_verified: bool
    # compose-manager, the author of the actions log, passed full validation
    # (boot and running images, and the launcher's provenance). Unlike
    # near_images_verified it leaves out the proxy, so the weights markers
    # can rest on the log without depending on the proxy's verdict.
    compose_manager_verified: bool
    # Hardware-rooted anchor for the actions-log running image: the booted
    # compose-manager is fully verified at a commit in
    # BOOT_COMPOSE_MANAGER_COMMITS (a set; boot images vary per replica). A CVM
    # that never self-updated boots the running image, held to its pin.
    boot_compose_manager_verified: bool
    # Full verification result for the boot compose-manager image, read by
    # `make review-pins` to find unreviewed boot commits.
    boot_compose_manager_image: dict[str, Any] | None
    compose_manager_tdx_verified: bool
    proxy_report_data_valid: bool
    actions_hash_bound: bool
    nonce_bound: bool
    # Prevents stitching proxy and compose-manager quotes from two CVMs.
    same_cvm: bool
    report_data_valid: bool
    serving_yaml_verified: bool
    model_weights_approved: bool
    serving_weights: list[str]
    # Every compose file a running service came from (file, commit,
    # file_sha256, approved), once the actions log replays cleanly.
    serving_composes: list[dict[str, Any]]
    # Head of compose_log_chain for the replayed actions log ("" if none).
    compose_log: str
    image_verification: SourceVerificationResult | None
    gpu_verified: bool | None
    signing_public_key: str | None
    signing_address: str | None
    signing_algo: str | None


_CM_REGISTRY = "nearaidev/compose-manager"
# sglang takes --model as an alias of --model-path; vLLM spells it --model.
_MODEL_FLAGS = ("--model-path", "--model")
# Other files a server loads that shape its output, held to the same rule.
_ARTIFACT_FLAGS = (
    "--chat-template",
    "--tokenizer-path",
    "--tokenizer",
    "--speculative-draft-model-path",
    "--speculative-model",
    "--speculative-config",
    "--lora-paths",
    "--lora-modules",
)
# A $ that compose would interpolate ($$ is a literal $).
_INTERPOLATED = re.compile(r"(?<!\$)\$(?!\$)")
# The whole path must be a snapshot in the Hugging Face cache the model
# services mount, or a file inside one, so "..", a ${VAR:-default} or a
# look-alike directory elsewhere cannot stand in for it. HF forbids "--"
# inside an org or repo name.
_HF_SNAPSHOT_RE = re.compile(
    r"/root/\.cache/huggingface/hub/models--([A-Za-z0-9._-]+?)--([A-Za-z0-9._-]+)"
    r"/snapshots/([0-9a-f]{40})(?:/(?!\.\.?(?:/|$))[A-Za-z0-9._-]+)*/?"
)
# A service that runs an inference server, so it must load approved weights.
# Limitation: a custom image whose entrypoint serves a model with none of
# these markers is not seen here. compose_file_approved still refuses a file
# whose unrecognised service can reach the GPUs.
_SERVER_MARKERS = (
    "sglang serve",
    "sglang.launch_server",
    "vllm serve",
    "vllm.entrypoints",
    "--served-model-name",
)
_SERVER_IMAGES = ("vllm/vllm-openai",)
# Images allowed GPU access without serving a model (metrics only).
_GPU_TOOL_IMAGES = ("nvcr.io/nvidia/k8s/dcgm-exporter",)
_LAUNCHER = "nearaidev/compose-manager-launcher"
_PROXY = "nearaidev/vllm-proxy-rs"


def _measurements(intel_result: IntelResult) -> tuple[str, ...]:
    """TDX measurements used to confirm two quotes come from one CVM.

    MRTD, MRCONFIG and RTMR0-2 are the same on every replica of an app.
    RTMR3 carries the instance's boot events, so it is what tells replicas
    apart. A runtime event between the two quotes would fail closed.
    """
    body = intel_result["quote"]["body"]
    rtmrs = list(body.get("rtmrs", []))
    return (body.get("mrtd", ""), body.get("mrconfig", ""), *rtmrs[:4])


def _measurements_present(measurements: tuple[str, ...]) -> bool:
    """True only if the core measurements are non-empty, so the same-CVM check
    cannot pass vacuously."""
    return bool(measurements[0]) and bool(measurements[1])


def _same_cvm(proxy: IntelResult, compose_manager: IntelResult | None) -> bool:
    """Whether the proxy and compose-manager quotes come from one CVM."""
    if compose_manager is None:
        return False
    measurements = _measurements(proxy)
    return _measurements_present(measurements) and measurements == _measurements(
        compose_manager
    )


def _proxy_binding_ok(report_data: Mapping[str, object]) -> bool:
    """The proxy quote binds its signing address or TLS certificate, and the
    nonce."""
    return bool(
        (report_data.get("binds_address") or report_data.get("binds_tls_cert"))
        and report_data.get("embeds_nonce")
    )


class CvmState(NamedTuple):
    """What the main pass verified about a model CVM, beyond its boot image."""

    app_compose: str
    # Head of compose_log_chain: the exact compose_up/compose_down history.
    compose_log: str
    # Running compose-manager image ("" when the boot one never self-updated).
    compose_manager: str


def cvm_state(attestation: dict[str, Any]) -> CvmState:
    """The :class:`CvmState` an attestation claims, read from its actions log.

    Only meaningful once the actions log is bound to the CVM's quote.
    """
    actions = (attestation.get("compose_manager_attestation") or {}).get(
        "actions"
    ) or []
    chain = compose_log_chain(actions)
    return CvmState(
        _extract_app_compose(attestation),
        chain[-1] if chain else "",
        _running_compose_manager_image(actions),
    )


def model_names_match(returned: str, requested: str) -> bool:
    """True when the gateway's attested model id is the one we asked for.

    An empty attested id never matches.
    """
    if not returned:
        return False
    return returned.strip().casefold() == requested.strip().casefold()


async def signing_key_from_inference_attestation(
    attestation: dict[str, Any],
    nonce: str,
    signing_algo: str,
    label: str,
    expected: CvmState,
) -> dict[str, str] | None:
    """Extract a model CVM's signing key from one already-fetched attestation.

    Skips the image chain, so the CVM must be in the state the main pass fully
    verified: MR_CONFIG_ID is ``expected.app_compose``, and a same-CVM,
    nonce-bound compose-manager quote attests an actions log whose serving
    compose and running compose-manager equal ``expected``. The boot compose
    alone is not enough, since compose-manager swaps images at runtime.
    Returns None if anything fails.
    """
    if str(attestation.get("signing_algo") or "").lower() != signing_algo:
        return None
    try:
        intel_result = await verify_tdx_quote(attestation)
    except (ValueError, RuntimeError) as e:
        logger.warning("Signing-key capture: proxy quote failed for %s: %s", label, e)
        return None
    if not intel_result.get("verified"):
        return None
    if not (
        check_os_measurements(intel_result, f"Signing-key capture ({label})")
        and _validate_mrconfig(
            expected.app_compose, intel_result["quote"]["body"]["mrconfig"]
        )
    ):
        logger.warning("Signing-key capture: %s is not the verified CVM image", label)
        return None
    if not _proxy_binding_ok(check_report_data(attestation, nonce, intel_result)):
        logger.warning(
            "Signing-key capture: report_data binding failed for %s (%s)",
            label,
            signing_algo,
        )
        return None
    cma = attestation.get("compose_manager_attestation") or {}
    cm_tdx, actions_bound, nonce_bound, cm_intel = await _verify_compose_manager_quote(
        cma, nonce
    )
    if not (
        cm_tdx and actions_bound and nonce_bound and _same_cvm(intel_result, cm_intel)
    ):
        logger.warning(
            "Signing-key capture: %s has no bound compose-manager actions log", label
        )
        return None
    state = cvm_state(attestation)
    if not expected.compose_log or (
        state.compose_log,
        state.compose_manager,
    ) != (expected.compose_log, expected.compose_manager):
        logger.warning(
            "Signing-key capture: %s runs a different serving compose or "
            "compose-manager than the verified CVM",
            label,
        )
        return None
    return {
        "signing_public_key": str(attestation.get("signing_public_key") or ""),
        "signing_address": str(attestation.get("signing_address") or ""),
        "signing_algo": str(attestation.get("signing_algo") or ""),
        "model_name": str(attestation.get("model_name") or label),
    }


def _check_compose_hash(attestation: dict[str, Any]) -> bool:
    """Confirm the served app_compose hashes to the report's declared compose_hash."""
    app_compose = _extract_app_compose(attestation)
    declared = str(attestation.get("info", {}).get("compose_hash", ""))
    if not app_compose or not declared:
        return False
    computed = sha256(app_compose.encode()).hexdigest()
    return computed.lower() == declared.lower()


def _boot_docker_compose(attestation: dict[str, Any]) -> str:
    """Return the boot docker_compose_file text from the served app_compose."""
    app_compose = _extract_app_compose(attestation)
    if not app_compose:
        return ""
    try:
        return str(json.loads(app_compose).get("docker_compose_file", ""))
    except (json.JSONDecodeError, AttributeError):
        logger.error("Could not parse app_compose to extract docker_compose_file")
        return ""


_COMPOSE_ACTIONS = ("compose_up", "compose_down")
# A log entry names an exact commit and a plain path in the compose repo.
_LOG_FILE_RE = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")
# compose-manager's Compose project when the caller names none.
_DEFAULT_PROJECT = "work"


def _compose_entries(actions: list[Any]) -> list[dict[str, Any]]:
    return [
        a
        for a in actions
        if isinstance(a, dict) and a.get("action") in _COMPOSE_ACTIONS
    ]


def compose_log_chain(actions: list[Any]) -> list[str]:
    """A rolling sha256 over the ``compose_up``/``compose_down`` entries.

    Entry ``k`` hashes entry ``k-1`` with the k-th action's fields, so a head
    names one exact compose history. The gateway relay computes the same chain
    (``aichat/serve/services/near.py`` in brave/ai-gateway), so keep the two
    in step.
    """
    head, chain = "", []
    for a in _compose_entries(actions):
        line = "|".join(
            [
                str(a.get("action") or ""),
                str(a.get("file") or ""),
                str(a.get("commit") or ""),
                str(a.get("file_sha256") or ""),
                ",".join(str(x) for x in a.get("services") or []),
                str(a.get("timestamp") or ""),
            ]
        )
        head = sha256(f"{head}\n{line}".encode()).hexdigest()
        chain.append(head)
    return chain


class ServingFile(NamedTuple):
    commit: str
    file: str
    file_sha256: str
    text: str


def _compose_doc(text: str) -> tuple[str, dict[str, Any]]:
    """(project, services) of a compose file, services as Compose resolves
    them; project is the file's own top-level name."""
    project = str(_yaml_doc(text).get("name") or _DEFAULT_PROJECT).lower()
    return project, _services(canonical_compose(text))


def serving_state(
    actions: list[Any],
) -> dict[tuple[str, str], ServingFile] | None:
    """Replay the actions log into ``{(project, service): file it runs from}``.

    compose-manager runs ``up -d --remove-orphans [services]``: an up starts
    the listed services and what they depend on (all of the file's when none
    are listed) and evicts the project's containers whose service the file
    does not define. A down
    stops the listed services (all of the file's when none are listed).
    ``None`` when a file cannot be fetched or fails its sha256, so the state
    is unknown and verification fails closed.

    Limitation: the log omits the caller-chosen Compose project, so a file's
    top-level ``name`` stands in for it (default ``work``). The log also
    omits the ``env`` an up may pass, and when a one-shot service exits.
    Logging these in compose-manager would remove the guess.
    """
    texts: dict[tuple[str, str, str], str] = {}
    running: dict[tuple[str, str], ServingFile] = {}
    for a in _compose_entries(actions):
        commit, file = str(a.get("commit") or ""), str(a.get("file") or "")
        up = a["action"] == "compose_up"
        sha = str(a.get("file_sha256") or "").lower() if up else ""
        if not (
            COMMIT_SHA_RE.fullmatch(commit)
            and _LOG_FILE_RE.fullmatch(file)
            and ".." not in file.split("/")
            and (sha or not up)
        ):
            logger.error("Unusable %s entry in actions log: %s", a["action"], a)
            return None
        if (commit, file, sha) not in texts:
            ok, text = fetch_and_verify_serving_yaml(commit, file, sha or None)
            if not ok:
                return None
            if not canonical_compose(text):
                logger.error(
                    "Compose cannot read %s at %s; state unknown", file, commit
                )
                return None
            texts[(commit, file, sha)] = text
        text = texts[(commit, file, sha)]
        project, defined = _compose_doc(text)
        listed = [str(x) for x in a.get("services") or []] or list(defined)
        if not up:
            for service in listed:
                running.pop((project, service), None)
            continue
        for key in [k for k in running if k[0] == project and k[1] not in defined]:
            del running[key]
        entry = ServingFile(commit, file, sha, text)
        for service in _with_dependencies(listed, defined):
            running[(project, service)] = entry
    return running


def _with_dependencies(listed: list[str], defined: dict[str, Any]) -> list[str]:
    """``listed`` plus every service they ``depends_on``, which ``up`` also
    starts."""
    out, pending = [], list(listed)
    while pending:
        name = pending.pop()
        if name in out:
            continue
        out.append(name)
        service = defined.get(name)
        deps = service.get("depends_on") if isinstance(service, dict) else None
        pending += [str(d) for d in deps or []]
    return out


def running_services(
    state: dict[tuple[str, str], ServingFile],
) -> dict[str, Any]:
    """``{"project/service": definition}`` for every running service, as
    Compose resolves the file it runs from."""
    services = {}
    for (project, service), entry in state.items():
        definition = _compose_doc(entry.text)[1].get(service)
        services[f"{project}/{service}"] = definition if definition else {}
    return services


def running_compose(state: dict[tuple[str, str], ServingFile]) -> str:
    """One compose document holding only the running services' definitions."""
    return yaml.safe_dump({"services": running_services(state)}, sort_keys=True)


def _running_compose_manager_image(actions: list[dict[str, Any]]) -> str:
    """Return the running compose-manager image from the latest
    ``compose_manager_started`` action, or "" if none.

    compose-manager self-updates, so the boot compose shows a stale image.
    """
    for action in reversed(actions):
        if (
            isinstance(action, dict)
            and action.get("action") == "compose_manager_started"
        ):
            return str(action.get("image", ""))
    return ""


def _verify_boot_compose_manager(
    boot_text: str,
    policy: VerificationPolicy,
    overridable_envs: frozenset[str],
    already_verified: dict[str, Any],
) -> tuple[bool, dict[str, Any] | None]:
    """Fully verify the hardware-measured boot compose-manager image.

    This anchors the actions-log running-image check: the boot build decides
    what runs next, so it gets the same provenance + reproducible rebuild as
    any NEAR image, and its commit must be one a human reviewed
    (``BOOT_COMPOSE_MANAGER_COMMITS``). It is a set, not the running pin,
    because the boot image is per-replica and goes stale after the first
    self-update. ``already_verified`` (image ref -> result) avoids rebuilding
    a boot image that is also the running one.

    A ``pre_launch_script`` alone does not fail the compose-manager image:
    NEAR's restores the launcher's last choice on reboot, and the launcher is
    verified separately. Other boot images get no such exception.

    Returns ``(verified, result)``; ``result`` is None if no image was found.
    """
    images = compose_images(boot_text)
    cm_images = [v for v in images if image_path(v) == _CM_REGISTRY]
    others = [v for v in images if image_path(v) != _CM_REGISTRY]
    problems = [
        *compose_image_problems(others, policy.required_images, overridable_envs)[0],
        *compose_image_problems(
            cm_images, policy.required_images, overridable_envs - {ANY_VAR}
        )[0],
    ]
    if problems:
        for problem in problems:
            logger.error("Boot compose: %s", problem)
        return False, None
    pinned = [
        (path, digest) for path, digest in pinned_images(images) if path == _CM_REGISTRY
    ]
    if not pinned:
        logger.error(
            "Boot compose-manager image not found in app_compose. Cannot anchor "
            "the running-image check to a hardware-measured boot build"
        )
        return False, None
    if len(set(pinned)) != 1:
        logger.error("Boot compose must run exactly one compose-manager: %s", pinned)
        return False, None
    registry, digest = pinned[0]
    ref = f"{registry}@{digest}"
    result = already_verified.get(ref) or verify_image_full(
        digest, registry, policy, allowed_commits=BOOT_COMPOSE_MANAGER_COMMITS
    )
    ok = all_images_fully_verified({"images": {ref: result}}, policy)
    commit = (result.get("provenance") or {}).get("commit_sha", "")
    if ok and commit not in BOOT_COMPOSE_MANAGER_COMMITS:
        logger.error(
            "Boot compose-manager %s was built from unreviewed commit %s. Audit it"
            " (make review-pins), then add it to BOOT_COMPOSE_MANAGER_COMMITS",
            ref,
            commit,
        )
        ok = False
    return ok, dict(result)


def _actions_report_data_hash(actions: Any) -> str:
    """Reproduce the canonical serialization compose-manager hashes into
    report_data.

    Null/empty-array fields are already omitted by compose-manager's serde.
    """
    canonical = json.dumps(
        actions, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return sha256(canonical.encode()).hexdigest()


async def _verify_compose_manager_quote(
    cma: dict[str, Any], nonce: str
) -> tuple[bool, bool, bool, IntelResult | None]:
    """Verify the compose-manager TDX quote and its report-data binding.

    Returns ``(tdx_verified, actions_hash_bound, nonce_bound, intel_result)``.
    ``actions_hash_bound`` compares the recomputed hash of the emitted actions to
    ``report_data[0:32]``, never the attacker-supplied ``actions_hash`` field.
    """
    quote = cma.get("quote")
    if not quote:
        logger.error("compose_manager_attestation missing quote")
        return False, False, False, None
    try:
        intel_result = await verify_tdx_quote({"intel_quote": quote})
    except (ValueError, RuntimeError) as e:
        logger.error("compose-manager TDX quote verification failed: %s", e)
        return False, False, False, None

    report_data = intel_result["quote"]["body"]["reportdata"].removeprefix("0x").lower()
    # actions_hash is attacker-supplied and logged only; the binding uses the
    # recomputed hash.
    actions = cma.get("actions") or []
    actions_hash_field = str(cma.get("actions_hash", "")).lower()
    rd_prefix = report_data[0:64] if len(report_data) >= 64 else ""
    # Accept only the canonical form: a second, key-order-dependent
    # serialization would let a malicious build craft a matching forged log.
    canonical_hex = _actions_report_data_hash(actions)
    actions_hash_bound = bool(rd_prefix) and rd_prefix == canonical_hex
    nonce_bound = len(report_data) >= 128 and report_data[64:128] == nonce.lower()

    if not actions_hash_bound:
        logger.error(
            "compose-manager actions do NOT hash to report_data[0:32]: "
            "report_data=%s canonical=%s actions_hash_field=%s",
            rd_prefix,
            canonical_hex,
            actions_hash_field,
        )
    if not nonce_bound:
        logger.error(
            "compose-manager report_data does not bind nonce: "
            "report_data[64:128]=%s nonce=%s",
            report_data[64:128] if len(report_data) >= 128 else report_data,
            nonce.lower(),
        )
    return intel_result["verified"], actions_hash_bound, nonce_bound, intel_result


def fetch_and_verify_serving_yaml(
    commit: str, file: str, file_sha256: str | None
) -> tuple[bool, str]:
    """Fetch the serving compose YAML and verify its sha256.

    Returns ``(verified, yaml_text)``; ``yaml_text`` is "" unless verified.
    ``file_sha256=None`` (a ``compose_down``, which logs none) skips the hash
    check; the commit still pins the content.
    """
    url = f"{CVM_COMPOSE_FILES_RAW_BASE}/{CVM_COMPOSE_FILES_REPO}/{commit}/{file}"
    logger.info("Fetching serving compose file: %s", url)
    response = get_http_session().get(url, timeout=30)
    if not response.ok:
        logger.error(
            "Failed to fetch serving compose file %s: HTTP %d",
            url,
            response.status_code,
        )
        return False, ""
    actual_sha256 = sha256(response.content).hexdigest()
    if file_sha256 is not None and actual_sha256.lower() != file_sha256.lower():
        logger.error(
            "Serving compose file sha256 mismatch: expected %s, got %s",
            file_sha256,
            actual_sha256,
        )
        return False, ""
    logger.info("Serving compose file verified: %s", url)
    return True, response.text


def _argv(value: Any) -> list[str]:
    """A compose ``command``/``entrypoint`` as argv, split the way compose does.

    Arguments with spaces (an ``sh -c`` script) are split once more so a flag
    inside one is still seen. Unsplittable text is kept whole.
    """
    if isinstance(value, list):
        args = [str(v) for v in value]
    else:
        try:
            args = shlex.split(str(value or ""))
        except ValueError:
            args = [str(value)]
    out: list[str] = []
    for arg in args:
        try:
            out += shlex.split(arg) if any(c.isspace() for c in arg) else [arg]
        except ValueError:
            out.append(arg)
    return out


def _flag_values(argv: list[str], flags: tuple[str, ...]) -> list[str]:
    """Values of ``flags`` in ``argv``, read the way argparse would.

    vLLM accepts ``_`` for ``-``, and argparse accepts any unique prefix of a
    long flag. A prefix of a watched flag yields a value that never matches
    an approved entry, so an abbreviation fails closed.
    """
    values = []
    for i, arg in enumerate(argv):
        flag, eq, value = arg.partition("=")
        if flag.startswith("--"):
            # vLLM reads --speculative-config.model as a key of that flag.
            flag = "--" + flag[2:].split(".", 1)[0].replace("_", "-")
        value = value if eq else argv[i + 1] if i + 1 < len(argv) else ""
        if flag in flags:
            values.append(value)
        elif len(flag) > 2 and any(f.startswith(flag) for f in flags):
            values.append(f"abbreviated flag {flag}")
    return values


def _positional_models(argv: list[str]) -> list[str]:
    """The positional model of ``vllm serve <model>``, which overrides
    ``--model``."""
    return [
        argv[i + 1]
        for i in range(1, len(argv) - 1)
        if argv[i] == "serve"
        and argv[i - 1].rsplit("/", 1)[-1] in ("vllm", "sglang")
        and not argv[i + 1].startswith("-")
    ]


def _uses_gpu(service: dict[str, Any]) -> bool:
    """Whether a compose service can reach the GPUs.

    A ``${VAR}`` in runtime, privileged or a device driver could become
    anything at up time, so it counts, as does any device reservation, an
    ``env_file`` (it can set NVIDIA_VISIBLE_DEVICES) and a variable passed
    through from the up-time environment. A ``device_cgroup_rules`` entry
    grants access to whole device classes by major number (NVIDIA nodes are
    ``c 195:*``) and lets the container create the nodes itself, so any rule
    counts, as does a bind of ``/dev`` or of a device node under it.
    """
    runtime, privileged = service.get("runtime"), service.get("privileged")
    if runtime == "nvidia" or "$" in str(runtime or ""):
        return True
    if privileged is True or (isinstance(privileged, str) and privileged != "false"):
        return True
    if service.get("gpus") or service.get("env_file"):
        return True
    if service.get("device_cgroup_rules"):
        return True
    deploy = service.get("deploy")
    resources = deploy.get("resources") if isinstance(deploy, dict) else None
    reservations = (
        resources.get("reservations") if isinstance(resources, dict) else None
    )
    devices = reservations.get("devices") if isinstance(reservations, dict) else None
    if devices:
        return True
    if any("nvidia" in str(d) for d in service.get("devices") or []):
        return True
    if _binds_device_tree(service):
        return True
    env = service.get("environment")
    if isinstance(env, list):
        env = {
            k: v if sep else None for k, sep, v in (str(e).partition("=") for e in env)
        }
    env = env if isinstance(env, dict) else {}
    if "NVIDIA_VISIBLE_DEVICES" not in env:
        return False
    visible = env["NVIDIA_VISIBLE_DEVICES"]
    return visible is None or str(visible).strip().lower() not in ("", "void", "none")


# /dev subpaths that are not device nodes: /dev/shm is the shared-memory
# tmpfs, which non-server services bind for ordinary IPC. It is a device-tree
# path here, not a temp directory.
_HARMLESS_DEV_PATHS = frozenset({"/dev/shm"})  # nosec B108


def _binds_device_tree(service: dict[str, Any]) -> bool:
    """Whether a host bind puts device nodes in the container's reach: a bind
    of ``/dev`` exposes every node, a bind of one node (e.g. ``/dev/nvidia0``)
    that device, and a ``${VAR}`` could be either at up time."""
    sources: list[str] = []
    for volume in service.get("volumes") or []:
        if isinstance(volume, dict):
            if volume.get("type") not in (None, "bind"):
                continue
            sources.append(str(volume.get("source") or ""))
        else:
            sources.append(str(volume).split(":", 1)[0])
    for device in service.get("devices") or []:
        if isinstance(device, dict):
            sources.append(str(device.get("source") or ""))
        else:
            sources.append(str(device).split(":", 1)[0])
    return any(
        "$" in source
        or source == "/dev"
        or (source.startswith("/dev/") and source not in _HARMLESS_DEV_PATHS)
        for source in sources
    )


# Host paths that would hand a container the dstack or Docker socket.
_SOCKET_DIRS = frozenset({"/", "/var", "/var/run", "/run"})


def _mount_sources(service: dict[str, Any], key: str) -> list[str]:
    """The host paths a service reaches through volume- or device-shaped
    entries under ``key`` (``volumes``, ``devices``).

    Strings spell ``source:target[:mode]``; mappings spell the host side
    ``source``/``pathOnHost``. Devices reach host paths the same way volumes
    do, so a socket passed with ``devices:`` is treated like one mounted with
    ``volumes:``.
    """
    sources: list[str] = []
    for mount in service.get(key) or []:
        if isinstance(mount, dict):
            sources.append(str(mount.get("source") or mount.get("pathOnHost") or ""))
        else:
            sources.append(str(mount).split(":", 1)[0])
    return sources


def _socket_mounts(service: dict[str, Any], volumes: dict[str, Any]) -> set[str]:
    """Which sockets a service's host mounts reach: "dstack" (it can get a
    quote for any report_data) and "docker" (it can start any container).

    A host path from ``${VAR}`` cannot be known, so it counts as both, as does
    a named volume backed by such a host path. ``volumes_from`` inherits
    another service's mounts, which the Compose program leaves unresolved, so
    it counts as reaching both.
    """
    reached: set[str] = set()
    if service.get("volumes_from"):
        reached |= {"dstack", "docker"}
    for source in _mount_sources(service, "volumes") + _mount_sources(
        service, "devices"
    ):
        named = volumes.get(source) if not source.startswith(("/", ".", "$")) else None
        if isinstance(named, dict):
            opts = named.get("driver_opts")
            source = str(opts.get("device") or "") if isinstance(opts, dict) else ""
        if not source:
            continue
        if source.startswith("/"):
            # normpath keeps a leading "//", which the kernel reads as "/".
            path = "/" + posixpath.normpath(source).lstrip("/")
        else:
            path = source
        if "$" in path or path in _SOCKET_DIRS:
            reached |= {"dstack", "docker"}
        elif "docker.sock" in path:
            reached.add("docker")
        elif "dstack.sock" in path or "tappd.sock" in path:
            reached.add("dstack")
    return reached


def _socket_problems(
    services: dict[str, Any], volumes: dict[str, Any], label: str = ""
) -> list[str]:
    """Services that could forge the CVM's quotes or start containers outside
    the actions log: only the digest-pinned proxy may reach the dstack
    socket, and nothing may reach the Docker socket."""
    problems = []
    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        reached = _socket_mounts(service, volumes)
        image = str(service.get("image") or "")
        if "dstack" in reached and not image.startswith(f"{_PROXY}@sha256:"):
            problems.append(f"{label}{name}: mounts the dstack socket")
        if "docker" in reached:
            problems.append(f"{label}{name}: mounts the Docker socket")
    return problems


def running_service_problems(state: dict[tuple[str, str], ServingFile]) -> list[str]:
    """:func:`_gpu_problems`, :func:`_socket_problems` and :func:`_hook_problems`
    for every running service, read from the file it runs from. Reviewed
    maintenance files are exempt."""
    problems = []
    for (project, service), entry in state.items():
        if entry.file_sha256 in APPROVED_MAINTENANCE_COMPOSES:
            continue
        doc = canonical_compose(entry.text)
        services = _services(doc)
        if service in services:
            problems += _gpu_problems({service: services[service]}, f"{project}/")
            problems += _socket_problems(
                {service: services[service]},
                doc.get("volumes") or {},
                f"{project}/",
            )
            problems += _hook_problems(f"{project}/{service}", services[service])
    return problems


def _yaml_doc(text: str) -> dict[str, Any]:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return {}
    return doc if isinstance(doc, dict) else {}


# One-level stand-ins for the project directory and HOME. A relative or ~
# path that climbs out of them lands at /, so it can only over-match the
# socket rule, whatever directory compose-manager really runs from.
_FAKE_PROJECT_DIR = "/__project__"
_FAKE_HOME = "/__home__"


@lru_cache(maxsize=1)
def _compose_version_ok() -> bool:
    """Whether the Compose we run is the version compose-manager runs; another
    version could read a file differently."""
    try:
        out = subprocess.run(  # nosec B603
            [*COMPOSE_COMMAND, "version", "--short"],
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.error("docker compose could not run (%s): %s", COMPOSE_COMMAND, e)
        return False
    if out.removeprefix("v") != COMPOSE_VERSION:
        logger.error(
            "docker compose %r is not the pinned %s that compose-manager runs;"
            " install it, or set COMPOSE_BIN to that binary",
            out,
            COMPOSE_VERSION,
        )
        return False
    return True


@lru_cache(maxsize=256)
def canonical_compose(text: str) -> dict[str, Any]:
    """A compose file as Docker Compose itself resolves it, or {} if it
    cannot.

    ``docker compose config`` applies include, extends, merge keys, implicit
    dependencies and path resolution exactly as ``up`` would, so the checks
    below read what compose-manager runs rather than a second parse of the
    YAML. Interpolation is left off, since the env given at up time is not
    logged. Callers must not mutate the result, which is cached.
    """
    if not _compose_version_ok():
        return {}
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "compose.yaml"
        path.write_text(text)
        try:
            proc = subprocess.run(  # nosec B603
                [
                    *COMPOSE_COMMAND,
                    "-f",
                    str(path),
                    "--project-directory",
                    _FAKE_PROJECT_DIR,
                    "config",
                    "--no-interpolate",
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=60,
                env={"PATH": os.environ.get("PATH", ""), "HOME": _FAKE_HOME},
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            logger.error("docker compose could not run (%s): %s", COMPOSE_COMMAND, e)
            return {}
    if proc.returncode != 0:
        logger.error("docker compose rejected a compose file: %s", proc.stderr.strip())
        return {}
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError:
        logger.error("docker compose config printed no JSON")
        return {}
    return doc if isinstance(doc, dict) else {}


def _services(doc: dict[str, Any]) -> dict[str, Any]:
    services = doc.get("services")
    return services if isinstance(services, dict) else {}


def serving_weights(compose: str) -> list[str]:
    """``org/name@revision`` for every model path in a compose file, and for
    every chat template, tokenizer or draft model a server is given.

    Read from each service's parsed ``command`` and ``entrypoint``, so a
    comment or label cannot stand in for the real argument. A path that is not
    a pinned Hugging Face snapshot is returned as-is, and an inference server
    with no model path as ``<service>: no model path``; neither ever matches
    an approved entry.
    """
    return weights_of(_services(canonical_compose(compose)))


def weights_of(services: dict[str, Any]) -> list[str]:
    """:func:`serving_weights` for already-resolved service definitions."""
    weights: list[str] = []
    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        argv = _argv(service.get("entrypoint")) + _argv(service.get("command"))
        paths = _flag_values(argv, _MODEL_FLAGS) + _positional_models(argv)
        for path in paths + _flag_values(argv, _ARTIFACT_FLAGS):
            m = _HF_SNAPSHOT_RE.fullmatch(path)
            weights.append(f"{m.group(1)}/{m.group(2)}@{m.group(3)}" if m else path)
        server = _is_server(service)
        if server and not paths:
            weights.append(f"{name}: no model path")
        if any(v.lower() == "dummy" for v in _flag_values(argv, ("--load-format",))):
            weights.append(f"{name}: --load-format dummy")
        if server and _flag_values(argv, ("--config",)):
            # Loads any of the flags above from a file the check cannot see.
            weights.append(f"{name}: server reads a --config file")
        if server and any(_INTERPOLATED.search(a) for a in argv):
            # Env given at up time is not logged, so ${VAR} could become a flag.
            weights.append(f"{name}: interpolated server argument")
    return weights


def _is_server(service: dict[str, Any]) -> bool:
    argv = _argv(service.get("entrypoint")) + _argv(service.get("command"))
    joined = " ".join(argv)
    image = str(service.get("image") or "")
    return any(marker in joined for marker in _SERVER_MARKERS) or any(
        image.startswith(i) for i in _SERVER_IMAGES
    )


def _gpu_problems(services: dict[str, Any], label: str = "") -> list[str]:
    """Services outside a recognised inference server that can reach the GPUs:
    they could change what runs on the GPUs without loading a model path the
    weights check sees. The proxy and the DCGM exporter are exempt."""
    problems = []
    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        image = image_path(str(service.get("image") or ""))
        if (
            _uses_gpu(service)
            and not _is_server(service)
            and image not in (_PROXY, *_GPU_TOOL_IMAGES)
        ):
            problems.append(f"{label}{name}: GPU access without a recognised server")
    return problems


def _service_problems(compose: str) -> list[str]:
    """Services that could change what runs on the GPUs without loading a
    model path the weights check sees: GPU access outside a recognised
    server, or a mounted dstack or Docker socket."""
    doc = canonical_compose(compose)
    services = _services(doc)
    if not services:
        return ["no services Compose can read in the file"]
    volumes = doc.get("volumes")
    if not isinstance(volumes, dict):
        volumes = {}
    problems = _gpu_problems(services)
    problems += [
        p
        for name, service in services.items()
        if isinstance(service, dict)
        for p in _hook_problems(name, service)
    ]
    return problems + _socket_problems(services, volumes)


def _hook_problems(name: str, service: dict[str, Any]) -> list[str]:
    """Commands Compose runs in a container besides its entrypoint: lifecycle
    hooks are refused, and a healthcheck may not start a server."""
    problems = [
        f"{name}: {hook} hook"
        for hook in ("post_start", "pre_stop")
        if service.get(hook)
    ]
    healthcheck = service.get("healthcheck")
    test = healthcheck.get("test") if isinstance(healthcheck, dict) else None
    joined = " ".join(_argv(test))
    if any(marker in joined for marker in _SERVER_MARKERS):
        problems.append(f"{name}: healthcheck starts a server")
    return problems


def compose_file_approved(compose: str, model: str) -> bool:
    """True when running any service of this file cannot change the weights:
    every snapshot it can load is approved for ``model``, and nothing else in
    it can reach the GPUs or the dstack or Docker socket. A reviewed
    maintenance file in APPROVED_MAINTENANCE_COMPOSES passes."""
    if sha256(compose.encode()).hexdigest() in APPROVED_MAINTENANCE_COMPOSES:
        return True
    if problems := _service_problems(compose):
        logger.warning("Compose file not approved: %s", problems)
        return False
    return not unapproved_weights(serving_weights(compose), model)


def unapproved_weights(weights: list[str], model: str) -> list[str]:
    """The entries of ``weights`` not in APPROVED_MODEL_WEIGHTS for ``model``."""
    approved = APPROVED_MODEL_WEIGHTS.get(model, frozenset())
    return [w for w in weights if w not in approved]


def model_weights_approved(compose: str, model: str) -> bool:
    """True when every model the compose loads is approved for ``model``."""
    return weights_approved(serving_weights(compose), model)


def weights_approved(weights: list[str], model: str) -> bool:
    """True when ``weights`` is non-empty and every entry is approved."""
    unapproved = unapproved_weights(weights, model)
    if not weights or unapproved:
        logger.error(
            "Serving compose for %s loads unapproved model weights: %s. Audit "
            "them and add them to APPROVED_MODEL_WEIGHTS.",
            model,
            unapproved or "no --model-path found",
        )
        return False
    return True


def blank_inference_summary(label: str, model_name: str) -> InferenceAttestationSummary:
    """An inference summary with every check failed, before any is run."""
    return {
        "type": f"Inference: {label}",
        "model_name": model_name,
        "model_name_matches": False,
        "tdx_verified": False,
        "os_measurements_valid": False,
        "mrconfig_valid": False,
        "compose_hash_valid": False,
        "near_images_verified": False,
        "compose_manager_verified": False,
        "boot_compose_manager_verified": False,
        "boot_compose_manager_image": None,
        "compose_manager_tdx_verified": False,
        "proxy_report_data_valid": False,
        "actions_hash_bound": False,
        "nonce_bound": False,
        "same_cvm": False,
        "report_data_valid": False,
        "serving_yaml_verified": False,
        "model_weights_approved": False,
        "serving_weights": [],
        "serving_composes": [],
        "compose_log": "",
        "image_verification": None,
        "gpu_verified": None,
        "signing_public_key": None,
        "signing_address": None,
        "signing_algo": None,
    }


async def verify_inference_attestation(
    attestation: dict[str, Any],
    nonce: str,
    policy: VerificationPolicy,
    requested_model: str,
) -> InferenceAttestationSummary:
    """Verify a per-model inference attestation end-to-end."""
    model_name = str(attestation.get("model_name", ""))
    summary = blank_inference_summary(model_name or requested_model, model_name)
    summary["signing_public_key"] = attestation.get("signing_public_key")
    summary["signing_address"] = attestation.get("signing_address")
    summary["signing_algo"] = attestation.get("signing_algo")

    if not model_names_match(model_name, requested_model):
        logger.error(
            "Attested model does not match the requested model: requested %r, "
            "gateway attested %r. Refusing to verify a substituted model; check "
            "MODEL_NAME against the gateway's /v1/models.",
            requested_model,
            model_name,
        )
        return summary
    summary["model_name_matches"] = True

    try:
        intel_result = await verify_tdx_quote(attestation)
    except (ValueError, RuntimeError) as e:
        logger.error("Inference-proxy TDX quote verification failed: %s", e)
        return summary

    summary["tdx_verified"] = intel_result["verified"]
    summary["os_measurements_valid"] = check_os_measurements(
        intel_result, summary["type"]
    )
    summary["mrconfig_valid"] = _validate_mrconfig(
        _extract_app_compose(attestation), intel_result["quote"]["body"]["mrconfig"]
    )
    summary["compose_hash_valid"] = _check_compose_hash(attestation)

    proxy_rd = check_report_data(attestation, nonce, intel_result)
    proxy_report_data_valid = _proxy_binding_ok(proxy_rd)
    summary["proxy_report_data_valid"] = proxy_report_data_valid

    cma = attestation.get("compose_manager_attestation") or {}
    (
        cm_tdx,
        actions_hash_bound,
        nonce_bound,
        cm_intel_result,
    ) = await _verify_compose_manager_quote(cma, nonce)
    summary["compose_manager_tdx_verified"] = cm_tdx
    summary["actions_hash_bound"] = actions_hash_bound
    summary["nonce_bound"] = nonce_bound

    same_cvm = _same_cvm(intel_result, cm_intel_result)
    summary["same_cvm"] = same_cvm
    if cm_intel_result is not None and not same_cvm:
        logger.error(
            "inference-proxy and compose-manager quotes are not the same CVM: "
            "proxy=%s compose-manager=%s",
            _measurements(intel_result),
            _measurements(cm_intel_result),
        )

    summary["report_data_valid"] = (
        proxy_report_data_valid
        and cm_tdx
        and actions_hash_bound
        and nonce_bound
        and same_cvm
    )

    serving_text = ""
    state = serving_state(cma.get("actions") or [])
    if state:
        serving_text = running_compose(state)
        problems = running_service_problems(state)
        for problem in problems:
            logger.error("Running service can bypass the actions log: %s", problem)
        summary["serving_yaml_verified"] = not problems
        summary["serving_composes"] = [
            {
                "file": f.file,
                "commit": f.commit,
                "file_sha256": f.file_sha256,
                "approved": compose_file_approved(f.text, requested_model),
            }
            for f in dict.fromkeys(state.values())
        ]
        summary["compose_log"] = compose_log_chain(cma.get("actions") or [])[-1]
        summary["serving_weights"] = weights_of(running_services(state))
        summary["model_weights_approved"] = weights_approved(
            summary["serving_weights"], requested_model
        )
    else:
        logger.warning("The actions log does not replay to any running service")

    # compose-manager comes from the actions log (the boot compose's is stale);
    # fall back to the boot compose only if the log has no started entry.
    running_cm = _running_compose_manager_image(cma.get("actions") or [])
    # The log's author must be compose-manager itself, pinned by digest; a
    # decoy elsewhere in the compose cannot satisfy the required image.
    running_cm_ok = not running_cm or (
        image_path(running_cm) == _CM_REGISTRY and bool(pinned_images([running_cm]))
    )
    if not running_cm_ok:
        logger.error(
            "Running compose-manager is not a pinned %s: %s", _CM_REGISTRY, running_cm
        )
    boot_text = _boot_docker_compose(attestation)
    boot_envs = overridable_envs(_extract_app_compose(attestation))
    serving_images = compose_images(serving_text) if serving_text else []
    if running_cm:
        # The launcher is never swapped by the actions log, so it comes from
        # the measured boot compose.
        boot_launcher = [
            v for v in compose_images(boot_text) if image_path(v) == _LAUNCHER
        ]
        images = [*serving_images, running_cm, *boot_launcher]
    else:
        images = [*compose_images(boot_text), *serving_images]
    if summary["serving_yaml_verified"] and images:
        try:
            image_verification = verify_compose_images_full(images, policy, boot_envs)
        except ValueError as e:
            logger.error("NEAR inference image verification failed: %s", e)
            image_verification = {"images": {}}
        summary["image_verification"] = image_verification
        extra = ACCEPTED_EXTRA_PROXY_IMAGES.get(model_name, frozenset())
        checked = {
            ref: result
            for ref, result in image_verification.get("images", {}).items()
            if ref not in extra
        }
        running_ok = all_images_fully_verified({"images": checked}, policy) and (
            not extra or any(image_path(ref) == _PROXY for ref in checked)
        )
        # In the fallback path the boot image was already verified above.
        if running_cm:
            boot_ok, boot_result = _verify_boot_compose_manager(
                boot_text, policy, boot_envs, image_verification.get("images", {})
            )
            summary["boot_compose_manager_verified"] = boot_ok
            summary["boot_compose_manager_image"] = boot_result
            # The boot compose's other images still run; report them too.
            boot_unverified = compose_image_problems(
                compose_images(boot_text), policy.required_images, boot_envs
            )[1]
            listed = image_verification.setdefault("unverified_images", [])
            listed += [u for u in boot_unverified if u not in listed]
        else:
            summary["boot_compose_manager_verified"] = running_ok
        summary["near_images_verified"] = (
            running_ok and summary["boot_compose_manager_verified"] and running_cm_ok
        )
        log_images = {
            ref: result
            for ref, result in image_verification.get("images", {}).items()
            if image_path(ref) != _PROXY
        }
        summary["compose_manager_verified"] = all_images_fully_verified(
            {"images": log_images}, policy
        ) and (
            running_cm_ok
            and (not running_cm or summary["boot_compose_manager_verified"])
        )

    if "nvidia_payload" in attestation:
        try:
            gpu_result = await asyncio.to_thread(check_gpu, attestation, nonce)
            summary["gpu_verified"] = (
                gpu_result["nonce_matches"] and gpu_result["verdict"]
            )
        except (RuntimeError, KeyError, ValueError) as e:
            logger.error("GPU verification failed for %s: %s", model_name, e)
            summary["gpu_verified"] = False

    return summary
