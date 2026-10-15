# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Detect image-pin drift and rewrite the pins in config.py.

Used by ``scripts/review_pins.py``.
"""

import re
from typing import NamedTuple

from .config import (
    _GATEWAY_EXPECTED_COMMITS,
    _INFERENCE_EXPECTED_COMMITS,
    _PROXY_EXPECTED_COMMITS,
    APPROVED_MODEL_WEIGHTS,
    BOOT_COMPOSE_MANAGER_COMMITS,
    CERT_REPOSITORIES,
    INFERENCE_REPOSITORIES,
)

_PROXY_REGISTRY = "nearaidev/vllm-proxy-rs"
_CM_REGISTRY = "nearaidev/compose-manager"
# Drift.registry for an unreviewed boot compose-manager commit. Approving it
# adds the commit to BOOT_COMPOSE_MANAGER_COMMITS instead of replacing a pin.
BOOT_CM = "nearaidev/compose-manager (boot)"
# Drift.registry for model weights the serving compose loads that
# APPROVED_MODEL_WEIGHTS does not list. have/need are "org/name@revision";
# have, shown for context, is an approved revision of the same Hugging Face
# repo, or "" if none. Approving adds need and leaves have in place.
WEIGHTS = "model weights"
_PINNED_WEIGHTS_RE = re.compile(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+@[0-9a-f]{40}")

MISMATCH_RE = re.compile(
    r"Commit SHA mismatch for '(?P<img>[^']+)':.*?"
    r"expected:\s*(?P<have>[0-9a-f]{40}).*?"
    r"got:\s*(?P<need>[0-9a-f]{40})",
    re.DOTALL,
)
# The deployed commit from either mismatch form (single pin or reviewed set).
_GOT_RE = re.compile(
    r"Commit SHA mismatch for '[^']+':.*?got:\s*(?P<need>[0-9a-f]{40})", re.DOTALL
)


class Drift(NamedTuple):
    registry: str  # e.g. "nearaidev/cloud-api"
    have: str  # currently pinned commit
    need: str  # deployed commit (Sigstore-verified)
    is_inference: bool  # True -> pin lives in _INFERENCE_EXPECTED_COMMITS
    source_repo: str | None  # e.g. "nearai/cloud-api", for review links
    # Set for vllm-proxy-rs, whose pins are per-model.
    model: str | None = None


def expected_pins(env: str, model: str | None = None) -> dict[str, str]:
    """The pins for ``env`` from the imported config, with ``model``'s proxy pin
    if given."""
    pins = {**_INFERENCE_EXPECTED_COMMITS, **_GATEWAY_EXPECTED_COMMITS[env]}
    if model is not None:
        pins[_PROXY_REGISTRY] = _PROXY_EXPECTED_COMMITS.get(model, "")
    return pins


def _block_marker(stripped: str) -> str | None:
    """Which pin block a config.py line opens, if any."""
    if stripped.startswith("_INFERENCE_EXPECTED_COMMITS"):
        return "inference"
    if stripped.startswith("_PROXY_EXPECTED_COMMITS"):
        return "proxy"
    if stripped.startswith('"prod":'):
        return "prod"
    if stripped.startswith('"staging":'):
        return "staging"
    return None


def _deployed_commit(entry: dict) -> str | None:
    """The deployed commit from a report entry, or None if undeterminable
    (callers must treat None as a failure, never as 'no drift')."""
    provenance = entry.get("provenance") or {}
    commit = provenance.get("commit_sha")
    if commit:
        return str(commit)
    for message in entry.get("messages", []):
        match = _GOT_RE.search(message)
        if match:
            return match.group("need")
    return None


class Coverage(NamedTuple):
    drifts: list[Drift]  # pinned images whose deployed commit != pin
    matched: list[str]  # pinned images positively confirmed matching
    unresolved: list[str]  # pinned images whose deployed commit couldn't be read


def analyze(
    summaries: list[dict], expected: dict[str, str], model: str | None = None
) -> Coverage:
    """Check the deployed commit of EVERY image in ``expected`` against the report.

    Enumerates every pin rather than scanning for mismatch messages, which
    would silently pass an incomplete run.
    """
    entries: dict[str, dict] = {}
    for summary in summaries:
        images = (summary.get("image_verification") or {}).get("images", {})
        for ref, entry in images.items():
            entries[ref.split("@")[0]] = entry

    repos = {**CERT_REPOSITORIES, **INFERENCE_REPOSITORIES}
    drifts: list[Drift] = []
    matched: list[str] = []
    unresolved: list[str] = []
    for registry, pinned in expected.items():
        deployed = _deployed_commit(entries[registry]) if registry in entries else None
        if deployed is None:
            unresolved.append(registry)
        elif deployed == pinned:
            matched.append(registry)
        else:
            drifts.append(
                Drift(
                    registry=registry,
                    have=pinned,
                    need=deployed,
                    is_inference=registry in _INFERENCE_EXPECTED_COMMITS,
                    source_repo=repos.get(registry),
                    model=model if registry == _PROXY_REGISTRY else None,
                )
            )
    # The boot compose-manager is checked against a set of reviewed commits; a
    # new one is diffed from the reviewed running pin.
    for summary in summaries:
        entry = summary.get("boot_compose_manager_image")
        if entry is None:
            continue
        deployed = _deployed_commit(entry)
        if deployed is None:
            unresolved.append(BOOT_CM)
        elif deployed in BOOT_COMPOSE_MANAGER_COMMITS:
            matched.append(BOOT_CM)
        else:
            drifts.append(
                Drift(
                    registry=BOOT_CM,
                    have=expected.get(_CM_REGISTRY, ""),
                    need=deployed,
                    is_inference=True,
                    source_repo=repos.get(_CM_REGISTRY),
                )
            )
    if model is not None:
        _analyze_weights(summaries, model, drifts, matched, unresolved)
    return Coverage(sorted(set(drifts)), sorted(set(matched)), sorted(set(unresolved)))


def _analyze_weights(
    summaries: list[dict],
    model: str,
    drifts: list[Drift],
    matched: list[str],
    unresolved: list[str],
) -> None:
    """Check the weights each inference summary loads against the approved set.

    Weights that are not a pinned snapshot are unresolved, never a drift, so
    an unpinned path can never be approved.
    """
    approved = APPROVED_MODEL_WEIGHTS.get(model, frozenset())
    for summary in summaries:
        if "serving_weights" not in summary:
            continue
        weights = summary["serving_weights"]
        if not weights or not all(_PINNED_WEIGHTS_RE.fullmatch(w) for w in weights):
            unresolved.append(WEIGHTS)
            continue
        for w in weights:
            if w in approved:
                matched.append(WEIGHTS)
                continue
            repo = w.split("@")[0]
            have = next((a for a in sorted(approved) if a.split("@")[0] == repo), "")
            drifts.append(Drift(WEIGHTS, have, w, True, None, model))


def compare_url(drift: Drift) -> str | None:
    """GitHub compare link (old→new) to review the service's code changes, or
    the Hugging Face snapshot for a weights drift."""
    if drift.registry == WEIGHTS:
        repo, rev = drift.need.split("@")
        return f"https://huggingface.co/{repo}/tree/{rev}"
    if not drift.source_repo:
        return None
    return f"https://github.com/{drift.source_repo}/compare/{drift.have}...{drift.need}"


def rewrite_pins(text: str, drifts: list[Drift], env: str) -> tuple[str, list[Drift]]:
    """Return (new_text, applied). Gateway edits are scoped to the ``env`` block.

    A line is rewritten only inside its own block and only while it still
    holds the exact ``have`` commit, so a staging run never touches a prod pin.
    A proxy drift without a model is never applied.
    """
    proxy = {d.model: d for d in drifts if d.registry == _PROXY_REGISTRY and d.model}
    inference = {
        d.registry: d
        for d in drifts
        if d.is_inference and d.registry != _PROXY_REGISTRY
    }
    gateway = {d.registry: d for d in drifts if not d.is_inference}
    applied: list[Drift] = []
    block: str | None = None
    out: list[str] = []
    for line in text.splitlines(keepends=True):
        block = _block_marker(line.lstrip()) or block

        if block == "proxy":
            for model, drift in proxy.items():
                if f'"{model}": "' in line and f'"{drift.have}"' in line:
                    line = line.replace(f'"{drift.have}"', f'"{drift.need}"')
                    applied.append(drift)
        targets = (
            inference if block == "inference" else (gateway if block == env else {})
        )
        for registry, drift in targets.items():
            if f'"{registry}": "' in line and f'"{drift.have}"' in line:
                line = line.replace(f'"{drift.have}"', f'"{drift.need}"')
                applied.append(drift)
        out.append(line)
    return "".join(out), applied


def add_boot_commits(text: str, commits: list[str]) -> tuple[str, list[str]]:
    """Return (new_text, added): ``commits`` appended to the
    ``BOOT_COMPOSE_MANAGER_COMMITS`` set in config.py text. A commit already
    listed counts as added; nothing is added if the block is not found."""
    out: list[str] = []
    in_block = False
    added: list[str] = []
    for line in text.splitlines(keepends=True):
        if line.startswith("BOOT_COMPOSE_MANAGER_COMMITS"):
            in_block = True
        elif in_block and line.strip() == "}":
            for sha in commits:
                if f'"{sha}"' not in "".join(out) and sha not in added:
                    out.append(f'        "{sha}",\n')
                added.append(sha)
            in_block = False
        out.append(line)
    return "".join(out), list(dict.fromkeys(added))


def approve_weights(text: str, drifts: list[Drift]) -> tuple[str, list[Drift]]:
    """Return (new_text, applied): each weights drift added to its model's set
    in ``APPROVED_MODEL_WEIGHTS``; a model with no set gets one.

    Approval only adds. Other services, or a chat template, may still load an
    older revision of the same repo, so stale entries are removed by hand.
    """
    pending = [d for d in drifts if d.registry == WEIGHTS and d.model]
    applied: list[Drift] = []
    out: list[str] = []
    in_block = False
    model: str | None = None
    seen: set[str] = set()
    for line in text.splitlines(keepends=True):
        if line.startswith("APPROVED_MODEL_WEIGHTS"):
            in_block = True
        elif in_block and line.rstrip() == "}":
            new: dict[str, list[Drift]] = {}
            for d in pending:
                if d.model not in seen and d not in applied:
                    new.setdefault(str(d.model), []).append(d)
            for new_model, ds in new.items():
                out += [f'    "{new_model}": frozenset(\n', "        {\n"]
                out += [f'            "{d.need}",\n' for d in ds]
                out += ["        }\n", "    ),\n"]
                applied += ds
            in_block = False
        elif in_block:
            opened = re.match(r'\s+"(?P<model>[^"]+)": frozenset\(', line)
            if opened:
                model = opened.group("model")
                seen.add(model)
            elif model and line.strip() == "}":
                for d in pending:
                    if d.model == model and d not in applied:
                        out.append(f'            "{d.need}",\n')
                        applied.append(d)
                model = None
        out.append(line)
    return "".join(out), applied
