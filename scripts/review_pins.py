#!/usr/bin/env python3
# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.
"""Review NEAR attestation pin drift and cut a release from the terminal.

Needs the GitHub CLI (``gh``), authenticated, and git. The diff viewer defaults
to neovim with Diffview (PIN_REVIEW_DIFF_CMD changes it).

  1. For each chosen environment (prod and staging by default), fetch NEAR's
     live attestation and read the deployed commit of every pinned image
     (Sigstore-verified from SLSA provenance).
  2. Print how each differs from THIS checkout's verifier/config.py, with the
     release date/time of both the pinned and the deployed commit.
  3. For each changed service, optionally open the old→new code diff (neovim by
     default, or the GitHub compare page), then approve the ones you want.
  4. Approved changes are written to config.py, committed on a release branch cut
     from master, and opened as a PR.
  5. When you merge the PR, the CodeBuild verification is fired for the changed
     environment(s).

Run from a clean checkout of master:
  poetry run python scripts/review_pins.py            # both prod and staging
  poetry run python scripts/review_pins.py --env prod # just prod
  make review-pins ENV=staging                        # just staging

Only the chosen environment(s) are reviewed, and only their CodeBuild
verification is fired on merge. A change to a shared inference image fires every
chosen environment (both, by default).

Env vars (all optional):
  PIN_REVIEW_DIFF_CMD       editor diff command; {have}/{need} are the commits
                            (default: nvim -c "DiffviewOpen {have}..{need}")
  PIN_REVIEW_BASE_BRANCH    branch the PR targets (default: master)
  PIN_REVIEW_CODEBUILD_CMD  override the CodeBuild command; {env} is substituted
  PIN_REVIEW_PROMPT_FILE    privacy-review prompt for [s]can (not shipped)
  CODEBUILD_PROJECT         CodeBuild project fired on merge (Brave-internal)
  AWS_VAULT_PROFILE         aws-vault profile allowed to start it
                            (both also read from .env.local; if either is
                            unset, nothing is fired on merge)
  PIN_REVIEW_CLAUDE_CMD     Claude CLI for the privacy review (default: claude)

.env.local (both environments need a bearer token):
  NEAR_API_KEY_PROD         key used when checking prod (required)
  NEAR_API_KEY_STAGING      key used when checking staging (required)
  NEAR_API_KEY / API_KEY    fallback used for any env without a per-env key

Shell environment only (not read from .env.local):
  MODEL_NAME                model id(s) to review; defaults to every model in
                            config._PROXY_EXPECTED_COMMITS (comma-separated)
"""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import time
import webbrowser
from collections.abc import Sequence
from datetime import datetime
from functools import cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from verifier.config import _PROXY_EXPECTED_COMMITS  # noqa: E402
from verifier.pin_drift import (  # noqa: E402
    BOOT_CM,
    WEIGHTS,
    Coverage,
    Drift,
    add_boot_commits,
    analyze,
    approve_weights,
    compare_url,
    expected_pins,
    rewrite_pins,
)
from verifier.utils import COMMIT_SHA_RE  # noqa: E402

ENVS = ("prod", "staging")
# The vllm-proxy-rs pin is per-model, so each model gets its own verifier run.
MODELS: tuple[str, ...] = tuple(
    m.strip() for m in os.environ.get("MODEL_NAME", "").split(",") if m.strip()
) or tuple(sorted(_PROXY_EXPECTED_COMMITS))
DIFF_CMD = os.environ.get(
    "PIN_REVIEW_DIFF_CMD", 'nvim -c "DiffviewOpen {have}..{need}"'
)
BASE_BRANCH = os.environ.get("PIN_REVIEW_BASE_BRANCH", "master")
CODEBUILD_CMD = os.environ.get("PIN_REVIEW_CODEBUILD_CMD", "")
CLAUDE_CMD = os.environ.get("PIN_REVIEW_CLAUDE_CMD", "claude")
CONFIG = REPO_ROOT / "verifier" / "config.py"
# Not distributed with the repo; without it [s]can declines.
_PROMPT_OVERRIDE = os.environ.get("PIN_REVIEW_PROMPT_FILE", "")
PROMPT_FILE = (
    Path(_PROMPT_OVERRIDE)
    if _PROMPT_OVERRIDE
    else REPO_ROOT / "scripts" / "privacy_review_prompt.md"
)
CLONE_CACHE = Path.home() / ".cache" / "near-pin-review"


def codebuild_command(env: str, model: str | None = None) -> list[str]:
    """CodeBuild trigger as an argv list; [] if no project/profile is configured.
    model=None runs the buildspec's default model."""
    if CODEBUILD_CMD:
        return shlex.split(CODEBUILD_CMD.format(env=env))
    dotenv = _dotenv()
    project = os.environ.get("CODEBUILD_PROJECT") or dotenv.get("CODEBUILD_PROJECT")
    profile = os.environ.get("AWS_VAULT_PROFILE") or dotenv.get("AWS_VAULT_PROFILE")
    if not (project and profile):
        return []
    base = ["aws-vault", "exec", profile, "--", "aws", "codebuild", "start-build"]
    base += ["--project-name", project]
    overrides = []
    if env != "prod":
        overrides.append(f"name=NEAR_ENV,value={env}")
    if model:
        overrides.append(f"name=MODEL_NAME,value={model}")
    if overrides:
        base += ["--environment-variables-override", *overrides]
    return base


def git(*args: str, check: bool = True, capture: bool = False) -> str:
    r = subprocess.run(  # nosec B603 B607  # nosemgrep
        ["git", "-C", str(REPO_ROOT), *args],
        check=check,
        text=True,
        capture_output=capture,
    )
    return (r.stdout or "").strip() if capture else ""


def _dotenv() -> dict[str, str]:
    """Parse .env.local (KEY=VALUE lines) into a dict. Empty if absent."""
    out: dict[str, str] = {}
    envfile = REPO_ROOT / ".env.local"
    if envfile.exists():
        for line in envfile.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            out[key.strip()] = val.strip()
    return out


def _env_for_run(env: str, model: str) -> dict[str, str]:
    """Verifier subprocess env: .env.local, with NEAR_ENV and MODEL_NAME forced
    and BASE_URL dropped so they can't override the env/model under review."""
    run_env = dict(os.environ)
    run_env.update(_dotenv())
    run_env.pop("BASE_URL", None)
    run_env["NEAR_ENV"] = env
    run_env["MODEL_NAME"] = model
    return run_env


def run_verifier(env: str, model: str) -> list[dict] | None:
    """Run the verifier for `env`, checking `model`'s inference CVM
    (provenance-only, quiet, output captured) and return its summaries. Return
    None (printing why) so one run failing never hides the others."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        report_path = tf.name
    proc = subprocess.run(  # nosec B603  # nosemgrep
        [
            sys.executable,
            "-m",
            "verifier.main",
            "--model",
            model,
            "--skip-reproducibility",
            "--no-persist",
            "--quiet",
            "--output",
            report_path,
        ],
        cwd=str(REPO_ROOT),
        env=_env_for_run(env, model),
        capture_output=True,
        text=True,
    )
    report = Path(report_path)
    if report.exists() and report.read_text().strip():
        summaries: list[dict] = json.loads(report.read_text())
        report.unlink(missing_ok=True)
        return summaries
    report.unlink(missing_ok=True)
    tail = (proc.stderr or proc.stdout or "").strip().splitlines()
    reason = tail[-1] if tail else "no output"
    print(f"  ⚠ {env} [{model}]: could not fetch attestation ({reason})")
    return None


def _push(branch: str) -> bool:
    """Push ``branch`` to origin with upstream tracking; print why on failure."""
    push = subprocess.run(  # nosec B603 B607  # nosemgrep
        ["git", "-C", str(REPO_ROOT), "push", "-u", "origin", branch],
        text=True,
        capture_output=True,
    )
    if push.returncode != 0:
        print(f"✗ git push failed:\n{push.stderr.strip()}")
    return push.returncode == 0


@cache
def commit_date(repo: str | None, sha: str) -> str:
    """Committer date (e.g. '2026-07-20 14:31') of a commit via gh; '' if unknown."""
    if not repo or not COMMIT_SHA_RE.fullmatch(sha):
        return ""
    proc = subprocess.run(  # nosec B603 B607  # nosemgrep
        ["gh", "api", f"repos/{repo}/commits/{sha}", "--jq", ".commit.committer.date"],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
    )
    iso = proc.stdout.strip() if proc.returncode == 0 else ""
    return iso[:16].replace("T", " ") if iso else ""


# ── diff report ────────────────────────────────────────────────────────────────
def print_env_diff(env: str, cov: Coverage) -> None:
    """Print how config.py differs from what NEAR runs in `env`, with dates."""
    if cov.unresolved:
        print(
            f"  ❌ {env}: could not read the deployed commit for {cov.unresolved}\n"
            f"     (cache hit without provenance, or an errored image check)."
            f" These pins are UNVERIFIED, not in sync. Re-run with"
            f" PRE_VERIFY_DISABLED=1 to force a full read."
        )
    if not cov.drifts:
        if cov.unresolved:
            print(f"  ⚠ {env}: no drift in the {len(cov.matched)} readable image(s)")
        else:
            print(
                f"  ✅ {env}: config.py matches NEAR"
                f" ({len(cov.matched)} images in sync)"
            )
        return
    print(f"  ❌ {env}: {len(cov.drifts)} image(s) differ from config.py:")
    for d in cov.drifts:
        pin_dt = commit_date(d.source_repo, d.have) or "date unknown"
        dep_dt = commit_date(d.source_repo, d.need) or "date unknown"
        print(f"     {d.registry}")
        print(f"        pinned    {_short(d.have, 12) or '(none)'}   {pin_dt}")
        print(f"        deployed  {_short(d.need, 12)}   {dep_dt}")
        url = compare_url(d)
        if url:
            print(f"        changes   {url}")


# ── per-service review ──────────────────────────────────────────────────────────
def _clone(repo: str) -> Path | None:
    if not re.match(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$", repo):
        print(f"  refusing to clone unexpected repo: {repo!r}")
        return None
    dest = CLONE_CACHE / repo.replace("/", "__")
    CLONE_CACHE.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/{repo}"
    if dest.exists():
        subprocess.run(  # nosec B603 B607  # nosemgrep
            ["git", "-C", str(dest), "fetch", "--quiet", "--all"]
        )
    elif (
        subprocess.run(  # nosec B603 B607  # nosemgrep
            ["git", "clone", "--quiet", url, str(dest)]
        ).returncode
        != 0
    ):
        return None
    return dest


def _fetched_clone(drift: Drift) -> Path | None:
    """Clone the source repo and fetch both commits. None (with reason) on failure."""
    if drift.registry == WEIGHTS:
        print("  model weights have no code diff; [c]ompare opens the snapshot")
        return None
    if not drift.source_repo:
        print("  (no source repo known for this image)")
        return None
    if not (
        COMMIT_SHA_RE.fullmatch(drift.have) and COMMIT_SHA_RE.fullmatch(drift.need)
    ):
        print("  refusing to diff: commit SHAs are not 40-char hex")
        return None
    dest = _clone(drift.source_repo)
    if dest is None:
        print(f"  clone of {drift.source_repo} failed")
        return None
    for sha in (drift.have, drift.need):
        subprocess.run(  # nosec B603 B607  # nosemgrep
            ["git", "-C", str(dest), "fetch", "--quiet", "origin", sha],
            stderr=subprocess.DEVNULL,
        )
    return dest


def open_diff(drift: Drift) -> None:
    dest = _fetched_clone(drift)
    if dest is None:
        return
    # shell=False: DIFF_CMD is split into argv; have/need are validated 40-hex.
    subprocess.run(  # nosec B603  # nosemgrep
        shlex.split(DIFF_CMD.format(have=drift.have, need=drift.need)), cwd=str(dest)
    )


def scan_diff(drift: Drift) -> None:
    """Pipe the service's diff plus the privacy prompt to the Claude CLI.

    Runs from THIS repo, never the untrusted clone, so the clone's .claude
    config and hooks cannot execute."""
    if not PROMPT_FILE.is_file():
        print(
            f"  ⚠ privacy scan unavailable: no prompt file at {PROMPT_FILE}\n"
            "    This prompt is not shipped with the repo. Place a copy at the\n"
            "    path above or point PIN_REVIEW_PROMPT_FILE at it.\n"
            "    Meanwhile review the change with [v]iew or [c]ompare."
        )
        return
    dest = _fetched_clone(drift)
    if dest is None:
        return
    diff = subprocess.run(  # nosec B603 B607  # nosemgrep
        ["git", "-C", str(dest), "diff", f"{drift.have}..{drift.need}"],
        text=True,
        capture_output=True,
    ).stdout
    if not diff.strip():
        print("  (empty diff, nothing to review)")
        return
    header = (
        f"Diff is for {drift.source_repo}, commits "
        f"{drift.have[:12]}..{drift.need[:12]}.\n\n"
    )
    payload = f"{PROMPT_FILE.read_text()}\n\n{header}```diff\n{diff}\n```\n"
    print(f"  ⟳ running Claude scan ({drift.source_repo})…")
    # No --bare: that forces API-key mode; plain -p uses the logged-in session.
    subprocess.run(  # nosec B603 B607  # nosemgrep
        [CLAUDE_CMD, "-p"], input=payload, text=True, cwd=str(REPO_ROOT)
    )
    print()


def _short(value: str, n: int) -> str:
    """A commit cut to ``n`` hex digits; weights ("org/name@rev") stay whole."""
    return value if "@" in value else value[:n]


def _drift_name(d: Drift) -> str:
    """Registry plus the model id for a per-model (proxy) pin."""
    return f"{d.registry} [{d.model}]" if d.model else d.registry


def review_changes(changed: list[tuple[str, Drift]]) -> list[tuple[str, Drift]]:
    approved: list[tuple[str, Drift]] = []
    for env, drift in changed:
        url = compare_url(drift)
        arrow = f"{_short(drift.have, 8) or '(new)'} → {_short(drift.need, 8)}"
        print(f"\n── [{env}] {_drift_name(drift)}   {arrow}")
        if url:
            print(f"   {url}")
        scan = "[s]can" if PROMPT_FILE.is_file() else "[s]can(n/a)"
        menu = f"   [v]iew  [c]ompare  {scan}  [a]pprove  [Enter] skip  [q]uit > "
        while True:
            choice = input(menu).strip().lower()
            if choice == "v":
                open_diff(drift)
            elif choice == "c":
                webbrowser.open(url) if url else print("   no compare URL")
            elif choice == "s":
                scan_diff(drift)
            elif choice == "a":
                approved.append((env, drift))
                print("   ✓ approved")
                break
            elif choice in ("", "n"):
                break
            elif choice == "q":
                print("\nAborted. No changes made.")
                sys.exit(0)
            else:
                print("   ? v / c / s / a / Enter / q")
    return approved


# ── commit + PR ─────────────────────────────────────────────────────────────────
def _pr_for_current_branch() -> tuple[str, str] | None:
    proc = subprocess.run(  # nosec B603 B607  # nosemgrep
        ["gh", "pr", "view", "--json", "state,url"],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    data = json.loads(proc.stdout)
    return data.get("state", ""), data.get("url", "")


def _apply_approved(text: str, approved: list[tuple[str, Drift]]) -> tuple[str, int]:
    """Apply approved drifts to config text. Gateway drifts go to their env block.
    Inference drifts (shared, or per-model for the proxy) are applied once.
    Returns (new_text, applied_count)."""
    gateway_by_env: dict[str, list[Drift]] = {}
    inference: dict[tuple[str, str | None], Drift] = {}
    boot: dict[str, Drift] = {}
    weights: dict[tuple[str | None, str], Drift] = {}
    for env, d in approved:
        if d.registry == BOOT_CM:
            boot[d.need] = d
        elif d.registry == WEIGHTS:
            weights[(d.model, d.need)] = d
        elif d.is_inference:
            inference[(d.registry, d.model)] = d
        else:
            gateway_by_env.setdefault(env, []).append(d)
    applied = 0
    for env, drifts in gateway_by_env.items():
        text, done = rewrite_pins(text, drifts, env)
        applied += len(done)
    if inference:
        text, done = rewrite_pins(text, list(inference.values()), ENVS[0])
        applied += len(done)
    if weights:
        text, done = approve_weights(text, list(weights.values()))
        applied += len(done)
    if boot:
        text, added = add_boot_commits(text, list(boot))
        # Duplicate approvals of one boot commit count once each.
        applied += sum(
            1 for _, d in approved if d.registry == BOOT_CM and d.need in added
        )
    return text, applied


def _release_envs(
    approved: list[tuple[str, Drift]], chosen: tuple[str, ...]
) -> list[str]:
    """Environments to re-verify on merge: all chosen for a shared inference
    change, otherwise only the gateway's own environment."""
    if any(d.is_inference for _, d in approved):
        return [e for e in ENVS if e in chosen]
    return sorted({env for env, _ in approved})


def _release_models(approved: list[tuple[str, Drift]]) -> list[str]:
    """Models to re-run on merge: a proxy change fires its own model; any other
    change is in every model's artifact set, so all models re-run."""
    models = {d.model for _, d in approved if d.model}
    if any(d.model is None for _, d in approved):
        models |= set(MODELS)
    return sorted(models) or list(MODELS)


def commit_and_pr(
    approved: list[tuple[str, Drift]], chosen: tuple[str, ...]
) -> tuple[str, list[str]] | None:
    if git("status", "--porcelain", capture=True):
        sys.exit(
            "✗ Working tree isn't clean. Commit or stash first. The release branch "
            f"is cut from origin/{BASE_BRANCH} and must contain only the pin bump."
        )
    print("\n── Pins to bump ──")
    for env, d in approved:
        print(f"  [{env}] {_drift_name(d)}  {_short(d.have, 8)} → {_short(d.need, 8)}")
    envs = _release_envs(approved, chosen)
    prompt = f"\nCommit on a release branch off {BASE_BRANCH} and open a PR? [y/N] "
    if input(prompt).strip().lower() != "y":
        print("Nothing committed.")
        return None

    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    branch = f"pins/{'-'.join(envs)}-{stamp}"
    subject = f"Bump attestation pins ({len(approved)} image(s): {', '.join(envs)})"
    body = (
        "Bumps pins to the commits NEAR currently attests, each verified from the "
        "deployed image's SLSA provenance.\n\n"
        + "\n".join(
            f"- `[{env}]` `{_drift_name(d)}` `{_short(d.have, 12)}` → "
            f"`{_short(d.need, 12)}`  {compare_url(d)}"
            for env, d in approved
        )
        + f"\n\nMerging triggers the CodeBuild verification for: {', '.join(envs)}."
    )

    subprocess.run(  # nosec B603 B607  # nosemgrep
        ["git", "-C", str(REPO_ROOT), "fetch", "--quiet", "origin", BASE_BRANCH],
        capture_output=True,
    )
    git("checkout", "-b", branch, f"origin/{BASE_BRANCH}")
    new_text, applied = _apply_approved(CONFIG.read_text(), approved)
    if applied != len(approved):
        git("checkout", "-", check=False)
        sys.exit(
            f"✗ origin/{BASE_BRANCH}'s pins differ from what was reviewed, "
            f"aborting. Pull {BASE_BRANCH} and re-run."
        )
    CONFIG.write_text(new_text)
    git("add", str(CONFIG))
    lines = [
        f"[{env}] {_drift_name(d)} {_short(d.have, 8)}->{_short(d.need, 8)}"
        for env, d in approved
    ]
    git("commit", "-m", f"{subject}\n\n" + "\n".join(lines))
    if not _push(branch):
        return None
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as bf:
        bf.write(body)
        body_file = bf.name
    proc = subprocess.run(  # nosec B603 B607  # nosemgrep
        [
            "gh",
            "pr",
            "create",
            "--base",
            BASE_BRANCH,
            "--head",
            branch,
            "--title",
            subject,
            "--body-file",
            body_file,
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
    )
    Path(body_file).unlink(missing_ok=True)
    url = proc.stdout.strip()
    if proc.returncode != 0 or not url.startswith("http"):
        existing = _pr_for_current_branch()
        if existing and existing[0] == "OPEN":
            print(f"\n✓ PR already exists: {existing[1]}")
            return existing[1], envs
        print(f"✗ gh pr create failed:\n{proc.stderr.strip()}")
        return None
    print(f"\n✓ PR opened: {url}")
    return url, envs


# ── merge watch + CodeBuild ─────────────────────────────────────────────────────
def watch_and_fire(
    pr_url: str, envs: list[str], models: Sequence[str | None] | None = None
) -> None:
    if input(f"\nMerge {pr_url} now? [y/N] ").strip().lower() == "y":
        merge = subprocess.run(  # nosec B603 B607  # nosemgrep
            ["gh", "pr", "merge", pr_url, "--merge", "--delete-branch"],
            cwd=str(REPO_ROOT),
            text=True,
            capture_output=True,
        )
        if merge.returncode != 0:
            print(f"  gh merge failed ({merge.stderr.strip()}). Merge it yourself.")
    print("\n⏳ Waiting for merge… Ctrl-C to stop.")
    while True:
        state = subprocess.run(  # nosec B603 B607  # nosemgrep
            ["gh", "pr", "view", pr_url, "--json", "state", "--jq", ".state"],
            cwd=str(REPO_ROOT),
            text=True,
            capture_output=True,
        ).stdout.strip()
        if state == "MERGED":
            break
        if state == "CLOSED":
            print("PR closed without merging. Not firing CodeBuild.")
            return
        time.sleep(10)
    for env in envs:
        # None -> the buildspec's default model (resume paths don't know models).
        for model in models or [None]:
            cmd = codebuild_command(env, model)
            what = f"{env} [{model}]" if model else env
            if not cmd:
                print(
                    f"\n✓ merged. Not firing {what} verification: set"
                    " CODEBUILD_PROJECT and AWS_VAULT_PROFILE (or"
                    " PIN_REVIEW_CODEBUILD_CMD) to fire it."
                )
                continue
            print(f"\n✓ merged. Firing {what} verification:\n  $ {shlex.join(cmd)}")
            subprocess.run(cmd, cwd=str(REPO_ROOT))  # nosec B603  # nosemgrep
    return_to_main()


def return_to_main() -> None:
    """After a release, drop back to an up-to-date base branch if the tree is clean."""
    if git("status", "--porcelain", capture=True):
        print("  (working tree dirty, staying on this branch)")
        return
    if git("rev-parse", "--abbrev-ref", "HEAD", capture=True) != BASE_BRANCH:
        subprocess.run(  # nosec B603 B607  # nosemgrep
            ["git", "-C", str(REPO_ROOT), "checkout", "--quiet", BASE_BRANCH],
            capture_output=True,
        )
    subprocess.run(  # nosec B603 B607  # nosemgrep
        ["git", "-C", str(REPO_ROOT), "pull", "--quiet", "--ff-only"],
        capture_output=True,
    )
    print(f"  ✓ back on {BASE_BRANCH}, up to date")


def open_pr_fill(branch: str) -> str | None:
    if not _push(branch):
        return None
    proc = subprocess.run(  # nosec B603 B607  # nosemgrep
        ["gh", "pr", "create", "--base", BASE_BRANCH, "--head", branch, "--fill"],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
    )
    url = proc.stdout.strip()
    if proc.returncode != 0 or not url.startswith("http"):
        existing = _pr_for_current_branch()
        if existing and existing[0] == "OPEN":
            return existing[1]
        print(f"✗ gh pr create failed:\n{proc.stderr.strip()}")
        return None
    return url


def _envs_from_branch(branch: str) -> list[str]:
    found = [e for e in ENVS if e in branch]
    return found or ["staging"]


def resume_if_release_in_progress() -> bool:
    """If the current pins/ branch already carries an unfinished release, resume or
    redirect instead of starting a fresh review."""
    branch = git("rev-parse", "--abbrev-ref", "HEAD", capture=True)
    if not branch.startswith("pins/"):
        return False
    pr = _pr_for_current_branch()
    if pr:
        state, url = pr
        if state == "OPEN":
            print(f"↩ This branch already has an open release PR:\n   {url}")
            if (
                input("Resume: watch for merge, then fire verification? [Y/n] ")
                .strip()
                .lower()
                != "n"
            ):
                watch_and_fire(url, _envs_from_branch(branch))
            return True
        if state == "MERGED":
            print(f"✓ This branch's PR is already merged:\n   {url}")
            return_to_main()
            return True
        print(f"This branch's PR is {state.lower()}:\n   {url}")
        return True
    if _commits_ahead_of_main():
        print(f"↩ '{branch}' has committed pin changes but no PR, opening one…")
        opened = open_pr_fill(branch)
        if opened:
            print(f"✓ PR opened: {opened}")
            watch_and_fire(opened, _envs_from_branch(branch))
        return True
    return False


def _commits_ahead_of_main() -> int:
    subprocess.run(  # nosec B603 B607  # nosemgrep
        ["git", "-C", str(REPO_ROOT), "fetch", "--quiet", "origin", BASE_BRANCH],
        capture_output=True,
    )
    out = git(
        "rev-list", "--count", f"origin/{BASE_BRANCH}..HEAD", capture=True, check=False
    )
    return int(out) if out.isdigit() else 0


# ── main ────────────────────────────────────────────────────────────────────────
def main(chosen: tuple[str, ...]) -> None:
    if shutil.which("gh") is None:
        sys.exit("review_pins needs the GitHub CLI (gh): https://cli.github.com")
    if resume_if_release_in_progress():
        return
    label = " + ".join(chosen)
    print(f"Comparing verifier/config.py against NEAR's live {label} deploy(s)…")
    print(f"Models under review: {', '.join(MODELS)}\n")
    changed: list[tuple[str, Drift]] = []
    incomplete = False  # any run skipped or with unreadable pins: green is off
    for env in chosen:
        for model in MODELS:
            print(f"▶ {env} [{model}]: fetching attestation (this takes a bit)…")
            summaries = run_verifier(env, model)
            if summaries is None:
                incomplete = True
                print()
                continue
            cov = analyze(summaries, expected_pins(env, model), model=model)
            print_env_diff(f"{env} [{model}]", cov)
            changed.extend((env, d) for d in cov.drifts)
            incomplete = incomplete or bool(cov.unresolved)
            print()

    # Dedupe drifts seen in several runs; proxy drifts are per-model.
    seen: set[tuple[str, str, str, str | None]] = set()
    deduped: list[tuple[str, Drift]] = []
    for env, d in changed:
        key = (d.registry, d.have, d.need, d.model)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((env, d))
    changed = deduped

    if not changed:
        if incomplete:
            print(
                f"❌ Review INCOMPLETE: some pins could not be checked against"
                f" {label}. Fix the errors above and re-run."
            )
            sys.exit(1)
        print(f"✅ config.py matches {label}. Nothing to review.")
        return
    prompt = f"Review the {len(changed)} changed service(s)? [Y/n] "
    if input(prompt).strip().lower() == "n":
        return
    approved = review_changes(changed)
    if not approved:
        print("\nNothing approved, config.py unchanged.")
        return
    result = commit_and_pr(approved, chosen)
    if result:
        url, envs = result
        watch_and_fire(url, envs, _release_models(approved))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Review NEAR attestation pin drift and cut a release."
    )
    parser.add_argument(
        "--env",
        choices=(*ENVS, "both"),
        default="both",
        help="Environment(s) to review and verify on merge (default: both).",
    )
    args = parser.parse_args()
    chosen = ENVS if args.env == "both" else (args.env,)
    try:
        main(chosen)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
