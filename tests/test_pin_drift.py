# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tests for pin-drift analysis and the env-scoped config.py rewriter."""

from verifier.pin_drift import Drift, rewrite_pins


def test_rewrite_scoped_to_env_leaves_other_env_untouched() -> None:
    have, need = "a" * 40, "c" * 40
    text = (
        "_GATEWAY_EXPECTED_COMMITS = {\n"
        '    "prod": {\n'
        f'        "nearaidev/cloud-api": "{have}",\n'  # same commit in both envs
        "    },\n"
        '    "staging": {\n'
        f'        "nearaidev/cloud-api": "{have}",\n'
        "    },\n"
        "}\n"
    )
    drift = Drift("nearaidev/cloud-api", have, need, False, "nearai/cloud-api")
    new_text, applied = rewrite_pins(text, [drift], "staging")
    assert len(applied) == 1
    # Only the staging line moved; the identical prod pin is untouched.
    assert new_text.count(f'"{need}"') == 1
    staging_line = new_text.split('"staging"')[1]
    assert f'"{need}"' in staging_line


def test_rewrite_refuses_when_pin_no_longer_matches() -> None:
    text = '"staging": {\n"nearaidev/cloud-api": "' + "f" * 40 + '"\n}\n'
    stale = Drift("nearaidev/cloud-api", "a" * 40, "c" * 40, False, "nearai/cloud-api")
    new_text, applied = rewrite_pins(text, [stale], "staging")
    assert applied == []
    assert new_text == text  # nothing written


def test_compare_url() -> None:
    from verifier.pin_drift import compare_url

    d = Drift("nearaidev/cloud-api", "a" * 40, "b" * 40, False, "nearai/cloud-api")
    assert compare_url(d) == (
        "https://github.com/nearai/cloud-api/compare/" + "a" * 40 + "..." + "b" * 40
    )
    assert compare_url(d._replace(source_repo=None)) is None


# --- analyze() must positively confirm every pinned image ---
from verifier.pin_drift import (  # noqa: E402
    _deployed_commit,
    analyze,
    expected_pins,
)

# The proxy pin is per-model, keyed by marketplace model id.
MODEL = "z-ai/glm-5.3-flash"


def _report_all_matching(env: str) -> list[dict]:
    """A report where every pinned image is present and matches its pin."""
    images = {
        f"{reg}@sha256:dead": {"provenance": {"commit_sha": commit}, "messages": []}
        for reg, commit in expected_pins(env, MODEL).items()
    }
    return [{"image_verification": {"images": images}}]


def _key_for(report: list[dict], registry: str) -> str:
    imgs = report[0]["image_verification"]["images"]
    return str(next(k for k in imgs if k.split("@")[0] == registry))


def test_deployed_commit_sources() -> None:
    assert _deployed_commit({"provenance": {"commit_sha": "a" * 40}}) == "a" * 40
    msg = (
        f"Commit SHA mismatch for 'x':\n\texpected: {'a' * 40}\n\tgot:      {'b' * 40}"
    )
    assert _deployed_commit({"messages": [msg]}) == "b" * 40
    assert _deployed_commit({"messages": ["all good"]}) is None
    assert _deployed_commit({}) is None


def test_analyze_all_match() -> None:
    cov = analyze(_report_all_matching("staging"), expected_pins("staging", MODEL))
    assert cov.drifts == []
    assert cov.unresolved == []
    assert set(cov.matched) == set(expected_pins("staging", MODEL))


def test_analyze_detects_drift() -> None:
    report = _report_all_matching("staging")
    target = sorted(expected_pins("staging", MODEL))[0]
    report[0]["image_verification"]["images"][_key_for(report, target)]["provenance"][
        "commit_sha"
    ] = "f" * 40
    cov = analyze(report, expected_pins("staging", MODEL))
    assert [d.registry for d in cov.drifts] == [target]
    assert cov.unresolved == []


def test_analyze_tags_proxy_drift_with_model() -> None:
    report = _report_all_matching("staging")
    target = "nearaidev/vllm-proxy-rs"
    report[0]["image_verification"]["images"][_key_for(report, target)]["provenance"][
        "commit_sha"
    ] = "f" * 40
    cov = analyze(report, expected_pins("staging", MODEL), model=MODEL)
    (drift,) = cov.drifts
    assert drift.registry == target
    assert drift.model == MODEL


def test_analyze_flags_missing_image_as_unresolved() -> None:
    report = _report_all_matching("staging")
    target = sorted(expected_pins("staging", MODEL))[0]
    del report[0]["image_verification"]["images"][_key_for(report, target)]
    cov = analyze(report, expected_pins("staging", MODEL))
    assert target in cov.unresolved
    assert cov.drifts == []


def test_analyze_flags_undeterminable_entry_as_unresolved() -> None:
    # Entry present but no provenance and no mismatch (e.g. a cache hit) -> unresolved.
    report = _report_all_matching("staging")
    target = sorted(expected_pins("staging", MODEL))[0]
    report[0]["image_verification"]["images"][_key_for(report, target)] = {
        "messages": ["Using pre-verified result"]
    }
    cov = analyze(report, expected_pins("staging", MODEL))
    assert target in cov.unresolved


# Model ids contain "/" and ".", so the rewriter must match them exactly.
_PROXY_BLOCK = (
    "_PROXY_EXPECTED_COMMITS = {\n"
    f'    "z-ai/glm-5.3-flash": "{"4" * 40}",\n'
    f'    "openai/gpt-oss-120b": "{"5" * 40}",\n'
    "}\n"
)


def test_rewrite_proxy_pin_touches_only_its_model() -> None:
    have, need = "4" * 40, "b" * 40
    drift = Drift(
        "nearaidev/vllm-proxy-rs",
        have,
        need,
        True,
        "nearai/inference-proxy",
        model="z-ai/glm-5.3-flash",
    )
    new_text, applied = rewrite_pins(_PROXY_BLOCK, [drift], "prod")
    assert applied == [drift]
    assert f'"z-ai/glm-5.3-flash": "{need}"' in new_text
    assert f'"openai/gpt-oss-120b": "{"5" * 40}"' in new_text  # other model untouched
    # Without a model the proxy drift must not be applied anywhere.
    _, applied = rewrite_pins(_PROXY_BLOCK, [drift._replace(model=None)], "prod")
    assert applied == []


def test_drift_measured_against_baseline_not_local() -> None:
    # Drift is measured against the baseline pins, here stale, not the local tree.
    deployed = "d" * 40
    report = [
        {
            "image_verification": {
                "images": {
                    "nearaidev/cloud-api@z": {
                        "provenance": {"commit_sha": deployed},
                        "messages": [],
                    }
                }
            }
        }
    ]
    cov = analyze(report, {"nearaidev/cloud-api": "0" * 40})
    assert [(d.registry, d.have, d.need) for d in cov.drifts] == [
        ("nearaidev/cloud-api", "0" * 40, deployed)
    ]


# --- boot compose-manager: a set of reviewed commits, not a single pin ---
from verifier.config import BOOT_COMPOSE_MANAGER_COMMITS  # noqa: E402
from verifier.pin_drift import BOOT_CM, add_boot_commits  # noqa: E402


def _with_boot(commit_or_msg: str) -> list[dict]:
    report = _report_all_matching("prod")
    entry: dict = (
        {"provenance": {"commit_sha": commit_or_msg}, "messages": []}
        if len(commit_or_msg) == 40
        else {"messages": [commit_or_msg]}
    )
    report.append({"boot_compose_manager_image": entry})
    return report


def test_analyze_boot_commit_in_reviewed_set_matches() -> None:
    reviewed = sorted(BOOT_COMPOSE_MANAGER_COMMITS)[0]
    cov = analyze(_with_boot(reviewed), expected_pins("prod", MODEL))
    assert BOOT_CM in cov.matched
    assert cov.drifts == []


def test_analyze_unreviewed_boot_commit_is_drift_from_running_pin() -> None:
    msg = (
        "❌ Provenance check failed: Commit SHA mismatch for "
        f"'nearaidev/compose-manager':\n\texpected one of: {'a' * 40}\n"
        f"\tgot:      {'e' * 40}"
    )
    cov = analyze(_with_boot(msg), expected_pins("prod", MODEL))
    (drift,) = cov.drifts
    assert drift.registry == BOOT_CM
    assert drift.need == "e" * 40
    assert drift.have == expected_pins("prod")["nearaidev/compose-manager"]
    assert drift.source_repo == "nearai/compose-manager"


def test_analyze_unreadable_boot_commit_is_unresolved() -> None:
    cov = analyze(_with_boot("Using pre-verified result"), expected_pins("prod"))
    assert BOOT_CM in cov.unresolved


_BOOT_BLOCK = (
    "BOOT_COMPOSE_MANAGER_COMMITS: frozenset[str] = frozenset(\n"
    "    {\n"
    f'        "{"1" * 40}",\n'
    "    }\n"
    ")\n"
    '_OTHER = {\n    "x": "y",\n}\n'
)


def test_add_boot_commits_appends_inside_the_set_only() -> None:
    new, added = add_boot_commits(_BOOT_BLOCK, ["2" * 40, "2" * 40])
    assert added == ["2" * 40]
    assert new.count(f'"{"2" * 40}"') == 1
    assert new.index("2" * 40) < new.index("_OTHER")


def test_add_boot_commits_already_listed_is_not_duplicated() -> None:
    new, added = add_boot_commits(_BOOT_BLOCK, ["1" * 40])
    assert added == ["1" * 40]
    assert new == _BOOT_BLOCK


def test_add_boot_commits_without_block_adds_nothing() -> None:
    assert add_boot_commits("X = 1\n", ["2" * 40]) == ("X = 1\n", [])


# --- model weights ---
from verifier.config import APPROVED_MODEL_WEIGHTS  # noqa: E402
from verifier.pin_drift import WEIGHTS, approve_weights, compare_url  # noqa: E402

_QUANT = "graphistry/GLM-5.3-Flash-W4AFP8"
_APPROVED_QUANT = next(w for w in APPROVED_MODEL_WEIGHTS[MODEL] if w.startswith(_QUANT))


def _with_weights(*weights: str) -> list[dict]:
    report = _report_all_matching("prod")
    report.append({"serving_weights": list(weights)})
    return report


def test_analyze_approved_weights_match() -> None:
    cov = analyze(_with_weights(_APPROVED_QUANT), expected_pins("prod", MODEL), MODEL)
    assert WEIGHTS in cov.matched
    assert cov.drifts == []


def test_analyze_new_revision_is_drift_from_same_repo() -> None:
    new = f"{_QUANT}@{'c' * 40}"
    cov = analyze(_with_weights(new), expected_pins("prod", MODEL), MODEL)
    (drift,) = cov.drifts
    assert (drift.registry, drift.have, drift.need, drift.model) == (
        WEIGHTS,
        _APPROVED_QUANT,
        new,
        MODEL,
    )
    assert compare_url(drift) == f"https://huggingface.co/{_QUANT}/tree/{'c' * 40}"


def test_analyze_new_repo_has_no_have() -> None:
    cov = analyze(
        _with_weights(f"other/model@{'d' * 40}"), expected_pins("prod", MODEL), MODEL
    )
    assert cov.drifts[0].have == ""


def test_analyze_unpinned_or_missing_weights_unresolved() -> None:
    for weights in ([], [_QUANT], [_APPROVED_QUANT, "/models/local"]):
        cov = analyze(_with_weights(*weights), expected_pins("prod", MODEL), MODEL)
        assert WEIGHTS in cov.unresolved
        assert cov.drifts == []


_WEIGHTS_BLOCK = (
    "APPROVED_MODEL_WEIGHTS: dict[str, frozenset[str]] = {\n"
    '    "m/a": frozenset(\n'
    "        {\n"
    f'            "org/x@{"1" * 40}",\n'
    "        }\n"
    "    ),\n"
    "}\n"
    '_OTHER = {\n    "x": "y",\n}\n'
)


def _wdrift(model: str, have: str, need: str) -> Drift:
    return Drift(WEIGHTS, have, need, True, None, model)


def test_approve_weights_keeps_same_repo_revision() -> None:
    """Another service or a chat template may still load the old revision."""
    d = _wdrift("m/a", f"org/x@{'1' * 40}", f"org/x@{'2' * 40}")
    text, applied = approve_weights(_WEIGHTS_BLOCK, [d])
    assert applied == [d]
    assert f"org/x@{'2' * 40}" in text and f"org/x@{'1' * 40}" in text


def test_approve_weights_appends_new_repo() -> None:
    d = _wdrift("m/a", "", f"org/y@{'3' * 40}")
    text, applied = approve_weights(_WEIGHTS_BLOCK, [d])
    assert applied == [d]
    assert f"org/x@{'1' * 40}" in text and f"org/y@{'3' * 40}" in text
    assert text.count('"m/a"') == 1


def test_approve_weights_adds_new_model_block() -> None:
    ds = [_wdrift("m/b", "", f"org/z@{c * 40}") for c in "45"]
    text, applied = approve_weights(_WEIGHTS_BLOCK, ds)
    assert applied == ds
    assert text.count('"m/b": frozenset(') == 1
    assert text.endswith('_OTHER = {\n    "x": "y",\n}\n')
    ns: dict = {}
    exec(text.split("_OTHER")[0], ns)  # noqa: S102
    assert ns["APPROVED_MODEL_WEIGHTS"]["m/b"] == {f"org/z@{c * 40}" for c in "45"}
