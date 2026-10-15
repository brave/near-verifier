# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Fail-closed tests for the OS-measurement pin, the exact MR_CONFIG_ID match,
the compose image checks and the signing-key / persistence gates."""

import asyncio
from hashlib import sha256
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from verifier import main
from verifier.models import VerificationPolicy
from verifier.verifications.image import (
    compose_image_problems,
    compose_images,
    verify_compose_images_full,
)
from verifier.verifications.tdx import (
    _validate_mrconfig,
    check_os_measurements,
    overridable_envs,
)

MEAS = ("aa" * 48, "00" * 48, "11" * 48, "22" * 48)
CM = "nearaidev/compose-manager"
DIGEST = "sha256:" + "a" * 64


def _quote(mrtd: str = MEAS[0], rtmrs: tuple[str, ...] = MEAS[1:]) -> Any:
    return {"quote": {"body": {"mrtd": mrtd, "rtmrs": [*rtmrs, "33" * 48]}}}


# --- OS measurements -------------------------------------------------------


def test_os_measurements_fail_closed_when_nothing_pinned() -> None:
    with patch("verifier.verifications.tdx.EXPECTED_OS_MEASUREMENTS", frozenset()):
        assert check_os_measurements(_quote(), "Gateway") is False


def test_os_measurements_pass_only_for_a_pinned_tuple() -> None:
    pins = frozenset({MEAS})
    with patch("verifier.verifications.tdx.EXPECTED_OS_MEASUREMENTS", pins):
        assert check_os_measurements(_quote(), "Gateway") is True
        # A different kernel (RTMR1) is a different OS, not a pinned one.
        other = _quote(rtmrs=(MEAS[1], "ff" * 48, MEAS[3]))
        assert check_os_measurements(other, "Gateway") is False


def test_os_measurements_empty_quote_never_matches() -> None:
    pins = frozenset({("", "", "", "")})
    with patch("verifier.verifications.tdx.EXPECTED_OS_MEASUREMENTS", pins):
        assert check_os_measurements(_quote(mrtd="", rtmrs=("", "", "")), "G") is False


# --- MR_CONFIG_ID ----------------------------------------------------------


def test_mrconfig_must_match_exactly_including_padding() -> None:
    compose = '{"docker_compose_file": ""}'
    good = ("01" + sha256(compose.encode()).hexdigest()).ljust(96, "0")
    assert _validate_mrconfig(compose, good) is True
    # The 15 trailing bytes are host-chosen; a prefix match ignored them.
    assert _validate_mrconfig(compose, good[:-2] + "ff") is False
    assert _validate_mrconfig(compose, good[:66]) is False


# --- compose images --------------------------------------------------------


def _problems(compose: str, envs: frozenset[str] = frozenset()) -> list[str]:
    return compose_image_problems(compose_images(compose), [CM], envs)[0]


def _verified_refs(compose: str) -> list[str]:
    """Image refs verify_compose_images_full sends to full verification."""
    policy = VerificationPolicy([], [], [CM], True, set())
    ok = {"provenance_found": True, "provenance_verified": True}
    with patch("verifier.verifications.image.verify_image_full", return_value=ok):
        result = verify_compose_images_full(compose_images(compose), policy)
    return [k for k, v in result["images"].items() if v.get("provenance_verified")]


def test_commented_image_line_does_not_satisfy_required_image() -> None:
    compose = f"services:\n  cm:\n    image: {CM}:latest\n    # image: {CM}@{DIGEST}\n"
    assert _problems(compose)  # the tag-only reference is what actually runs
    policy = VerificationPolicy([], [], [CM], True, set())
    result = verify_compose_images_full(compose_images(compose), policy)
    assert all(not r["provenance_verified"] for r in result["images"].values())


def test_unpinned_required_image_next_to_pinned_decoy_fails() -> None:
    compose = (
        f"services:\n  a:\n    image: {CM}@{DIGEST}\n  b:\n    image: {CM}:latest\n"
    )
    assert len(_problems(compose)) == 1


def test_image_string_outside_an_image_key_is_not_an_image() -> None:
    # A decoy in a label must not satisfy the required image while the
    # service's real image runs unverified.
    compose = (
        "services:\n  cm:\n    image: evil/cm:latest\n    labels:\n"
        f'      note: "image: {CM}@{DIGEST}"\n'
    )
    assert _verified_refs(compose) == []


def test_quoted_and_docker_hub_spellings_are_the_required_image() -> None:
    evil = "sha256:" + "e" * 64
    for spelling in (f'"{CM}@{evil}"', f"docker.io/{CM}:latest", f"'{CM}:x'"):
        compose = f"services:\n  cm:\n    image: {spelling}\n"
        if "@" in spelling:
            assert _verified_refs(compose) == [f"{CM}@{evil}"], spelling
        else:
            assert _problems(compose), spelling


def test_required_image_with_trailing_junk_is_not_pinned() -> None:
    compose = f"services:\n  cm:\n    image: {CM}@{DIGEST}${{X}}\n"
    assert _problems(compose)


def test_invalid_compose_yields_no_images() -> None:
    assert compose_images("services: [unclosed") == []
    assert compose_images("just a string") == []


def test_service_without_image_is_reported_unverified() -> None:
    compose = f"services:\n  cm:\n    image: {CM}@{DIGEST}\n  b:\n    build: .\n"
    _, unverified = compose_image_problems(compose_images(compose), [CM], frozenset())
    assert unverified == ["<service b: no image>"]


def test_operator_overridable_image_variable_fails() -> None:
    compose = f"services:\n  cm:\n    image: ${{CM_IMAGE:-{CM}@{DIGEST}}}\n"
    assert _problems(compose) == []
    assert _problems(compose, frozenset({"CM_IMAGE"}))


def test_unverified_images_are_reported() -> None:
    compose = (
        f"services:\n  a:\n    image: {CM}@{DIGEST}\n"
        "  b:\n    image: datadog/agent:7\n  c:\n    image: ${X}\n"
    )
    _, unverified = compose_image_problems(compose_images(compose), [CM], frozenset())
    assert unverified == ["datadog/agent:7", "${X}"]


def test_overridable_envs_parses_app_compose() -> None:
    assert overridable_envs('{"allowed_envs": ["A", "B"]}') == {"A", "B"}
    assert overridable_envs("not json") == {"*"}
    # A pre_launch_script can export anything, so every variable counts.
    script = '{"allowed_envs": ["A"], "pre_launch_script": "export X=1"}'
    assert overridable_envs(script) == {"A", "*"}
    assert overridable_envs('{"pre_launch_script": "  "}') == frozenset()


def test_any_var_marks_every_interpolated_required_image() -> None:
    compose = f"services:\n  cm:\n    image: ${{CM_IMAGE:-{CM}@{DIGEST}}}\n"
    assert _problems(compose, frozenset({"*"}))
    # A literal digest is unaffected by a pre_launch_script.
    assert (
        _problems(f"services:\n  cm:\n    image: {CM}@{DIGEST}\n", frozenset({"*"}))
        == []
    )


# --- persistence gates -----------------------------------------------------


def _run_main(validation_passed: bool, argv: list[str]) -> tuple[Any, Any]:
    """Run main() with every network step mocked; return the key/persist mocks."""
    record = MagicMock()
    persist = MagicMock(return_value=True)
    with (
        patch("sys.argv", ["verify-near-tee", *argv]),
        patch.dict("os.environ", {"NEAR_BUCKET_NAME": "bucket"}),
        patch.object(main, "fetch_attestation_report", return_value={}),
        patch.object(main, "verify_cloud_api", AsyncMock(return_value={})),
        patch.object(main, "verify_models", AsyncMock(return_value=[])),
        patch.object(main, "verify_inference_models", AsyncMock(return_value=[])),
        patch.object(main, "verify_tls_certificate", AsyncMock(return_value={})),
        patch.object(main, "validate_report_values", return_value=validation_passed),
        patch.object(main, "record_gateway_signing_key", record),
        patch.object(main, "record_inference_signing_keys"),
        patch.object(main, "record_other_scheme_gateway_key", AsyncMock()),
        patch.object(main, "record_other_scheme_inference_keys", AsyncMock()),
        patch.object(main, "persist_results", persist),
        patch.object(main, "_report_pin_drift"),
    ):
        try:
            asyncio.run(main.main())
        except SystemExit:
            pass
    return record, persist


def test_no_signing_key_marker_on_a_failed_run() -> None:
    record, persist = _run_main(False, [])
    record.assert_not_called()
    persist.assert_not_called()


def test_signing_key_marker_on_a_passing_run() -> None:
    record, persist = _run_main(True, [])
    record.assert_called_once()
    persist.assert_called_once()


def test_provenance_only_run_writes_nothing_to_s3() -> None:
    record, persist = _run_main(True, ["--skip-reproducibility"])
    record.assert_not_called()
    persist.assert_not_called()
