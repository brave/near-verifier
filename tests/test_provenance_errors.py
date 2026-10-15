# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Error-path coverage for extract_provenance_attestation.

The empty-pin case must surface the deployed commit (so the operator has a
concrete value to audit and pin); the mismatch case must keep showing both.
"""

from contextlib import ExitStack
from unittest.mock import patch

import pytest

from verifier.verifications.provenance import (
    ProvenanceInfo,
    extract_provenance_attestation,
)

IMAGE = "nearaidev/cloud-api@sha256:" + "a" * 64
GOT_COMMIT = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
PROV = ProvenanceInfo(
    source_repo="https://github.com/nearai/cloud-api",
    commit_sha=GOT_COMMIT,
    builder_id="https://github.com/nearai/cloud-api/.github/workflows/build.yml@refs/heads/main",
    build_type="https://actions.github.io/buildtypes/workflow/v1",
)


def _enter_cosign_stubs(stack: ExitStack) -> None:
    """Stub the cosign helpers so the loop sees a valid provenance payload."""
    stack.enter_context(
        patch(
            "verifier.verifications.provenance._run_cosign_verification",
            return_value="cosign-output",
        )
    )
    stack.enter_context(
        patch(
            "verifier.verifications.provenance._extract_payload",
            return_value={"predicate": {}},
        )
    )
    stack.enter_context(
        patch(
            "verifier.verifications.provenance._parse_provenance",
            return_value=PROV,
        )
    )


def test_empty_pin_surfaces_deployed_commit() -> None:
    """When the pin is empty but provenance is extractable, the error must
    include the deployed commit so the operator can audit and pin it."""
    with ExitStack() as stack:
        stack.enter_context(
            patch.dict(
                "verifier.verifications.provenance.CERT_EXPECTED_COMMITS",
                {"nearaidev/cloud-api": ""},
                clear=False,
            )
        )
        _enter_cosign_stubs(stack)
        with pytest.raises(ValueError) as exc:
            extract_provenance_attestation(IMAGE)
    msg = str(exc.value)
    assert GOT_COMMIT in msg
    assert "No expected commit SHA configured" in msg
    assert "nearaidev/cloud-api" in msg


def test_commit_mismatch_shows_both_commits() -> None:
    """The mismatch path keeps reporting both expected and got commits."""
    expected = "1111111111111111111111111111111111111111"
    with ExitStack() as stack:
        stack.enter_context(
            patch.dict(
                "verifier.verifications.provenance.CERT_EXPECTED_COMMITS",
                {"nearaidev/cloud-api": expected},
                clear=False,
            )
        )
        _enter_cosign_stubs(stack)
        with pytest.raises(ValueError) as exc:
            extract_provenance_attestation(IMAGE)
    msg = str(exc.value)
    assert expected in msg
    assert GOT_COMMIT in msg
    assert "Commit SHA mismatch" in msg


def test_empty_pin_with_no_provenance_still_raises() -> None:
    """If no provenance is found AND the pin is empty, the audit can't
    proceed. The error must still surface that explicitly."""
    with (
        patch.dict(
            "verifier.verifications.provenance.CERT_EXPECTED_COMMITS",
            {"nearaidev/cloud-api": ""},
            clear=False,
        ),
        patch(
            "verifier.verifications.provenance._run_cosign_verification",
            return_value=None,
        ),
    ):
        with pytest.raises(ValueError, match="no SLSA provenance attestation"):
            extract_provenance_attestation(IMAGE)


def test_reviewed_set_accepts_member_and_rejects_others() -> None:
    with ExitStack() as stack:
        _enter_cosign_stubs(stack)
        assert extract_provenance_attestation(IMAGE, frozenset({GOT_COMMIT})) == PROV
        with pytest.raises(ValueError, match=f"got:\\s*{GOT_COMMIT}"):
            extract_provenance_attestation(IMAGE, frozenset({"a" * 40}))
        # An empty reviewed set accepts nothing.
        with pytest.raises(ValueError):
            extract_provenance_attestation(IMAGE, frozenset())
