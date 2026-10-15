# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tests for the inference leg read from the gateway report's
``model_attestations``: an empty list, a substituted model, and a
per-attestation failure that must not take the run down.
"""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch

from verifier import verification_steps as vs
from verifier.models import VerificationPolicy
from verifier.validation import validate_report_values
from verifier.verifications import CvmState

_STATE = CvmState("{}", "", "")

MODEL = "z-ai/glm-5.3-flash"
_POLICY = VerificationPolicy(
    allowed_repos=[],
    allowed_builders=[],
    required_images=[],
    require_reproducible_build=False,
    skip_reproducibility_images=set(),
)


def _run(attestations: list[dict[str, Any]], **kw: Any) -> list[Any]:
    return asyncio.run(
        vs.verify_inference_models(attestations, "nn", _POLICY, kw.pop("model", MODEL))
    )


class TestEmptyAttestations:
    """No attestation must never read as success."""

    def test_empty_list_yields_one_failed_summary(self) -> None:
        results = _run([])
        assert len(results) == 1
        assert results[0]["model_name_matches"] is False
        assert results[0]["tdx_verified"] is False
        assert results[0]["model_name"] == MODEL

    def test_empty_list_fails_overall_validation(self) -> None:
        # The report shape a gateway with no model_attestations would produce:
        # gateway + GPU + TLS all fine, inference absent. Must not validate.
        report = [
            {
                "type": "Gateway",
                "tdx_verified": True,
                "mrconfig_valid": True,
                "report_data_valid": True,
                "compose_verified": True,
            },
            {"type": "Model #1", "gpu_verified": True},
            *_run([]),
            {
                "type": "Domain TLS Certificate",
                "domain": "cloud-api.near.ai",
                "certificate_verified": True,
                "fingerprint_matches": True,
                "dns_caa_verified": True,
            },
        ]
        assert validate_report_values(report) is False


class TestPerAttestationFailure:
    def test_exception_fails_that_model_closed(self) -> None:
        # A crash verifying one attestation becomes a failed summary, not an
        # aborted run.
        with patch.object(
            vs,
            "verify_inference_attestation",
            AsyncMock(side_effect=RuntimeError("boom")),
        ):
            results = _run([{"model_name": MODEL}])
        assert len(results) == 1
        assert results[0]["tdx_verified"] is False
        assert results[0]["model_name"] == MODEL

    def test_requested_model_is_passed_through(self) -> None:
        # The requested id must reach verify_inference_attestation, which is
        # what enforces the model_name check.
        with patch.object(
            vs, "verify_inference_attestation", AsyncMock(return_value={})
        ) as verify:
            _run([{"model_name": "something-else"}], model=MODEL)
        assert verify.call_args.args[3] == MODEL

    def test_each_attestation_is_verified(self) -> None:
        with patch.object(
            vs, "verify_inference_attestation", AsyncMock(return_value={})
        ) as verify:
            _run([{"model_name": MODEL}, {"model_name": MODEL}])
        assert verify.await_count == 2


class TestCaptureInferenceSigningKey:
    """A substituted model never causes a marker write."""

    def _report(self, attested: str) -> dict[str, Any]:
        return {
            "model_attestations": [{"model_name": attested, "signing_algo": "ed25519"}]
        }

    def test_skips_when_gateway_attests_another_model(self) -> None:
        with (
            patch.object(
                vs, "fetch_attestation_report", return_value=self._report("z-ai/other")
            ),
            patch.object(
                vs, "signing_key_from_inference_attestation", AsyncMock()
            ) as extract,
        ):
            out = asyncio.run(
                vs.capture_inference_signing_key(MODEL, "nn", "ed25519", _STATE)
            )
        assert out is None
        extract.assert_not_called()

    def test_none_when_report_has_no_model_attestation(self) -> None:
        with patch.object(
            vs, "fetch_attestation_report", return_value={"model_attestations": []}
        ):
            out = asyncio.run(
                vs.capture_inference_signing_key(MODEL, "nn", "ed25519", _STATE)
            )
        assert out is None

    def test_extracts_when_model_matches(self) -> None:
        key = {"signing_public_key": "ab", "signing_algo": "ed25519"}
        with (
            patch.object(
                vs, "fetch_attestation_report", return_value=self._report(MODEL)
            ),
            patch.object(
                vs,
                "signing_key_from_inference_attestation",
                AsyncMock(return_value=key),
            ),
        ):
            out = asyncio.run(
                vs.capture_inference_signing_key(MODEL, "nn", "ed25519", _STATE)
            )
        assert out == key
