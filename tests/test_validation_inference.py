# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tests for inference-CVM validation in validate_report_values."""

from typing import Any

from verifier.validation import (
    _validate_inference_component,
    validate_report_values,
)


def _passing_inference(**overrides: Any) -> dict[str, Any]:
    item = {
        "type": "Inference: openai/gpt-oss-120b",
        "model_name": "openai/gpt-oss-120b",
        "model_name_matches": True,
        "tdx_verified": True,
        "os_measurements_valid": True,
        "mrconfig_valid": True,
        "compose_hash_valid": True,
        "near_images_verified": True,
        "compose_manager_tdx_verified": True,
        "proxy_report_data_valid": True,
        "same_cvm": True,
        "report_data_valid": True,
        "serving_yaml_verified": True,
        "model_weights_approved": True,
        "gpu_verified": True,
    }
    item.update(overrides)
    return item


class TestValidateInferenceComponent:
    def test_full_chain_passes(self) -> None:
        assert _validate_inference_component(_passing_inference()) is True

    def test_gpu_none_fails(self) -> None:
        # None means the server omitted nvidia_payload; it must not opt out.
        item = _passing_inference(gpu_verified=None)
        assert _validate_inference_component(item) is False

    def test_gpu_missing_key_fails(self) -> None:
        item = _passing_inference()
        del item["gpu_verified"]
        assert _validate_inference_component(item) is False

    def test_substituted_model_fails(self) -> None:
        item = _passing_inference(model_name_matches=False)
        assert _validate_inference_component(item) is False

    def test_missing_model_name_matches_fails(self) -> None:
        item = _passing_inference()
        del item["model_name_matches"]
        assert _validate_inference_component(item) is False

    def test_gpu_false_fails(self) -> None:
        assert (
            _validate_inference_component(_passing_inference(gpu_verified=False))
            is False
        )

    def test_unverified_near_images_fail(self) -> None:
        assert (
            _validate_inference_component(
                _passing_inference(near_images_verified=False)
            )
            is False
        )

    def test_unapproved_model_weights_fail(self) -> None:
        assert (
            _validate_inference_component(
                _passing_inference(model_weights_approved=False)
            )
            is False
        )

    def test_missing_serving_yaml_fails(self) -> None:
        assert (
            _validate_inference_component(
                _passing_inference(serving_yaml_verified=False)
            )
            is False
        )

    def test_report_data_unbound_fails(self) -> None:
        assert (
            _validate_inference_component(_passing_inference(report_data_valid=False))
            is False
        )

    def test_proxy_report_data_unbound_fails(self) -> None:
        assert (
            _validate_inference_component(
                _passing_inference(proxy_report_data_valid=False)
            )
            is False
        )

    def test_different_cvm_fails(self) -> None:
        assert (
            _validate_inference_component(_passing_inference(same_cvm=False)) is False
        )


class TestValidateReportValuesRouting:
    def _base_summaries(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "Gateway",
                "tdx_verified": True,
                "mrconfig_valid": True,
                "report_data_valid": True,
                "compose_verified": True,
            },
            {
                "type": "Domain TLS Certificate",
                "domain": "cloud-api.near.ai",
                "certificate_verified": True,
                "fingerprint_matches": True,
                "dns_caa_verified": True,
            },
        ]

    def test_failing_inference_fails_overall(self, monkeypatch: Any) -> None:
        monkeypatch.setattr("verifier.validation.BASE_URL", "https://cloud-api.near.ai")
        summaries = self._base_summaries()
        summaries.append(_passing_inference(serving_yaml_verified=False))
        assert validate_report_values(summaries) is False

    def test_inference_routed_not_as_gpu(self, monkeypatch: Any) -> None:
        # Inference items carry gpu_verified but must be validated as the full
        # chain, not the GPU-only path.
        monkeypatch.setattr("verifier.validation.BASE_URL", "https://cloud-api.near.ai")
        summaries = self._base_summaries()
        # Chain fails despite gpu_verified=True -> overall must fail.
        summaries.append(_passing_inference(compose_hash_valid=False))
        assert validate_report_values(summaries) is False
