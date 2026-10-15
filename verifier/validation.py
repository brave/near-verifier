# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Validation logic for verification reports."""

import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .config import BASE_URL

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Track validation state for different components."""

    gateway: bool = False
    gpu_all: bool = True
    domain_tls: bool = False
    inference_all: bool = True
    # Zero components seen fails closed rather than passing on the default True.
    gpu_components_seen: int = 0
    inference_components_seen: int = 0

    def _gpu_ok(self) -> bool:
        return self.gpu_all and self.gpu_components_seen > 0

    def _inference_ok(self) -> bool:
        return self.inference_all and self.inference_components_seen > 0

    def is_valid(self) -> bool:
        """Check if all validations passed."""
        return all(
            [
                self.gateway,
                self._gpu_ok(),
                self.domain_tls,
                self._inference_ok(),
            ]
        )

    def failed_checks(self) -> list[str]:
        """Return list of failed validation checks."""
        checks = {
            "gateway": self.gateway,
            "gpu_all": self._gpu_ok(),
            "domain_tls": self.domain_tls,
            "inference_all": self._inference_ok(),
        }
        return [name for name, passed in checks.items() if not passed]


_GATEWAY_CHECKS = (
    "tdx_verified",
    "os_measurements_valid",
    "mrconfig_valid",
    "report_data_valid",
    "compose_verified",
)
# GPU evidence is required outright: the server under audit decides whether
# ``nvidia_payload`` is present, so absence must not be acceptable.
_INFERENCE_CHECKS = (
    "model_name_matches",
    "tdx_verified",
    "os_measurements_valid",
    "mrconfig_valid",
    "compose_hash_valid",
    "near_images_verified",
    "compose_manager_tdx_verified",
    "proxy_report_data_valid",
    "same_cvm",
    "report_data_valid",
    "serving_yaml_verified",
    "model_weights_approved",
    "gpu_verified",
)
_TLS_CHECKS = (
    "certificate_verified",
    "fingerprint_matches",
    "attestation_fingerprint_matches",
    "dns_caa_verified",
)


def _all_true(item: dict[str, Any], keys: tuple[str, ...], label: str) -> bool:
    """Whether every ``keys`` field of ``item`` is exactly True."""
    failed = [k for k in keys if item.get(k) is not True]
    logger.debug("%s validation: %s (failed: %s)", label, not failed, failed)
    return not failed


def _validate_tdx_component(item: dict[str, Any], component_name: str) -> bool:
    """Validate TDX-related fields for a component."""
    return _all_true(item, _GATEWAY_CHECKS, component_name)


def _validate_gpu_component(item: dict[str, Any]) -> bool:
    """Validate GPU component."""
    return _all_true(item, ("gpu_verified",), str(item.get("type", "GPU")))


def _validate_inference_component(item: dict[str, Any]) -> bool:
    """Validate an inference CVM (compose-manager chain) component."""
    return _all_true(item, _INFERENCE_CHECKS, str(item.get("type", "Inference")))


def _validate_domain_certificate(item: dict[str, Any]) -> bool:
    """Validate domain TLS certificate."""
    expected_domain = urlparse(BASE_URL).hostname or BASE_URL
    if item.get("domain") != expected_domain:
        logger.debug(
            "Domain TLS validation: domain %r is not %r",
            item.get("domain"),
            expected_domain,
        )
        return False
    return _all_true(item, _TLS_CHECKS, "Domain TLS")


def _process_validation_item(item: dict[str, Any], result: ValidationResult) -> None:
    """Process a single validation item and update result."""
    item_type = item.get("type", "")

    if item_type == "Gateway":
        result.gateway = _validate_tdx_component(item, "Gateway")
    elif item_type.startswith("Inference:"):
        # Checked before the GPU branch: inference summaries also carry
        # "gpu_verified" but require the full compose-manager chain.
        result.inference_components_seen += 1
        if not _validate_inference_component(item):
            result.inference_all = False
    elif "gpu_verified" in item:
        result.gpu_components_seen += 1
        if not _validate_gpu_component(item):
            result.gpu_all = False
    elif item_type == "Domain TLS Certificate":
        result.domain_tls = _validate_domain_certificate(item)


def _log_validation_results(result: ValidationResult) -> None:
    """Log validation results."""
    logger.info(
        f"Validation results: gateway={result.gateway}, "
        f"gpu_all={result._gpu_ok()} ({result.gpu_components_seen} seen), "
        f"domain_tls={result.domain_tls}, "
        f"inference_all={result._inference_ok()} "
        f"({result.inference_components_seen} seen)"
    )

    if not result.is_valid():
        logger.warning(f"Overall validation FAILED. Missing: {result.failed_checks()}")
        if "domain_tls" in result.failed_checks():
            logger.warning(
                "domain_tls: see the 🔐 TLS certificate warnings above for"
                " which comparison failed and why."
            )


def validate_report_values(data: Any) -> bool:
    """True only if every component (gateway, GPU, inference, TLS) validates."""
    if not isinstance(data, list):
        logger.error("Validation failed: data is not a list")
        return False

    result = ValidationResult()

    for item in data:
        if not isinstance(item, dict):
            logger.error(f"Validation failed: item is not a dict: {item}")
            return False
        _process_validation_item(item, result)

    _log_validation_results(result)
    return result.is_valid()
