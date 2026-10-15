# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Verification modules for attestation checking."""

from .compose_manager import (
    CvmState,
    InferenceAttestationSummary,
    cvm_state,
    model_names_match,
    signing_key_from_inference_attestation,
    verify_inference_attestation,
)
from .gpu import verify_model_attestation
from .image import verify_image_full
from .tdx import GatewayAttestationSummary, verify_gateway_attestation
from .tls import TLSVerificationResult, verify_certificate

__all__ = [
    "CvmState",
    "cvm_state",
    "verify_model_attestation",
    "verify_image_full",
    "GatewayAttestationSummary",
    "verify_gateway_attestation",
    "TLSVerificationResult",
    "verify_certificate",
    "InferenceAttestationSummary",
    "model_names_match",
    "signing_key_from_inference_attestation",
    "verify_inference_attestation",
]
