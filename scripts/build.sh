#!/bin/bash
# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.
set -euo pipefail

echo "Running TEE verification..."
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "🔐 Starting Verification"
echo "═══════════════════════════════════════════════════════════════"
echo ""

mkdir -p /tmp/verification

# No --model: the verifier reads MODEL_NAME itself, keeping it in sync with the proxy pin.
if poetry run python -m verifier.main --output /tmp/verification/verification-report.json \
    2>&1 | tee /tmp/verification/verification-output.log; then
    echo ""
    echo "✅ Model verification completed successfully"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "✅ Verification completed"
    echo "═══════════════════════════════════════════════════════════════"
else
    echo ""
    echo "❌ Model verification FAILED. See /tmp/verification/verification-output.log for details"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "❌ Verification FAILED"
    echo "═══════════════════════════════════════════════════════════════"
    exit 1
fi
