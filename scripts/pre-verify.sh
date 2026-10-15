#!/bin/bash
# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.
# Pre-verify container images ahead of a release (optional warm-up).
# Populates the S3 cache so unchanged digests skip cosign and the
# reproducibility build at release time.
#
# Required env vars:
#   NEAR_BUCKET_NAME   S3 bucket (same one used by the release verifier)
#   COMPOSE_FILE       path to the docker-compose file whose images to verify
#                        (mutually exclusive with IMAGE_REFS)
#   IMAGE_REFS         space-separated list of registry@sha256:... refs
#                        (mutually exclusive with COMPOSE_FILE)
set -euo pipefail

echo "═══════════════════════════════════════════════════════════════"
echo "🔍 Starting image pre-verification"
echo "═══════════════════════════════════════════════════════════════"
echo ""

mkdir -p /tmp/verification

if [[ -n "${COMPOSE_FILE:-}" ]]; then
    ARGS="--compose ${COMPOSE_FILE}"
elif [[ -n "${IMAGE_REFS:-}" ]]; then
    # shellcheck disable=SC2086
    ARGS="--image ${IMAGE_REFS}"
else
    echo "❌ Set COMPOSE_FILE or IMAGE_REFS before running pre-verify.sh" >&2
    exit 1
fi

# shellcheck disable=SC2086
if poetry run python -m verifier.pre_verify ${ARGS} 2>&1 | tee /tmp/verification/pre-verify-output.log; then
    echo ""
    echo "✅ Image pre-verification completed successfully"
    echo "═══════════════════════════════════════════════════════════════"
else
    echo ""
    echo "❌ Image pre-verification FAILED. See /tmp/verification/pre-verify-output.log"
    echo "═══════════════════════════════════════════════════════════════"
    exit 1
fi
