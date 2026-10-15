#!/bin/bash
# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.
set -euo pipefail

echo "Generating verification reports..."

cat > /tmp/verification/final-report.txt << REPORT_EOF
================================================================================
TEE VERIFICATION REPORT
================================================================================
Build Time: $(date)
CodeBuild Project: ${CODEBUILD_BUILD_ID:-unknown}
================================================================================
VERIFICATION SUMMARY
================================================================================
REPORT_EOF

cat /tmp/verification/verification-output.log >> /tmp/verification/final-report.txt 2>/dev/null || echo "No verification output" >> /tmp/verification/final-report.txt

cat /tmp/verification/final-report.txt

echo "✅ Post-build phase completed"
