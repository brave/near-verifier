#!/bin/bash
# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.
set -euo pipefail

SOURCE_DIR="${1:-.}"
cd "$SOURCE_DIR"

if ! docker buildx inspect buildkit_20 &>/dev/null; then
    docker buildx create --use --driver-opt image=moby/buildkit:v0.20.2 --name buildkit_20
fi

touch pinned-packages-builder.txt pinned-packages-runtime.txt
git rev-parse HEAD > .GIT_REV
trap 'rm -f .GIT_REV' EXIT

TEMP_TAG="cloud-api-temp:$(date +%s)"

docker buildx build --builder buildkit_20 --no-cache --platform linux/amd64 \
    --build-arg SOURCE_DATE_EPOCH="0" \
    --output type=oci,dest=./oci.tar,rewrite-timestamp=true \
    --output type=docker,name="$TEMP_TAG",rewrite-timestamp=true .

if command -v skopeo &> /dev/null; then
    echo "Build completed, manifest digest:"
    skopeo inspect oci-archive:./oci.tar | jq .Digest
else
    echo "Build completed (skopeo not available for digest inspection)"
fi

echo "Extracting package information from built image: $TEMP_TAG"
docker run --rm "$TEMP_TAG" cat /app/pinned-packages-builder.txt > pinned-packages-builder.txt 2>/dev/null || echo "" > pinned-packages-builder.txt
echo "Package information extracted to pinned-packages-builder.txt"

docker run --rm --entrypoint bash "$TEMP_TAG" -c "dpkg -l | grep '^ii' | awk '{print \$2\"=\"\$3}' | sort" > pinned-packages-runtime.txt 2>/dev/null || echo "" > pinned-packages-runtime.txt
echo "Package information extracted to pinned-packages-runtime.txt"

docker rmi "$TEMP_TAG" 2>/dev/null || true
