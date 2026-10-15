#!/bin/bash
# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.
# Buildspec Manager and CodeBuild Local Runner

# Not `-o pipefail`: the build pipeline ends in a grep that may exit 1.
# Not `-u`: the flag parser reads $2 for option values.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_ARTIFACT_DIR="$SCRIPT_DIR/remote-artifacts"

IMAGE="public.ecr.aws/codebuild/amazonlinux2-x86_64-standard:5.0"
OUTPUT_DIR="./output"
SOURCE_DIR="."
# Unpinned: local convenience only, not part of the verification path.
AGENT_IMAGE="public.ecr.aws/codebuild/local-builds:latest"
AWS_REGION="${AWS_REGION:-us-east-1}"
BUILDSPEC_FILE="buildspec.yml"
ENV_FILE=".env.local"
VERBOSE=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${GREEN}✓${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_status() { echo -e "${BLUE}▶${NC} $1"; }
print_verbose() { [ "$VERBOSE" = true ] && echo -e "${NC}  $1${NC}"; }

usage() {
    cat << EOF
Usage: ./scripts/run-codebuild-local.sh [options]

Run CodeBuild locally for testing buildspec.yml

OPTIONS:
    -v, --verbose       Verbose output
    -i <image>          Build image (default: amazonlinux2-x86_64-standard:5.0)
    -o <output_dir>     Output directory (default: $OUTPUT_DIR)
    -r <region>         AWS Region (default: $AWS_REGION)
    -b <buildspec>      Buildspec file (default: $BUILDSPEC_FILE)
    -e <env_file>       Environment file (default: $ENV_FILE)
    -h, --help          Show this help message

EXAMPLES:
    # Run build with verbose output
    ./scripts/run-codebuild-local.sh -v

    # Custom region and output
    ./scripts/run-codebuild-local.sh -r us-west-2 -o ./build-output -v

NOTES:
    - Ensure Docker is installed and running
    - Create .env.local with required environment variables
    - Output artifacts will be in $OUTPUT_DIR/
EOF
    exit "${1:-1}"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -i) IMAGE="$2"; shift 2 ;;
        -o) OUTPUT_DIR="$2"; shift 2 ;;
        -r) AWS_REGION="$2"; shift 2 ;;
        -b) BUILDSPEC_FILE="$2"; shift 2 ;;
        -e) ENV_FILE="$2"; shift 2 ;;
        -v|--verbose) VERBOSE=true; shift ;;
        -h|--help) usage 0 ;;
        *) print_error "Unknown option: $1"; usage ;;
    esac
done

print_status "CodeBuild Local Runner"
echo ""

print_verbose "Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed"
    echo "Install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi
print_verbose "Docker: installed"

if ! docker info &> /dev/null 2>&1; then
    print_error "Docker is not running"
    echo "Start Docker and try again"
    exit 1
fi
print_verbose "Docker: running"

if [ ! -f "$BUILDSPEC_FILE" ]; then
    print_error "Buildspec not found: $BUILDSPEC_FILE"
    exit 1
fi
print_verbose "Buildspec: $BUILDSPEC_FILE"

# Called from an if, so a failed pull does not trip set -e.
pull_image() {
    if [ "$VERBOSE" = true ]; then
        docker pull "$1"
    else
        docker pull "$1" > /dev/null 2>&1
    fi
}

print_status "Preparing build environment..."
print_verbose "Image: $IMAGE"

if pull_image "$IMAGE"; then
    print_info "Build image ready"
elif docker image inspect "$IMAGE" &> /dev/null; then
    print_warning "Using cached image (pull failed)"
else
    print_error "Image not available: $IMAGE"
    exit 1
fi

print_verbose "Agent: $AGENT_IMAGE"

if pull_image "$AGENT_IMAGE"; then
    print_info "Agent ready"
elif docker image inspect "$AGENT_IMAGE" &> /dev/null; then
    print_warning "Using cached agent (pull failed)"
else
    print_error "Agent not available"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
mkdir -p "$REMOTE_ARTIFACT_DIR"
print_verbose "Output directory: $OUTPUT_DIR"

SCRIPT_PATH="$REMOTE_ARTIFACT_DIR/codebuild_build.sh"
CODEBUILD_SCRIPT_COMMIT="2cc2e02f70748027447d55b5e82229dd7d69bd70"
CODEBUILD_SCRIPT_SHA256="0e10dda810a2418bd7ba5df013a6143e1d71fc549a73071db5d71429d645930d"

script_checksum_ok() {
    echo "$CODEBUILD_SCRIPT_SHA256  $1" | sha256sum -c - > /dev/null 2>&1
}

if [ -f "$SCRIPT_PATH" ] && script_checksum_ok "$SCRIPT_PATH"; then
    print_verbose "Using existing codebuild_build.sh"
else
    print_status "Downloading CodeBuild script..."
    CURL_FLAGS="-fsSL"
    [ "$VERBOSE" = true ] && CURL_FLAGS="-fSL"

    if ! curl $CURL_FLAGS -o "$SCRIPT_PATH.tmp" \
        "https://raw.githubusercontent.com/aws/aws-codebuild-docker-images/$CODEBUILD_SCRIPT_COMMIT/local_builds/codebuild_build.sh"; then
        rm -f "$SCRIPT_PATH.tmp"
        print_error "Failed to download CodeBuild script"
        exit 1
    fi
    if ! script_checksum_ok "$SCRIPT_PATH.tmp"; then
        rm -f "$SCRIPT_PATH.tmp"
        print_error "Checksum mismatch for codebuild_build.sh"
        exit 1
    fi
    mv "$SCRIPT_PATH.tmp" "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
    print_info "Script ready"
fi

# Trap first: the vars file receives .env.local's secrets.
ENV_VARS_FILE="$SOURCE_DIR/.codebuild-env-vars"
BUILD_LOG=$(mktemp)
trap 'rm -f "$BUILD_LOG" "$ENV_VARS_FILE"' EXIT
cat > "$ENV_VARS_FILE" << EOF
AWS_REGION=$AWS_REGION
AWS_DEFAULT_REGION=$AWS_REGION
EOF

if [ -f "$ENV_FILE" ]; then
    print_status "Loading environment variables..."
    print_verbose "Environment file: $ENV_FILE"

    cat "$ENV_FILE" >> "$ENV_VARS_FILE"

    # Show loaded vars (redact sensitive ones)
    if [ "$VERBOSE" = true ]; then
        while IFS='=' read -r line; do
            [[ "$line" =~ ^#.*$ ]] && continue
            [[ -z "$line" ]] && continue
            key="${line%%=*}"
            value="${line#*=}"
            
            if [[ "$key" =~ (KEY|SECRET|TOKEN|PASSWORD) ]]; then
                print_verbose "  $key=***"
            else
                print_verbose "  $key=$value"
            fi
        done < "$ENV_FILE"
    fi

    ENV_FILE_ARG="-e $ENV_VARS_FILE"
else
    print_warning "Environment file not found: $ENV_FILE"
    ENV_FILE_ARG=""
fi

echo ""
print_status "Running build..."
print_verbose "Region: $AWS_REGION"
print_verbose "Source: $SOURCE_DIR"
print_verbose "Output: $OUTPUT_DIR"

cd "$SOURCE_DIR" || exit 1

if [ "$VERBOSE" = true ]; then
    print_status "Executing CodeBuild (verbose)..."
    "$SCRIPT_PATH" -i "$IMAGE" -a "$OUTPUT_DIR" -b "$BUILDSPEC_FILE" $ENV_FILE_ARG 2>&1 | tee "$BUILD_LOG"
    BUILD_EXIT_CODE=${PIPESTATUS[0]}
else
    print_status "Executing CodeBuild..."
    "$SCRIPT_PATH" -i "$IMAGE" -a "$OUTPUT_DIR" -b "$BUILDSPEC_FILE" $ENV_FILE_ARG 2>&1 | \
        tee "$BUILD_LOG" | \
        grep -E "(Phase complete|ERROR|FAILED|State: SUCCEEDED|State: FAILED|Running command)" | \
        sed 's/agent-1  | //'
    BUILD_EXIT_CODE=${PIPESTATUS[0]}
fi

echo ""
echo "────────────────────────────────────────────────────────────────"

if [ $BUILD_EXIT_CODE -eq 0 ]; then
    print_info "Build completed successfully"
    print_status "Output directory: $OUTPUT_DIR"

    if [ -d "$OUTPUT_DIR" ] && [ -n "$(ls -A "$OUTPUT_DIR" 2>/dev/null)" ]; then
        echo ""
        echo "Output files:"
        find "$OUTPUT_DIR" -type f 2>/dev/null | head -20 | sed 's/^/  /' || echo "  (none)"
    else
        print_warning "Output directory is empty"
    fi

    if [ -f "$OUTPUT_DIR/artifacts.zip" ]; then
        echo ""
        print_info "Artifact: artifacts.zip"
        unzip -l "$OUTPUT_DIR/artifacts.zip" 2>/dev/null | tail -n +4 | head -n -2 | sed 's/^/  /' || true
    fi
else
    print_error "Build failed with exit code $BUILD_EXIT_CODE"
    echo ""
    echo "Last 50 lines of build log:"
    tail -50 "$BUILD_LOG" | sed 's/^/  /'
    echo ""
    print_status "For full logs, run with -v flag"
fi

echo "────────────────────────────────────────────────────────────────"

exit $BUILD_EXIT_CODE
