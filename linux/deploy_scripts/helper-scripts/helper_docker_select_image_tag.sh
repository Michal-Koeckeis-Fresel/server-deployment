#!/bin/bash
#
# Copyright (c) 2025 Michal Koeckeis-Fresel
# 
# This software is dual-licensed under your choice of:
# - MIT License (see LICENSE-MIT)
# - GNU Affero General Public License v3.0 (see LICENSE-AGPL)
# 
# SPDX-License-Identifier: MIT OR AGPL-3.0-or-later
#

TAG_LIMIT=15

# Parse arguments
IMAGE_NAME=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --image)
            IMAGE_NAME="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 --image <docker_image>"
            exit 1
            ;;
    esac
done

if [ -z "$IMAGE_NAME" ]; then
    echo "Error: --image <docker_image> is required"
    exit 1
fi

# Ensure required tools are installed
for pkg in curl jq; do
    if ! command -v "$pkg" &>/dev/null; then
        echo "Installing missing package: $pkg"
        apt-get update -qq && apt-get install -y "$pkg"
    fi
done

echo "Fetching available tags for $IMAGE_NAME..." >&2

# Get and sort tags by last updated, descending
TAGS=$(curl -s "https://hub.docker.com/v2/repositories/${IMAGE_NAME}/tags?page_size=100" | jq -r '.results[] | "\(.name)\t\(.last_updated)"' | sort -rk2 | head -n "$TAG_LIMIT")

if [ -z "$TAGS" ]; then
    echo "No tags found or invalid image name: $IMAGE_NAME" >&2
    exit 1
fi

# Display selection
echo "Available versions for $IMAGE_NAME:" >&2
i=1
declare -A TAG_MAP
while IFS=$'\t' read -r tag date; do
    echo "$i) $tag (last updated: $date)" >&2
    TAG_MAP["$i"]="$tag"
    ((i++))
done <<< "$TAGS"

echo "" >&2
read -rp "Select a version by number: " choice

SELECTED_TAG="${TAG_MAP[$choice]}"
if [ -z "$SELECTED_TAG" ]; then
    echo "Invalid selection. Exiting." >&2
    exit 1
fi

# Output for eval
echo "export SELECTED_TAG=\"$SELECTED_TAG\""
echo "SELECTED_TAG: $SELECTED_TAG"