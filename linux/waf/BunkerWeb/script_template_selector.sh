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

# BunkerWeb Template Selector Script
# Provides interactive selection of BunkerWeb Docker image versions from Docker Hub

CONFIG_FILE="/data/BunkerWeb/BunkerWeb.conf"
IMAGE_NAME="bunkerity/bunkerweb"
TAG_LIMIT=15

# Install required packages if missing
for pkg in curl jq; do
    if ! command -v "$pkg" &>/dev/null; then
        echo "Installing missing package: $pkg"
        apt-get update -qq && apt-get install -y "$pkg"
    fi
done

echo "Fetching available tags for $IMAGE_NAME..."

# Retrieve and sort tags by last updated date
TAGS=$(curl -s "https://hub.docker.com/v2/repositories/${IMAGE_NAME}/tags?page_size=100" | jq -r '.results[] | "\(.name)\t\(.last_updated)"' | sort -rk2 | head -n "$TAG_LIMIT")

if [ -z "$TAGS" ]; then
    echo "No tags found. Exiting."
    exit 1
fi

# Display available versions for selection
echo "Available versions:"
i=1
declare -A TAG_MAP
while IFS=$'\t' read -r tag date; do
    echo "$i) $tag (last updated: $date)"
    TAG_MAP["$i"]="$tag"
    ((i++))
done <<< "$TAGS"

echo ""
read -rp "Select a version by number: " choice

SELECTED_TAG="${TAG_MAP[$choice]}"
if [ -z "$SELECTED_TAG" ]; then
    echo "Invalid selection. Exiting."
    exit 1
fi

echo "Selected version: $SELECTED_TAG"
echo ""

# Update configuration file with selected version
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Config file not found: $CONFIG_FILE"
    exit 1
fi

sed -i "s|^RELEASE_CHANNEL=\".*\"|RELEASE_CHANNEL=\"${SELECTED_TAG}\"|" "$CONFIG_FILE"
echo "Configuration updated: RELEASE_CHANNEL=\"$SELECTED_TAG\""

echo "Next step: edit /data/BunkerWeb/BunkerWeb.conf"
echo "nano /data/BunkerWeb/BunkerWeb.conf"

exit 0