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

# BunkerWeb Release Channel Manager
# Handles release channel detection, validation, and Docker image tag management

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to validate release channel or version
validate_release_channel() {
    local channel="$1"
    
    case "$channel" in
        "latest"|"RC"|"dev"|"testing"|"nightly")
            return 0
            ;;
        *)
            # Check if it's a version pattern (e.g., 1.6.1, v1.6.1, 1.6.1-beta, etc.)
            if [[ "$channel" =~ ^v?[0-9]+\.[0-9]+(\.[0-9]+)?(-[a-zA-Z0-9]+)?$ ]]; then
                return 0
            else
                return 1
            fi
            ;;
    esac
}

# Function to check if channel is a custom version
is_custom_version() {
    local channel="$1"
    
    case "$channel" in
        "latest"|"RC"|"dev"|"testing"|"nightly")
            return 1  # Not a custom version
            ;;
        *)
            if [[ "$channel" =~ ^v?[0-9]+\.[0-9]+(\.[0-9]+)?(-[a-zA-Z0-9]+)?$ ]]; then
                return 0  # Is a custom version
            else
                return 1  # Invalid format
            fi
            ;;
    esac
}

# Function to get Docker image tag based on release channel
get_image_tag_for_channel() {
    local release_channel="$1"
    
    case "$release_channel" in
        "latest")
            echo "latest"
            ;;
        "RC")
            echo "dev"
            ;;
        "dev")
            echo "dev"
            ;;
        "testing")
            echo "testing"
            ;;
        "nightly")
            echo "dev"
            ;;
        *)
            # For custom versions, use the version as-is (remove 'v' prefix if present)
            if is_custom_version "$release_channel"; then
                echo "${release_channel#v}"  # Remove 'v' prefix if present
            else
                echo "latest"  # Fallback
            fi
            ;;
    esac
}

# Function to get release channel description
get_channel_description() {
    local channel="$1"
    
    case "$channel" in
        "latest")
            echo "Stable releases (Production Ready)"
            ;;
        "RC")
            echo "Release Candidates (Beta Testing)"
            ;;
        "dev")
            echo "Development Builds (Latest Features)"
            ;;
        "testing")
            echo "Testing Builds (QA and Integration Testing)"
            ;;
        "nightly")
            echo "Development Builds (Hardcore Testers Only)"
            ;;
        *)
            if is_custom_version "$channel"; then
                echo "Custom Version (Pinned Release)"
            else
                echo "Unknown channel"
            fi
            ;;
    esac
}

# Function to get stability level
get_stability_level() {
    local channel="$1"
    
    case "$channel" in
        "latest")
            echo -e "${GREEN}Production Ready${NC}"
            ;;
        "RC")
            echo -e "${YELLOW}Beta/Testing${NC}"
            ;;
        "dev")
            echo -e "${YELLOW}Development/Beta${NC}"
            ;;
        "testing")
            echo -e "${YELLOW}Testing/QA${NC}"
            ;;
        "nightly")
            echo -e "${RED}Unstable/Development${NC}"
            ;;
        *)
            if is_custom_version "$channel"; then
                echo -e "${BLUE}Version Pinned${NC}"
            else
                echo -e "${YELLOW}Unknown${NC}"
            fi
            ;;
    esac
}

# Function to get recommendation
get_recommendation() {
    local channel="$1"
    
    case "$channel" in
        "latest")
            echo -e "${GREEN}✓ Recommended for production use${NC}"
            ;;
        "RC")
            echo -e "${YELLOW}⚠ Use for testing/staging environments only${NC}"
            ;;
        "dev")
            echo -e "${YELLOW}⚠ Use for development and testing environments${NC}"
            ;;
        "testing")
            echo -e "${YELLOW}⚠ Use for QA and integration testing environments${NC}"
            ;;
        "nightly")
            echo -e "${RED}⚠ Development use only - NOT for production!${NC}"
            ;;
        *)
            if is_custom_version "$channel"; then
                echo -e "${CYAN}ℹ Pinned to specific version - verify compatibility${NC}"
            else
                echo -e "${YELLOW}⚠ Unknown stability${NC}"
            fi
            ;;
    esac
}

# Function to display release channel information
show_channel_info() {
    local channel="$1"
    local tag=$(get_image_tag_for_channel "$channel")
    local description=$(get_channel_description "$channel")
    
    echo -e "${BLUE}Release Channel Information:${NC}"
    echo -e "${GREEN}• Channel: $channel${NC}"
    echo -e "${GREEN}• Description: $description${NC}"
    echo -e "${GREEN}• Docker Tag: $tag${NC}"
    echo -e "${GREEN}• Stability: $(get_stability_level "$channel")${NC}"
    echo -e "${GREEN}• Recommendation: $(get_recommendation "$channel")${NC}"
    echo ""
}

# Function to replace image tags in docker-compose file
replace_image_tags() {
    local compose_file="$1"
    local image_tag="$2"
    
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${RED}✗ Docker compose file not found: $compose_file${NC}" >&2
        return 1
    fi
    
    if [[ -z "$image_tag" ]]; then
        echo -e "${RED}✗ Image tag cannot be empty${NC}" >&2
        return 1
    fi
    
    echo -e "${BLUE}Replacing image tags with: $image_tag${NC}" >&2
    
    # Create backup
    local backup_file="$compose_file.backup.tags.$(date +%Y%m%d_%H%M%S)"
    cp "$compose_file" "$backup_file"
    
    # Replace REPLACEME_TAG with the actual tag
    if sed -i "s|REPLACEME_TAG|$image_tag|g" "$compose_file"; then
        echo -e "${GREEN}✓ Image tags updated to: $image_tag${NC}" >&2
        
        # Verify the replacement worked
        local remaining_tags=$(grep -c "REPLACEME_TAG" "$compose_file" 2>/dev/null || echo "0")
        
        if [[ $remaining_tags -eq 0 ]]; then
            echo -e "${GREEN}✓ All image tags successfully replaced${NC}" >&2
            return 0
        else
            echo -e "${YELLOW}⚠ Some REPLACEME_TAG placeholders may remain: $remaining_tags${NC}" >&2
            return 1
        fi
    else
        echo -e "${RED}✗ Failed to replace image tags${NC}" >&2
        return 1
    fi
}

# Function to replace image tags in template processing
replace_image_tag_placeholders() {
    local compose_file="$1"
    local image_tag="$2"
    local description="${3:-Docker image tags}"
    
    echo -e "${BLUE}Replacing $description with: $image_tag${NC}" >&2
    
    # Use sed to replace REPLACEME_TAG placeholder
    if sed -i "s|REPLACEME_TAG|$image_tag|g" "$compose_file"; then
        echo -e "${GREEN}✓ $description updated to: $image_tag${NC}" >&2
        return 0
    else
        echo -e "${RED}✗ Failed to replace $description${NC}" >&2
        return 1
    fi
}

# Function to get available release channels
get_available_channels() {
    echo "Available release channels:"
    echo "• latest     - Stable production releases"
    echo "• RC         - Release candidates (beta)"
    echo "• dev        - Development builds (latest features)"
    echo "• testing    - Testing builds (QA)"
    echo "• nightly    - Development builds"
    echo "• X.Y.Z      - Specific version (e.g., 1.6.1)"
}

# Function to list available release channels with details
list_available_channels() {
    echo -e "${BLUE}Available Release Channels:${NC}"
    echo ""
    
    echo -e "${GREEN}1. latest (Stable)${NC}"
    echo -e "   • Description: $(get_channel_description "latest")"
    echo -e "   • Docker Tag: $(get_image_tag_for_channel "latest")"
    echo -e "   • $(get_recommendation "latest")"
    echo ""
    
    echo -e "${YELLOW}2. RC (Release Candidate)${NC}"
    echo -e "   • Description: $(get_channel_description "RC")"
    echo -e "   • Docker Tag: $(get_image_tag_for_channel "RC")"
    echo -e "   • $(get_recommendation "RC")"
    echo ""
    
    echo -e "${YELLOW}3. dev (Development)${NC}"
    echo -e "   • Description: $(get_channel_description "dev")"
    echo -e "   • Docker Tag: $(get_image_tag_for_channel "dev")"
    echo -e "   • $(get_recommendation "dev")"
    echo ""
    
    echo -e "${YELLOW}4. testing (Testing)${NC}"
    echo -e "   • Description: $(get_channel_description "testing")"
    echo -e "   • Docker Tag: $(get_image_tag_for_channel "testing")"
    echo -e "   • $(get_recommendation "testing")"
    echo ""
    
    echo -e "${RED}5. nightly (Development)${NC}"
    echo -e "   • Description: $(get_channel_description "nightly")"
    echo -e "   • Docker Tag: $(get_image_tag_for_channel "nightly")"
    echo -e "   • $(get_recommendation "nightly")"
    echo ""
    
    echo -e "${CYAN}6. Custom Version (Version Pinning)${NC}"
    echo -e "   • Description: Pin to specific BunkerWeb version"
    echo -e "   • Docker Tag: Uses exact version number (e.g., 1.6.1)"
    echo -e "   • Examples: 1.6.1, 1.5.4, 1.6.0-beta1"
    echo -e "   • $(get_recommendation "1.6.1")"
    echo -e "   • ${BLUE}Use case: Production environments requiring version consistency${NC}"
    echo ""
}

# If script is run directly, show usage
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "BunkerWeb Release Channel Manager Script"
    echo ""
    echo "This script is designed to be sourced by other scripts."
    echo ""
    echo "Available functions:"
    echo "  validate_release_channel <channel>"
    echo "  is_custom_version <channel>"
    echo "  get_image_tag_for_channel <channel>"
    echo "  get_channel_description <channel>"
    echo "  show_channel_info <channel>"
    echo "  replace_image_tags <compose_file> <image_tag>"
    echo "  replace_image_tag_placeholders <compose_file> <image_tag> [description]"
    echo "  list_available_channels"
    echo ""
    echo "Example usage:"
    echo "  source helper_release_channel_manager.sh"
    echo "  TAG=\$(get_image_tag_for_channel \"latest\")"
    echo "  replace_image_tags docker-compose.yml \"\$TAG\""
fi