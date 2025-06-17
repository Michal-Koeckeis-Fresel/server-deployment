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

# Global variables
INSTALL_DIR="/data/BunkerWeb"
CONFIG_FILE="$INSTALL_DIR/BunkerWeb.conf"

# Function to validate release channel or version
validate_release_channel() {
    local channel="$1"
    
    case "$channel" in
        "latest"|"RC"|"nightly")
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
        "latest"|"RC"|"nightly")
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
            echo "rc"
            ;;
        "nightly")
            echo "nightly"
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

# Function to list available release channels
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
    
    echo -e "${RED}3. nightly (Development)${NC}"
    echo -e "   • Description: $(get_channel_description "nightly")"
    echo -e "   • Docker Tag: $(get_image_tag_for_channel "nightly")"
    echo -e "   • $(get_recommendation "nightly")"
    echo ""
    
    echo -e "${CYAN}4. Custom Version (Version Pinning)${NC}"
    echo -e "   • Description: Pin to specific BunkerWeb version"
    echo -e "   • Docker Tag: Uses exact version number (e.g., 1.6.1)"
    echo -e "   • Examples: 1.6.1, 1.5.4, 1.6.0-beta1"
    echo -e "   • $(get_recommendation "1.6.1")"
    echo -e "   • ${BLUE}Use case: Production environments requiring version consistency${NC}"
    echo ""
}

# Function to read current release channel from config
get_current_channel() {
    if [[ -f "$CONFIG_FILE" ]]; then
        local current=$(grep "^RELEASE_CHANNEL=" "$CONFIG_FILE" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
        if [[ -n "$current" ]]; then
            echo "$current"
        else
            echo "latest"  # Default fallback
        fi
    else
        echo "latest"  # Default fallback
    fi
}

# Function to update release channel in config file
update_config_channel() {
    local new_channel="$1"
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${RED}Error: Configuration file not found at $CONFIG_FILE${NC}"
        return 1
    fi
    
    # Validate the new channel
    if ! validate_release_channel "$new_channel"; then
        echo -e "${RED}Error: Invalid release channel '$new_channel'${NC}"
        echo -e "${YELLOW}Valid channels: latest, RC, nightly${NC}"
        return 1
    fi
    
    # Create backup
    local backup_file="$CONFIG_FILE.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$CONFIG_FILE" "$backup_file"
    echo -e "${GREEN}✓ Configuration backup created: $backup_file${NC}"
    
    # Update the configuration file
    if grep -q "^RELEASE_CHANNEL=" "$CONFIG_FILE"; then
        # Replace existing RELEASE_CHANNEL line
        sed -i "s/^RELEASE_CHANNEL=.*/RELEASE_CHANNEL=\"$new_channel\"/" "$CONFIG_FILE"
    else
        # Add RELEASE_CHANNEL line after the admin username line
        sed -i "/^ADMIN_USERNAME=/a RELEASE_CHANNEL=\"$new_channel\"" "$CONFIG_FILE"
    fi
    
    # Verify the update
    local updated_channel=$(get_current_channel)
    if [[ "$updated_channel" == "$new_channel" ]]; then
        echo -e "${GREEN}✓ Release channel updated successfully to: $new_channel${NC}"
        return 0
    else
        echo -e "${RED}✗ Failed to update release channel${NC}"
        echo -e "${YELLOW}Restoring backup...${NC}"
        cp "$backup_file" "$CONFIG_FILE"
        return 1
    fi
}

# Function to update running containers to new release channel
update_running_containers() {
    local new_channel="$1"
    local compose_file="$INSTALL_DIR/docker-compose.yml"
    
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${YELLOW}⚠ docker-compose.yml not found - containers not running${NC}"
        return 0
    fi
    
    echo -e "${BLUE}Updating running containers to release channel: $new_channel${NC}"
    
    local new_tag=$(get_image_tag_for_channel "$new_channel")
    echo -e "${BLUE}• Target Docker image tag: $new_tag${NC}"
    
    # Change to BunkerWeb directory
    cd "$INSTALL_DIR"
    
    # Check if containers are running
    if ! docker compose ps --status running | grep -q "bw-"; then
        echo -e "${YELLOW}⚠ No BunkerWeb containers currently running${NC}"
        echo -e "${BLUE}The new release channel will be used on next startup${NC}"
        return 0
    fi
    
    echo -e "${BLUE}Pulling new images for release channel '$new_channel'...${NC}"
    
    # Pull new images
    local images=(
        "bunkerity/bunkerweb:$new_tag"
        "bunkerity/bunkerweb-scheduler:$new_tag"
        "bunkerity/bunkerweb-autoconf:$new_tag"
        "bunkerity/bunkerweb-ui:$new_tag"
    )
    
    local pull_errors=0
    for image in "${images[@]}"; do
        echo -e "${CYAN}• Pulling $image...${NC}"
        if docker pull "$image" >/dev/null 2>&1; then
            echo -e "${GREEN}  ✓ Successfully pulled $image${NC}"
        else
            echo -e "${RED}  ✗ Failed to pull $image${NC}"
            ((pull_errors++))
        fi
    done
    
    if [[ $pull_errors -gt 0 ]]; then
        echo -e "${RED}⚠ Some images failed to pull${NC}"
        echo -e "${YELLOW}You may need to check if the release channel images are available${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Recreating containers with new images...${NC}"
    
    # Recreate containers with new images
    if docker compose up -d --force-recreate; then
        echo -e "${GREEN}✓ Containers updated successfully${NC}"
        
        # Wait a moment for containers to start
        sleep 5
        
        # Check container status
        echo -e "${BLUE}Checking container status...${NC}"
        docker compose ps
        
        return 0
    else
        echo -e "${RED}✗ Failed to recreate containers${NC}"
        return 1
    fi
}

# Function to show current status
show_status() {
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                    BUNKERWEB RELEASE CHANNEL STATUS                    ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    local current_channel=$(get_current_channel)
    echo -e "${GREEN}Current Release Channel Configuration:${NC}"
    show_channel_info "$current_channel"
    
    # Check if BunkerWeb is running and show actual image versions
    local compose_file="$INSTALL_DIR/docker-compose.yml"
    if [[ -f "$compose_file" ]]; then
        cd "$INSTALL_DIR"
        echo -e "${BLUE}Running Container Status:${NC}"
        
        if docker compose ps --status running | grep -q "bw-"; then
            echo -e "${GREEN}✓ BunkerWeb containers are running${NC}"
            echo ""
            echo -e "${BLUE}Current Image Versions:${NC}"
            docker compose images | grep bunkerity | while read -r line; do
                echo -e "${CYAN}  $line${NC}"
            done
        else
            echo -e "${YELLOW}⚠ BunkerWeb containers are not currently running${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ BunkerWeb not yet deployed${NC}"
    fi
    
    echo ""
}

# Function to change release channel interactively
change_channel_interactive() {
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                    CHANGE RELEASE CHANNEL                    ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    local current_channel=$(get_current_channel)
    echo -e "${GREEN}Current Channel: $current_channel${NC}"
    echo ""
    
    list_available_channels
    
    echo -e "${BLUE}Please select a new release channel:${NC}"
    echo -e "1) latest (Stable - Recommended for production)"
    echo -e "2) RC (Release Candidate - For testing)"
    echo -e "3) nightly (Development - Hardcore testers only)"
    echo -e "4) Custom version (Pin to specific version)"
    echo -e "5) Cancel"
    echo ""
    
    local choice
    read -p "Enter your choice (1-5): " choice
    
    local new_channel=""
    case $choice in
        1)
            new_channel="latest"
            ;;
        2)
            new_channel="RC"
            ;;
        3)
            new_channel="nightly"
            ;;
        4)
            echo ""
            echo -e "${CYAN}Enter custom version (e.g., 1.6.1, 1.5.4, 1.6.0-beta1):${NC}"
            read -p "Version: " new_channel
            
            # Validate custom version format
            if ! is_custom_version "$new_channel"; then
                echo -e "${RED}Invalid version format!${NC}"
                echo -e "${YELLOW}Expected format: X.Y.Z or X.Y.Z-suffix (e.g., 1.6.1, 1.6.0-beta1)${NC}"
                return 1
            fi
            ;;
        5)
            echo -e "${YELLOW}Operation cancelled${NC}"
            return 0
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            return 1
            ;;
    esac
    
    if [[ "$new_channel" == "$current_channel" ]]; then
        echo -e "${YELLOW}Selected channel is the same as current channel${NC}"
        return 0
    fi
    
    echo ""
    echo -e "${BLUE}Selected Release Channel:${NC}"
    show_channel_info "$new_channel"
    
    # Show warnings for non-stable channels
    case "$new_channel" in
        "RC")
            echo -e "${YELLOW}⚠ WARNING: You are switching to a Release Candidate channel${NC}"
            echo -e "${YELLOW}• This contains pre-release software${NC}"
            echo -e "${YELLOW}• Some features may be experimental${NC}"
            echo -e "${YELLOW}• Recommended for testing environments only${NC}"
            ;;
        "nightly")
            echo -e "${RED}⚠ WARNING: You are switching to the Nightly channel${NC}"
            echo -e "${RED}• This contains development builds that may be unstable${NC}"
            echo -e "${RED}• Features may change or break between updates${NC}"
            echo -e "${RED}• DO NOT use in production environments${NC}"
            echo -e "${RED}• Only for hardcore testers and developers${NC}"
            ;;
        *)
            if is_custom_version "$new_channel"; then
                echo -e "${CYAN}ℹ CUSTOM VERSION: You are pinning to version $new_channel${NC}"
                echo -e "${CYAN}• Ensure this version exists on Docker Hub${NC}"
                echo -e "${CYAN}• You will not receive automatic updates${NC}"
                echo -e "${CYAN}• Verify compatibility with your current data${NC}"
                echo -e "${CYAN}• Consider security implications of older versions${NC}"
            fi
            ;;
    esac
    
    echo ""
    read -p "Do you want to proceed with this change? (y/N): " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Operation cancelled${NC}"
        return 0
    fi
    
    echo ""
    echo -e "${BLUE}Updating configuration...${NC}"
    
    if update_config_channel "$new_channel"; then
        echo -e "${GREEN}✓ Configuration updated successfully${NC}"
        
        # Ask if user wants to update running containers
        local compose_file="$INSTALL_DIR/docker-compose.yml"
        if [[ -f "$compose_file" ]]; then
            echo ""
            read -p "Do you want to update running containers now? (y/N): " -n 1 -r
            echo ""
            
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                if update_running_containers "$new_channel"; then
                    echo -e "${GREEN}✓ Release channel change completed successfully${NC}"
                else
                    echo -e "${YELLOW}⚠ Configuration updated but container update failed${NC}"
                    echo -e "${BLUE}You can manually restart containers with: cd $INSTALL_DIR && docker compose down && docker compose up -d${NC}"
                fi
            else
                echo -e "${BLUE}Configuration updated. Restart containers manually to use the new channel:${NC}"
                echo -e "${BLUE}cd $INSTALL_DIR && docker compose down && docker compose up -d${NC}"
            fi
        else
            echo -e "${BLUE}Configuration updated. The new channel will be used when you deploy BunkerWeb.${NC}"
        fi
    else
        echo -e "${RED}✗ Failed to update configuration${NC}"
        return 1
    fi
}

# Function to show usage
show_usage() {
    echo -e "${BLUE}BunkerWeb Release Channel Manager${NC}"
    echo ""
    echo -e "${YELLOW}Usage: $(basename "$0") [COMMAND] [OPTIONS]${NC}"
    echo ""
    echo -e "${YELLOW}Commands:${NC}"
    echo -e "  status                 Show current release channel status"
    echo -e "  list                   List available release channels"
    echo -e "  change                 Change release channel (interactive)"
    echo -e "  set <channel>          Set release channel directly"
    echo -e "  update                 Update running containers to current channel"
    echo -e "  info <channel>         Show information about a specific channel"
    echo -e "  validate <channel>     Validate a channel or version format"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  -h, --help             Show this help message"
    echo ""
    echo -e "${YELLOW}Available Channels:${NC}"
    echo -e "  latest                 Stable releases (recommended for production)"
    echo -e "  RC                     Release candidates (for testing)"
    echo -e "  nightly                Development builds (hardcore testers only)"
    echo -e "  X.Y.Z                  Custom version pinning (e.g., 1.6.1, 1.5.4)"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo -e "  $(basename "$0") status              # Show current status"
    echo -e "  $(basename "$0") change              # Interactive channel change"
    echo -e "  $(basename "$0") set latest          # Set to stable releases"
    echo -e "  $(basename "$0") set RC              # Set to release candidates"
    echo -e "  $(basename "$0") set 1.6.1           # Pin to specific version"
    echo -e "  $(basename "$0") set 1.6.0-beta1     # Pin to beta version"
    echo -e "  $(basename "$0") info nightly        # Show info about nightly channel"
    echo -e "  $(basename "$0") validate 1.5.4      # Validate version format"
    echo ""
}

# Main function
main() {
    local command="${1:-status}"
    
    case "$command" in
        "status")
            show_status
            ;;
        "list")
            list_available_channels
            ;;
        "change")
            change_channel_interactive
            ;;
        "set")
            local channel="$2"
            if [[ -z "$channel" ]]; then
                echo -e "${RED}Error: Please specify a release channel or version${NC}"
                echo -e "${YELLOW}Usage: $(basename "$0") set <channel>${NC}"
                echo -e "${YELLOW}Available: latest, RC, nightly, or version (e.g., 1.6.1)${NC}"
                exit 1
            fi
            
            if update_config_channel "$channel"; then
                echo -e "${GREEN}✓ Release channel set to: $channel${NC}"
                show_channel_info "$channel"
            else
                echo -e "${RED}✗ Failed to set release channel${NC}"
                exit 1
            fi
            ;;
        "update")
            local current_channel=$(get_current_channel)
            update_running_containers "$current_channel"
            ;;
        "info")
            local channel="$2"
            if [[ -z "$channel" ]]; then
                echo -e "${RED}Error: Please specify a release channel or version${NC}"
                echo -e "${YELLOW}Usage: $(basename "$0") info <channel>${NC}"
                echo -e "${YELLOW}Available: latest, RC, nightly, or version (e.g., 1.6.1)${NC}"
                exit 1
            fi
            
            if validate_release_channel "$channel"; then
                show_channel_info "$channel"
            else
                echo -e "${RED}Error: Invalid release channel or version format '$channel'${NC}"
                echo -e "${YELLOW}Valid channels: latest, RC, nightly${NC}"
                echo -e "${YELLOW}Valid version format: X.Y.Z or X.Y.Z-suffix (e.g., 1.6.1, 1.6.0-beta1)${NC}"
                exit 1
            fi
            ;;
        "validate")
            local channel="$2"
            if [[ -z "$channel" ]]; then
                echo -e "${RED}Error: Please specify a release channel or version to validate${NC}"
                echo -e "${YELLOW}Usage: $(basename "$0") validate <channel>${NC}"
                echo -e "${YELLOW}Examples: latest, RC, nightly, 1.6.1, 1.6.0-beta1${NC}"
                exit 1
            fi
            
            if validate_release_channel "$channel"; then
                echo -e "${GREEN}✓ Valid: $channel${NC}"
                if is_custom_version "$channel"; then
                    echo -e "${CYAN}• Type: Custom Version${NC}"
                    echo -e "${CYAN}• Docker Tag: $(get_image_tag_for_channel "$channel")${NC}"
                else
                    echo -e "${BLUE}• Type: Release Channel${NC}"
                    echo -e "${BLUE}• Docker Tag: $(get_image_tag_for_channel "$channel")${NC}"
                fi
                exit 0
            else
                echo -e "${RED}✗ Invalid: $channel${NC}"
                echo -e "${YELLOW}Valid channels: latest, RC, nightly${NC}"
                echo -e "${YELLOW}Valid version format: X.Y.Z or X.Y.Z-suffix (e.g., 1.6.1, 1.6.0-beta1)${NC}"
                exit 1
            fi
            ;;
        "-h"|"--help"|"help")
            show_usage
            ;;
        *)
            echo -e "${RED}Error: Unknown command '$command'${NC}"
            echo ""
            show_usage
            exit 1
            ;;
    esac
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi