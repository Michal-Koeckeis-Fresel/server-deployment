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

# BunkerWeb Setup Script - MODULAR VERSION with API Whitelist Auto-Detection and Release Channel Support
# This script orchestrates the setup using separate modules for each major function
# MUST BE RUN AS ROOT: sudo ./script_autoconf_display.sh --type <autoconf|basic|integrated>

set -e

# Script directory and installation directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/data/BunkerWeb"
SETUP_MODE="automated"  # Default to automated mode

# Default values (can be overridden by BunkerWeb.conf or command line)
ADMIN_USERNAME="admin"
AUTO_CERT_TYPE=""
AUTO_CERT_CONTACT=""
FQDN=""
MULTISITE="yes"
SERVER_NAME=""
SECURITY_MODE="block"
SERVER_TYPE="http"
RELEASE_CHANNEL="latest"  # Default to stable releases

# Network Configuration
PRIVATE_NETWORKS_ALREADY_IN_USE=""
AUTO_DETECT_NETWORK_CONFLICTS="yes"
PREFERRED_DOCKER_SUBNET=""

# Service Configuration
REDIS_ENABLED="yes"
REDIS_PASSWORD=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to get Docker image tag based on release channel
get_image_tag() {
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
            echo -e "${YELLOW}⚠ Unknown release channel '$release_channel', defaulting to 'latest'${NC}" >&2
            echo "latest"
            ;;
    esac
}

# Function to validate release channel
validate_release_channel() {
    local channel="$1"
    
    case "$channel" in
        "latest"|"RC"|"nightly")
            return 0
            ;;
        *)
            echo -e "${RED}Error: Invalid release channel '$channel'${NC}" >&2
            echo -e "${YELLOW}Valid channels: latest, RC, nightly${NC}" >&2
            return 1
            ;;
    esac
}

# Function to display release channel information
show_release_channel_info() {
    local channel="$1"
    local tag=$(get_image_tag "$channel")
    
    echo -e "${BLUE}Release Channel Information:${NC}"
    echo -e "${GREEN}• Selected Channel: $channel${NC}"
    echo -e "${GREEN}• Docker Image Tag: $tag${NC}"
    
    case "$channel" in
        "latest")
            echo -e "${GREEN}• Stability: Production Ready (Stable)${NC}"
            echo -e "${GREEN}• Recommendation: ✓ Recommended for production use${NC}"
            echo -e "${GREEN}• Description: Stable, tested releases with full support${NC}"
            ;;
        "RC")
            echo -e "${YELLOW}• Stability: Release Candidate (Beta)${NC}"
            echo -e "${YELLOW}• Recommendation: ⚠ Use for testing/staging only${NC}"
            echo -e "${YELLOW}• Description: Pre-release versions with new features${NC}"
            ;;
        "nightly")
            echo -e "${RED}• Stability: Development Build (Unstable)${NC}"
            echo -e "${RED}• Recommendation: ⚠ Hardcore testers only!${NC}"
            echo -e "${RED}• Description: Latest development code - may be unstable${NC}"
            ;;
    esac
    echo ""
}

# Source the modular scripts
source_modules() {
    local modules=(
        "helper_password_manager.sh"
        "helper_network_detection.sh" 
        "helper_template_processor.sh"
        "helper_release_channel_manager.sh"
    )
    
    echo -e "${BLUE}Loading BunkerWeb modules...${NC}"
    
    for module in "${modules[@]}"; do
        local module_path="$SCRIPT_DIR/$module"
        
        if [[ -f "$module_path" ]]; then
            if source "$module_path"; then
                echo -e "${GREEN}✓ Loaded: $module${NC}"
            else
                echo -e "${RED}✗ Failed to load: $module${NC}"
                return 1
            fi
        else
            echo -e "${RED}✗ Module not found: $module_path${NC}"
            echo -e "${YELLOW}ℹ Please ensure all modules are in the same directory as this script${NC}"
            return 1
        fi
    done
    
    echo -e "${GREEN}✓ All modules loaded successfully${NC}"
    return 0
}

# Function to detect and build comprehensive API whitelist
build_comprehensive_api_whitelist() {
    local docker_subnet="$1"
    local api_whitelist="127.0.0.0/8"  # Always include localhost
    
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                    API WHITELIST AUTO-DETECTION                    ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    echo -e "${BLUE}Building comprehensive API whitelist for Docker networks...${NC}"
    
    # Add the main Docker subnet
    if [[ -n "$docker_subnet" ]]; then
        api_whitelist="$api_whitelist $docker_subnet"
        echo -e "${GREEN}• Added main subnet: $docker_subnet${NC}"
    fi
    
    # Add comprehensive Docker Compose network ranges
    echo -e "${BLUE}Adding Docker Compose network ranges...${NC}"
    
    # Common Docker Compose networks that might be created
    local docker_ranges=(
        "172.16.0.0/12"   # Standard Docker bridge networks
        "172.17.0.0/16"   # Default Docker bridge
        "172.18.0.0/16"   # Docker Compose networks
        "172.19.0.0/16"   # Docker Compose networks  
        "172.20.0.0/16"   # Docker Compose networks (this is where your scheduler is!)
        "172.21.0.0/16"   # Docker Compose networks
        "172.22.0.0/16"   # Docker Compose networks
        "172.23.0.0/16"   # Docker Compose networks
        "172.24.0.0/16"   # Docker Compose networks
        "172.25.0.0/16"   # Docker Compose networks
    )
    
    for range in "${docker_ranges[@]}"; do
        if [[ ! "$api_whitelist" =~ $range ]]; then
            api_whitelist="$api_whitelist $range"
            echo -e "${GREEN}• Added Docker range: $range${NC}"
        fi
    done
    
    # Detect existing Docker networks if Docker is available
    if command -v docker >/dev/null 2>&1; then
        echo -e "${BLUE}Detecting existing Docker networks...${NC}"
        
        # Get existing Docker bridge networks
        local existing_networks=()
        while IFS= read -r line; do
            if [[ "$line" =~ \"Subnet\":[[:space:]]*\"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+)\" ]]; then
                local network="${BASH_REMATCH[1]}"
                existing_networks+=("$network")
            fi
        done < <(docker network ls -q 2>/dev/null | xargs -I {} docker network inspect {} 2>/dev/null | grep -E "\"Subnet\":" || true)
        
        # Add existing Docker networks that are in private ranges
        for network in "${existing_networks[@]}"; do
            # Check if it's a private network (RFC1918) and not already included
            if [[ "$network" =~ ^10\. ]] || [[ "$network" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || [[ "$network" =~ ^192\.168\. ]]; then
                if [[ ! "$api_whitelist" =~ $network ]]; then
                    api_whitelist="$api_whitelist $network"
                    echo -e "${GREEN}• Added existing Docker network: $network${NC}"
                fi
            fi
        done
    fi
    
    # Add broader ranges for safety
    echo -e "${BLUE}Adding broader private network ranges for safety...${NC}"
    local broad_ranges=(
        "10.0.0.0/8"      # Class A private networks
        "192.168.0.0/16"  # Class C private networks
    )
    
    for range in "${broad_ranges[@]}"; do
        if [[ ! "$api_whitelist" =~ $range ]]; then
            api_whitelist="$api_whitelist $range"
            echo -e "${GREEN}• Added private range: $range${NC}"
        fi
    done
    
    echo ""
    echo -e "${GREEN}Final comprehensive API whitelist:${NC}"
    echo -e "${GREEN}$api_whitelist${NC}"
    echo ""
    
    echo "$api_whitelist"
}

# Enhanced template processing with release channel and automatic API whitelist replacement
process_template_with_release_channel() {
    local template_path="$1"
    local compose_file="$2"
    local mysql_password="$3"
    local redis_password="$4"
    local totp_secret="$5"
    local admin_password="$6"
    local flask_secret="$7"
    local admin_username="$8"
    local auto_cert_type="$9"
    local auto_cert_contact="${10}"
    local fqdn="${11}"
    local server_name="${12}"
    local docker_subnet="${13}"
    local setup_mode="${14}"
    local redis_enabled="${15:-yes}"
    local api_whitelist="${16}"
    local release_channel="${17:-latest}"
    
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                        TEMPLATE PROCESSING                        ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    echo -e "${BLUE}Processing template with release channel and enhanced API whitelist...${NC}"
    echo -e "${BLUE}Release Channel: $release_channel${NC}"
    echo -e "${BLUE}API Whitelist: $api_whitelist${NC}"
    
    # Get the appropriate image tag for the release channel
    local image_tag=$(get_image_tag_for_channel "$release_channel")
    echo -e "${GREEN}• Using Docker image tag: $image_tag${NC}"
    
    # First, run the standard template processing
    if ! process_template "$template_path" "$compose_file" "$mysql_password" "$redis_password" "$totp_secret" "$admin_password" "$flask_secret" "$admin_username" "$auto_cert_type" "$auto_cert_contact" "$fqdn" "$server_name" "$docker_subnet" "$setup_mode" "$redis_enabled"; then
        echo -e "${RED}✗ Standard template processing failed${NC}"
        return 1
    fi
    
    # Update Docker image tags based on release channel
    echo -e "${BLUE}Updating Docker image tags for release channel '$release_channel'...${NC}"
    
    # Replace image tags in the docker-compose.yml
    local temp_file=$(mktemp)
    local updates_made=0
    
    # Update BunkerWeb images
    if sed "s|bunkerity/bunkerweb:REPLACEME_TAG|bunkerity/bunkerweb:$image_tag|g" "$compose_file" > "$temp_file"; then
        mv "$temp_file" "$compose_file"
        ((updates_made++))
        echo -e "${GREEN}✓ Updated bunkerity/bunkerweb image tag${NC}"
    fi
    
    if sed "s|bunkerity/bunkerweb-scheduler:REPLACEME_TAG|bunkerity/bunkerweb-scheduler:$image_tag|g" "$compose_file" > "$temp_file"; then
        mv "$temp_file" "$compose_file"
        ((updates_made++))
        echo -e "${GREEN}✓ Updated bunkerity/bunkerweb-scheduler image tag${NC}"
    fi
    
    if sed "s|bunkerity/bunkerweb-autoconf:REPLACEME_TAG|bunkerity/bunkerweb-autoconf:$image_tag|g" "$compose_file" > "$temp_file"; then
        mv "$temp_file" "$compose_file"
        ((updates_made++))
        echo -e "${GREEN}✓ Updated bunkerity/bunkerweb-autoconf image tag${NC}"
    fi
    
    if sed "s|bunkerity/bunkerweb-ui:REPLACEME_TAG|bunkerity/bunkerweb-ui:$image_tag|g" "$compose_file" > "$temp_file"; then
        mv "$temp_file" "$compose_file"
        ((updates_made++))
        echo -e "${GREEN}✓ Updated bunkerity/bunkerweb-ui image tag${NC}"
    fi
    
    # Also update any existing :latest tags to the selected channel (if different from latest)
    if [[ "$image_tag" != "latest" ]]; then
        if sed "s|bunkerity/bunkerweb:latest|bunkerity/bunkerweb:$image_tag|g" "$compose_file" > "$temp_file"; then
            mv "$temp_file" "$compose_file"
            echo -e "${GREEN}✓ Updated existing :latest tags to :$image_tag${NC}"
        fi
        
        if sed "s|bunkerity/bunkerweb-scheduler:latest|bunkerity/bunkerweb-scheduler:$image_tag|g" "$compose_file" > "$temp_file"; then
            mv "$temp_file" "$compose_file"
        fi
        
        if sed "s|bunkerity/bunkerweb-autoconf:latest|bunkerity/bunkerweb-autoconf:$image_tag|g" "$compose_file" > "$temp_file"; then
            mv "$temp_file" "$compose_file"
        fi
        
        if sed "s|bunkerity/bunkerweb-ui:latest|bunkerity/bunkerweb-ui:$image_tag|g" "$compose_file" > "$temp_file"; then
            mv "$temp_file" "$compose_file"
        fi
    fi
    
    # Then, update the API whitelist with comprehensive network coverage
    echo -e "${BLUE}Updating API whitelist in docker-compose.yml...${NC}"
    
    # Use a more robust approach with awk instead of sed for complex strings
    local old_pattern='API_WHITELIST_IP: "127.0.0.0/8 10.20.30.0/24'
    local new_value="API_WHITELIST_IP: \"$api_whitelist\""
    
    # Use awk to replace the API whitelist lines
    awk -v new="$new_value" '
        {
            if (index($0, "API_WHITELIST_IP:") > 0) {
                gsub(/API_WHITELIST_IP: "[^"]*"/, new, $0)
            }
            print $0
        }
    ' "$compose_file" > "$temp_file"
    
    # Check if the replacement worked
    if [[ -s "$temp_file" ]]; then
        mv "$temp_file" "$compose_file"
        echo -e "${GREEN}✓ API whitelist updated successfully${NC}"
        
        # Verify the replacement worked
        local updated_count=$(grep -c "API_WHITELIST_IP:" "$compose_file" || echo "0")
        echo -e "${GREEN}✓ Updated $updated_count API_WHITELIST_IP entries${NC}"
        
        # Show the updated entries for verification (truncated for readability)
        echo -e "${BLUE}Verification - Updated API whitelist entries:${NC}"
        grep "API_WHITELIST_IP:" "$compose_file" | sed 's/^\s*/  /' | cut -c1-100 | sed 's/$/.../' || true
        
    else
        echo -e "${RED}✗ Failed to update API whitelist${NC}"
        rm -f "$temp_file"
        return 1
    fi
    
    # Clean up
    rm -f "$temp_file"
    
    # Also ensure BUNKERWEB_INSTANCES is set correctly for autoconf mode
    echo -e "${BLUE}Configuring BunkerWeb instances for autoconf mode...${NC}"
    if sed -i 's|BUNKERWEB_INSTANCES: ""|BUNKERWEB_INSTANCES: "bunkerweb"|g' "$compose_file"; then
        echo -e "${GREEN}✓ BUNKERWEB_INSTANCES configured for autoconf${NC}"
    else
        echo -e "${YELLOW}⚠ Could not update BUNKERWEB_INSTANCES${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}✓ Template processing with release channel and API whitelist completed successfully${NC}"
    echo ""
    
    return 0
}

# Auto-detect FQDN if not provided
detect_fqdn() {
    if [[ -n "$FQDN" ]]; then
        echo -e "${GREEN}✓ Using provided FQDN: $FQDN${NC}"
        return 0
    fi
    
    echo -e "${BLUE}Auto-detecting FQDN...${NC}"
    
    local detected_fqdn=""
    
    # Try hostname -f
    if command -v hostname &> /dev/null; then
        detected_fqdn=$(hostname -f 2>/dev/null || echo "")
    fi
    
    # Try dnsdomainname + hostname
    if [[ -z "$detected_fqdn" ]] && command -v dnsdomainname &> /dev/null; then
        local domain=$(dnsdomainname 2>/dev/null || echo "")
        local hostname=$(hostname 2>/dev/null || echo "")
        if [[ -n "$domain" && -n "$hostname" ]]; then
            detected_fqdn="$hostname.$domain"
        fi
    fi
    
    # Check /etc/hostname
    if [[ -z "$detected_fqdn" && -f "/etc/hostname" ]]; then
        local hostname=$(cat /etc/hostname 2>/dev/null | head -1)
        if [[ "$hostname" == *.* ]]; then
            detected_fqdn="$hostname"
        fi
    fi
    
    # Validate detected FQDN
    if [[ -n "$detected_fqdn" && "$detected_fqdn" == *.* && "$detected_fqdn" != "localhost."* ]]; then
        FQDN="$detected_fqdn"
        echo -e "${GREEN}✓ FQDN auto-detected: $FQDN${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ Could not auto-detect valid FQDN${NC}"
        if [[ -n "$AUTO_CERT_TYPE" ]]; then
            echo -e "${RED}Error: FQDN is required for SSL certificate enrollment${NC}"
            exit 1
        else
            echo -e "${BLUE}ℹ Using localhost as fallback${NC}"
            FQDN="localhost"
            return 0
        fi
    fi
}

# Load configuration from BunkerWeb.conf if it exists
load_configuration() {
    local config_file="$INSTALL_DIR/BunkerWeb.conf"
    
    if [[ -f "$config_file" ]]; then
        echo -e "${BLUE}Loading configuration from $config_file...${NC}"
        source "$config_file"
        echo -e "${GREEN}✓ Configuration loaded${NC}"
        
        # Validate release channel
        if ! validate_release_channel "$RELEASE_CHANNEL"; then
            echo -e "${RED}Invalid RELEASE_CHANNEL in configuration file${NC}"
            exit 1
        fi
        
        # Simple validation for SSL configuration
        if [[ -n "$AUTO_CERT_TYPE" ]]; then
            if [[ "$AUTO_CERT_CONTACT" == "me@example.com" ]] || [[ "$AUTO_CERT_CONTACT" == *"@example.com"* ]] || [[ "$AUTO_CERT_CONTACT" == *"@yourdomain.com"* ]]; then
                if [[ "$FORCE_INSTALL" != "yes" ]]; then
                    echo -e "${RED}=================================================================================${NC}"
                    echo -e "${RED}                    CONFIGURATION VALIDATION FAILED                    ${NC}"
                    echo -e "${RED}=================================================================================${NC}"
                    echo ""
                    echo -e "${YELLOW}SSL certificates are enabled but using example email addresses.${NC}"
                    echo -e "${YELLOW}Please edit $config_file and change AUTO_CERT_CONTACT to a real email.${NC}"
                    echo ""
                    echo -e "${GREEN}To fix: nano $config_file${NC}"
                    echo -e "${GREEN}Change: AUTO_CERT_CONTACT=\"your-real-email@your-domain.com\"${NC}"
                    echo ""
                    echo -e "${RED}To bypass validation: add --force${NC}"
                    exit 1
                fi
            fi
        fi
    else
        echo -e "${YELLOW}No configuration file found - using defaults${NC}"
    fi
}

# Function to display usage
show_usage() {
    echo -e "${BLUE}Usage: $0 --type <autoconf|basic|integrated> [OPTIONS]${NC}"
    echo ""
    echo -e "${YELLOW}Required Options:${NC}"
    echo -e "  --type autoconf     Use template_autoconf_display.yml"
    echo -e "  --type basic        Use template_basic_display.yml"
    echo -e "  --type integrated   Use template_ui_integrated_display.yml"
    echo ""
    echo -e "${YELLOW}Optional Parameters:${NC}"
    echo -e "  --wizard            Enable setup wizard mode (default: automated setup)"
    echo -e "  --admin-name NAME   Set admin username"
    echo -e "  --FQDN DOMAIN       Set Fully Qualified Domain Name"
    echo -e "  --force             Skip configuration validation"
    echo ""
    echo -e "${YELLOW}Release Channel Options:${NC}"
    echo -e "  --release-channel latest   Use stable releases (recommended for production)"
    echo -e "  --release-channel RC       Use release candidates (for testing)"
    echo -e "  --release-channel nightly  Use development builds (hardcore testers only)"
    echo -e "  --release-channel X.Y.Z    Pin to specific version (e.g., 1.6.1, 1.5.4)"
    echo ""
    echo -e "${YELLOW}Network Configuration:${NC}"
    echo -e "  --private-networks \"NET1 NET2\"  Specify existing networks to avoid"
    echo -e "  --preferred-subnet SUBNET       Preferred Docker subnet"
    echo -e "  --no-network-check              Disable network conflict detection"
    echo ""
    echo -e "${YELLOW}Service Configuration:${NC}"
    echo -e "  --redis-enabled yes|no       Enable Redis support (default: yes)"
    echo -e "  --redis-password PASS        Set custom Redis password"
    echo ""
    echo -e "${YELLOW}SSL Certificate Options:${NC}"
    echo -e "  --AUTO_CERT LE|ZeroSSL       Enable automatic certificates"
    echo -e "  --AUTO_CERT_CONTACT EMAIL    Contact email for certificate registration"
    echo ""
    echo -e "${YELLOW}Help:${NC}"
    echo -e "  -h, --help          Show this help message"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo -e "  sudo $0 --type autoconf"
    echo -e "  sudo $0 --type autoconf --release-channel RC"
    echo -e "  sudo $0 --type autoconf --release-channel 1.6.1"
    echo -e "  sudo $0 --type autoconf --release-channel nightly --private-networks \"192.168.1.0/24\""
    echo -e "  sudo $0 --type autoconf --FQDN bunkerweb.example.com --release-channel latest"
    echo ""
}

# Parse command line arguments
parse_arguments() {
    DEPLOYMENT_TYPE=""
    FORCE_INSTALL="no"

    while [[ $# -gt 0 ]]; do
        case $1 in
            --type)
                DEPLOYMENT_TYPE="$2"
                shift 2
                ;;
            --wizard)
                SETUP_MODE="wizard"
                shift
                ;;
            --admin-name)
                ADMIN_USERNAME="$2"
                shift 2
                ;;
            --FQDN)
                FQDN="$2"
                shift 2
                ;;
            --release-channel)
                RELEASE_CHANNEL="$2"
                if ! validate_release_channel "$RELEASE_CHANNEL"; then
                    exit 1
                fi
                shift 2
                ;;
            --private-networks)
                PRIVATE_NETWORKS_ALREADY_IN_USE="$2"
                shift 2
                ;;
            --preferred-subnet)
                PREFERRED_DOCKER_SUBNET="$2"
                shift 2
                ;;
            --no-network-check)
                AUTO_DETECT_NETWORK_CONFLICTS="no"
                shift
                ;;
            --redis-enabled)
                REDIS_ENABLED="$2"
                shift 2
                ;;
            --redis-password)
                REDIS_PASSWORD="$2"
                shift 2
                ;;
            --AUTO_CERT)
                AUTO_CERT_TYPE="$2"
                shift 2
                ;;
            --AUTO_CERT_CONTACT)
                AUTO_CERT_CONTACT="$2"
                shift 2
                ;;
            --force)
                FORCE_INSTALL="yes"
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                echo -e "${RED}Error: Unknown option '$1'${NC}"
                show_usage
                exit 1
                ;;
        esac
    done

    # Validate that --type was provided
    if [[ -z "$DEPLOYMENT_TYPE" ]]; then
        echo -e "${RED}Error: --type parameter is required${NC}"
        echo ""
        show_usage
        exit 1
    fi

    # Validate deployment type and set template file
    case "$DEPLOYMENT_TYPE" in
        autoconf)
            TEMPLATE_FILE="template_autoconf_display.yml"
            DEPLOYMENT_NAME="Autoconf Display"
            ;;
        basic)
            TEMPLATE_FILE="template_basic_display.yml"
            DEPLOYMENT_NAME="Basic Display"
            ;;
        integrated)
            TEMPLATE_FILE="template_ui_integrated_display.yml"
            DEPLOYMENT_NAME="UI Integrated Display"
            ;;
        *)
            echo -e "${RED}Error: Invalid deployment type '$DEPLOYMENT_TYPE'${NC}"
            echo -e "${YELLOW}Valid types: autoconf, basic, integrated${NC}"
            exit 1
            ;;
    esac
}

# Create required directories with proper permissions
setup_directories() {
    echo -e "${BLUE}Creating directories...${NC}"
    
    local directories=(
        "$INSTALL_DIR/storage"
        "$INSTALL_DIR/database" 
        "$INSTALL_DIR/apps"
    )
    
    # Add Redis directory if enabled
    if [[ "$REDIS_ENABLED" == "yes" ]]; then
        directories+=("$INSTALL_DIR/redis")
    fi
    
    # Create directories
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
    done
    
    echo -e "${BLUE}Setting permissions for BunkerWeb containers...${NC}"
    
    # Set ownership for storage directory to nginx user (uid 101, gid 101)
    chown -R 101:101 "$INSTALL_DIR/storage"
    chmod -R 755 "$INSTALL_DIR/storage"
    echo -e "${GREEN}✓ Storage directory ownership set to nginx (101:101)${NC}"
    
    # Set ownership for database directory to mysql user (uid 999, gid 999) 
    chown -R 999:999 "$INSTALL_DIR/database"
    chmod -R 755 "$INSTALL_DIR/database"
    echo -e "${GREEN}✓ Database directory ownership set to mysql (999:999)${NC}"
    
    # Set ownership for Redis directory if enabled
    if [[ "$REDIS_ENABLED" == "yes" ]]; then
        chown -R 999:999 "$INSTALL_DIR/redis"
        chmod -R 755 "$INSTALL_DIR/redis"
        echo -e "${GREEN}✓ Redis directory ownership set to redis (999:999)${NC}"
    fi
    
    # Set general ownership for other files
    if [[ -n "$SUDO_USER" ]]; then
        local owner_user="$SUDO_USER"
        local owner_group=$(id -gn "$SUDO_USER")
        echo -e "${GREEN}Setting general ownership to: $owner_user:$owner_group${NC}"
        
        chown "$owner_user:$owner_group" "$INSTALL_DIR"
        chown "$owner_user:$owner_group" "$INSTALL_DIR"/*.yml 2>/dev/null || true
        chown "$owner_user:$owner_group" "$INSTALL_DIR"/*.sh 2>/dev/null || true
        chown "$owner_user:$owner_group" "$INSTALL_DIR/apps"
    else
        echo -e "${YELLOW}Running as root directly, keeping root ownership for config files${NC}"
    fi
    
    chmod 755 "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR/apps"
    echo -e "${GREEN}✓ All directories created and permissions properly set${NC}"
}

# Display setup summary
show_setup_summary() {
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}          Setup Complete!${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    echo -e "${YELLOW}Deployment Type:${NC} $DEPLOYMENT_NAME"
    echo -e "${YELLOW}Installation Directory:${NC} $INSTALL_DIR"
    echo -e "${YELLOW}Template Used:${NC} $TEMPLATE_FILE"
    echo -e "${YELLOW}Setup Mode:${NC} $SETUP_MODE"
    echo -e "${YELLOW}Domain (FQDN):${NC} $FQDN"
    echo -e "${YELLOW}Release Channel:${NC} $RELEASE_CHANNEL ($(get_image_tag_for_channel "$RELEASE_CHANNEL"))"
    echo -e "${YELLOW}Redis Enabled:${NC} $REDIS_ENABLED"
    echo -e "${YELLOW}Network Detection:${NC} $AUTO_DETECT_NETWORK_CONFLICTS"
    
    local detected_subnet=$(get_detected_subnet)
    if [[ -n "$detected_subnet" ]]; then
        echo -e "${YELLOW}Docker Subnet:${NC} $detected_subnet"
    fi
    
    if [[ -n "$AUTO_CERT_TYPE" ]]; then
        echo -e "${YELLOW}SSL Certificates:${NC} $AUTO_CERT_TYPE ($AUTO_CERT_CONTACT)"
    else
        echo -e "${YELLOW}SSL Certificates:${NC} Manual configuration"
    fi
    
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo -e "${GREEN}1. Start BunkerWeb: cd $INSTALL_DIR && docker compose up -d${NC}"
    
    if [[ $SETUP_MODE == "automated" ]]; then
        echo -e "${GREEN}2. Access web interface: http://$(hostname -I | awk '{print $1}')${NC}"
        echo -e "${GREEN}3. Login with credentials from: $INSTALL_DIR/credentials.txt${NC}"
    else
        echo -e "${GREEN}2. Complete setup wizard: http://$(hostname -I | awk '{print $1}')/setup${NC}"
        echo -e "${GREEN}3. Use pre-generated credentials from: $INSTALL_DIR/credentials.txt${NC}"
    fi
    
    if [[ -n "$AUTO_CERT_TYPE" ]]; then
        echo ""
        echo -e "${BLUE}SSL Certificate Information:${NC}"
        echo -e "${GREEN}• Let's Encrypt will automatically generate certificates for: $FQDN${NC}"
        echo -e "${GREEN}• Monitor certificate generation: docker compose logs -f bw-scheduler | grep -i cert${NC}"
        echo -e "${GREEN}• Check certificate status after a few minutes${NC}"
    fi
    
    # Show release channel specific warnings
    case "$RELEASE_CHANNEL" in
        "RC")
            echo ""
            echo -e "${YELLOW}⚠ RELEASE CANDIDATE WARNING:${NC}"
            echo -e "${YELLOW}• You are using pre-release software${NC}"
            echo -e "${YELLOW}• Some features may be experimental${NC}"
            echo -e "${YELLOW}• Monitor logs closely for any issues${NC}"
            ;;
        "nightly")
            echo ""
            echo -e "${RED}⚠ NIGHTLY BUILD WARNING:${NC}"
            echo -e "${RED}• You are using development builds - may be unstable!${NC}"
            echo -e "${RED}• Features may change or break between updates${NC}"
            echo -e "${RED}• DO NOT use in production environments${NC}"
            echo -e "${RED}• Report issues to the BunkerWeb development team${NC}"
            ;;
    esac
    
    echo ""
    echo -e "${BLUE}Troubleshooting:${NC}"
    echo -e "${GREEN}• Check logs: docker compose logs -f${NC}"
    echo -e "${GREEN}• Check API connectivity: docker compose logs bunkerweb | grep API${NC}"
    echo -e "${GREEN}• Monitor Let's Encrypt: docker compose logs bw-scheduler | grep -i lets${NC}"
    echo -e "${GREEN}• Check image versions: docker compose images${NC}"
    
    echo ""
    echo -e "${GREEN}Setup completed successfully!${NC}"
}

# Main execution function
main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}      BunkerWeb Enhanced Setup Script${NC}"
    echo -e "${BLUE}       with Release Channel Support${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
       echo -e "${RED}This script must be run as root${NC}"
       echo -e "${YELLOW}Please run: sudo $0 --type <autoconf|basic|integrated>${NC}"
       exit 1
    fi
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Source modular scripts
    if ! source_modules; then
        echo -e "${RED}✗ Failed to load required modules${NC}"
        exit 1
    fi
    
    # Load configuration
    load_configuration
    
    # Show release channel information
    show_channel_info "$RELEASE_CHANNEL"
    
    # Auto-detect FQDN
    detect_fqdn
    
    # Set paths
    local compose_file="$INSTALL_DIR/docker-compose.yml"
    local template_path="$INSTALL_DIR/$TEMPLATE_FILE"
    local creds_file="$INSTALL_DIR/credentials.txt"
    
    # Check if template file exists
    if [[ ! -f "$template_path" ]]; then
        echo -e "${RED}Error: Template file not found at $template_path${NC}"
        echo -e "${YELLOW}Available templates should be in: $INSTALL_DIR${NC}"
        exit 1
    fi
    
    # Display initial configuration
    echo -e "${GREEN}Configuration Summary:${NC}"
    echo -e "${GREEN}• Deployment Type: $DEPLOYMENT_NAME${NC}"
    echo -e "${GREEN}• Template File: $TEMPLATE_FILE${NC}"
    echo -e "${GREEN}• Setup Mode: $SETUP_MODE${NC}"
    echo -e "${GREEN}• Domain (FQDN): $FQDN${NC}"
    echo -e "${GREEN}• Release Channel: $RELEASE_CHANNEL ($(get_image_tag_for_channel "$RELEASE_CHANNEL"))${NC}"
    echo -e "${GREEN}• Redis Enabled: $REDIS_ENABLED${NC}"
    echo -e "${GREEN}• Network Detection: $AUTO_DETECT_NETWORK_CONFLICTS${NC}"
    echo ""
    
    # 1. Network Conflict Detection
    echo -e "${BLUE}Step 1: Network Conflict Detection${NC}"
    if ! detect_network_conflicts "$AUTO_DETECT_NETWORK_CONFLICTS" "$PRIVATE_NETWORKS_ALREADY_IN_USE" "$PREFERRED_DOCKER_SUBNET"; then
        echo -e "${RED}✗ Network detection failed${NC}"
        exit 1
    fi
    local docker_subnet=$(get_detected_subnet)
    
    # 2. Build Comprehensive API Whitelist
    echo -e "${BLUE}Step 2: API Whitelist Auto-Detection${NC}"
    local api_whitelist=$(build_comprehensive_api_whitelist "$docker_subnet")
    
    # 3. Credential Management  
    echo -e "${BLUE}Step 3: Credential Management${NC}"
    if ! manage_credentials "$creds_file" "$REDIS_ENABLED" "$DEPLOYMENT_NAME" "$TEMPLATE_FILE" "$SETUP_MODE" "$FQDN" "$SERVER_NAME" "$docker_subnet" "$PRIVATE_NETWORKS_ALREADY_IN_USE"; then
        echo -e "${RED}✗ Credential management failed${NC}"
        exit 1
    fi
    
    # Load the generated passwords
    eval "$(get_passwords)"
    
    # 4. Enhanced Template Processing with Release Channel and API Whitelist
    echo -e "${BLUE}Step 4: Enhanced Template Processing with Release Channel${NC}"
    if ! process_template_with_release_channel "$template_path" "$compose_file" "$MYSQL_PASSWORD" "$REDIS_PASSWORD" "$TOTP_SECRET" "$ADMIN_PASSWORD" "$FLASK_SECRET" "$ADMIN_USERNAME" "$AUTO_CERT_TYPE" "$AUTO_CERT_CONTACT" "$FQDN" "$SERVER_NAME" "$docker_subnet" "$SETUP_MODE" "$REDIS_ENABLED" "$api_whitelist" "$RELEASE_CHANNEL"; then
        echo -e "${RED}✗ Template processing failed${NC}"
        exit 1
    fi
    
    # 5. Directory Setup
    echo -e "${BLUE}Step 5: Directory Setup${NC}"
    setup_directories
    
    # 6. Final Summary
    show_setup_summary
}

# Run main function with all arguments
main "$@"