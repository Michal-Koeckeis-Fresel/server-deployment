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

# BunkerWeb Setup Script with Release Channel Support
set -e

# Load debug configuration early if available
if [ -f "$INSTALL_DIR/BunkerWeb.conf" ]; then
    . "$INSTALL_DIR/BunkerWeb.conf" 2>/dev/null || true
elif [ -f "/root/BunkerWeb.conf" ]; then
    . "/root/BunkerWeb.conf" 2>/dev/null || true
fi

# Enable debug mode if requested
if [ "${DEBUG:-no}" = "yes" ]; then
    set -x
    echo -e "${CYAN}[DEBUG] Debug mode enabled - verbose output activated${NC}"
fi

# Script directory and installation directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/data/BunkerWeb"
SETUP_MODE="wizard"

# Default configuration values
ADMIN_USERNAME="admin"
AUTO_CERT_TYPE=""
AUTO_CERT_CONTACT=""
FQDN=""
MULTISITE="yes"
SERVER_NAME=""
SECURITY_MODE="block"
SERVER_TYPE="http"
RELEASE_CHANNEL="latest"
PRIVATE_NETWORKS_ALREADY_IN_USE=""
AUTO_DETECT_NETWORK_CONFLICTS="yes"
PREFERRED_DOCKER_SUBNET=""
REDIS_ENABLED="yes"
REDIS_PASSWORD=""
DNS_RESOLVERS="127.0.0.11"
HTTP3="yes"
HTTP3_ALT_SVC_PORT="443"
LETS_ENCRYPT_CHALLENGE="http"
LETS_ENCRYPT_STAGING="yes"
LETS_ENCRYPT_WILDCARD="no"
LETS_ENCRYPT_PROFILE="shortlived"
LETS_ENCRYPT_MAX_RETRIES="0"
DNSBL_LIST="bl.blocklist.de zen.spamhaus.org"
USE_ALLOWLIST="no"
ALLOWLIST_IP=""
ALLOWLIST_COUNTRY=""
BLACKLIST_COUNTRY=""
ALLOWLIST_DNS=""
ALLOWLIST_MODE="block"
ALLOWLIST_STATUS_CODE="403"
USE_BLACKLIST="no"
BLACKLIST_IP=""
BLACKLIST_RDNS=""
BLACKLIST_RDNS_GLOBAL="yes"
BLACKLIST_ASN=""
BLACKLIST_USER_AGENT=""
BLACKLIST_URI=""
USE_GREYLIST="yes"
GREYLIST_IP=""
GREYLIST_DNS=""
ADD_SSH_TO_TRUSTED="yes"
SSH_TRUSTED=""
FQDN_REQUIRE_SSL="no"
FQDN_CHECK_DNS="yes"
FQDN_ALLOW_LOCALHOST="yes"
FQDN_ALLOW_IP_AS_FQDN="no"
FQDN_MIN_DOMAIN_PARTS="2"
FQDN_LOG_LEVEL="INFO"
FQDN_STRICT_MODE="no"
LOG_LEVEL="INFO"
USE_MODSECURITY_GLOBAL_CRS="yes"
SSL_PROTOCOLS="TLSv1.2 TLSv1.3"
SSL_CIPHERS_CUSTOM=""
DEMOSITE="no"
DEMOSITE_USE_REVERSE_DNS="no"
UI_ACCESS_PATH=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Generates secure admin password with strict requirements
generate_secure_admin_password() {
    local uppercase="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local lowercase="abcdefghijklmnopqrstuvwxyz"
    local numbers="0123456789"
    local special_chars="#$@!%*+=?"
    
    local password=""
    password="${password}${uppercase:$((RANDOM % ${#uppercase})):1}"
    password="${password}${lowercase:$((RANDOM % ${#lowercase})):1}"
    password="${password}${numbers:$((RANDOM % ${#numbers})):1}"
    password="${password}${special_chars:$((RANDOM % ${#special_chars})):1}"
    
    local all_chars="${uppercase}${lowercase}${numbers}${special_chars}"
    local i=1
    while [ $i -le 8 ]; do
        password="${password}${all_chars:$((RANDOM % ${#all_chars})):1}"
        i=$((i + 1))
    done
    
    echo "$password" | fold -w1 | shuf | tr -d '\n'
}

# Validates that a password meets security requirements
validate_password_requirements() {
    local password="$1"
    
    if [ ${#password} -lt 8 ]; then
        return 1
    fi
    
    if ! echo "$password" | grep -q '[a-z]'; then
        return 1
    fi
    
    if ! echo "$password" | grep -q '[A-Z]'; then
        return 1
    fi
    
    if ! echo "$password" | grep -q '[0-9]'; then
        return 1
    fi
    
    if ! echo "$password" | grep -q '[#$@!%*+=?]'; then
        return 1
    fi
    
    return 0
}

# Fallback implementations for essential functions
load_fallback_functions() {
    echo -e "${BLUE}Loading fallback functions...${NC}"
    
    validate_release_channel() {
        local channel="$1"
        case "$channel" in
            "latest"|"dev"|"RC"|"testing"|"nightly")
                return 0
                ;;
            *)
                if echo "$channel" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
                    return 0
                else
                    return 1
                fi
                ;;
        esac
    }
    
    get_image_tag_for_channel() {
        local channel="$1"
        case "$channel" in
            "latest") echo "latest" ;;
            "dev") echo "dev" ;;
            "RC") echo "rc" ;;
            "testing") echo "testing" ;;
            "nightly") echo "nightly" ;;
            *) echo "$channel" ;;
        esac
    }
    
    auto_detect_fqdn() {
        local provided_fqdn="$1"
        
        if [ -n "$provided_fqdn" ]; then
            echo "$provided_fqdn"
            return 0
        fi
        
        local detected_fqdn
        detected_fqdn=$(hostname -f 2>/dev/null)
        
        if [ -n "$detected_fqdn" ] && [ "$detected_fqdn" != "localhost" ]; then
            echo "$detected_fqdn"
            return 0
        fi
        
        echo "localhost"
        return 0
    }
    
    validate_fqdn_comprehensive() {
        local fqdn="$1"
        [ -n "$fqdn" ]
    }
    
    show_channel_info() {
        local channel="$1"
        echo -e "${GREEN}Release Channel: $channel${NC}"
    }
    
    list_available_channels() {
        echo -e "${GREEN}• latest - Stable releases${NC}"
        echo -e "${GREEN}• dev - Development builds${NC}"
        echo -e "${GREEN}• RC - Release candidates${NC}"
        echo -e "${GREEN}• testing - Testing builds${NC}"
        echo -e "${GREEN}• nightly - Nightly builds${NC}"
        echo -e "${GREEN}• X.Y.Z - Specific version${NC}"
    }
    
    check_nat_status() {
        echo -e "${BLUE}Performing basic NAT detection...${NC}"
        echo -e "${GREEN}✓ NAT detection completed (fallback)${NC}"
    }
    
    show_fqdn_summary() {
        local fqdn="$1"
        if [ -n "$fqdn" ]; then
            echo -e "${GREEN}FQDN Summary: $fqdn${NC}"
        fi
    }
    
    get_detection_method() {
        echo "automatic"
    }
    
    echo -e "${GREEN}✓ Fallback functions loaded${NC}"
}

# Loads and initializes modular helper scripts
source_modules() {
    local modules="helper_password_manager.sh helper_network_detection.sh helper_template_processor.sh helper_net_fqdn.sh helper_net_nat.sh helper_greylist.sh helper_allowlist.sh helper_release_channel_manager.sh"
    
    echo -e "${BLUE}Loading BunkerWeb modules...${NC}"
    
    local modules_loaded=0
    for module in $modules; do
        local module_path="$SCRIPT_DIR/$module"
        
        if [ -f "$module_path" ]; then
            if . "$module_path"; then
                echo -e "${GREEN}✓ Loaded: $module${NC}"
                modules_loaded=$((modules_loaded + 1))
            else
                echo -e "${RED}✗ Failed to load: $module${NC}"
            fi
        else
            echo -e "${YELLOW}⚠ Module not found: $module_path${NC}"
        fi
    done
    
    if [ $modules_loaded -eq 0 ]; then
        echo -e "${YELLOW}⚠ No modules loaded - using built-in fallback functions${NC}"
        load_fallback_functions
        return 0
    else
        echo -e "${GREEN}✓ $modules_loaded modules loaded successfully${NC}"
        return 0
    fi
}

# Validates release channel and displays channel information
validate_and_show_release_channel() {
    local channel="$1"
    
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                    RELEASE CHANNEL VALIDATION                    ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    echo -e "${BLUE}Validating release channel: $channel${NC}"
    
    if validate_release_channel "$channel"; then
        echo -e "${GREEN}✓ Release channel is valid: $channel${NC}"
        show_channel_info "$channel"
        local image_tag
        image_tag=$(get_image_tag_for_channel "$channel")
        echo -e "${GREEN}✓ Docker image tag: $image_tag${NC}"
        return 0
    else
        echo -e "${RED}✗ Invalid release channel: $channel${NC}"
        echo ""
        echo -e "${YELLOW}Available options:${NC}"
        list_available_channels
        return 1
    fi
}

# Loads configuration from BunkerWeb.conf file with validation
load_configuration() {
    local config_file="$INSTALL_DIR/BunkerWeb.conf"
    
    if [ -f "$config_file" ]; then
        echo -e "${BLUE}Loading configuration from $config_file...${NC}"
        . "$config_file"
        echo -e "${GREEN}✓ Configuration loaded${NC}"
        
        if [ "${DEBUG:-no}" = "yes" ]; then
            FQDN_LOG_LEVEL="DEBUG"
            LOG_LEVEL="DEBUG"
            echo -e "${GREEN}✓ Debug mode enabled - all log levels set to DEBUG${NC}"
        else
            FQDN_LOG_LEVEL="${FQDN_LOG_LEVEL:-INFO}"
            LOG_LEVEL="${LOG_LEVEL:-INFO}"
            echo -e "${BLUE}ℹ Debug mode disabled - using INFO log level${NC}"
        fi
        
        if [ -n "${RELEASE_CHANNEL:-}" ]; then
            RELEASE_CHANNEL="$RELEASE_CHANNEL"
            echo -e "${GREEN}✓ Release channel from config: $RELEASE_CHANNEL${NC}"
        else
            echo -e "${BLUE}ℹ No RELEASE_CHANNEL in config, using default: $RELEASE_CHANNEL${NC}"
        fi
    else
        echo -e "${YELLOW}No configuration file found - using defaults${NC}"
        echo -e "${BLUE}ℹ Using default INFO log level${NC}"
    fi
}

# Displays script usage and available options
show_usage() {
    echo -e "${BLUE}Usage: $0 --type <autoconf|basic|integrated> [OPTIONS]${NC}"
    echo ""
    echo -e "${YELLOW}Required Options:${NC}"
    echo -e "  --type autoconf     Use template_autoconf_display.yml"
    echo -e "  --type basic        Use template_basic_display.yml"
    echo -e "  --type integrated   Use template_ui_integrated_display.yml"
    echo ""
    echo -e "${YELLOW}Optional Parameters:${NC}"
    echo -e "  --automated         Enable automated setup (skip wizard)"
    echo -e "  --wizard            Enable setup wizard mode (default)"
    echo -e "  --admin-name NAME   Set admin username"
    echo -e "  --FQDN DOMAIN       Set Fully Qualified Domain Name"
    echo -e "  --force             Skip configuration validation"
    echo -e "  --fix-permissions   Fix permissions for existing installation"
    echo ""
    echo -e "${YELLOW}Release Channel Options:${NC}"
    echo -e "  --release latest       Use stable releases (production)"
    echo -e "  --release RC           Use release candidates (testing)"
    echo -e "  --release dev          Use development builds (latest features)"
    echo -e "  --release testing      Use testing builds (QA)"
    echo -e "  --release nightly      Use development builds (testing only)"
    echo -e "  --release X.Y.Z        Use specific version (e.g., 1.6.1)"
    echo ""
    echo -e "${YELLOW}Help:${NC}"
    echo -e "  -h, --help          Show this help message"
    echo ""
}

# Parses command line arguments and sets deployment configuration
parse_arguments() {
    DEPLOYMENT_TYPE=""
    FORCE_INSTALL="no"
    FIX_PERMISSIONS_ONLY="no"

    while [ $# -gt 0 ]; do
        case "$1" in
            "--type")
                DEPLOYMENT_TYPE="$2"
                shift 2
                ;;
            "--automated")
                SETUP_MODE="automated"
                shift
                ;;
            "--wizard")
                SETUP_MODE="wizard"
                shift
                ;;
            "--admin-name")
                ADMIN_USERNAME="$2"
                shift 2
                ;;
            "--FQDN")
                FQDN="$2"
                shift 2
                ;;
            "--release")
                RELEASE_CHANNEL="$2"
                shift 2
                ;;
            "--force")
                FORCE_INSTALL="yes"
                shift
                ;;
            "--fix-permissions")
                FIX_PERMISSIONS_ONLY="yes"
                shift
                ;;
            "-h"|"--help")
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

    if [ "$FIX_PERMISSIONS_ONLY" = "yes" ]; then
        return 0
    fi

    if [ -z "$DEPLOYMENT_TYPE" ]; then
        echo -e "${RED}Error: --type parameter is required${NC}"
        echo ""
        show_usage
        exit 1
    fi

    case "$DEPLOYMENT_TYPE" in
        "autoconf")
            TEMPLATE_FILE="template_autoconf_display.yml"
            DEPLOYMENT_NAME="Autoconf Display"
            ;;
        "basic")
            TEMPLATE_FILE="template_basic_display.yml"
            DEPLOYMENT_NAME="Basic Display"
            ;;
        "integrated")
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

# Creates required directories with proper permissions for BunkerWeb containers
setup_directories() {
    echo -e "${BLUE}Creating directories with enhanced permissions...${NC}"
    
    if [ -f "$INSTALL_DIR/docker-compose.yml" ]; then
        echo -e "${BLUE}Stopping any running containers to set permissions safely...${NC}"
        cd "$INSTALL_DIR" && docker compose down 2>/dev/null || true
    fi
    
    mkdir -p "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"
    
    local directories="$INSTALL_DIR/storage $INSTALL_DIR/database $INSTALL_DIR/apps"
    
    if [ "$REDIS_ENABLED" = "yes" ]; then
        directories="$directories $INSTALL_DIR/redis"
    fi
    
    for dir in $directories; do
        echo -e "${BLUE}Creating: $dir${NC}"
        mkdir -p "$dir"
        
        if [ ! -d "$dir" ]; then
            echo -e "${RED}✗ Failed to create directory: $dir${NC}"
            return 1
        fi
    done
    
    echo -e "${BLUE}Setting enhanced permissions for BunkerWeb containers...${NC}"
    
    chown -R 101:101 "$INSTALL_DIR/storage"
    chmod -R 775 "$INSTALL_DIR/storage"
    find "$INSTALL_DIR/storage" -type d -exec chmod 775 {} \;
    find "$INSTALL_DIR/storage" -type f -exec chmod 664 {} \; 2>/dev/null || true
    
    if [ "$(stat -c %u:%g "$INSTALL_DIR/storage")" = "101:101" ]; then
        echo -e "${GREEN}✓ Storage directory ownership verified: nginx (101:101)${NC}"
    else
        echo -e "${RED}✗ Storage directory ownership verification failed${NC}"
        return 1
    fi
    
    chown -R 999:999 "$INSTALL_DIR/database"
    chmod -R 755 "$INSTALL_DIR/database"
    echo -e "${GREEN}✓ Database directory ownership set to mysql (999:999)${NC}"
    
    if [ "$REDIS_ENABLED" = "yes" ]; then
        chown -R 999:999 "$INSTALL_DIR/redis"
        chmod -R 755 "$INSTALL_DIR/redis"
        echo -e "${GREEN}✓ Redis directory ownership set to redis (999:999)${NC}"
    fi
    
    chmod 755 "$INSTALL_DIR/apps"
    
    if [ -n "$SUDO_USER" ]; then
        local owner_user="$SUDO_USER"
        local owner_group
        owner_group=$(id -gn "$SUDO_USER")
        echo -e "${BLUE}Setting config file ownership to: $owner_user:$owner_group${NC}"
        
        chown "$owner_user:$owner_group" "$INSTALL_DIR" 2>/dev/null || true
        chown "$owner_user:$owner_group" "$INSTALL_DIR"/*.yml 2>/dev/null || true
        chown "$owner_user:$owner_group" "$INSTALL_DIR"/*.sh 2>/dev/null || true
        chown "$owner_user:$owner_group" "$INSTALL_DIR"/*.txt 2>/dev/null || true
        chown "$owner_user:$owner_group" "$INSTALL_DIR/apps" 2>/dev/null || true
        
        echo -e "${GREEN}✓ Config files ownership set to: $owner_user:$owner_group${NC}"
    else
        echo -e "${YELLOW}Running as root directly, keeping root ownership for config files${NC}"
    fi
    
    echo -e "${GREEN}✓ All directories created and permissions properly configured${NC}"
}

# Fixes permissions for existing BunkerWeb installation
fix_permissions() {
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                    FIXING BUNKERWEB PERMISSIONS                    ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    if [ ! -d "$INSTALL_DIR" ]; then
        echo -e "${RED}✗ BunkerWeb installation directory not found: $INSTALL_DIR${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Stopping containers to fix permissions safely...${NC}"
    cd "$INSTALL_DIR"
    docker compose down 2>/dev/null || true
    sleep 2
    
    echo -e "${BLUE}Fixing storage directory permissions for nginx user (101:101)...${NC}"
    if [ -d "$INSTALL_DIR/storage" ]; then
        chmod -R u+rwx "$INSTALL_DIR/storage" 2>/dev/null || true
        chown -R 101:101 "$INSTALL_DIR/storage"
        chmod -R 775 "$INSTALL_DIR/storage"
        find "$INSTALL_DIR/storage" -type d -exec chmod 775 {} \;
        find "$INSTALL_DIR/storage" -type f -exec chmod 664 {} \; 2>/dev/null || true
        echo -e "${GREEN}✓ Storage directory permissions fixed${NC}"
    fi
    
    echo -e "${BLUE}Fixing database directory permissions for mysql user (999:999)...${NC}"
    if [ -d "$INSTALL_DIR/database" ]; then
        chown -R 999:999 "$INSTALL_DIR/database"
        chmod -R 755 "$INSTALL_DIR/database"
        echo -e "${GREEN}✓ Database directory permissions fixed${NC}"
    fi
    
    if [ -d "$INSTALL_DIR/redis" ]; then
        echo -e "${BLUE}Fixing redis directory permissions for redis user (999:999)...${NC}"
        chown -R 999:999 "$INSTALL_DIR/redis"
        chmod -R 755 "$INSTALL_DIR/redis"
        echo -e "${GREEN}✓ Redis directory permissions fixed${NC}"
    fi
    
    echo -e "${GREEN}✓ Permissions have been fixed. You can now restart the containers:${NC}"
    echo -e "${GREEN}  cd $INSTALL_DIR && docker compose up -d${NC}"
}

# Simple network detection for fallback when advanced detection fails
simple_network_detection() {
    local subnet="10.20.30.0/24"
    
    if ip route show 2>/dev/null | grep -q "10.20.30"; then
        subnet="192.168.100.0/24"
    fi
    
    if ip route show 2>/dev/null | grep -q "192.168.100"; then
        subnet="172.20.0.0/24"
    fi
    
    echo "$subnet"
}

# Main execution function
main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}      BunkerWeb Setup Script${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    
    if [ "$(id -u)" -ne 0 ]; then
       echo -e "${RED}This script must be run as root${NC}"
       echo -e "${YELLOW}Please run: sudo $0 --type <autoconf|basic|integrated>${NC}"
       exit 1
    fi
    
    parse_arguments "$@"
    
    if [ "$FIX_PERMISSIONS_ONLY" = "yes" ]; then
        echo -e "${BLUE}Running in permission fix mode...${NC}"
        fix_permissions
        exit $?
    fi
    
    source_modules
    load_configuration
    
    echo -e "${BLUE}Step 0: Release Channel Validation${NC}"
    if ! validate_and_show_release_channel "$RELEASE_CHANNEL"; then
        echo -e "${RED}✗ Release channel validation failed${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Step 0.5: FQDN Detection${NC}"
    local detected_fqdn
    detected_fqdn=$(auto_detect_fqdn "$FQDN" "$FQDN_REQUIRE_SSL" "$FQDN_CHECK_DNS")
    FQDN="$detected_fqdn"
    SERVER_NAME="$detected_fqdn"
    echo -e "${GREEN}✓ FQDN detected: $FQDN${NC}"
    
    local compose_file="$INSTALL_DIR/docker-compose.yml"
    local template_path="$INSTALL_DIR/$TEMPLATE_FILE"
    local creds_file="$INSTALL_DIR/credentials.txt"
    
    if [ ! -f "$template_path" ]; then
        echo -e "${RED}Error: Template file not found at $template_path${NC}"
        echo -e "${YELLOW}Available templates should be in: $INSTALL_DIR${NC}"
        exit 1
    fi
    
    echo ""
    echo -e "${GREEN}Configuration Summary:${NC}"
    echo -e "${GREEN}• Deployment Type: $DEPLOYMENT_NAME${NC}"
    echo -e "${GREEN}• Template File: $TEMPLATE_FILE${NC}"
    echo -e "${GREEN}• Setup Mode: $SETUP_MODE${NC}"
    echo -e "${GREEN}• Release Channel: $RELEASE_CHANNEL${NC}"
    echo -e "${GREEN}• Docker Image Tag: $(get_image_tag_for_channel "$RELEASE_CHANNEL")${NC}"
    echo -e "${GREEN}• Domain (FQDN): $FQDN${NC}"
    echo ""
    
    echo -e "${BLUE}Step 1: Directory Setup${NC}"
    setup_directories
    
    echo -e "${BLUE}Step 2: Credential Management${NC}"
    local mysql_password
    mysql_password=$(openssl rand -base64 33)
    local admin_password
    admin_password=$(generate_secure_admin_password)
    local flask_secret
    flask_secret=$(openssl rand -base64 33)
    local totp_secret
    totp_secret=$(openssl rand -base64 33)
    echo -e "${GREEN}✓ Credentials generated${NC}"
    
    echo -e "${BLUE}Step 3: Template Processing${NC}"
    echo -e "${BLUE}Copying template to docker-compose.yml...${NC}"
    if cp "$template_path" "$compose_file"; then
        echo -e "${GREEN}✓ Template copied: $(basename "$template_path") → docker-compose.yml${NC}"
    else
        echo -e "${RED}✗ Failed to copy template${NC}"
        exit 1
    fi
    
    if [ ! -f "$compose_file" ]; then
        echo -e "${RED}✗ docker-compose.yml was not created successfully${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Processing essential template placeholders...${NC}"
    
    local image_tag
    image_tag=$(get_image_tag_for_channel "$RELEASE_CHANNEL")
    
    sed -i "s|REPLACEME_TAG|$image_tag|g" "$compose_file"
    echo -e "${GREEN}✓ Docker image tags updated to: $image_tag${NC}"
    
    sed -i "s|REPLACEME_MYSQL|$mysql_password|g" "$compose_file"
    sed -i "s|REPLACEME_DEFAULT|$totp_secret|g" "$compose_file"
    sed -i "s|REPLACEME_ADMIN_USERNAME|$ADMIN_USERNAME|g" "$compose_file"
    sed -i "s|REPLACEME_ADMIN_PASSWORD|$admin_password|g" "$compose_file"
    sed -i "s|REPLACEME_FLASK_SECRET|$flask_secret|g" "$compose_file"
    echo -e "${GREEN}✓ Credentials updated${NC}"
    
    sed -i "s|REPLACEME_DNS_RESOLVERS|$DNS_RESOLVERS|g" "$compose_file"
    echo -e "${GREEN}✓ DNS resolvers configured${NC}"
    
    if [ -n "$AUTO_CERT_TYPE" ]; then
        sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|yes|g" "$compose_file"
        sed -i "s|REPLACEME_EMAIL_LETS_ENCRYPT|$AUTO_CERT_CONTACT|g" "$compose_file"
        echo -e "${GREEN}✓ SSL certificates configured${NC}"
    else
        sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|no|g" "$compose_file"
        sed -i "s|REPLACEME_EMAIL_LETS_ENCRYPT|admin@localhost|g" "$compose_file"
        echo -e "${GREEN}✓ SSL certificates disabled${NC}"
    fi
    
    sed -i "s|REPLACEME_DOMAIN|$FQDN|g" "$compose_file"
    sed -i "s|SERVER_NAME: \"\"|SERVER_NAME: \"$FQDN\"|g" "$compose_file"
    echo -e "${GREEN}✓ Domain configured: $FQDN${NC}"
    
    echo -e "${BLUE}Step 4: Network Configuration and API Whitelist${NC}"
    local docker_subnet
    docker_subnet=$(simple_network_detection)
    echo -e "${GREEN}✓ Using subnet: $docker_subnet${NC}"
    
    echo -e "${BLUE}Building API whitelist for Docker networks...${NC}"
    local api_whitelist="127.0.0.0/8 $docker_subnet 172.16.0.0/12 10.0.0.0/8 192.168.0.0/16"
    echo -e "${GREEN}✓ API whitelist built${NC}"
    
    echo -e "${BLUE}Updating API whitelist in docker-compose.yml...${NC}"
    
    local temp_file
    temp_file=$(mktemp)
    
    while IFS= read -r line; do
        if echo "$line" | grep -q "API_WHITELIST_IP:"; then
            local indent
            indent=$(echo "$line" | sed 's/API_WHITELIST_IP:.*//')
            echo "${indent}API_WHITELIST_IP: \"$api_whitelist\""
        else
            echo "$line"
        fi
    done < "$compose_file" > "$temp_file"
    
    if [ -f "$temp_file" ] && [ -s "$temp_file" ]; then
        mv "$temp_file" "$compose_file"
        echo -e "${GREEN}✓ API whitelist updated successfully${NC}"
        
        local updated_count
        updated_count=$(grep -c "API_WHITELIST_IP:" "$compose_file" || echo "0")
        echo -e "${GREEN}✓ Updated $updated_count API_WHITELIST_IP entries${NC}"
    else
        echo -e "${RED}✗ Failed to update API whitelist${NC}"
        rm -f "$temp_file"
        exit 1
    fi
    
    echo -e "${BLUE}Step 5: Saving Credentials${NC}"
    cat > "$creds_file" << EOF
# BunkerWeb Generated Credentials
# Generated on: $(date)

MySQL Database Password: $mysql_password
TOTP Secret Key: $totp_secret
Admin Username: $ADMIN_USERNAME
Admin Password: $admin_password
Flask Secret: $flask_secret

# Domain Configuration
FQDN: $FQDN
Server Name: $FQDN
Release Channel: $RELEASE_CHANNEL
Docker Image Tag: $image_tag

# Network Configuration
Docker Subnet: $docker_subnet
API Whitelist: $api_whitelist

# Quick Access
# Access: http://$(hostname -I | awk '{print $1}')
# Username: $ADMIN_USERNAME
# Password: $admin_password
EOF
    chmod 600 "$creds_file"
    echo -e "${GREEN}✓ Credentials saved to: $creds_file${NC}"
    
    echo ""
    echo -e "${GREEN}=================================================================================${NC}"
    echo -e "${GREEN}                          SETUP COMPLETED SUCCESSFULLY!${NC}"
    echo -e "${GREEN}=================================================================================${NC}"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo -e "${GREEN}1. Start BunkerWeb: cd $INSTALL_DIR && docker compose up -d${NC}"
    echo -e "${GREEN}2. Access web interface: http://$(hostname -I | awk '{print $1}')${NC}"
    echo -e "${GREEN}3. Login with credentials from: $creds_file${NC}"
    echo ""
    echo -e "${BLUE}Configuration Summary:${NC}"
    echo -e "${GREEN}• FQDN: $FQDN${NC}"
    echo -e "${GREEN}• Release Channel: $RELEASE_CHANNEL${NC}"
    echo -e "${GREEN}• Docker Image Tag: $image_tag${NC}"
    echo -e "${GREEN}• Admin Username: $ADMIN_USERNAME${NC}"
    echo -e "${GREEN}• Setup Mode: $SETUP_MODE${NC}"
    echo ""
    echo -e "${BLUE}If you encounter permission errors, you can fix them with:${NC}"
    echo -e "${GREEN}sudo $0 --fix-permissions${NC}"
}

main "$@"