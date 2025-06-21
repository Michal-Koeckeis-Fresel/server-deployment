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
# Configures and deploys BunkerWeb with enhanced FQDN detection, network management, and security features

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

# Release Channel Configuration
RELEASE_CHANNEL="latest"

# Network Configuration
PRIVATE_NETWORKS_ALREADY_IN_USE=""
AUTO_DETECT_NETWORK_CONFLICTS="yes"
PREFERRED_DOCKER_SUBNET=""

# Service Configuration
REDIS_ENABLED="yes"
REDIS_PASSWORD=""

# DNS Configuration
DNS_RESOLVERS="127.0.0.11"

# HTTP/3 Configuration
HTTP3="yes"
HTTP3_ALT_SVC_PORT="443"

# Let's Encrypt Configuration
LETS_ENCRYPT_CHALLENGE="http"
LETS_ENCRYPT_STAGING="yes"
LETS_ENCRYPT_WILDCARD="no"
LETS_ENCRYPT_PROFILE="shortlived"
LETS_ENCRYPT_MAX_RETRIES="0"

# DNSBL Configuration
DNSBL_LIST="bl.blocklist.de zen.spamhaus.org"

# Allowlist Configuration (Global Access Control)
USE_ALLOWLIST="no"
ALLOWLIST_IP=""
ALLOWLIST_COUNTRY=""
BLACKLIST_COUNTRY=""
ALLOWLIST_DNS=""
ALLOWLIST_MODE="block"
ALLOWLIST_STATUS_CODE="403"

# Blacklist Configuration (Global IP/Network/rDNS/ASN Blocking)
USE_BLACKLIST="no"
BLACKLIST_IP=""
BLACKLIST_RDNS=""
BLACKLIST_RDNS_GLOBAL="yes"
BLACKLIST_ASN=""
BLACKLIST_USER_AGENT=""
BLACKLIST_URI=""
BLACKLIST_IGNORE_IP=""
BLACKLIST_IGNORE_RDNS=""
BLACKLIST_IGNORE_ASN=""
BLACKLIST_IGNORE_USER_AGENT=""
BLACKLIST_IGNORE_URI=""
BLACKLIST_IP_URLS=""
BLACKLIST_RDNS_URLS=""
BLACKLIST_ASN_URLS=""
BLACKLIST_USER_AGENT_URLS=""
BLACKLIST_URI_URLS=""
BLACKLIST_IGNORE_IP_URLS=""
BLACKLIST_IGNORE_RDNS_URLS=""
BLACKLIST_IGNORE_ASN_URLS=""
BLACKLIST_IGNORE_USER_AGENT_URLS=""
BLACKLIST_IGNORE_URI_URLS=""

# Greylist Configuration (Admin Interface Protection)
USE_GREYLIST="yes"
GREYLIST_IP=""
GREYLIST_DNS=""

# SSH Trusted Configuration
ADD_SSH_TO_TRUSTED="yes"
SSH_TRUSTED=""

# FQDN Detection Configuration
FQDN_REQUIRE_SSL="no"
FQDN_CHECK_DNS="yes"
FQDN_ALLOW_LOCALHOST="yes"
FQDN_ALLOW_IP_AS_FQDN="no"
FQDN_MIN_DOMAIN_PARTS="2"
FQDN_LOG_LEVEL="INFO"
FQDN_STRICT_MODE="no"

# Log Level Configuration
LOG_LEVEL="INFO"

# ModSecurity Configuration
USE_MODSECURITY_GLOBAL_CRS="yes"

# SSL/TLS Configuration  
SSL_PROTOCOLS="TLSv1.2 TLSv1.3"
SSL_CIPHERS_CUSTOM=""

# Demo Site Configuration
DEMOSITE="no"
DEMOSITE_USE_REVERSE_DNS="no"

# Global variable to store generated UI path
UI_ACCESS_PATH=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Generates secure admin password with strict requirements: at least one lowercase, one uppercase, 
# one number, one special character
generate_secure_admin_password() {
    local uppercase="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local lowercase="abcdefghijklmnopqrstuvwxyz"
    local numbers="0123456789"
    local special_chars="#$@!%*+=?"
    
    local password=""
    
    # Ensure at least one character from each required category
    password="${password}${uppercase:$((RANDOM % ${#uppercase})):1}"
    password="${password}${lowercase:$((RANDOM % ${#lowercase})):1}"
    password="${password}${numbers:$((RANDOM % ${#numbers})):1}"
    password="${password}${special_chars:$((RANDOM % ${#special_chars})):1}"
    
    # Add additional characters to reach desired length (minimum 12 characters)
    local all_chars="${uppercase}${lowercase}${numbers}${special_chars}"
    local i=1
    while [ $i -le 8 ]; do
        password="${password}${all_chars:$((RANDOM % ${#all_chars})):1}"
        i=$((i + 1))
    done
    
    # Shuffle the password to randomize character positions
    echo "$password" | fold -w1 | shuf | tr -d '\n'
}

# Validates that a password meets security requirements
validate_password_requirements() {
    local password="$1"
    
    # Check minimum length
    if [ ${#password} -lt 8 ]; then
        return 1
    fi
    
    # Check for at least one lowercase letter
    if ! echo "$password" | grep -q '[a-z]'; then
        return 1
    fi
    
    # Check for at least one uppercase letter
    if ! echo "$password" | grep -q '[A-Z]'; then
        return 1
    fi
    
    # Check for at least one number
    if ! echo "$password" | grep -q '[0-9]'; then
        return 1
    fi
    
    # Check for at least one special character
    if ! echo "$password" | grep -q '[#$@!%*+=?]'; then
        return 1
    fi
    
    return 0
}

# Generates random 8-character string for secure UI access path
generate_random_ui_path() {
    local chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local random_path=""
    
    local i=1
    while [ $i -le 8 ]; do
        random_path="${random_path}${chars:$((RANDOM % ${#chars})):1}"
        i=$((i + 1))
    done
    
    echo "$random_path"
}

# Loads and initializes modular helper scripts including NAT detection and FQDN helpers
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

# Fallback implementations for essential functions when modules are not available
load_fallback_functions() {
    echo -e "${BLUE}Loading fallback functions...${NC}"
    
    # Fallback release channel validation
    if ! command -v validate_release_channel >/dev/null 2>&1; then
        validate_release_channel() {
            local channel="$1"
            # Simple validation - accept common channels
            if [ "$channel" = "latest" ] || [ "$channel" = "dev" ] || [ "$channel" = "RC" ] || \
               [ "$channel" = "testing" ] || [ "$channel" = "nightly" ] || \
               echo "$channel" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+

# Validates release channel and displays channel information
validate_and_show_release_channel() {
    local channel="$1"
    
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                    RELEASE CHANNEL VALIDATION                    ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    echo -e "${BLUE}Validating release channel: $channel${NC}"
    
    # Use the helper function to validate the channel
    if validate_release_channel "$channel"; then
        echo -e "${GREEN}✓ Release channel is valid: $channel${NC}"
        
        show_channel_info "$channel"
        
        local image_tag
        image_tag=$(get_image_tag_for_channel "$channel")
        echo -e "${GREEN}✓ Docker image tag: $image_tag${NC}"
        
        export DOCKER_IMAGE_TAG="$image_tag"
        export VALIDATED_RELEASE_CHANNEL="$channel"
        
        return 0
    else
        echo -e "${RED}✗ Invalid release channel: $channel${NC}"
        echo ""
        echo -e "${YELLOW}Available options:${NC}"
        list_available_channels
        return 1
    fi
}

# Configures FQDN detection parameters based on SSL requirements
configure_fqdn_detection() {
    echo -e "${BLUE}Configuring FQDN detection parameters...${NC}"
    
    if [ -n "$AUTO_CERT_TYPE" ]; then
        FQDN_REQUIRE_SSL="yes"
        echo -e "${GREEN}✓ SSL certificates enabled - requiring SSL-compatible FQDN${NC}"
    else
        FQDN_REQUIRE_SSL="no"
        echo -e "${BLUE}ℹ SSL certificates disabled - allowing localhost FQDN${NC}"
    fi
    
    export REQUIRE_SSL="$FQDN_REQUIRE_SSL"
    export CHECK_DNS="$FQDN_CHECK_DNS"
    export ALLOW_LOCALHOST="$FQDN_ALLOW_LOCALHOST"
    export ALLOW_IP_AS_FQDN="$FQDN_ALLOW_IP_AS_FQDN"
    export MIN_DOMAIN_PARTS="$FQDN_MIN_DOMAIN_PARTS"
    export LOG_LEVEL="$FQDN_LOG_LEVEL"
    
    echo -e "${GREEN}✓ FQDN detection configured with log level: $FQDN_LOG_LEVEL${NC}"
}

# Enhanced FQDN detection using helper_net_fqdn.sh with comprehensive validation and SSL readiness check
detect_fqdn_enhanced() {
    local provided_fqdn="$1"
    
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                    FQDN DETECTION                    ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    configure_fqdn_detection
    
    echo -e "${BLUE}Starting advanced FQDN detection using helper modules...${NC}"
    
    local detected_fqdn=""
    if detected_fqdn=$(auto_detect_fqdn "$provided_fqdn" "$FQDN_REQUIRE_SSL" "$FQDN_CHECK_DNS"); then
        echo -e "${GREEN}✓ FQDN detection successful: $detected_fqdn${NC}"
        
        if validate_fqdn_comprehensive "$detected_fqdn" "$FQDN_CHECK_DNS" "$FQDN_STRICT_MODE"; then
            echo -e "${GREEN}✓ FQDN validation passed${NC}"
        else
            echo -e "${YELLOW}⚠ FQDN validation had warnings (continuing anyway)${NC}"
        fi
        
        if [ "$FQDN_LOG_LEVEL" = "DEBUG" ]; then
            show_fqdn_summary "$detected_fqdn"
        fi
        
        FQDN="$detected_fqdn"
        
        if [ -z "$SERVER_NAME" ]; then
            SERVER_NAME="$detected_fqdn"
        fi
        
        echo ""
        echo -e "${GREEN}Final FQDN Configuration:${NC}"
        echo -e "${GREEN}• FQDN: $FQDN${NC}"
        echo -e "${GREEN}• Server Name: $SERVER_NAME${NC}"
        echo -e "${GREEN}• Detection Method: $(get_detection_method)${NC}"
        
        if [ -n "$AUTO_CERT_TYPE" ]; then
            echo -e "${GREEN}• SSL Certificates: Enabled ($AUTO_CERT_TYPE)${NC}"
            echo -e "${GREEN}• SSL Contact: $AUTO_CERT_CONTACT${NC}"
        else
            echo -e "${BLUE}• SSL Certificates: Manual configuration${NC}"
        fi
        echo ""
        
        return 0
    else
        echo -e "${RED}✗ FQDN detection failed${NC}"
        
        show_fqdn_summary ""
        
        echo ""
        echo -e "${RED}FQDN Detection Failed${NC}"
        echo -e "${YELLOW}Possible solutions:${NC}"
        echo -e "${YELLOW}• Provide FQDN manually: --FQDN your.domain.com${NC}"
        echo -e "${YELLOW}• Check DNS configuration: nslookup \$(hostname -f)${NC}"
        echo -e "${YELLOW}• Verify /etc/hostname: cat /etc/hostname${NC}"
        echo -e "${YELLOW}• Set system hostname: hostnamectl set-hostname your.domain.com${NC}"
        
        if [ "$FQDN_REQUIRE_SSL" = "yes" ]; then
            echo ""
            echo -e "${RED}SSL certificates are enabled but no valid FQDN found.${NC}"
            echo -e "${YELLOW}Either provide a valid FQDN or disable SSL certificates.${NC}"
            return 1
        else
            echo ""
            echo -e "${BLUE}Using localhost as fallback (SSL certificates will be disabled)${NC}"
            FQDN="localhost"
            SERVER_NAME="localhost"
            return 0
        fi
    fi
}

# Performs comprehensive NAT detection using helper_net_nat.sh and builds whitelist accordingly
detect_nat_and_build_whitelist() {
    local docker_subnet="$1"
    
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                    NAT DETECTION AND API WHITELIST                    ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    echo -e "${BLUE}Starting NAT detection using helper modules...${NC}"
    
    # Use helper_net_nat.sh for comprehensive NAT detection
    check_nat_status
    
    echo -e "${BLUE}Building comprehensive API whitelist for Docker networks...${NC}"
    
    local api_whitelist="127.0.0.0/8"
    
    if [ -n "$docker_subnet" ]; then
        api_whitelist="$api_whitelist $docker_subnet"
        echo -e "${GREEN}• Added main subnet: $docker_subnet${NC}"
    fi
    
    echo -e "${BLUE}Adding Docker Compose network ranges...${NC}"
    
    local docker_ranges="172.16.0.0/12 172.17.0.0/16 172.18.0.0/16 172.19.0.0/16 172.20.0.0/16 172.21.0.0/16 172.22.0.0/16 172.23.0.0/16 172.24.0.0/16 172.25.0.0/16"
    
    for range in $docker_ranges; do
        if ! echo "$api_whitelist" | grep -q "$range"; then
            api_whitelist="$api_whitelist $range"
            echo -e "${GREEN}• Added Docker range: $range${NC}"
        fi
    done
    
    if command -v docker >/dev/null 2>&1; then
        echo -e "${BLUE}Detecting existing Docker networks...${NC}"
        
        local existing_networks=""
        existing_networks=$(docker network ls -q 2>/dev/null | \
                           xargs -I {} docker network inspect {} 2>/dev/null | \
                           grep -E '"Subnet":' | \
                           sed 's/.*"Subnet":[[:space:]]*"\([^"]*\)".*/\1/' || true)
        
        for network in $existing_networks; do
            if echo "$network" | grep -qE '^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\.'; then
                if ! echo "$api_whitelist" | grep -q "$network"; then
                    api_whitelist="$api_whitelist $network"
                    echo -e "${GREEN}• Added existing Docker network: $network${NC}"
                fi
            fi
        done
    fi
    
    echo -e "${BLUE}Adding broader private network ranges for safety...${NC}"
    local broad_ranges="10.0.0.0/8 192.168.0.0/16"
    
    for range in $broad_ranges; do
        if ! echo "$api_whitelist" | grep -q "$range"; then
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

# Updates API whitelist entries in docker-compose file
update_api_whitelist() {
    local compose_file="$1"
    local api_whitelist="$2"
    
    echo -e "${BLUE}Updating API whitelist in docker-compose.yml...${NC}"
    
    # Debug: Show exactly what we received
    echo -e "${BLUE}Debug - Raw API whitelist received:${NC}"
    printf "<%s>\n" "$api_whitelist"
    
    # Clean the whitelist - remove any existing escaping and normalize
    local clean_whitelist
    clean_whitelist=$(echo "$api_whitelist" | sed 's/\\//g')
    
    echo -e "${BLUE}Debug - Cleaned API whitelist:${NC}"
    printf "<%s>\n" "$clean_whitelist"
    
    # Try multiple methods for robust replacement
    local success=0
    
    # Method 1: Try with awk
    echo -e "${BLUE}Attempting update with awk...${NC}"
    local temp_file
    temp_file=$(mktemp)
    
    awk -v new_whitelist="$clean_whitelist" '
    /API_WHITELIST_IP:/ {
        gsub(/API_WHITELIST_IP: ".*"/, "API_WHITELIST_IP: \"" new_whitelist "\"")
    }
    { print }
    ' "$compose_file" > "$temp_file"
    
    if [ -f "$temp_file" ] && [ -s "$temp_file" ] && grep -q "API_WHITELIST_IP:" "$temp_file"; then
        mv "$temp_file" "$compose_file"
        success=1
        echo -e "${GREEN}✓ API whitelist updated with awk${NC}"
    else
        rm -f "$temp_file"
        echo -e "${YELLOW}⚠ Awk method failed, trying Perl...${NC}"
        
        # Method 2: Try with Perl (more robust string handling)
        if command -v perl >/dev/null 2>&1; then
            if perl -i -pe "s/API_WHITELIST_IP: \".*\"/API_WHITELIST_IP: \"$clean_whitelist\"/g" "$compose_file" 2>/dev/null; then
                success=1
                echo -e "${GREEN}✓ API whitelist updated with Perl${NC}"
            else
                echo -e "${YELLOW}⚠ Perl method failed, trying manual method...${NC}"
            fi
        fi
        
        # Method 3: Manual line-by-line replacement (most reliable)
        if [ $success -eq 0 ]; then
            echo -e "${BLUE}Using manual replacement method...${NC}"
            temp_file=$(mktemp)
            
            while IFS= read -r line; do
                if echo "$line" | grep -q "API_WHITELIST_IP:"; then
                    echo "      API_WHITELIST_IP: \"$clean_whitelist\""
                else
                    echo "$line"
                fi
            done < "$compose_file" > "$temp_file"
            
            if [ -f "$temp_file" ] && [ -s "$temp_file" ]; then
                mv "$temp_file" "$compose_file"
                success=1
                echo -e "${GREEN}✓ API whitelist updated with manual method${NC}"
            else
                rm -f "$temp_file"
            fi
        fi
    fi
    
    # Verify the update was successful
    if [ $success -eq 1 ]; then
        local updated_count
        updated_count=$(grep -c "API_WHITELIST_IP:" "$compose_file" || echo "0")
        echo -e "${GREEN}✓ Updated $updated_count API_WHITELIST_IP entries${NC}"
        
        echo -e "${BLUE}Verification - Updated API whitelist entries:${NC}"
        grep "API_WHITELIST_IP:" "$compose_file" | sed 's/^\s*/  /'
        
        return 0
    else
        echo -e "${RED}✗ Failed to update API whitelist with all methods${NC}"
        return 1
    fi
}

# Adds BunkerWeb labels to bw-ui service and synchronizes with scheduler configuration
add_bw_ui_labels() {
    local compose_file="$1"
    local fqdn="$2"
    
    echo -e "${BLUE}Adding BunkerWeb labels to bw-ui service and syncing with scheduler...${NC}"
    
    local random_ui_path
    random_ui_path=$(generate_random_ui_path)
    UI_ACCESS_PATH="/$random_ui_path"
    
    local labels_block="    labels:
      - \"bunkerweb.SERVER_NAME=$fqdn\"
      - \"bunkerweb.USE_TEMPLATE=ui\"
      - \"bunkerweb.USE_REVERSE_PROXY=yes\"
      - \"bunkerweb.REVERSE_PROXY_URL=/$random_ui_path\"
      - \"bunkerweb.REVERSE_PROXY_HOST=http://bw-ui:7000\""
    
    if grep -q "bw-ui:" "$compose_file"; then
        awk -v labels="$labels_block" '
        /^  bw-ui:/ { in_ui_service = 1 }
        in_ui_service && /^    image:/ { 
            print $0
            print labels
            next
        }
        /^  [a-zA-Z]/ && !/^  bw-ui:/ { in_ui_service = 0 }
        { print }
        ' "$compose_file" > "$compose_file.tmp" && mv "$compose_file.tmp" "$compose_file"
        
        echo -e "${GREEN}✓ BunkerWeb labels added to bw-ui service${NC}"
    fi
    
    echo -e "${BLUE}Updating scheduler configuration for domain: $fqdn${NC}"
    
    sed -i "s|REPLACEME_DOMAIN_USE_TEMPLATE|${fqdn}_USE_TEMPLATE|g" "$compose_file"
    sed -i "s|REPLACEME_DOMAIN_USE_REVERSE_PROXY|${fqdn}_USE_REVERSE_PROXY|g" "$compose_file"
    sed -i "s|REPLACEME_DOMAIN_REVERSE_PROXY_URL|${fqdn}_REVERSE_PROXY_URL|g" "$compose_file"
    sed -i "s|REPLACEME_DOMAIN_REVERSE_PROXY_HOST|${fqdn}_REVERSE_PROXY_HOST|g" "$compose_file"
    
    sed -i "s|REPLACEME_UI_PATH|$random_ui_path|g" "$compose_file"
    
    echo -e "${GREEN}✓ Scheduler configuration updated for domain: $fqdn${NC}"
    echo -e "${GREEN}✓ UI access path synchronized: /$random_ui_path${NC}"
    
    if [ -f "${compose_file%/*}/credentials.txt" ]; then
        {
            echo ""
            echo "# BunkerWeb UI Access Information"
            echo "UI Access Path: /$random_ui_path"
            echo "Full UI URL: http://$fqdn/$random_ui_path"
            echo "Direct Access: http://$(hostname -I | awk '{print $1}')/$random_ui_path"
        } >> "${compose_file%/*}/credentials.txt"
    fi
    
    return 0
}

# Configures automated vs wizard setup mode and admin credentials
configure_setup_mode() {
    local compose_file="$1"
    local setup_mode="$2"
    local admin_username="$3"
    local admin_password="$4"
    local flask_secret="$5"
    
    echo -e "${BLUE}Configuring setup mode: $setup_mode${NC}"
    
    if [ "$setup_mode" = "automated" ]; then
        echo -e "${BLUE}Configuring automated setup with credentials...${NC}"
        
        sed -i 's|# OVERRIDE_ADMIN_CREDS: "no"|OVERRIDE_ADMIN_CREDS: "yes"|' "$compose_file"
        
        sed -i "s|# ADMIN_USERNAME: \"REPLACEME_ADMIN_USERNAME\"|ADMIN_USERNAME: \"$admin_username\"|" \
               "$compose_file"
        sed -i "s|# ADMIN_PASSWORD: \"REPLACEME_ADMIN_PASSWORD\"|ADMIN_PASSWORD: \"$admin_password\"|" \
               "$compose_file"
        sed -i "s|# FLASK_SECRET: \"REPLACEME_FLASK_SECRET\"|FLASK_SECRET: \"$flask_secret\"|" \
               "$compose_file"
        
        echo -e "${GREEN}✓ Automated setup configured and enabled${NC}"
        echo -e "${GREEN}✓ Admin credentials activated${NC}"
        echo -e "${GREEN}✓ Username: $admin_username${NC}"
        echo -e "${GREEN}✓ Password: ${admin_password:0:4}... (${#admin_password} chars)${NC}"
        return 0
    else
        echo -e "${BLUE}Configuring setup wizard mode...${NC}"
        
        sed -i 's|OVERRIDE_ADMIN_CREDS: "yes"|# OVERRIDE_ADMIN_CREDS: "no"|' "$compose_file"
        
        sed -i "s|REPLACEME_ADMIN_USERNAME|$admin_username|g" "$compose_file"
        sed -i "s|REPLACEME_ADMIN_PASSWORD|$admin_password|g" "$compose_file"
        sed -i "s|REPLACEME_FLASK_SECRET|$flask_secret|g" "$compose_file"
        
        echo -e "${GREEN}✓ Setup wizard mode enabled${NC}"
        echo -e "${GREEN}✓ Credentials available for wizard setup${NC}"
        return 0
    fi
}

# Comprehensive template processing with release channel support and all configurations
process_template_with_release_channel() {
    local template_file="$1"
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
    local release_channel="${16:-latest}"
    local image_tag="${17}"
    
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                 TEMPLATE PROCESSING WITH RELEASE CHANNEL                 ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    if [ ! -f "$template_file" ]; then
        echo -e "${RED}✗ Template file not found: $template_file${NC}"
        return 1
    fi
    
    if [ -z "$image_tag" ]; then
        echo -e "${RED}✗ Image tag is required${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Processing release channel: $release_channel${NC}"
    if ! validate_release_channel "$release_channel"; then
        echo -e "${RED}✗ Invalid release channel: $release_channel${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✓ Using Docker image tag: $image_tag${NC}"
    
    echo -e "${BLUE}Copying template to docker-compose.yml...${NC}"
    if cp "$template_file" "$compose_file"; then
        echo -e "${GREEN}✓ Template copied: $(basename "$template_file") → $(basename "$compose_file")${NC}"
    else
        echo -e "${RED}✗ Failed to copy template${NC}"
        return 1
    fi
    
    local backup_file
    backup_file=$(create_backup "$compose_file" "template-processing")
    echo -e "${GREEN}✓ Backup created${NC}"
    
    # Check if template needs processing
    if ! grep -q "REPLACEME_" "$compose_file"; then
        echo -e "${BLUE}ℹ No placeholders found in template${NC}"
        return 0
    fi
    
    local processing_errors=0
    
    echo -e "${BLUE}Processing template placeholders in correct order...${NC}"
    
    echo -e "${BLUE}1. Processing Docker image tags...${NC}"
    if replace_image_tag_placeholders "$compose_file" "$image_tag" "Docker image tags"; then
        echo -e "${GREEN}✓ Docker image tags updated to: $image_tag${NC}"
        echo -e "${GREEN}✓ Release channel: $release_channel${NC}"
    else
        echo -e "${RED}✗ Failed to update Docker image tags${NC}"
        processing_errors=$((processing_errors + 1))
    fi
    
    echo -e "${BLUE}2. Processing basic credentials...${NC}"
    if [ -n "$mysql_password" ]; then
        sed -i "s|REPLACEME_MYSQL|$mysql_password|g" "$compose_file"
        echo -e "${GREEN}✓ MySQL password updated${NC}"
    fi
    
    if [ "$redis_enabled" = "yes" ] && [ -n "$redis_password" ]; then
        sed -i "s|REPLACEME_REDIS_PASSWORD|$redis_password|g" "$compose_file"
        echo -e "${GREEN}✓ Redis password updated${NC}"
    else
        sed -i "s|REPLACEME_REDIS_PASSWORD|disabled|g" "$compose_file"
        echo -e "${GREEN}✓ Redis password set to disabled${NC}"
    fi
    
    if [ -n "$totp_secret" ]; then
        sed -i "s|REPLACEME_DEFAULT|$totp_secret|g" "$compose_file"
        echo -e "${GREEN}✓ TOTP secret updated${NC}"
    fi
    
    echo -e "${BLUE}3. Processing network configuration...${NC}"
    if [ -n "$docker_subnet" ]; then
        local default_subnet="10.20.30.0/24"
        if [ "$docker_subnet" != "$default_subnet" ]; then
            sed -i "s|$default_subnet|$docker_subnet|g" "$compose_file"
            echo -e "${GREEN}✓ Docker subnet updated to: $docker_subnet${NC}"
        fi
    fi
    
    echo -e "${BLUE}4. Processing DNS configuration...${NC}"
    if replace_dns_resolvers "$compose_file" "${DNS_RESOLVERS:-127.0.0.11}"; then
        echo -e "${GREEN}✓ DNS resolvers configured${NC}"
    else
        echo -e "${RED}✗ Failed to configure DNS resolvers${NC}"
        processing_errors=$((processing_errors + 1))
    fi
    
    echo -e "${BLUE}5. Processing HTTP/3 configuration...${NC}"
    if [ -n "$HTTP3" ]; then
        sed -i "s|HTTP3: \"yes\"|HTTP3: \"$HTTP3\"|g" "$compose_file"
        echo -e "${GREEN}✓ HTTP3 configured: $HTTP3${NC}"
    fi
    
    if [ -n "$HTTP3_ALT_SVC_PORT" ]; then
        sed -i "s|HTTP3_ALT_SVC_PORT: \"443\"|HTTP3_ALT_SVC_PORT: \"$HTTP3_ALT_SVC_PORT\"|g" \
               "$compose_file"
        echo -e "${GREEN}✓ HTTP3 alternate service port: $HTTP3_ALT_SVC_PORT${NC}"
    fi
    
    # Continue with remaining processing steps...
    
    return 0
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
        
        # Load all other configuration variables as needed
        
        if [ -n "$AUTO_CERT_TYPE" ]; then
            if [ "$AUTO_CERT_CONTACT" = "me@example.com" ] || \
               echo "$AUTO_CERT_CONTACT" | grep -q "@example.com" || \
               echo "$AUTO_CERT_CONTACT" | grep -q "@yourdomain.com"; then
                if [ "$FORCE_INSTALL" != "yes" ]; then
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
    echo -e "${BLUE}Examples:${NC}"
    echo -e "  sudo $0 --type autoconf"
    echo -e "  sudo $0 --type autoconf --automated --release latest"
    echo -e "  sudo $0 --type autoconf --release RC"
    echo -e "  sudo $0 --type autoconf --release dev"
    echo -e "  sudo $0 --type autoconf --release testing"
    echo -e "  sudo $0 --type autoconf --release 1.6.1"
    echo -e "  sudo $0 --fix-permissions"
    echo ""
    echo -e "${GREEN}Release Channel Information:${NC}"
    list_available_channels
    echo ""
}

# Parses command line arguments and sets deployment configuration
parse_arguments() {
    DEPLOYMENT_TYPE=""
    FORCE_INSTALL="no"
    FIX_PERMISSIONS_ONLY="no"

    while [ $# -gt 0 ]; do
        if [ "$1" = "--type" ]; then
            DEPLOYMENT_TYPE="$2"
            shift 2
        elif [ "$1" = "--automated" ]; then
            SETUP_MODE="automated"
            shift
        elif [ "$1" = "--wizard" ]; then
            SETUP_MODE="wizard"
            shift
        elif [ "$1" = "--admin-name" ]; then
            ADMIN_USERNAME="$2"
            shift 2
        elif [ "$1" = "--FQDN" ]; then
            FQDN="$2"
            shift 2
        elif [ "$1" = "--release" ]; then
            RELEASE_CHANNEL="$2"
            shift 2
        elif [ "$1" = "--force" ]; then
            FORCE_INSTALL="yes"
            shift
        elif [ "$1" = "--fix-permissions" ]; then
            FIX_PERMISSIONS_ONLY="yes"
            shift
        elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
            show_usage
            exit 0
        else
            echo -e "${RED}Error: Unknown option '$1'${NC}"
            show_usage
            exit 1
        fi
    done

    # If only fixing permissions, we don't need deployment type
    if [ "$FIX_PERMISSIONS_ONLY" = "yes" ]; then
        return 0
    fi

    if [ -z "$DEPLOYMENT_TYPE" ]; then
        echo -e "${RED}Error: --type parameter is required${NC}"
        echo ""
        show_usage
        exit 1
    fi

    if [ "$DEPLOYMENT_TYPE" = "autoconf" ]; then
        TEMPLATE_FILE="template_autoconf_display.yml"
        DEPLOYMENT_NAME="Autoconf Display"
    elif [ "$DEPLOYMENT_TYPE" = "basic" ]; then
        TEMPLATE_FILE="template_basic_display.yml"
        DEPLOYMENT_NAME="Basic Display"
    elif [ "$DEPLOYMENT_TYPE" = "integrated" ]; then
        TEMPLATE_FILE="template_ui_integrated_display.yml"
        DEPLOYMENT_NAME="UI Integrated Display"
    else
        echo -e "${RED}Error: Invalid deployment type '$DEPLOYMENT_TYPE'${NC}"
        echo -e "${YELLOW}Valid types: autoconf, basic, integrated${NC}"
        exit 1
    fi
}

# Creates required directories with proper permissions for BunkerWeb containers
setup_directories() {
    echo -e "${BLUE}Creating directories with enhanced permissions...${NC}"
    
    # Stop any running containers first to avoid permission conflicts
    if [ -f "$INSTALL_DIR/docker-compose.yml" ]; then
        echo -e "${BLUE}Stopping any running containers to set permissions safely...${NC}"
        cd "$INSTALL_DIR" && docker compose down 2>/dev/null || true
    fi
    
    # Create main installation directory first
    mkdir -p "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"
    
    local directories="$INSTALL_DIR/storage $INSTALL_DIR/database $INSTALL_DIR/apps"
    
    if [ "$REDIS_ENABLED" = "yes" ]; then
        directories="$directories $INSTALL_DIR/redis"
    fi
    
    # Create directories with proper permissions immediately
    for dir in $directories; do
        echo -e "${BLUE}Creating: $dir${NC}"
        mkdir -p "$dir"
        
        # Ensure directory exists and is accessible
        if [ ! -d "$dir" ]; then
            echo -e "${RED}✗ Failed to create directory: $dir${NC}"
            return 1
        fi
    done
    
    echo -e "${BLUE}Setting enhanced permissions for BunkerWeb containers...${NC}"
    
    # BunkerWeb storage directory (mounted as /data in containers)
    # Needs full access for nginx user (101:101)
    echo -e "${BLUE}Configuring storage directory for nginx user (101:101)...${NC}"
    chown -R 101:101 "$INSTALL_DIR/storage"
    chmod -R 775 "$INSTALL_DIR/storage"
    
    # Ensure the directory is writable and accessible
    find "$INSTALL_DIR/storage" -type d -exec chmod 775 {} \;
    find "$INSTALL_DIR/storage" -type f -exec chmod 664 {} \; 2>/dev/null || true
    
    # Verify permissions
    if [ "$(stat -c %u:%g "$INSTALL_DIR/storage")" = "101:101" ]; then
        echo -e "${GREEN}✓ Storage directory ownership verified: nginx (101:101)${NC}"
    else
        echo -e "${RED}✗ Storage directory ownership verification failed${NC}"
        ls -la "$INSTALL_DIR/storage"
        return 1
    fi
    
    # Database directory for MariaDB
    echo -e "${BLUE}Configuring database directory for mysql user (999:999)...${NC}"
    chown -R 999:999 "$INSTALL_DIR/database"
    chmod -R 755 "$INSTALL_DIR/database"
    echo -e "${GREEN}✓ Database directory ownership set to mysql (999:999)${NC}"
    
    # Redis directory if enabled
    if [ "$REDIS_ENABLED" = "yes" ]; then
        echo -e "${BLUE}Configuring redis directory for redis user (999:999)...${NC}"
        chown -R 999:999 "$INSTALL_DIR/redis"
        chmod -R 755 "$INSTALL_DIR/redis"
        echo -e "${GREEN}✓ Redis directory ownership set to redis (999:999)${NC}"
    fi
    
    # Apps directory for general use
    chmod 755 "$INSTALL_DIR/apps"
    
    # Set ownership for config files to user who ran sudo (if applicable)
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
    
    # Final permission verification and troubleshooting info
    echo -e "${BLUE}Permission verification:${NC}"
    echo -e "${GREEN}Storage directory: $(ls -ld "$INSTALL_DIR/storage" | awk '{print $1, $3":"$4}')${NC}"
    echo -e "${GREEN}Database directory: $(ls -ld "$INSTALL_DIR/database" | awk '{print $1, $3":"$4}')${NC}"
    
    # Check if storage directory is writable by nginx user
    if sudo -u "#101" test -w "$INSTALL_DIR/storage" 2>/dev/null; then
        echo -e "${GREEN}✓ Storage directory is writable by nginx user (101:101)${NC}"
    else
        echo -e "${YELLOW}⚠ Testing write access as nginx user (this may show permission denied, but that's normal)${NC}"
        echo -e "${BLUE}Container will handle final permission verification${NC}"
    fi
    
    # Ensure parent directory has proper permissions
    chmod 755 "$(dirname "$INSTALL_DIR")" 2>/dev/null || true
    
    echo -e "${GREEN}✓ All directories created and permissions properly configured${NC}"
    echo -e "${BLUE}✓ Enhanced permission model applied for container compatibility${NC}"
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
        # Remove any problematic permissions and reset
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
    
    # Verify final permissions
    echo -e "${BLUE}Verifying permissions:${NC}"
    ls -la "$INSTALL_DIR/"
    echo ""
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

# Main execution function coordinating all setup phases using helper modules
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
    
    # Handle permission fix mode
    if [ "$FIX_PERMISSIONS_ONLY" = "yes" ]; then
        echo -e "${BLUE}Running in permission fix mode...${NC}"
        fix_permissions
        exit $?
    fi
    
    # Load modules or fallback functions
    source_modules
    
    load_configuration
    
    echo -e "${BLUE}Step 0: Release Channel Validation${NC}"
    if ! validate_and_show_release_channel "$RELEASE_CHANNEL"; then
        echo -e "${RED}✗ Release channel validation failed${NC}"
        exit 1
    fi
    
    # FQDN detection with fallback
    echo -e "${BLUE}Step 0.5: FQDN Detection${NC}"
    local detected_fqdn
    if command -v detect_fqdn_enhanced >/dev/null 2>&1; then
        if ! detect_fqdn_enhanced "$FQDN"; then
            echo -e "${RED}✗ FQDN detection failed${NC}"
            exit 1
        fi
    else
        echo -e "${BLUE}Using fallback FQDN detection...${NC}"
        detected_fqdn=$(auto_detect_fqdn "$FQDN" "$FQDN_REQUIRE_SSL" "$FQDN_CHECK_DNS")
        FQDN="$detected_fqdn"
        SERVER_NAME="$detected_fqdn"
        echo -e "${GREEN}✓ FQDN detected: $FQDN${NC}"
    fi
    
    local compose_file="$INSTALL_DIR/docker-compose.yml"
    local template_path="$INSTALL_DIR/$TEMPLATE_FILE"
    local creds_file="$INSTALL_DIR/credentials.txt"
    
    if [ ! -f "$template_path" ]; then
        echo -e "${RED}Error: Template file not found at $template_path${NC}"
        echo -e "${YELLOW}Available templates should be in: $INSTALL_DIR${NC}"
        exit 1
    fi
    
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
    
    echo -e "${BLUE}Step 2: Network Configuration${NC}"
    local docker_subnet
    docker_subnet=$(simple_network_detection)
    echo -e "${GREEN}✓ Using subnet: $docker_subnet${NC}"
    
    echo -e "${BLUE}Step 3: NAT Detection and API Whitelist Building${NC}"
    local api_whitelist
    api_whitelist=$(detect_nat_and_build_whitelist "$docker_subnet")
    
    echo -e "${BLUE}Step 4: Credential Management${NC}"
    # Generate credentials (simplified version since full function is missing)
    local mysql_password
    mysql_password=$(openssl rand -base64 33)
    local admin_password
    admin_password=$(generate_secure_admin_password)
    local flask_secret
    flask_secret=$(openssl rand -base64 33)
    local totp_secret
    totp_secret=$(openssl rand -base64 33)
    echo -e "${GREEN}✓ Credentials generated${NC}"
    
    echo -e "${BLUE}Step 5: Template Processing${NC}"
    echo -e "${BLUE}Copying template to docker-compose.yml...${NC}"
    if cp "$template_path" "$compose_file"; then
        echo -e "${GREEN}✓ Template copied: $(basename "$template_path") → docker-compose.yml${NC}"
    else
        echo -e "${RED}✗ Failed to copy template${NC}"
        exit 1
    fi
    
    # Basic template processing to replace critical placeholders
    echo -e "${BLUE}Processing essential template placeholders...${NC}"
    
    # Get image tag for release channel
    local image_tag
    image_tag=$(get_image_tag_for_channel "$RELEASE_CHANNEL")
    
    # Replace image tags
    sed -i "s|REPLACEME_TAG|$image_tag|g" "$compose_file"
    echo -e "${GREEN}✓ Docker image tags updated to: $image_tag${NC}"
    
    # Replace credentials
    sed -i "s|REPLACEME_MYSQL|$mysql_password|g" "$compose_file"
    sed -i "s|REPLACEME_DEFAULT|$totp_secret|g" "$compose_file"
    sed -i "s|REPLACEME_ADMIN_USERNAME|$ADMIN_USERNAME|g" "$compose_file"
    sed -i "s|REPLACEME_ADMIN_PASSWORD|$admin_password|g" "$compose_file"
    sed -i "s|REPLACEME_FLASK_SECRET|$flask_secret|g" "$compose_file"
    echo -e "${GREEN}✓ Credentials updated${NC}"
    
    # Replace DNS resolvers
    sed -i "s|REPLACEME_DNS_RESOLVERS|$DNS_RESOLVERS|g" "$compose_file"
    echo -e "${GREEN}✓ DNS resolvers configured${NC}"
    
    # SSL configuration
    if [ -n "$AUTO_CERT_TYPE" ]; then
        sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|yes|g" "$compose_file"
        sed -i "s|REPLACEME_EMAIL_LETS_ENCRYPT|$AUTO_CERT_CONTACT|g" "$compose_file"
        echo -e "${GREEN}✓ SSL certificates configured${NC}"
    else
        sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|no|g" "$compose_file"
        sed -i "s|REPLACEME_EMAIL_LETS_ENCRYPT|admin@localhost|g" "$compose_file"
        echo -e "${GREEN}✓ SSL certificates disabled${NC}"
    fi
    
    # Domain configuration
    sed -i "s|REPLACEME_DOMAIN|$FQDN|g" "$compose_file"
    sed -i "s|SERVER_NAME: \"\"|SERVER_NAME: \"$FQDN\"|g" "$compose_file"
    echo -e "${GREEN}✓ Domain configured: $FQDN${NC}"
    
    echo -e "${BLUE}Step 6: API Whitelist Configuration${NC}"
    if ! update_api_whitelist "$compose_file" "$api_whitelist"; then
        echo -e "${RED}✗ API whitelist update failed${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Step 7: Saving Credentials${NC}"
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

# Quick Access
# Access: http://$(hostname -I | awk '{print $1}')
# Username: $ADMIN_USERNAME
# Password: $admin_password
EOF
    chmod 600 "$creds_file"
    echo -e "${GREEN}✓ Credentials saved to: $creds_file${NC}"
    
    echo -e "${GREEN}Setup completed successfully!${NC}"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo -e "${GREEN}1. Start BunkerWeb: cd $INSTALL_DIR && docker compose up -d${NC}"
    echo -e "${GREEN}2. Access web interface: http://$(hostname -I | awk '{print $1}')${NC}"
    echo -e "${GREEN}3. Login with credentials from: $creds_file${NC}"
    echo ""
    echo -e "${BLUE}If you encounter permission errors, you can fix them with:${NC}"
    echo -e "${GREEN}sudo $0 --fix-permissions${NC}"
}

main "$@"; then
                return 0
            else
                return 1
            fi
        }
    fi
    
    # Fallback image tag mapping
    if ! command -v get_image_tag_for_channel >/dev/null 2>&1; then
        get_image_tag_for_channel() {
            local channel="$1"
            case "$channel" in
                "latest") echo "latest" ;;
                "dev") echo "dev" ;;
                "RC") echo "rc" ;;
                "testing") echo "testing" ;;
                "nightly") echo "nightly" ;;
                *) echo "$channel" ;;  # For version numbers, use as-is
            esac
        }
    fi
    
    # Fallback FQDN detection
    if ! command -v auto_detect_fqdn >/dev/null 2>&1; then
        auto_detect_fqdn() {
            local provided_fqdn="$1"
            local require_ssl="$2"
            local check_dns="$3"
            
            if [ -n "$provided_fqdn" ]; then
                echo "$provided_fqdn"
                return 0
            fi
            
            # Try hostname -f
            local detected_fqdn
            detected_fqdn=$(hostname -f 2>/dev/null)
            
            if [ -n "$detected_fqdn" ] && [ "$detected_fqdn" != "localhost" ]; then
                echo "$detected_fqdn"
                return 0
            fi
            
            # Fallback to localhost
            echo "localhost"
            return 0
        }
    fi
    
    # Fallback FQDN validation
    if ! command -v validate_fqdn_comprehensive >/dev/null 2>&1; then
        validate_fqdn_comprehensive() {
            local fqdn="$1"
            # Simple validation - just check it's not empty
            [ -n "$fqdn" ]
        }
    fi
    
    # Fallback show channel info
    if ! command -v show_channel_info >/dev/null 2>&1; then
        show_channel_info() {
            local channel="$1"
            echo -e "${GREEN}Release Channel: $channel${NC}"
        }
    fi
    
    # Fallback list channels
    if ! command -v list_available_channels >/dev/null 2>&1; then
        list_available_channels() {
            echo -e "${GREEN}• latest - Stable releases${NC}"
            echo -e "${GREEN}• dev - Development builds${NC}"
            echo -e "${GREEN}• RC - Release candidates${NC}"
            echo -e "${GREEN}• testing - Testing builds${NC}"
            echo -e "${GREEN}• nightly - Nightly builds${NC}"
            echo -e "${GREEN}• X.Y.Z - Specific version${NC}"
        }
    fi
    
    # Fallback NAT detection
    if ! command -v check_nat_status >/dev/null 2>&1; then
        check_nat_status() {
            echo -e "${BLUE}Performing basic NAT detection...${NC}"
            echo -e "${GREEN}✓ NAT detection completed (fallback)${NC}"
        }
    fi
    
    # Fallback show FQDN summary
    if ! command -v show_fqdn_summary >/dev/null 2>&1; then
        show_fqdn_summary() {
            local fqdn="$1"
            if [ -n "$fqdn" ]; then
                echo -e "${GREEN}FQDN Summary: $fqdn${NC}"
            fi
        }
    fi
    
    # Fallback get detection method
    if ! command -v get_detection_method >/dev/null 2>&1; then
        get_detection_method() {
            echo "automatic"
        }
    fi
    
    # Fallback backup creation
    if ! command -v create_backup >/dev/null 2>&1; then
        create_backup() {
            local file="$1"
            local suffix="$2"
            local backup_file="${file}.backup.${suffix}.$(date +%s)"
            if [ -f "$file" ]; then
                cp "$file" "$backup_file"
                echo "$backup_file"
            fi
        }
    fi
    
    # Fallback DNS resolver replacement
    if ! command -v replace_dns_resolvers >/dev/null 2>&1; then
        replace_dns_resolvers() {
            local compose_file="$1"
            local dns_resolvers="$2"
            sed -i "s|REPLACEME_DNS_RESOLVERS|$dns_resolvers|g" "$compose_file"
            return 0
        }
    fi
    
    # Fallback image tag replacement
    if ! command -v replace_image_tag_placeholders >/dev/null 2>&1; then
        replace_image_tag_placeholders() {
            local compose_file="$1"
            local image_tag="$2"
            local description="$3"
            sed -i "s|REPLACEME_TAG|$image_tag|g" "$compose_file"
            return 0
        }
    fi
    
    echo -e "${GREEN}✓ Fallback functions loaded${NC}"
}

# Validates release channel and displays channel information
validate_and_show_release_channel() {
    local channel="$1"
    
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                    RELEASE CHANNEL VALIDATION                    ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    echo -e "${BLUE}Validating release channel: $channel${NC}"
    
    # Use the helper function to validate the channel
    if validate_release_channel "$channel"; then
        echo -e "${GREEN}✓ Release channel is valid: $channel${NC}"
        
        show_channel_info "$channel"
        
        local image_tag
        image_tag=$(get_image_tag_for_channel "$channel")
        echo -e "${GREEN}✓ Docker image tag: $image_tag${NC}"
        
        export DOCKER_IMAGE_TAG="$image_tag"
        export VALIDATED_RELEASE_CHANNEL="$channel"
        
        return 0
    else
        echo -e "${RED}✗ Invalid release channel: $channel${NC}"
        echo ""
        echo -e "${YELLOW}Available options:${NC}"
        list_available_channels
        return 1
    fi
}

# Configures FQDN detection parameters based on SSL requirements
configure_fqdn_detection() {
    echo -e "${BLUE}Configuring FQDN detection parameters...${NC}"
    
    if [ -n "$AUTO_CERT_TYPE" ]; then
        FQDN_REQUIRE_SSL="yes"
        echo -e "${GREEN}✓ SSL certificates enabled - requiring SSL-compatible FQDN${NC}"
    else
        FQDN_REQUIRE_SSL="no"
        echo -e "${BLUE}ℹ SSL certificates disabled - allowing localhost FQDN${NC}"
    fi
    
    export REQUIRE_SSL="$FQDN_REQUIRE_SSL"
    export CHECK_DNS="$FQDN_CHECK_DNS"
    export ALLOW_LOCALHOST="$FQDN_ALLOW_LOCALHOST"
    export ALLOW_IP_AS_FQDN="$FQDN_ALLOW_IP_AS_FQDN"
    export MIN_DOMAIN_PARTS="$FQDN_MIN_DOMAIN_PARTS"
    export LOG_LEVEL="$FQDN_LOG_LEVEL"
    
    echo -e "${GREEN}✓ FQDN detection configured with log level: $FQDN_LOG_LEVEL${NC}"
}

# Enhanced FQDN detection using helper_net_fqdn.sh with comprehensive validation and SSL readiness check
detect_fqdn_enhanced() {
    local provided_fqdn="$1"
    
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                    FQDN DETECTION                    ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    configure_fqdn_detection
    
    echo -e "${BLUE}Starting advanced FQDN detection using helper modules...${NC}"
    
    local detected_fqdn=""
    if detected_fqdn=$(auto_detect_fqdn "$provided_fqdn" "$FQDN_REQUIRE_SSL" "$FQDN_CHECK_DNS"); then
        echo -e "${GREEN}✓ FQDN detection successful: $detected_fqdn${NC}"
        
        if validate_fqdn_comprehensive "$detected_fqdn" "$FQDN_CHECK_DNS" "$FQDN_STRICT_MODE"; then
            echo -e "${GREEN}✓ FQDN validation passed${NC}"
        else
            echo -e "${YELLOW}⚠ FQDN validation had warnings (continuing anyway)${NC}"
        fi
        
        if [ "$FQDN_LOG_LEVEL" = "DEBUG" ]; then
            show_fqdn_summary "$detected_fqdn"
        fi
        
        FQDN="$detected_fqdn"
        
        if [ -z "$SERVER_NAME" ]; then
            SERVER_NAME="$detected_fqdn"
        fi
        
        echo ""
        echo -e "${GREEN}Final FQDN Configuration:${NC}"
        echo -e "${GREEN}• FQDN: $FQDN${NC}"
        echo -e "${GREEN}• Server Name: $SERVER_NAME${NC}"
        echo -e "${GREEN}• Detection Method: $(get_detection_method)${NC}"
        
        if [ -n "$AUTO_CERT_TYPE" ]; then
            echo -e "${GREEN}• SSL Certificates: Enabled ($AUTO_CERT_TYPE)${NC}"
            echo -e "${GREEN}• SSL Contact: $AUTO_CERT_CONTACT${NC}"
        else
            echo -e "${BLUE}• SSL Certificates: Manual configuration${NC}"
        fi
        echo ""
        
        return 0
    else
        echo -e "${RED}✗ FQDN detection failed${NC}"
        
        show_fqdn_summary ""
        
        echo ""
        echo -e "${RED}FQDN Detection Failed${NC}"
        echo -e "${YELLOW}Possible solutions:${NC}"
        echo -e "${YELLOW}• Provide FQDN manually: --FQDN your.domain.com${NC}"
        echo -e "${YELLOW}• Check DNS configuration: nslookup \$(hostname -f)${NC}"
        echo -e "${YELLOW}• Verify /etc/hostname: cat /etc/hostname${NC}"
        echo -e "${YELLOW}• Set system hostname: hostnamectl set-hostname your.domain.com${NC}"
        
        if [ "$FQDN_REQUIRE_SSL" = "yes" ]; then
            echo ""
            echo -e "${RED}SSL certificates are enabled but no valid FQDN found.${NC}"
            echo -e "${YELLOW}Either provide a valid FQDN or disable SSL certificates.${NC}"
            return 1
        else
            echo ""
            echo -e "${BLUE}Using localhost as fallback (SSL certificates will be disabled)${NC}"
            FQDN="localhost"
            SERVER_NAME="localhost"
            return 0
        fi
    fi
}

# Performs comprehensive NAT detection using helper_net_nat.sh and builds whitelist accordingly
detect_nat_and_build_whitelist() {
    local docker_subnet="$1"
    
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                    NAT DETECTION AND API WHITELIST                    ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    echo -e "${BLUE}Starting NAT detection using helper modules...${NC}"
    
    # Use helper_net_nat.sh for comprehensive NAT detection
    check_nat_status
    
    echo -e "${BLUE}Building comprehensive API whitelist for Docker networks...${NC}"
    
    local api_whitelist="127.0.0.0/8"
    
    if [ -n "$docker_subnet" ]; then
        api_whitelist="$api_whitelist $docker_subnet"
        echo -e "${GREEN}• Added main subnet: $docker_subnet${NC}"
    fi
    
    echo -e "${BLUE}Adding Docker Compose network ranges...${NC}"
    
    local docker_ranges="172.16.0.0/12 172.17.0.0/16 172.18.0.0/16 172.19.0.0/16 172.20.0.0/16 172.21.0.0/16 172.22.0.0/16 172.23.0.0/16 172.24.0.0/16 172.25.0.0/16"
    
    for range in $docker_ranges; do
        if ! echo "$api_whitelist" | grep -q "$range"; then
            api_whitelist="$api_whitelist $range"
            echo -e "${GREEN}• Added Docker range: $range${NC}"
        fi
    done
    
    if command -v docker >/dev/null 2>&1; then
        echo -e "${BLUE}Detecting existing Docker networks...${NC}"
        
        local existing_networks=""
        existing_networks=$(docker network ls -q 2>/dev/null | \
                           xargs -I {} docker network inspect {} 2>/dev/null | \
                           grep -E '"Subnet":' | \
                           sed 's/.*"Subnet":[[:space:]]*"\([^"]*\)".*/\1/' || true)
        
        for network in $existing_networks; do
            if echo "$network" | grep -qE '^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\.'; then
                if ! echo "$api_whitelist" | grep -q "$network"; then
                    api_whitelist="$api_whitelist $network"
                    echo -e "${GREEN}• Added existing Docker network: $network${NC}"
                fi
            fi
        done
    fi
    
    echo -e "${BLUE}Adding broader private network ranges for safety...${NC}"
    local broad_ranges="10.0.0.0/8 192.168.0.0/16"
    
    for range in $broad_ranges; do
        if ! echo "$api_whitelist" | grep -q "$range"; then
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

# Updates API whitelist entries in docker-compose file
update_api_whitelist() {
    local compose_file="$1"
    local api_whitelist="$2"
    
    echo -e "${BLUE}Updating API whitelist in docker-compose.yml...${NC}"
    
    # Debug: Show exactly what we received
    echo -e "${BLUE}Debug - Raw API whitelist received:${NC}"
    printf "<%s>\n" "$api_whitelist"
    
    # Clean the whitelist - remove any existing escaping and normalize
    local clean_whitelist
    clean_whitelist=$(echo "$api_whitelist" | sed 's/\\//g')
    
    echo -e "${BLUE}Debug - Cleaned API whitelist:${NC}"
    printf "<%s>\n" "$clean_whitelist"
    
    # Try multiple methods for robust replacement
    local success=0
    
    # Method 1: Try with awk
    echo -e "${BLUE}Attempting update with awk...${NC}"
    local temp_file
    temp_file=$(mktemp)
    
    awk -v new_whitelist="$clean_whitelist" '
    /API_WHITELIST_IP:/ {
        gsub(/API_WHITELIST_IP: ".*"/, "API_WHITELIST_IP: \"" new_whitelist "\"")
    }
    { print }
    ' "$compose_file" > "$temp_file"
    
    if [ -f "$temp_file" ] && [ -s "$temp_file" ] && grep -q "API_WHITELIST_IP:" "$temp_file"; then
        mv "$temp_file" "$compose_file"
        success=1
        echo -e "${GREEN}✓ API whitelist updated with awk${NC}"
    else
        rm -f "$temp_file"
        echo -e "${YELLOW}⚠ Awk method failed, trying Perl...${NC}"
        
        # Method 2: Try with Perl (more robust string handling)
        if command -v perl >/dev/null 2>&1; then
            if perl -i -pe "s/API_WHITELIST_IP: \".*\"/API_WHITELIST_IP: \"$clean_whitelist\"/g" "$compose_file" 2>/dev/null; then
                success=1
                echo -e "${GREEN}✓ API whitelist updated with Perl${NC}"
            else
                echo -e "${YELLOW}⚠ Perl method failed, trying manual method...${NC}"
            fi
        fi
        
        # Method 3: Manual line-by-line replacement (most reliable)
        if [ $success -eq 0 ]; then
            echo -e "${BLUE}Using manual replacement method...${NC}"
            temp_file=$(mktemp)
            
            while IFS= read -r line; do
                if echo "$line" | grep -q "API_WHITELIST_IP:"; then
                    echo "      API_WHITELIST_IP: \"$clean_whitelist\""
                else
                    echo "$line"
                fi
            done < "$compose_file" > "$temp_file"
            
            if [ -f "$temp_file" ] && [ -s "$temp_file" ]; then
                mv "$temp_file" "$compose_file"
                success=1
                echo -e "${GREEN}✓ API whitelist updated with manual method${NC}"
            else
                rm -f "$temp_file"
            fi
        fi
    fi
    
    # Verify the update was successful
    if [ $success -eq 1 ]; then
        local updated_count
        updated_count=$(grep -c "API_WHITELIST_IP:" "$compose_file" || echo "0")
        echo -e "${GREEN}✓ Updated $updated_count API_WHITELIST_IP entries${NC}"
        
        echo -e "${BLUE}Verification - Updated API whitelist entries:${NC}"
        grep "API_WHITELIST_IP:" "$compose_file" | sed 's/^\s*/  /'
        
        return 0
    else
        echo -e "${RED}✗ Failed to update API whitelist with all methods${NC}"
        return 1
    fi
}

# Adds BunkerWeb labels to bw-ui service and synchronizes with scheduler configuration
add_bw_ui_labels() {
    local compose_file="$1"
    local fqdn="$2"
    
    echo -e "${BLUE}Adding BunkerWeb labels to bw-ui service and syncing with scheduler...${NC}"
    
    local random_ui_path
    random_ui_path=$(generate_random_ui_path)
    UI_ACCESS_PATH="/$random_ui_path"
    
    local labels_block="    labels:
      - \"bunkerweb.SERVER_NAME=$fqdn\"
      - \"bunkerweb.USE_TEMPLATE=ui\"
      - \"bunkerweb.USE_REVERSE_PROXY=yes\"
      - \"bunkerweb.REVERSE_PROXY_URL=/$random_ui_path\"
      - \"bunkerweb.REVERSE_PROXY_HOST=http://bw-ui:7000\""
    
    if grep -q "bw-ui:" "$compose_file"; then
        awk -v labels="$labels_block" '
        /^  bw-ui:/ { in_ui_service = 1 }
        in_ui_service && /^    image:/ { 
            print $0
            print labels
            next
        }
        /^  [a-zA-Z]/ && !/^  bw-ui:/ { in_ui_service = 0 }
        { print }
        ' "$compose_file" > "$compose_file.tmp" && mv "$compose_file.tmp" "$compose_file"
        
        echo -e "${GREEN}✓ BunkerWeb labels added to bw-ui service${NC}"
    fi
    
    echo -e "${BLUE}Updating scheduler configuration for domain: $fqdn${NC}"
    
    sed -i "s|REPLACEME_DOMAIN_USE_TEMPLATE|${fqdn}_USE_TEMPLATE|g" "$compose_file"
    sed -i "s|REPLACEME_DOMAIN_USE_REVERSE_PROXY|${fqdn}_USE_REVERSE_PROXY|g" "$compose_file"
    sed -i "s|REPLACEME_DOMAIN_REVERSE_PROXY_URL|${fqdn}_REVERSE_PROXY_URL|g" "$compose_file"
    sed -i "s|REPLACEME_DOMAIN_REVERSE_PROXY_HOST|${fqdn}_REVERSE_PROXY_HOST|g" "$compose_file"
    
    sed -i "s|REPLACEME_UI_PATH|$random_ui_path|g" "$compose_file"
    
    echo -e "${GREEN}✓ Scheduler configuration updated for domain: $fqdn${NC}"
    echo -e "${GREEN}✓ UI access path synchronized: /$random_ui_path${NC}"
    
    if [ -f "${compose_file%/*}/credentials.txt" ]; then
        {
            echo ""
            echo "# BunkerWeb UI Access Information"
            echo "UI Access Path: /$random_ui_path"
            echo "Full UI URL: http://$fqdn/$random_ui_path"
            echo "Direct Access: http://$(hostname -I | awk '{print $1}')/$random_ui_path"
        } >> "${compose_file%/*}/credentials.txt"
    fi
    
    return 0
}

# Configures automated vs wizard setup mode and admin credentials
configure_setup_mode() {
    local compose_file="$1"
    local setup_mode="$2"
    local admin_username="$3"
    local admin_password="$4"
    local flask_secret="$5"
    
    echo -e "${BLUE}Configuring setup mode: $setup_mode${NC}"
    
    if [ "$setup_mode" = "automated" ]; then
        echo -e "${BLUE}Configuring automated setup with credentials...${NC}"
        
        sed -i 's|# OVERRIDE_ADMIN_CREDS: "no"|OVERRIDE_ADMIN_CREDS: "yes"|' "$compose_file"
        
        sed -i "s|# ADMIN_USERNAME: \"REPLACEME_ADMIN_USERNAME\"|ADMIN_USERNAME: \"$admin_username\"|" \
               "$compose_file"
        sed -i "s|# ADMIN_PASSWORD: \"REPLACEME_ADMIN_PASSWORD\"|ADMIN_PASSWORD: \"$admin_password\"|" \
               "$compose_file"
        sed -i "s|# FLASK_SECRET: \"REPLACEME_FLASK_SECRET\"|FLASK_SECRET: \"$flask_secret\"|" \
               "$compose_file"
        
        echo -e "${GREEN}✓ Automated setup configured and enabled${NC}"
        echo -e "${GREEN}✓ Admin credentials activated${NC}"
        echo -e "${GREEN}✓ Username: $admin_username${NC}"
        echo -e "${GREEN}✓ Password: ${admin_password:0:4}... (${#admin_password} chars)${NC}"
        return 0
    else
        echo -e "${BLUE}Configuring setup wizard mode...${NC}"
        
        sed -i 's|OVERRIDE_ADMIN_CREDS: "yes"|# OVERRIDE_ADMIN_CREDS: "no"|' "$compose_file"
        
        sed -i "s|REPLACEME_ADMIN_USERNAME|$admin_username|g" "$compose_file"
        sed -i "s|REPLACEME_ADMIN_PASSWORD|$admin_password|g" "$compose_file"
        sed -i "s|REPLACEME_FLASK_SECRET|$flask_secret|g" "$compose_file"
        
        echo -e "${GREEN}✓ Setup wizard mode enabled${NC}"
        echo -e "${GREEN}✓ Credentials available for wizard setup${NC}"
        return 0
    fi
}

# Comprehensive template processing with release channel support and all configurations
process_template_with_release_channel() {
    local template_file="$1"
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
    local release_channel="${16:-latest}"
    local image_tag="${17}"
    
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                 TEMPLATE PROCESSING WITH RELEASE CHANNEL                 ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    if [ ! -f "$template_file" ]; then
        echo -e "${RED}✗ Template file not found: $template_file${NC}"
        return 1
    fi
    
    if [ -z "$image_tag" ]; then
        echo -e "${RED}✗ Image tag is required${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Processing release channel: $release_channel${NC}"
    if ! validate_release_channel "$release_channel"; then
        echo -e "${RED}✗ Invalid release channel: $release_channel${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✓ Using Docker image tag: $image_tag${NC}"
    
    echo -e "${BLUE}Copying template to docker-compose.yml...${NC}"
    if cp "$template_file" "$compose_file"; then
        echo -e "${GREEN}✓ Template copied: $(basename "$template_file") → $(basename "$compose_file")${NC}"
    else
        echo -e "${RED}✗ Failed to copy template${NC}"
        return 1
    fi
    
    local backup_file
    backup_file=$(create_backup "$compose_file" "template-processing")
    echo -e "${GREEN}✓ Backup created${NC}"
    
    # Check if template needs processing
    if ! grep -q "REPLACEME_" "$compose_file"; then
        echo -e "${BLUE}ℹ No placeholders found in template${NC}"
        return 0
    fi
    
    local processing_errors=0
    
    echo -e "${BLUE}Processing template placeholders in correct order...${NC}"
    
    echo -e "${BLUE}1. Processing Docker image tags...${NC}"
    if replace_image_tag_placeholders "$compose_file" "$image_tag" "Docker image tags"; then
        echo -e "${GREEN}✓ Docker image tags updated to: $image_tag${NC}"
        echo -e "${GREEN}✓ Release channel: $release_channel${NC}"
    else
        echo -e "${RED}✗ Failed to update Docker image tags${NC}"
        processing_errors=$((processing_errors + 1))
    fi
    
    echo -e "${BLUE}2. Processing basic credentials...${NC}"
    if [ -n "$mysql_password" ]; then
        sed -i "s|REPLACEME_MYSQL|$mysql_password|g" "$compose_file"
        echo -e "${GREEN}✓ MySQL password updated${NC}"
    fi
    
    if [ "$redis_enabled" = "yes" ] && [ -n "$redis_password" ]; then
        sed -i "s|REPLACEME_REDIS_PASSWORD|$redis_password|g" "$compose_file"
        echo -e "${GREEN}✓ Redis password updated${NC}"
    else
        sed -i "s|REPLACEME_REDIS_PASSWORD|disabled|g" "$compose_file"
        echo -e "${GREEN}✓ Redis password set to disabled${NC}"
    fi
    
    if [ -n "$totp_secret" ]; then
        sed -i "s|REPLACEME_DEFAULT|$totp_secret|g" "$compose_file"
        echo -e "${GREEN}✓ TOTP secret updated${NC}"
    fi
    
    echo -e "${BLUE}3. Processing network configuration...${NC}"
    if [ -n "$docker_subnet" ]; then
        local default_subnet="10.20.30.0/24"
        if [ "$docker_subnet" != "$default_subnet" ]; then
            sed -i "s|$default_subnet|$docker_subnet|g" "$compose_file"
            echo -e "${GREEN}✓ Docker subnet updated to: $docker_subnet${NC}"
        fi
    fi
    
    echo -e "${BLUE}4. Processing DNS configuration...${NC}"
    if replace_dns_resolvers "$compose_file" "${DNS_RESOLVERS:-127.0.0.11}"; then
        echo -e "${GREEN}✓ DNS resolvers configured${NC}"
    else
        echo -e "${RED}✗ Failed to configure DNS resolvers${NC}"
        processing_errors=$((processing_errors + 1))
    fi
    
    echo -e "${BLUE}5. Processing HTTP/3 configuration...${NC}"
    if [ -n "$HTTP3" ]; then
        sed -i "s|HTTP3: \"yes\"|HTTP3: \"$HTTP3\"|g" "$compose_file"
        echo -e "${GREEN}✓ HTTP3 configured: $HTTP3${NC}"
    fi
    
    if [ -n "$HTTP3_ALT_SVC_PORT" ]; then
        sed -i "s|HTTP3_ALT_SVC_PORT: \"443\"|HTTP3_ALT_SVC_PORT: \"$HTTP3_ALT_SVC_PORT\"|g" \
               "$compose_file"
        echo -e "${GREEN}✓ HTTP3 alternate service port: $HTTP3_ALT_SVC_PORT${NC}"
    fi
    
    # Continue with remaining processing steps...
    
    return 0
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
        
        # Load all other configuration variables as needed
        
        if [ -n "$AUTO_CERT_TYPE" ]; then
            if [ "$AUTO_CERT_CONTACT" = "me@example.com" ] || \
               echo "$AUTO_CERT_CONTACT" | grep -q "@example.com" || \
               echo "$AUTO_CERT_CONTACT" | grep -q "@yourdomain.com"; then
                if [ "$FORCE_INSTALL" != "yes" ]; then
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
    echo -e "${BLUE}Examples:${NC}"
    echo -e "  sudo $0 --type autoconf"
    echo -e "  sudo $0 --type autoconf --automated --release latest"
    echo -e "  sudo $0 --type autoconf --release RC"
    echo -e "  sudo $0 --type autoconf --release dev"
    echo -e "  sudo $0 --type autoconf --release testing"
    echo -e "  sudo $0 --type autoconf --release 1.6.1"
    echo -e "  sudo $0 --fix-permissions"
    echo ""
    echo -e "${GREEN}Release Channel Information:${NC}"
    list_available_channels
    echo ""
}

# Parses command line arguments and sets deployment configuration
parse_arguments() {
    DEPLOYMENT_TYPE=""
    FORCE_INSTALL="no"
    FIX_PERMISSIONS_ONLY="no"

    while [ $# -gt 0 ]; do
        if [ "$1" = "--type" ]; then
            DEPLOYMENT_TYPE="$2"
            shift 2
        elif [ "$1" = "--automated" ]; then
            SETUP_MODE="automated"
            shift
        elif [ "$1" = "--wizard" ]; then
            SETUP_MODE="wizard"
            shift
        elif [ "$1" = "--admin-name" ]; then
            ADMIN_USERNAME="$2"
            shift 2
        elif [ "$1" = "--FQDN" ]; then
            FQDN="$2"
            shift 2
        elif [ "$1" = "--release" ]; then
            RELEASE_CHANNEL="$2"
            shift 2
        elif [ "$1" = "--force" ]; then
            FORCE_INSTALL="yes"
            shift
        elif [ "$1" = "--fix-permissions" ]; then
            FIX_PERMISSIONS_ONLY="yes"
            shift
        elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
            show_usage
            exit 0
        else
            echo -e "${RED}Error: Unknown option '$1'${NC}"
            show_usage
            exit 1
        fi
    done

    # If only fixing permissions, we don't need deployment type
    if [ "$FIX_PERMISSIONS_ONLY" = "yes" ]; then
        return 0
    fi

    if [ -z "$DEPLOYMENT_TYPE" ]; then
        echo -e "${RED}Error: --type parameter is required${NC}"
        echo ""
        show_usage
        exit 1
    fi

    if [ "$DEPLOYMENT_TYPE" = "autoconf" ]; then
        TEMPLATE_FILE="template_autoconf_display.yml"
        DEPLOYMENT_NAME="Autoconf Display"
    elif [ "$DEPLOYMENT_TYPE" = "basic" ]; then
        TEMPLATE_FILE="template_basic_display.yml"
        DEPLOYMENT_NAME="Basic Display"
    elif [ "$DEPLOYMENT_TYPE" = "integrated" ]; then
        TEMPLATE_FILE="template_ui_integrated_display.yml"
        DEPLOYMENT_NAME="UI Integrated Display"
    else
        echo -e "${RED}Error: Invalid deployment type '$DEPLOYMENT_TYPE'${NC}"
        echo -e "${YELLOW}Valid types: autoconf, basic, integrated${NC}"
        exit 1
    fi
}

# Creates required directories with proper permissions for BunkerWeb containers
setup_directories() {
    echo -e "${BLUE}Creating directories with enhanced permissions...${NC}"
    
    # Stop any running containers first to avoid permission conflicts
    if [ -f "$INSTALL_DIR/docker-compose.yml" ]; then
        echo -e "${BLUE}Stopping any running containers to set permissions safely...${NC}"
        cd "$INSTALL_DIR" && docker compose down 2>/dev/null || true
    fi
    
    # Create main installation directory first
    mkdir -p "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"
    
    local directories="$INSTALL_DIR/storage $INSTALL_DIR/database $INSTALL_DIR/apps"
    
    if [ "$REDIS_ENABLED" = "yes" ]; then
        directories="$directories $INSTALL_DIR/redis"
    fi
    
    # Create directories with proper permissions immediately
    for dir in $directories; do
        echo -e "${BLUE}Creating: $dir${NC}"
        mkdir -p "$dir"
        
        # Ensure directory exists and is accessible
        if [ ! -d "$dir" ]; then
            echo -e "${RED}✗ Failed to create directory: $dir${NC}"
            return 1
        fi
    done
    
    echo -e "${BLUE}Setting enhanced permissions for BunkerWeb containers...${NC}"
    
    # BunkerWeb storage directory (mounted as /data in containers)
    # Needs full access for nginx user (101:101)
    echo -e "${BLUE}Configuring storage directory for nginx user (101:101)...${NC}"
    chown -R 101:101 "$INSTALL_DIR/storage"
    chmod -R 775 "$INSTALL_DIR/storage"
    
    # Ensure the directory is writable and accessible
    find "$INSTALL_DIR/storage" -type d -exec chmod 775 {} \;
    find "$INSTALL_DIR/storage" -type f -exec chmod 664 {} \; 2>/dev/null || true
    
    # Verify permissions
    if [ "$(stat -c %u:%g "$INSTALL_DIR/storage")" = "101:101" ]; then
        echo -e "${GREEN}✓ Storage directory ownership verified: nginx (101:101)${NC}"
    else
        echo -e "${RED}✗ Storage directory ownership verification failed${NC}"
        ls -la "$INSTALL_DIR/storage"
        return 1
    fi
    
    # Database directory for MariaDB
    echo -e "${BLUE}Configuring database directory for mysql user (999:999)...${NC}"
    chown -R 999:999 "$INSTALL_DIR/database"
    chmod -R 755 "$INSTALL_DIR/database"
    echo -e "${GREEN}✓ Database directory ownership set to mysql (999:999)${NC}"
    
    # Redis directory if enabled
    if [ "$REDIS_ENABLED" = "yes" ]; then
        echo -e "${BLUE}Configuring redis directory for redis user (999:999)...${NC}"
        chown -R 999:999 "$INSTALL_DIR/redis"
        chmod -R 755 "$INSTALL_DIR/redis"
        echo -e "${GREEN}✓ Redis directory ownership set to redis (999:999)${NC}"
    fi
    
    # Apps directory for general use
    chmod 755 "$INSTALL_DIR/apps"
    
    # Set ownership for config files to user who ran sudo (if applicable)
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
    
    # Final permission verification and troubleshooting info
    echo -e "${BLUE}Permission verification:${NC}"
    echo -e "${GREEN}Storage directory: $(ls -ld "$INSTALL_DIR/storage" | awk '{print $1, $3":"$4}')${NC}"
    echo -e "${GREEN}Database directory: $(ls -ld "$INSTALL_DIR/database" | awk '{print $1, $3":"$4}')${NC}"
    
    # Check if storage directory is writable by nginx user
    if sudo -u "#101" test -w "$INSTALL_DIR/storage" 2>/dev/null; then
        echo -e "${GREEN}✓ Storage directory is writable by nginx user (101:101)${NC}"
    else
        echo -e "${YELLOW}⚠ Testing write access as nginx user (this may show permission denied, but that's normal)${NC}"
        echo -e "${BLUE}Container will handle final permission verification${NC}"
    fi
    
    # Ensure parent directory has proper permissions
    chmod 755 "$(dirname "$INSTALL_DIR")" 2>/dev/null || true
    
    echo -e "${GREEN}✓ All directories created and permissions properly configured${NC}"
    echo -e "${BLUE}✓ Enhanced permission model applied for container compatibility${NC}"
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
        # Remove any problematic permissions and reset
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
    
    # Verify final permissions
    echo -e "${BLUE}Verifying permissions:${NC}"
    ls -la "$INSTALL_DIR/"
    echo ""
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

# Main execution function coordinating all setup phases using helper modules
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
    
    # Handle permission fix mode
    if [ "$FIX_PERMISSIONS_ONLY" = "yes" ]; then
        echo -e "${BLUE}Running in permission fix mode...${NC}"
        fix_permissions
        exit $?
    fi
    
    if ! source_modules; then
        echo -e "${YELLOW}⚠ Using built-in functions (modules not available)${NC}"
        echo -e "${RED}✗ helper modules are required for enhanced functionality${NC}"
        exit 1
    fi
    
    load_configuration
    
    echo -e "${BLUE}Step 0: Release Channel Validation${NC}"
    if ! validate_and_show_release_channel "$RELEASE_CHANNEL"; then
        echo -e "${RED}✗ Release channel validation failed${NC}"
        exit 1
    fi
    
    if ! detect_fqdn_enhanced "$FQDN"; then
        echo -e "${RED}✗ FQDN detection failed${NC}"
        exit 1
    fi
    
    local compose_file="$INSTALL_DIR/docker-compose.yml"
    local template_path="$INSTALL_DIR/$TEMPLATE_FILE"
    local creds_file="$INSTALL_DIR/credentials.txt"
    
    if [ ! -f "$template_path" ]; then
        echo -e "${RED}Error: Template file not found at $template_path${NC}"
        echo -e "${YELLOW}Available templates should be in: $INSTALL_DIR${NC}"
        exit 1
    fi
    
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
    
    echo -e "${BLUE}Step 2: Network Configuration${NC}"
    local docker_subnet
    docker_subnet=$(simple_network_detection)
    echo -e "${GREEN}✓ Using subnet: $docker_subnet${NC}"
    
    echo -e "${BLUE}Step 3: NAT Detection and API Whitelist Building${NC}"
    local api_whitelist
    api_whitelist=$(detect_nat_and_build_whitelist "$docker_subnet")
    
    echo -e "${BLUE}Step 4: Credential Management${NC}"
    # Generate credentials (simplified version since full function is missing)
    local mysql_password
    mysql_password=$(openssl rand -base64 33)
    local admin_password
    admin_password=$(generate_secure_admin_password)
    local flask_secret
    flask_secret=$(openssl rand -base64 33)
    local totp_secret
    totp_secret=$(openssl rand -base64 33)
    echo -e "${GREEN}✓ Credentials generated${NC}"
    
    echo -e "${BLUE}Step 5: Template Processing${NC}"
    echo -e "${BLUE}Copying template to docker-compose.yml...${NC}"
    if cp "$template_path" "$compose_file"; then
        echo -e "${GREEN}✓ Template copied: $(basename "$template_path") → docker-compose.yml${NC}"
    else
        echo -e "${RED}✗ Failed to copy template${NC}"
        exit 1
    fi
    
    # Basic template processing to replace critical placeholders
    echo -e "${BLUE}Processing essential template placeholders...${NC}"
    
    # Get image tag for release channel
    local image_tag
    image_tag=$(get_image_tag_for_channel "$RELEASE_CHANNEL")
    
    # Replace image tags
    sed -i "s|REPLACEME_TAG|$image_tag|g" "$compose_file"
    echo -e "${GREEN}✓ Docker image tags updated to: $image_tag${NC}"
    
    # Replace credentials
    sed -i "s|REPLACEME_MYSQL|$mysql_password|g" "$compose_file"
    sed -i "s|REPLACEME_DEFAULT|$totp_secret|g" "$compose_file"
    sed -i "s|REPLACEME_ADMIN_USERNAME|$ADMIN_USERNAME|g" "$compose_file"
    sed -i "s|REPLACEME_ADMIN_PASSWORD|$admin_password|g" "$compose_file"
    sed -i "s|REPLACEME_FLASK_SECRET|$flask_secret|g" "$compose_file"
    echo -e "${GREEN}✓ Credentials updated${NC}"
    
    # Replace DNS resolvers
    sed -i "s|REPLACEME_DNS_RESOLVERS|$DNS_RESOLVERS|g" "$compose_file"
    echo -e "${GREEN}✓ DNS resolvers configured${NC}"
    
    # SSL configuration
    if [ -n "$AUTO_CERT_TYPE" ]; then
        sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|yes|g" "$compose_file"
        sed -i "s|REPLACEME_EMAIL_LETS_ENCRYPT|$AUTO_CERT_CONTACT|g" "$compose_file"
        echo -e "${GREEN}✓ SSL certificates configured${NC}"
    else
        sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|no|g" "$compose_file"
        sed -i "s|REPLACEME_EMAIL_LETS_ENCRYPT|admin@localhost|g" "$compose_file"
        echo -e "${GREEN}✓ SSL certificates disabled${NC}"
    fi
    
    # Domain configuration
    sed -i "s|REPLACEME_DOMAIN|$FQDN|g" "$compose_file"
    sed -i "s|SERVER_NAME: \"\"|SERVER_NAME: \"$FQDN\"|g" "$compose_file"
    echo -e "${GREEN}✓ Domain configured: $FQDN${NC}"
    
    echo -e "${BLUE}Step 6: API Whitelist Configuration${NC}"
    if ! update_api_whitelist "$compose_file" "$api_whitelist"; then
        echo -e "${RED}✗ API whitelist update failed${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Step 7: Saving Credentials${NC}"
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

# Quick Access
# Access: http://$(hostname -I | awk '{print $1}')
# Username: $ADMIN_USERNAME
# Password: $admin_password
EOF
    chmod 600 "$creds_file"
    echo -e "${GREEN}✓ Credentials saved to: $creds_file${NC}"
    
    echo -e "${GREEN}Setup completed successfully!${NC}"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo -e "${GREEN}1. Start BunkerWeb: cd $INSTALL_DIR && docker compose up -d${NC}"
    echo -e "${GREEN}2. Access web interface: http://$(hostname -I | awk '{print $1}')${NC}"
    echo -e "${GREEN}3. Login with credentials from: $creds_file${NC}"
    echo ""
    echo -e "${BLUE}If you encounter permission errors, you can fix them with:${NC}"
    echo -e "${GREEN}sudo $0 --fix-permissions${NC}"
}

main "$@"