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
if [[ -f "$INSTALL_DIR/BunkerWeb.conf" ]]; then
    source "$INSTALL_DIR/BunkerWeb.conf" 2>/dev/null || true
elif [[ -f "/root/BunkerWeb.conf" ]]; then
    source "/root/BunkerWeb.conf" 2>/dev/null || true
fi

# Enable debug mode if requested
if [[ "${DEBUG:-no}" == "yes" ]]; then
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
    password+="${uppercase:$((RANDOM % ${#uppercase})):1}"
    password+="${lowercase:$((RANDOM % ${#lowercase})):1}"
    password+="${numbers:$((RANDOM % ${#numbers})):1}"
    password+="${special_chars:$((RANDOM % ${#special_chars})):1}"
    
    # Add additional characters to reach desired length (minimum 12 characters)
    local all_chars="${uppercase}${lowercase}${numbers}${special_chars}"
    for i in {1..8}; do
        password+="${all_chars:$((RANDOM % ${#all_chars})):1}"
    done
    
    # Shuffle the password to randomize character positions
    echo "$password" | fold -w1 | shuf | tr -d '\n'
}

# Validates that a password meets security requirements
validate_password_requirements() {
    local password="$1"
    
    # Check minimum length
    if [[ ${#password} -lt 8 ]]; then
        return 1
    fi
    
    # Check for at least one lowercase letter
    if [[ ! "$password" =~ [a-z] ]]; then
        return 1
    fi
    
    # Check for at least one uppercase letter
    if [[ ! "$password" =~ [A-Z] ]]; then
        return 1
    fi
    
    # Check for at least one number
    if [[ ! "$password" =~ [0-9] ]]; then
        return 1
    fi
    
    # Check for at least one special character
    if [[ ! "$password" =~ [#$@!%*+=?] ]]; then
        return 1
    fi
    
    return 0
}

# Generates random 8-character string for secure UI access path
generate_random_ui_path() {
    local chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local random_path=""
    
    for i in {1..8}; do
        random_path+="${chars:$((RANDOM % ${#chars})):1}"
    done
    
    echo "$random_path"
}

# Loads and initializes modular helper scripts including NAT detection and FQDN helpers
source_modules() {
    local modules=(
        "helper_password_manager.sh"
        "helper_network_detection.sh" 
        "helper_template_processor.sh"
        "helper_net_fqdn.sh"
        "helper_net_nat.sh"
        "helper_greylist.sh"
        "helper_allowlist.sh"
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
        
        local image_tag=$(get_image_tag_for_channel "$channel")
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
    
    if [[ -n "$AUTO_CERT_TYPE" ]]; then
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
        
        if [[ "$FQDN_LOG_LEVEL" == "DEBUG" ]]; then
            show_fqdn_summary "$detected_fqdn"
        fi
        
        FQDN="$detected_fqdn"
        
        if [[ -z "$SERVER_NAME" ]]; then
            SERVER_NAME="$detected_fqdn"
        fi
        
        echo ""
        echo -e "${GREEN}Final FQDN Configuration:${NC}"
        echo -e "${GREEN}• FQDN: $FQDN${NC}"
        echo -e "${GREEN}• Server Name: $SERVER_NAME${NC}"
        echo -e "${GREEN}• Detection Method: $(get_detection_method)${NC}"
        
        if [[ -n "$AUTO_CERT_TYPE" ]]; then
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
        
        if [[ "$FQDN_REQUIRE_SSL" == "yes" ]]; then
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
    
    if [[ -n "$docker_subnet" ]]; then
        api_whitelist="$api_whitelist $docker_subnet"
        echo -e "${GREEN}• Added main subnet: $docker_subnet${NC}"
    fi
    
    echo -e "${BLUE}Adding Docker Compose network ranges...${NC}"
    
    local docker_ranges=(
        "172.16.0.0/12"
        "172.17.0.0/16"
        "172.18.0.0/16"
        "172.19.0.0/16"  
        "172.20.0.0/16"
        "172.21.0.0/16"
        "172.22.0.0/16"
        "172.23.0.0/16"
        "172.24.0.0/16"
        "172.25.0.0/16"
    )
    
    for range in "${docker_ranges[@]}"; do
        if [[ ! "$api_whitelist" =~ $range ]]; then
            api_whitelist="$api_whitelist $range"
            echo -e "${GREEN}• Added Docker range: $range${NC}"
        fi
    done
    
    if command -v docker >/dev/null 2>&1; then
        echo -e "${BLUE}Detecting existing Docker networks...${NC}"
        
        local existing_networks=()
        while IFS= read -r line; do
            if [[ "$line" =~ \"Subnet\":[[:space:]]*\"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+)\" ]]; then
                local network="${BASH_REMATCH[1]}"
                existing_networks+=("$network")
            fi
        done < <(docker network ls -q 2>/dev/null | xargs -I {} docker network inspect {} 2>/dev/null | \
                 grep -E "\"Subnet\":" || true)
        
        for network in "${existing_networks[@]}"; do
            if [[ "$network" =~ ^10\. ]] || [[ "$network" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || \
               [[ "$network" =~ ^192\.168\. ]]; then
                if [[ ! "$api_whitelist" =~ $network ]]; then
                    api_whitelist="$api_whitelist $network"
                    echo -e "${GREEN}• Added existing Docker network: $network${NC}"
                fi
            fi
        done
    fi
    
    echo -e "${BLUE}Adding broader private network ranges for safety...${NC}"
    local broad_ranges=(
        "10.0.0.0/8"
        "192.168.0.0/16"
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

# Updates API whitelist entries in docker-compose file
update_api_whitelist() {
    local compose_file="$1"
    local api_whitelist="$2"
    
    echo -e "${BLUE}Updating API whitelist in docker-compose.yml...${NC}"
    
    local escaped_whitelist=$(printf '%s\n' "$api_whitelist" | sed 's/[[\.*^$()+?{|]/\\&/g')
    
    if sed -i "s|API_WHITELIST_IP: \".*\"|API_WHITELIST_IP: \"$escaped_whitelist\"|g" "$compose_file"; then
        echo -e "${GREEN}✓ API whitelist updated successfully${NC}"
        
        local updated_count=$(grep -c "API_WHITELIST_IP:" "$compose_file" || echo "0")
        echo -e "${GREEN}✓ Updated $updated_count API_WHITELIST_IP entries${NC}"
        
        echo -e "${BLUE}Verification - Updated API whitelist entries:${NC}"
        grep "API_WHITELIST_IP:" "$compose_file" | sed 's/^\s*/  /' | cut -c1-100 | sed 's/$/.../'
        
        return 0
    else
        echo -e "${RED}✗ Failed to update API whitelist${NC}"
        return 1
    fi
}

# Adds BunkerWeb labels to bw-ui service and synchronizes with scheduler configuration
add_bw_ui_labels() {
    local compose_file="$1"
    local fqdn="$2"
    
    echo -e "${BLUE}Adding BunkerWeb labels to bw-ui service and syncing with scheduler...${NC}"
    
    local random_ui_path=$(generate_random_ui_path)
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
    
    if [[ -f "${compose_file%/*}/credentials.txt" ]]; then
        echo "" >> "${compose_file%/*}/credentials.txt"
        echo "# BunkerWeb UI Access Information" >> "${compose_file%/*}/credentials.txt"
        echo "UI Access Path: /$random_ui_path" >> "${compose_file%/*}/credentials.txt"
        echo "Full UI URL: http://$fqdn/$random_ui_path" >> "${compose_file%/*}/credentials.txt"
        echo "Direct Access: http://$(hostname -I | awk '{print $1}')/$random_ui_path" >> \
             "${compose_file%/*}/credentials.txt"
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
    
    if [[ "$setup_mode" == "automated" ]]; then
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
    
    if [[ ! -f "$template_file" ]]; then
        echo -e "${RED}✗ Template file not found: $template_file${NC}"
        return 1
    fi
    
    if [[ -z "$image_tag" ]]; then
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
    
    local backup_file=$(create_backup "$compose_file" "template-processing")
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
        ((processing_errors++))
    fi
    
    echo -e "${BLUE}2. Processing basic credentials...${NC}"
    if [[ -n "$mysql_password" ]]; then
        sed -i "s|REPLACEME_MYSQL|$mysql_password|g" "$compose_file"
        echo -e "${GREEN}✓ MySQL password updated${NC}"
    fi
    
    if [[ "$redis_enabled" == "yes" && -n "$redis_password" ]]; then
        sed -i "s|REPLACEME_REDIS_PASSWORD|$redis_password|g" "$compose_file"
        echo -e "${GREEN}✓ Redis password updated${NC}"
    else
        sed -i "s|REPLACEME_REDIS_PASSWORD|disabled|g" "$compose_file"
        echo -e "${GREEN}✓ Redis password set to disabled${NC}"
    fi
    
    if [[ -n "$totp_secret" ]]; then
        sed -i "s|REPLACEME_DEFAULT|$totp_secret|g" "$compose_file"
        echo -e "${GREEN}✓ TOTP secret updated${NC}"
    fi
    
    echo -e "${BLUE}3. Processing network configuration...${NC}"
    if [[ -n "$docker_subnet" ]]; then
        local default_subnet="10.20.30.0/24"
        if [[ "$docker_subnet" != "$default_subnet" ]]; then
            sed -i "s|$default_subnet|$docker_subnet|g" "$compose_file"
            echo -e "${GREEN}✓ Docker subnet updated to: $docker_subnet${NC}"
        fi
    fi
    
    echo -e "${BLUE}4. Processing DNS configuration...${NC}"
    if replace_dns_resolvers "$compose_file" "${DNS_RESOLVERS:-127.0.0.11}"; then
        echo -e "${GREEN}✓ DNS resolvers configured${NC}"
    else
        echo -e "${RED}✗ Failed to configure DNS resolvers${NC}"
        ((processing_errors++))
    fi
    
    echo -e "${BLUE}5. Processing HTTP/3 configuration...${NC}"
    if [[ -n "$HTTP3" ]]; then
        sed -i "s|HTTP3: \"yes\"|HTTP3: \"$HTTP3\"|g" "$compose_file"
        echo -e "${GREEN}✓ HTTP3 configured: $HTTP3${NC}"
    fi
    
    if [[ -n "$HTTP3_ALT_SVC_PORT" ]]; then
        sed -i "s|HTTP3_ALT_SVC_PORT: \"443\"|HTTP3_ALT_SVC_PORT: \"$HTTP3_ALT_SVC_PORT\"|g" \
               "$compose_file"
        echo -e "${GREEN}✓ HTTP3 alternate service port: $HTTP3_ALT_SVC_PORT${NC}"
    fi
    
    echo -e "${BLUE}6. Processing Let's Encrypt configuration...${NC}"
    if [[ -n "$LETS_ENCRYPT_CHALLENGE" ]]; then
        sed -i "s|LETS_ENCRYPT_CHALLENGE: \"http\"|LETS_ENCRYPT_CHALLENGE: \"$LETS_ENCRYPT_CHALLENGE\"|g" \
               "$compose_file"
        echo -e "${GREEN}✓ Let's Encrypt challenge type: $LETS_ENCRYPT_CHALLENGE${NC}"
    fi
    
    if [[ -n "$LETS_ENCRYPT_STAGING" ]]; then
        sed -i "s|USE_LETS_ENCRYPT_STAGING: \"yes\"|USE_LETS_ENCRYPT_STAGING: \"$LETS_ENCRYPT_STAGING\"|g" \
               "$compose_file"
        echo -e "${GREEN}✓ Let's Encrypt staging: $LETS_ENCRYPT_STAGING${NC}"
    fi
    
    echo -e "${BLUE}7. Processing multisite configuration...${NC}"
    if [[ -n "$MULTISITE" ]]; then
        sed -i "s|MULTISITE: \"yes\"|MULTISITE: \"$MULTISITE\"|g" "$compose_file"
        echo -e "${GREEN}✓ Multisite mode: $MULTISITE${NC}"
    fi
    
    echo -e "${BLUE}8. Processing ModSecurity and SSL configuration...${NC}"
    if [[ -n "$USE_MODSECURITY_GLOBAL_CRS" ]]; then
        sed -i "s|USE_MODSECURITY_GLOBAL_CRS: \"yes\"|USE_MODSECURITY_GLOBAL_CRS: \"$USE_MODSECURITY_GLOBAL_CRS\"|g" \
               "$compose_file"
        echo -e "${GREEN}✓ ModSecurity Global CRS: $USE_MODSECURITY_GLOBAL_CRS${NC}"
    fi
    
    if [[ -n "$SSL_PROTOCOLS" ]]; then
        sed -i "s|SSL_PROTOCOLS: \"TLSv1.2 TLSv1.3\"|SSL_PROTOCOLS: \"$SSL_PROTOCOLS\"|g" "$compose_file"
        echo -e "${GREEN}✓ SSL Protocols: $SSL_PROTOCOLS${NC}"
    fi
    
    if [[ -n "$SSL_CIPHERS_CUSTOM" ]]; then
        sed -i "s|#SSL_CIPHERS_CUSTOM: \".*\"|SSL_CIPHERS_CUSTOM: \"$SSL_CIPHERS_CUSTOM\"|g" "$compose_file"
        echo -e "${GREEN}✓ Custom SSL Ciphers configured${NC}"
    else
        echo -e "${BLUE}ℹ Custom SSL Ciphers disabled (using defaults)${NC}"
    fi
    
    echo -e "${BLUE}9. Processing Demo Site configuration...${NC}"
    if [[ "$DEMOSITE" == "yes" ]]; then
        sed -i "s|REPLACEME_DOMAIN_demo_USE_REVERSE_PROXY|${fqdn}_demo_USE_REVERSE_PROXY|g" "$compose_file"
        sed -i "s|REPLACEME_DOMAIN_demo_REVERSE_PROXY_URL|${fqdn}_demo_REVERSE_PROXY_URL|g" "$compose_file"
        sed -i "s|REPLACEME_DOMAIN_demo_REVERSE_PROXY_HOST|${fqdn}_demo_REVERSE_PROXY_HOST|g" "$compose_file"
        
        echo -e "${GREEN}✓ Demo site enabled and configured${NC}"
        echo -e "${GREEN}✓ Demo site accessible at: http://$fqdn/demo${NC}"
    else
        sed -i '/# Demo application/,/bw-services/d' "$compose_file"
        sed -i '/REPLACEME_DOMAIN_demo_/d' "$compose_file"
        echo -e "${BLUE}ℹ Demo site disabled and removed${NC}"
    fi
    
    echo -e "${BLUE}10. Processing Blacklist configuration...${NC}"
    if [[ "$USE_BLACKLIST" == "yes" ]]; then
        sed -i "s|USE_BLACKLIST: \"yes\"|USE_BLACKLIST: \"$USE_BLACKLIST\"|g" "$compose_file"
        echo -e "${GREEN}✓ Blacklist feature enabled${NC}"
        
        if [[ -n "$BLACKLIST_IP" ]]; then
            sed -i "s|BLACKLIST_IP: \".*\"|BLACKLIST_IP: \"$BLACKLIST_IP\"|g" "$compose_file"
            echo -e "${GREEN}✓ Blacklist IP addresses: $BLACKLIST_IP${NC}"
        fi
        
        if [[ -n "$BLACKLIST_RDNS" ]]; then
            sed -i "s|BLACKLIST_RDNS: \"\.shodan\.io \.censys\.io\"|BLACKLIST_RDNS: \"$BLACKLIST_RDNS\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist rDNS configured: $BLACKLIST_RDNS${NC}"
        fi
        
        if [[ -n "$BLACKLIST_RDNS_GLOBAL" ]]; then
            sed -i "s|BLACKLIST_RDNS_GLOBAL: \"yes\"|BLACKLIST_RDNS_GLOBAL: \"$BLACKLIST_RDNS_GLOBAL\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist rDNS global mode: $BLACKLIST_RDNS_GLOBAL${NC}"
        fi
        
        if [[ -n "$BLACKLIST_ASN" ]]; then
            sed -i "s|BLACKLIST_ASN: \".*\"|BLACKLIST_ASN: \"$BLACKLIST_ASN\"|g" "$compose_file"
            echo -e "${GREEN}✓ Blacklist ASN numbers: $BLACKLIST_ASN${NC}"
        fi
        
        if [[ -n "$BLACKLIST_USER_AGENT" ]]; then
            sed -i "s|BLACKLIST_USER_AGENT: \".*\"|BLACKLIST_USER_AGENT: \"$BLACKLIST_USER_AGENT\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist User-Agent patterns: $BLACKLIST_USER_AGENT${NC}"
        fi
        
        if [[ -n "$BLACKLIST_URI" ]]; then
            sed -i "s|BLACKLIST_URI: \".*\"|BLACKLIST_URI: \"$BLACKLIST_URI\"|g" "$compose_file"
            echo -e "${GREEN}✓ Blacklist URI patterns: $BLACKLIST_URI${NC}"
        fi
        
        if [[ -n "$BLACKLIST_COUNTRY" ]]; then
            sed -i "s|BLACKLIST_COUNTRY: \".*\"|BLACKLIST_COUNTRY: \"$BLACKLIST_COUNTRY\"|g" "$compose_file"
            echo -e "${GREEN}✓ Blacklist countries: $BLACKLIST_COUNTRY${NC}"
        fi
        
        if [[ -n "$BLACKLIST_IGNORE_IP" ]]; then
            sed -i "s|BLACKLIST_IGNORE_IP: \".*\"|BLACKLIST_IGNORE_IP: \"$BLACKLIST_IGNORE_IP\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist ignore IP addresses: $BLACKLIST_IGNORE_IP${NC}"
        fi
        
        if [[ -n "$BLACKLIST_IGNORE_RDNS" ]]; then
            sed -i "s|BLACKLIST_IGNORE_RDNS: \".*\"|BLACKLIST_IGNORE_RDNS: \"$BLACKLIST_IGNORE_RDNS\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist ignore rDNS: $BLACKLIST_IGNORE_RDNS${NC}"
        fi
        
        if [[ -n "$BLACKLIST_IGNORE_ASN" ]]; then
            sed -i "s|BLACKLIST_IGNORE_ASN: \".*\"|BLACKLIST_IGNORE_ASN: \"$BLACKLIST_IGNORE_ASN\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist ignore ASN: $BLACKLIST_IGNORE_ASN${NC}"
        fi
        
        if [[ -n "$BLACKLIST_IGNORE_USER_AGENT" ]]; then
            sed -i "s|BLACKLIST_IGNORE_USER_AGENT: \".*\"|BLACKLIST_IGNORE_USER_AGENT: \"$BLACKLIST_IGNORE_USER_AGENT\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist ignore User-Agent: $BLACKLIST_IGNORE_USER_AGENT${NC}"
        fi
        
        if [[ -n "$BLACKLIST_IGNORE_URI" ]]; then
            sed -i "s|BLACKLIST_IGNORE_URI: \".*\"|BLACKLIST_IGNORE_URI: \"$BLACKLIST_IGNORE_URI\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist ignore URI: $BLACKLIST_IGNORE_URI${NC}"
        fi
        
        if [[ -n "$BLACKLIST_IP_URLS" ]]; then
            local escaped_ip_urls=$(printf '%s\n' "$BLACKLIST_IP_URLS" | sed 's/[[\.*^$()+?{|]/\\&/g')
            sed -i "s|BLACKLIST_IP_URLS: \".*\"|BLACKLIST_IP_URLS: \"$escaped_ip_urls\"|g" "$compose_file"
            echo -e "${GREEN}✓ Blacklist IP URLs: TOR exit nodes + FireHOL Level 3${NC}"
        fi
        
        if [[ -n "$BLACKLIST_RDNS_URLS" ]]; then
            local escaped_rdns_urls=$(printf '%s\n' "$BLACKLIST_RDNS_URLS" | sed 's/[[\.*^$()+?{|]/\\&/g')
            sed -i "s|BLACKLIST_RDNS_URLS: \".*\"|BLACKLIST_RDNS_URLS: \"$escaped_rdns_urls\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist rDNS URLs: $BLACKLIST_RDNS_URLS${NC}"
        fi
        
        if [[ -n "$BLACKLIST_ASN_URLS" ]]; then
            local escaped_asn_urls=$(printf '%s\n' "$BLACKLIST_ASN_URLS" | sed 's/[[\.*^$()+?{|]/\\&/g')
            sed -i "s|BLACKLIST_ASN_URLS: \".*\"|BLACKLIST_ASN_URLS: \"$escaped_asn_urls\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist ASN URLs: $BLACKLIST_ASN_URLS${NC}"
        fi
        
        if [[ -n "$BLACKLIST_USER_AGENT_URLS" ]]; then
            local escaped_ua_urls=$(printf '%s\n' "$BLACKLIST_USER_AGENT_URLS" | sed 's/[[\.*^$()+?{|]/\\&/g')
            sed -i "s|BLACKLIST_USER_AGENT_URLS: \".*\"|BLACKLIST_USER_AGENT_URLS: \"$escaped_ua_urls\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist User-Agent URLs: Bad bot blocker list${NC}"
        fi
        
        if [[ -n "$BLACKLIST_URI_URLS" ]]; then
            local escaped_uri_urls=$(printf '%s\n' "$BLACKLIST_URI_URLS" | sed 's/[[\.*^$()+?{|]/\\&/g')
            sed -i "s|BLACKLIST_URI_URLS: \".*\"|BLACKLIST_URI_URLS: \"$escaped_uri_urls\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist URI URLs: $BLACKLIST_URI_URLS${NC}"
        fi
        
        if [[ -n "$BLACKLIST_IGNORE_IP_URLS" ]]; then
            local escaped_ignore_ip_urls=$(printf '%s\n' "$BLACKLIST_IGNORE_IP_URLS" | \
                                          sed 's/[[\.*^$()+?{|]/\\&/g')
            sed -i "s|BLACKLIST_IGNORE_IP_URLS: \".*\"|BLACKLIST_IGNORE_IP_URLS: \"$escaped_ignore_ip_urls\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist ignore IP URLs: $BLACKLIST_IGNORE_IP_URLS${NC}"
        fi
        
        if [[ -n "$BLACKLIST_IGNORE_RDNS_URLS" ]]; then
            local escaped_ignore_rdns_urls=$(printf '%s\n' "$BLACKLIST_IGNORE_RDNS_URLS" | \
                                            sed 's/[[\.*^$()+?{|]/\\&/g')
            sed -i "s|BLACKLIST_IGNORE_RDNS_URLS: \".*\"|BLACKLIST_IGNORE_RDNS_URLS: \"$escaped_ignore_rdns_urls\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist ignore rDNS URLs: $BLACKLIST_IGNORE_RDNS_URLS${NC}"
        fi
        
        if [[ -n "$BLACKLIST_IGNORE_ASN_URLS" ]]; then
            local escaped_ignore_asn_urls=$(printf '%s\n' "$BLACKLIST_IGNORE_ASN_URLS" | \
                                           sed 's/[[\.*^$()+?{|]/\\&/g')
            sed -i "s|BLACKLIST_IGNORE_ASN_URLS: \".*\"|BLACKLIST_IGNORE_ASN_URLS: \"$escaped_ignore_asn_urls\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist ignore ASN URLs: $BLACKLIST_IGNORE_ASN_URLS${NC}"
        fi
        
        if [[ -n "$BLACKLIST_IGNORE_USER_AGENT_URLS" ]]; then
            local escaped_ignore_ua_urls=$(printf '%s\n' "$BLACKLIST_IGNORE_USER_AGENT_URLS" | \
                                          sed 's/[[\.*^$()+?{|]/\\&/g')
            sed -i "s|BLACKLIST_IGNORE_USER_AGENT_URLS: \".*\"|BLACKLIST_IGNORE_USER_AGENT_URLS: \"$escaped_ignore_ua_urls\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist ignore User-Agent URLs: $BLACKLIST_IGNORE_USER_AGENT_URLS${NC}"
        fi
        
        if [[ -n "$BLACKLIST_IGNORE_URI_URLS" ]]; then
            local escaped_ignore_uri_urls=$(printf '%s\n' "$BLACKLIST_IGNORE_URI_URLS" | \
                                           sed 's/[[\.*^$()+?{|]/\\&/g')
            sed -i "s|BLACKLIST_IGNORE_URI_URLS: \".*\"|BLACKLIST_IGNORE_URI_URLS: \"$escaped_ignore_uri_urls\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Blacklist ignore URI URLs: $BLACKLIST_IGNORE_URI_URLS${NC}"
        fi
        
        if [[ -n "$DNSBL_LIST" ]]; then
            sed -i "s|USE_DNSBL: \"yes\"|USE_DNSBL: \"yes\"|g" "$compose_file"
            sed -i "s|DNSBL_LIST: \".*\"|DNSBL_LIST: \"$DNSBL_LIST\"|g" "$compose_file"
            echo -e "${GREEN}✓ DNSBL enabled with lists: $DNSBL_LIST${NC}"
        fi
        
        echo -e "${GREEN}✓ External blocklists will be automatically downloaded and updated${NC}"
        echo -e "${GREEN}✓ Blocking TOR exit nodes, FireHOL Level 3 threats, and malicious bots${NC}"
        echo -e "${GREEN}✓ Scanning services (Shodan, Censys) blocked by rDNS${NC}"
    else
        sed -i "s|USE_BLACKLIST: \"yes\"|USE_BLACKLIST: \"no\"|g" "$compose_file"
        echo -e "${BLUE}ℹ Blacklist feature disabled${NC}"
    fi
    
    echo -e "${BLUE}10a. Processing Allowlist configuration...${NC}"
    if [[ "$USE_ALLOWLIST" == "yes" ]]; then
        sed -i "s|USE_ALLOWLIST: \"yes\"|USE_ALLOWLIST: \"$USE_ALLOWLIST\"|g" "$compose_file"
        echo -e "${GREEN}✓ Allowlist feature enabled${NC}"
        
        if [[ -n "$ALLOWLIST_IP" ]]; then
            sed -i "s|ALLOWLIST_IP: \".*\"|ALLOWLIST_IP: \"$ALLOWLIST_IP\"|g" "$compose_file"
            echo -e "${GREEN}✓ Allowlist IP addresses: $ALLOWLIST_IP${NC}"
        fi
        
        if [[ -n "$ALLOWLIST_COUNTRY" ]]; then
            sed -i "s|ALLOWLIST_COUNTRY: \".*\"|ALLOWLIST_COUNTRY: \"$ALLOWLIST_COUNTRY\"|g" "$compose_file"
            echo -e "${GREEN}✓ Allowlist countries: $ALLOWLIST_COUNTRY${NC}"
        fi
        
        if [[ -n "$ALLOWLIST_RDNS" ]]; then
            sed -i "s|ALLOWLIST_RDNS: \".*\"|ALLOWLIST_RDNS: \"$ALLOWLIST_RDNS\"|g" "$compose_file"
            echo -e "${GREEN}✓ Allowlist rDNS: $ALLOWLIST_RDNS${NC}"
        fi
        
        if [[ -n "$ALLOWLIST_MODE" ]]; then
            sed -i "s|ALLOWLIST_MODE: \"block\"|ALLOWLIST_MODE: \"$ALLOWLIST_MODE\"|g" "$compose_file"
            echo -e "${GREEN}✓ Allowlist mode: $ALLOWLIST_MODE${NC}"
        fi
        
        if [[ -n "$ALLOWLIST_STATUS_CODE" ]]; then
            sed -i "s|ALLOWLIST_STATUS_CODE: \"403\"|ALLOWLIST_STATUS_CODE: \"$ALLOWLIST_STATUS_CODE\"|g" \
                   "$compose_file"
            echo -e "${GREEN}✓ Allowlist status code: $ALLOWLIST_STATUS_CODE${NC}"
        fi
    else
        sed -i "s|USE_ALLOWLIST: \"yes\"|USE_ALLOWLIST: \"no\"|g" "$compose_file"
        echo -e "${BLUE}ℹ Allowlist feature disabled${NC}"
    fi
    
    echo -e "${BLUE}10b. Processing Greylist configuration...${NC}"
    if [[ "$USE_GREYLIST" == "yes" ]]; then
        sed -i "s|USE_GREYLIST: \"yes\"|USE_GREYLIST: \"$USE_GREYLIST\"|g" "$compose_file"
        echo -e "${GREEN}✓ Greylist feature enabled${NC}"
        
        if [[ -n "$GREYLIST_IP" ]]; then
            sed -i "s|GREYLIST_IP: \".*\"|GREYLIST_IP: \"$GREYLIST_IP\"|g" "$compose_file"
            echo -e "${GREEN}✓ Greylist IP addresses: $GREYLIST_IP${NC}"
        fi
        
        if [[ -n "$GREYLIST_RDNS" ]]; then
            sed -i "s|GREYLIST_RDNS: \".*\"|GREYLIST_RDNS: \"$GREYLIST_RDNS\"|g" "$compose_file"
            echo -e "${GREEN}✓ Greylist rDNS: $GREYLIST_RDNS${NC}"
        fi
    else
        sed -i "s|USE_GREYLIST: \"yes\"|USE_GREYLIST: \"no\"|g" "$compose_file"
        echo -e "${BLUE}ℹ Greylist feature disabled${NC}"
    fi
    
    echo -e "${BLUE}11. Processing SSL configuration...${NC}"
    if [[ -n "$auto_cert_type" ]]; then
        sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|yes|g" "$compose_file"
        sed -i "s|REPLACEME_EMAIL_LETS_ENCRYPT|$auto_cert_contact|g" "$compose_file"
        echo -e "${GREEN}✓ SSL certificates configured ($auto_cert_type)${NC}"
    else
        sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|no|g" "$compose_file"
        echo -e "${GREEN}✓ SSL certificates disabled${NC}"
    fi
    
    echo -e "${BLUE}12. Processing domain configuration...${NC}"
    if [[ -n "$fqdn" ]]; then
        sed -i "s|REPLACEME_DOMAIN|$fqdn|g" "$compose_file"
        sed -i "s|SERVER_NAME: \"\"|SERVER_NAME: \"$fqdn\"|g" "$compose_file"
        echo -e "${GREEN}✓ Domain configured: $fqdn${NC}"
    fi
    
    echo -e "${BLUE}13. Adding UI labels and syncing scheduler...${NC}"
    add_bw_ui_labels "$compose_file" "$fqdn"
    
    echo -e "${BLUE}14. Configuring setup mode and credentials...${NC}"
    configure_setup_mode "$compose_file" "$setup_mode" "$admin_username" "$admin_password" "$flask_secret"
    
    echo -e "${BLUE}15. Validating placeholder replacement...${NC}"
    local remaining_critical=$(grep -o "REPLACEME_MYSQL\|REPLACEME_DEFAULT\|REPLACEME_AUTO_LETS_ENCRYPT\|REPLACEME_EMAIL_LETS_ENCRYPT\|REPLACEME_TAG\|REPLACEME_DNS_RESOLVERS" \
                              "$compose_file" || true)
    if [[ -n "$remaining_critical" ]]; then
        echo -e "${RED}✗ Critical placeholders not replaced: $remaining_critical${NC}"
        return 1
    fi
    
    local scheduler_path=$(grep -o "${fqdn}_REVERSE_PROXY_URL.*" "$compose_file" | head -1 || echo "")
    local ui_path=$(grep -o "bunkerweb.REVERSE_PROXY_URL.*" "$compose_file" | head -1 || echo "")
    
    if [[ -n "$scheduler_path" && -n "$ui_path" ]]; then
        echo -e "${GREEN}✓ UI path synchronization verified${NC}"
        echo -e "${GREEN}  Scheduler: $scheduler_path${NC}"
        echo -e "${GREEN}  UI Labels: $ui_path${NC}"
    fi
    
    echo -e "${BLUE}16. Validating Docker Compose syntax...${NC}"
    local current_dir=$(pwd)
    cd "$(dirname "$compose_file")"
    if docker compose config >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Docker Compose syntax is valid${NC}"
        cd "$current_dir"
    else
        echo -e "${RED}✗ Docker Compose syntax error detected${NC}"
        echo -e "${YELLOW}Validation output:${NC}"
        docker compose config 2>&1 | head -10
        cd "$current_dir"
        return 1
    fi
    
    echo ""
    echo -e "${GREEN}✓ Template processing with release channel completed successfully${NC}"
    echo -e "${GREEN}✓ Release channel: $release_channel${NC}"
    echo -e "${GREEN}✓ Docker image tag: $image_tag${NC}"
    echo -e "${GREEN}✓ DNS resolvers: $DNS_RESOLVERS${NC}"
    echo -e "${GREEN}✓ HTTP/3 enabled: $HTTP3${NC}"
    echo -e "${GREEN}✓ Multisite mode: $MULTISITE${NC}"
    echo -e "${GREEN}✓ ModSecurity Global CRS: $USE_MODSECURITY_GLOBAL_CRS${NC}"
    echo -e "${GREEN}✓ SSL Protocols: $SSL_PROTOCOLS${NC}"
    echo -e "${GREEN}✓ Demo Site: $DEMOSITE${NC}"
    echo -e "${GREEN}✓ Blacklist: $USE_BLACKLIST${NC}"
    echo -e "${GREEN}✓ All placeholders properly replaced${NC}"
    echo -e "${GREEN}✓ Admin credentials correctly configured${NC}"
    echo -e "${GREEN}✓ UI path synchronized between scheduler and UI service${NC}"
    echo -e "${GREEN}✓ Setup mode properly configured: $setup_mode${NC}"
    
    return 0
}

# Loads configuration from BunkerWeb.conf file with validation
load_configuration() {
    local config_file="$INSTALL_DIR/BunkerWeb.conf"
    
    if [[ -f "$config_file" ]]; then
        echo -e "${BLUE}Loading configuration from $config_file...${NC}"
        source "$config_file"
        echo -e "${GREEN}✓ Configuration loaded${NC}"
        
        if [[ "${DEBUG:-no}" == "yes" ]]; then
            FQDN_LOG_LEVEL="DEBUG"
            LOG_LEVEL="DEBUG"
            echo -e "${GREEN}✓ Debug mode enabled - all log levels set to DEBUG${NC}"
        else
            FQDN_LOG_LEVEL="${FQDN_LOG_LEVEL:-INFO}"
            LOG_LEVEL="${LOG_LEVEL:-INFO}"
            echo -e "${BLUE}ℹ Debug mode disabled - using INFO log level${NC}"
        fi
        
        if [[ -n "${RELEASE_CHANNEL:-}" ]]; then
            RELEASE_CHANNEL="$RELEASE_CHANNEL"
            echo -e "${GREEN}✓ Release channel from config: $RELEASE_CHANNEL${NC}"
        else
            echo -e "${BLUE}ℹ No RELEASE_CHANNEL in config, using default: $RELEASE_CHANNEL${NC}"
        fi
        
        if [[ -n "${FQDN_REQUIRE_SSL:-}" ]]; then
            FQDN_REQUIRE_SSL="$FQDN_REQUIRE_SSL"
        fi
        if [[ -n "${FQDN_CHECK_DNS:-}" ]]; then
            FQDN_CHECK_DNS="$FQDN_CHECK_DNS"
        fi
        if [[ -n "${FQDN_ALLOW_LOCALHOST:-}" ]]; then
            FQDN_ALLOW_LOCALHOST="$FQDN_ALLOW_LOCALHOST"
        fi
        
        if [[ -n "${USE_MODSECURITY_GLOBAL_CRS:-}" ]]; then
            USE_MODSECURITY_GLOBAL_CRS="$USE_MODSECURITY_GLOBAL_CRS"
        fi
        if [[ -n "${SSL_PROTOCOLS:-}" ]]; then
            SSL_PROTOCOLS="$SSL_PROTOCOLS"
        fi
        if [[ -n "${SSL_CIPHERS_CUSTOM:-}" ]]; then
            SSL_CIPHERS_CUSTOM="$SSL_CIPHERS_CUSTOM"
        fi
        
        if [[ -n "${DEMOSITE:-}" ]]; then
            DEMOSITE="$DEMOSITE"
        fi
        if [[ -n "${DEMOSITE_USE_REVERSE_DNS:-}" ]]; then
            DEMOSITE_USE_REVERSE_DNS="$DEMOSITE_USE_REVERSE_DNS"
        fi
        
        if [[ -n "${USE_BLACKLIST:-}" ]]; then
            USE_BLACKLIST="$USE_BLACKLIST"
        fi
        if [[ -n "${BLACKLIST_IP:-}" ]]; then
            BLACKLIST_IP="$BLACKLIST_IP"
        fi
        if [[ -n "${BLACKLIST_RDNS:-}" ]]; then
            BLACKLIST_RDNS="$BLACKLIST_RDNS"
        fi
        if [[ -n "${BLACKLIST_RDNS_GLOBAL:-}" ]]; then
            BLACKLIST_RDNS_GLOBAL="$BLACKLIST_RDNS_GLOBAL"
        fi
        if [[ -n "${BLACKLIST_ASN:-}" ]]; then
            BLACKLIST_ASN="$BLACKLIST_ASN"
        fi
        if [[ -n "${BLACKLIST_USER_AGENT:-}" ]]; then
            BLACKLIST_USER_AGENT="$BLACKLIST_USER_AGENT"
        fi
        if [[ -n "${BLACKLIST_URI:-}" ]]; then
            BLACKLIST_URI="$BLACKLIST_URI"
        fi
        if [[ -n "${BLACKLIST_IP_URLS:-}" ]]; then
            BLACKLIST_IP_URLS="$BLACKLIST_IP_URLS"
        fi
        if [[ -n "${BLACKLIST_RDNS_URLS:-}" ]]; then
            BLACKLIST_RDNS_URLS="$BLACKLIST_RDNS_URLS"
        fi
        if [[ -n "${BLACKLIST_ASN_URLS:-}" ]]; then
            BLACKLIST_ASN_URLS="$BLACKLIST_ASN_URLS"
        fi
        if [[ -n "${BLACKLIST_USER_AGENT_URLS:-}" ]]; then
            BLACKLIST_USER_AGENT_URLS="$BLACKLIST_USER_AGENT_URLS"
        fi
        if [[ -n "${BLACKLIST_URI_URLS:-}" ]]; then
            BLACKLIST_URI_URLS="$BLACKLIST_URI_URLS"
        fi
        
        if [[ -n "${LETS_ENCRYPT_PROFILE:-}" ]]; then
            LETS_ENCRYPT_PROFILE="$LETS_ENCRYPT_PROFILE"
        fi
        if [[ -n "${LETS_ENCRYPT_MAX_RETRIES:-}" ]]; then
            LETS_ENCRYPT_MAX_RETRIES="$LETS_ENCRYPT_MAX_RETRIES"
        fi
        
        if [[ -n "${DNSBL_LIST:-}" ]]; then
            DNSBL_LIST="$DNSBL_LIST"
        fi
        
        if [[ -n "${USE_ALLOWLIST:-}" ]]; then
            USE_ALLOWLIST="$USE_ALLOWLIST"
        fi
        if [[ -n "${ALLOWLIST_IP:-}" ]]; then
            ALLOWLIST_IP="$ALLOWLIST_IP"
        fi
        if [[ -n "${ALLOWLIST_COUNTRY:-}" ]]; then
            ALLOWLIST_COUNTRY="$ALLOWLIST_COUNTRY"
        fi
        if [[ -n "${ALLOWLIST_RDNS:-}" ]]; then
            ALLOWLIST_RDNS="$ALLOWLIST_RDNS"
        fi
        if [[ -n "${ALLOWLIST_MODE:-}" ]]; then
            ALLOWLIST_MODE="$ALLOWLIST_MODE"
        fi
        if [[ -n "${ALLOWLIST_STATUS_CODE:-}" ]]; then
            ALLOWLIST_STATUS_CODE="$ALLOWLIST_STATUS_CODE"
        fi
        
        if [[ -n "${USE_GREYLIST:-}" ]]; then
            USE_GREYLIST="$USE_GREYLIST"
        fi
        if [[ -n "${GREYLIST_IP:-}" ]]; then
            GREYLIST_IP="$GREYLIST_IP"
        fi
        if [[ -n "${GREYLIST_RDNS:-}" ]]; then
            GREYLIST_RDNS="$GREYLIST_RDNS"
        fi
        
        if [[ -n "$AUTO_CERT_TYPE" ]]; then
            if [[ "$AUTO_CERT_CONTACT" == "me@example.com" ]] || \
               [[ "$AUTO_CERT_CONTACT" == *"@example.com"* ]] || \
               [[ "$AUTO_CERT_CONTACT" == *"@yourdomain.com"* ]]; then
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
    echo ""
    echo -e "${GREEN}Release Channel Information:${NC}"
    list_available_channels
    echo ""
}

# Parses command line arguments and sets deployment configuration
parse_arguments() {
    DEPLOYMENT_TYPE=""
    FORCE_INSTALL="no"

    while [[ $# -gt 0 ]]; do
        case $1 in
            --type)
                DEPLOYMENT_TYPE="$2"
                shift 2
                ;;
            --automated)
                SETUP_MODE="automated"
                shift
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
            --release)
                RELEASE_CHANNEL="$2"
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

    if [[ -z "$DEPLOYMENT_TYPE" ]]; then
        echo -e "${RED}Error: --type parameter is required${NC}"
        echo ""
        show_usage
        exit 1
    fi

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

# Creates required directories with proper permissions for BunkerWeb containers
setup_directories() {
    echo -e "${BLUE}Creating directories...${NC}"
    
    local directories=(
        "$INSTALL_DIR/storage"
        "$INSTALL_DIR/database" 
        "$INSTALL_DIR/apps"
    )
    
    if [[ "$REDIS_ENABLED" == "yes" ]]; then
        directories+=("$INSTALL_DIR/redis")
    fi
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
    done
    
    echo -e "${BLUE}Setting permissions for BunkerWeb containers...${NC}"
    
    chown -R 101:101 "$INSTALL_DIR/storage"
    chmod -R 755 "$INSTALL_DIR/storage"
    echo -e "${GREEN}✓ Storage directory ownership set to nginx (101:101)${NC}"
    
    chown -R 999:999 "$INSTALL_DIR/database"
    chmod -R 755 "$INSTALL_DIR/database"
    echo -e "${GREEN}✓ Database directory ownership set to mysql (999:999)${NC}"
    
    if [[ "$REDIS_ENABLED" == "yes" ]]; then
        chown -R 999:999 "$INSTALL_DIR/redis"
        chmod -R 755 "$INSTALL_DIR/redis"
        echo -e "${GREEN}✓ Redis directory ownership set to redis (999:999)${NC}"
    fi
    
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

# Manages credential generation, loading, and saving with comprehensive validation
manage_credentials() {
    local creds_file="$1"
    local redis_enabled="$2"
    local deployment_name="$3"
    local template_file="$4"
    local setup_mode="$5"
    local fqdn="$6"
    local server_name="$7"
    local docker_subnet="$8"
    local networks_avoided="$9"
    local release_channel="${10:-latest}"
    
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                        CREDENTIAL MANAGEMENT                        ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    local mysql_password=""
    local redis_password=""
    local totp_secret=""
    local admin_password=""
    local flask_secret=""
    local admin_username="$ADMIN_USERNAME"
    
    if [[ -f "$creds_file" ]]; then
        echo -e "${BLUE}Loading existing credentials...${NC}"
        mysql_password=$(grep "MySQL Database Password:" "$creds_file" 2>/dev/null | cut -d' ' -f4 || echo "")
        redis_password=$(grep "Redis Password:" "$creds_file" 2>/dev/null | cut -d' ' -f3 || echo "")
        totp_secret=$(grep "TOTP Secret Key:" "$creds_file" 2>/dev/null | cut -d' ' -f4 || echo "")
        admin_password=$(grep "Admin Password:" "$creds_file" 2>/dev/null | cut -d' ' -f3 || echo "")
        flask_secret=$(grep "Flask Secret:" "$creds_file" 2>/dev/null | cut -d' ' -f3 || echo "")
        admin_username=$(grep "Admin Username:" "$creds_file" 2>/dev/null | cut -d' ' -f3 || echo "admin")
        
        local loaded_count=0
        [[ -n "$mysql_password" ]] && ((loaded_count++))
        [[ -n "$redis_password" && "$redis_enabled" == "yes" ]] && ((loaded_count++))
        [[ -n "$totp_secret" ]] && ((loaded_count++))
        [[ -n "$admin_password" ]] && ((loaded_count++))
        [[ -n "$flask_secret" ]] && ((loaded_count++))
        
        echo -e "${GREEN}✓ Loaded $loaded_count existing credentials${NC}"
    fi
    
    echo -e "${BLUE}Generating missing credentials...${NC}"
    
    if [[ -z "$mysql_password" ]]; then
        mysql_password=$(openssl rand -base64 33)
        echo -e "${GREEN}✓ Generated MySQL password${NC}"
    fi
    
    if [[ "$redis_enabled" == "yes" && -z "$redis_password" ]]; then
        redis_password=$(openssl rand -base64 33)
        echo -e "${GREEN}✓ Generated Redis password${NC}"
    fi
    
    if [[ -z "$totp_secret" ]]; then
        totp_secret=$(openssl rand -base64 33)
        echo -e "${GREEN}✓ Generated TOTP secret${NC}"
    fi
    
    if [[ -z "$admin_password" ]]; then
        admin_password=$(generate_secure_admin_password)
        
        # Validate the generated password meets requirements
        if validate_password_requirements "$admin_password"; then
            echo -e "${GREEN}✓ Generated secure admin password (${#admin_password} chars with lowercase, uppercase, numbers, special chars)${NC}"
        else
            echo -e "${RED}✗ Generated password does not meet security requirements, regenerating...${NC}"
            # Try up to 5 times to generate a valid password
            local attempts=0
            while [[ $attempts -lt 5 ]]; do
                admin_password=$(generate_secure_admin_password)
                if validate_password_requirements "$admin_password"; then
                    echo -e "${GREEN}✓ Generated secure admin password on attempt $((attempts+1)) (${#admin_password} chars)${NC}"
                    break
                fi
                ((attempts++))
            done
            
            if [[ $attempts -eq 5 ]]; then
                echo -e "${RED}✗ Failed to generate valid password after 5 attempts${NC}"
                return 1
            fi
        fi
    else
        # Validate existing password
        if validate_password_requirements "$admin_password"; then
            echo -e "${GREEN}✓ Existing admin password meets security requirements${NC}"
        else
            echo -e "${YELLOW}⚠ Existing admin password does not meet security requirements, regenerating...${NC}"
            admin_password=$(generate_secure_admin_password)
            if validate_password_requirements "$admin_password"; then
                echo -e "${GREEN}✓ Generated new secure admin password (${#admin_password} chars)${NC}"
            else
                echo -e "${RED}✗ Failed to generate secure admin password${NC}"
                return 1
            fi
        fi
    fi
    
    if [[ -z "$flask_secret" ]]; then
        flask_secret=$(openssl rand -base64 33)
        echo -e "${GREEN}✓ Generated Flask secret${NC}"
    fi
    
    local image_tag=$(get_image_tag_for_channel "$release_channel")
    
    echo -e "${BLUE}Saving credentials to: $creds_file${NC}"
    
    cat > "$creds_file" << EOF
# BunkerWeb Generated Credentials (Enhanced with Release Channel Support)
# Deployment Type: ${deployment_name:-"Unknown"}
# Template Used: ${template_file:-"Unknown"}
# Setup Mode: ${setup_mode:-"Unknown"}
# Release Channel: ${release_channel:-"latest"}
# Docker Image Tag: ${image_tag:-"latest"}
# Debug Mode: ${DEBUG:-"no"}
# Log Level: ${FQDN_LOG_LEVEL:-"INFO"}
# Generated on: $(date)

MySQL Database Password: $mysql_password
TOTP Secret Key: $totp_secret
$(if [[ "$redis_enabled" == "yes" ]]; then echo "Redis Password: $redis_password"; fi)

# Web UI Setup
Admin Username: $admin_username
Admin Password: $admin_password
Flask Secret: $flask_secret

# Password Security Requirements Met:
# ✓ Minimum 8 characters (actual: ${#admin_password})
# ✓ At least one lowercase letter
# ✓ At least one uppercase letter  
# ✓ At least one number
# ✓ At least one special character (#$@!%*+=?)

# Domain Configuration
FQDN: ${fqdn:-"localhost"}
Server Name: ${server_name:-"$fqdn"}
Detection Method: $(get_detection_method 2>/dev/null || echo "manual")

# Release Channel Configuration
Release Channel: $release_channel
Docker Image Tag: $image_tag
Channel Description: $(get_channel_description "$release_channel")
Stability Level: $(get_stability_level "$release_channel")

# Debug and Logging Configuration
Debug Mode: ${DEBUG:-"no"}
Log Level: ${FQDN_LOG_LEVEL:-"INFO"}

# DNS Configuration
DNS Resolvers: ${DNS_RESOLVERS:-"127.0.0.11"}

# HTTP/3 Configuration
HTTP3 Enabled: ${HTTP3:-"yes"}
HTTP3 Alt-Svc Port: ${HTTP3_ALT_SVC_PORT:-"443"}

# ModSecurity Configuration
ModSecurity Global CRS: ${USE_MODSECURITY_GLOBAL_CRS:-"yes"}

# SSL/TLS Configuration
SSL Protocols: ${SSL_PROTOCOLS:-"TLSv1.2 TLSv1.3"}
$(if [[ -n "$SSL_CIPHERS_CUSTOM" ]]; then echo "SSL Custom Ciphers: $SSL_CIPHERS_CUSTOM"; fi)

# Demo Site Configuration
Demo Site Enabled: ${DEMOSITE:-"no"}
$(if [[ "$DEMOSITE" == "yes" ]]; then echo "Demo Site URL: http://${fqdn:-localhost}/demo"; fi)

# Blacklist Configuration
Blacklist Enabled: ${USE_BLACKLIST:-"no"}
$(if [[ "$USE_BLACKLIST" == "yes" && -n "$BLACKLIST_IP_URLS" ]]; then echo "Blacklist IP URLs: $BLACKLIST_IP_URLS"; fi)
$(if [[ "$USE_BLACKLIST" == "yes" && -n "$BLACKLIST_RDNS" ]]; then echo "Blacklist rDNS: $BLACKLIST_RDNS"; fi)
$(if [[ "$USE_BLACKLIST" == "yes" && -n "$BLACKLIST_USER_AGENT_URLS" ]]; then echo "Blacklist User-Agent URLs: Enabled"; fi)

# Let's Encrypt Configuration
LE Challenge Type: ${LETS_ENCRYPT_CHALLENGE:-"http"}
LE Staging Mode: ${LETS_ENCRYPT_STAGING:-"yes"}
LE Certificate Profile: ${LETS_ENCRYPT_PROFILE:-"shortlived"}
LE Max Retries: ${LETS_ENCRYPT_MAX_RETRIES:-"0"}

# Network Configuration
$(if [[ -n "$docker_subnet" ]]; then echo "Docker Subnet: $docker_subnet"; fi)
$(if [[ -n "$networks_avoided" ]]; then echo "Private Networks Avoided: $networks_avoided"; fi)

# Setup Mode Information
Setup Mode: $setup_mode
$(if [[ "$setup_mode" == "wizard" ]]; then
    echo "# Setup Wizard: Use the credentials above during initial setup"
    echo "# Access: http://$(hostname -I | awk '{print $1}') and complete the wizard"
else
    echo "# Automated Setup: Login directly with the credentials above"
    echo "# Access: http://$(hostname -I | awk '{print $1}') and login"
fi)

# Connection Strings
# Database: mariadb+pymysql://bunkerweb:$mysql_password@bw-db:3306/db
$(if [[ "$redis_enabled" == "yes" ]]; then
echo "# Redis: redis://:$redis_password@bw-redis:6379/0"
echo "# Redis CLI: docker exec -it bw-redis redis-cli -a '$redis_password'"
fi)

# Container Information
# All BunkerWeb containers use tag: $image_tag
# To update: 
#   1. Change RELEASE_CHANNEL in BunkerWeb.conf
#   2. Re-run setup script
#   3. Or manually: docker compose pull && docker compose up -d

# Security Information:
# MySQL passwords: 264-bit entropy (~44 characters)
# Admin password: ${#admin_password} characters with strict security requirements
# All other secrets: 264-bit entropy for maximum security
EOF
    
    chmod 600 "$creds_file"
    echo -e "${GREEN}✓ Credentials saved successfully${NC}"
    
    export MYSQL_PASSWORD="$mysql_password"
    export REDIS_PASSWORD="$redis_password"
    export TOTP_SECRET="$totp_secret"
    export ADMIN_PASSWORD="$admin_password"
    export FLASK_SECRET="$flask_secret"
    export ADMIN_USERNAME="$admin_username"
    
    echo -e "${BLUE}Credential Summary:${NC}"
    echo -e "${GREEN}• Admin Username: $admin_username${NC}"
    echo -e "${GREEN}• Admin Password: ${admin_password:0:4}... (${#admin_password} chars, meets security requirements)${NC}"
    echo -e "${GREEN}• MySQL Password: ${mysql_password:0:8}... (${#mysql_password} chars)${NC}"
    echo -e "${GREEN}• TOTP Secret: ${totp_secret:0:8}... (${#totp_secret} chars)${NC}"
    echo -e "${GREEN}• Flask Secret: ${flask_secret:0:8}... (${#flask_secret} chars)${NC}"
    echo -e "${GREEN}• Release Channel: $release_channel${NC}"
    echo -e "${GREEN}• Docker Image Tag: $image_tag${NC}"
    echo -e "${GREEN}• DNS Resolvers: ${DNS_RESOLVERS:-"127.0.0.11"}${NC}"
    echo -e "${GREEN}• ModSecurity Global CRS: ${USE_MODSECURITY_GLOBAL_CRS:-"yes"}${NC}"
    echo -e "${GREEN}• SSL Protocols: ${SSL_PROTOCOLS:-"TLSv1.2 TLSv1.3"}${NC}"
    echo -e "${GREEN}• Log Level: ${FQDN_LOG_LEVEL:-"INFO"}${NC}"
    echo -e "${GREEN}• Debug Mode: ${DEBUG:-"no"}${NC}"
    
    if [[ "$redis_enabled" == "yes" ]]; then
        echo -e "${GREEN}• Redis Password: ${redis_password:0:8}... (${#redis_password} chars)${NC}"
    fi
    
    echo ""
    return 0
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

# Displays comprehensive setup summary with all configuration details
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
    echo -e "${YELLOW}Release Channel:${NC} $RELEASE_CHANNEL"
    echo -e "${YELLOW}Docker Image Tag:${NC} $(get_image_tag_for_channel "$RELEASE_CHANNEL")"
    echo -e "${YELLOW}Domain (FQDN):${NC} $FQDN"
    echo -e "${YELLOW}FQDN Detection Method:${NC} $(get_detection_method 2>/dev/null || echo "manual/fallback")"
    echo -e "${YELLOW}DNS Resolvers:${NC} ${DNS_RESOLVERS:-"127.0.0.11"}"
    echo -e "${YELLOW}HTTP/3 Enabled:${NC} ${HTTP3:-"yes"}"
    echo -e "${YELLOW}Multisite Mode:${NC} ${MULTISITE:-"yes"}"
    echo -e "${YELLOW}ModSecurity Global CRS:${NC} ${USE_MODSECURITY_GLOBAL_CRS:-"yes"}"
    echo -e "${YELLOW}SSL Protocols:${NC} ${SSL_PROTOCOLS:-"TLSv1.2 TLSv1.3"}"
    echo -e "${YELLOW}Log Level:${NC} $FQDN_LOG_LEVEL"
    echo -e "${YELLOW}Debug Mode:${NC} ${DEBUG:-"no"}"
    echo -e "${YELLOW}Demo Site:${NC} $DEMOSITE"
    echo -e "${YELLOW}Blacklist Enabled:${NC} $USE_BLACKLIST"
    echo -e "${YELLOW}Redis Enabled:${NC} $REDIS_ENABLED"
    echo -e "${YELLOW}Allowlist Enabled:${NC} $USE_ALLOWLIST"
    echo -e "${YELLOW}Greylist Enabled:${NC} $USE_GREYLIST"
    echo -e "${YELLOW}Network Detection:${NC} $AUTO_DETECT_NETWORK_CONFLICTS"
    
    if [[ -n "$AUTO_CERT_TYPE" ]]; then
        echo -e "${YELLOW}SSL Certificates:${NC} $AUTO_CERT_TYPE ($AUTO_CERT_CONTACT)"
        echo -e "${YELLOW}LE Challenge Type:${NC} ${LETS_ENCRYPT_CHALLENGE:-"http"}"
        echo -e "${YELLOW}LE Staging Mode:${NC} ${LETS_ENCRYPT_STAGING:-"yes"}"
        echo -e "${YELLOW}LE Certificate Profile:${NC} ${LETS_ENCRYPT_PROFILE:-"shortlived"}"
        echo -e "${YELLOW}LE Max Retries:${NC} ${LETS_ENCRYPT_MAX_RETRIES:-"0"}"
    else
        echo -e "${YELLOW}SSL Certificates:${NC} Manual configuration"
    fi
    
    echo ""
    echo -e "${BLUE}Release Channel Information:${NC}"
    echo -e "${GREEN}• Channel: $RELEASE_CHANNEL${NC}"
    echo -e "${GREEN}• Description: $(get_channel_description "$RELEASE_CHANNEL")${NC}"
    echo -e "${GREEN}• Docker Tag: $(get_image_tag_for_channel "$RELEASE_CHANNEL")${NC}"
    echo -e "${GREEN}• Stability: $(get_stability_level "$RELEASE_CHANNEL")${NC}"
    echo -e "${GREEN}• $(get_recommendation "$RELEASE_CHANNEL")${NC}"
    
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo -e "${GREEN}1. Start BunkerWeb: cd $INSTALL_DIR && docker compose up -d${NC}"
    
    local ui_path="$UI_ACCESS_PATH"
    if [[ -z "$ui_path" ]]; then
        local creds_file="$INSTALL_DIR/credentials.txt"
        if [[ -f "$creds_file" ]]; then
            ui_path=$(grep "UI Access Path:" "$creds_file" 2>/dev/null | cut -d' ' -f4 || echo "")
        fi
    fi
    
    if [[ $SETUP_MODE == "automated" ]]; then
        if [[ -n "$ui_path" ]]; then
            echo -e "${GREEN}2. Access web interface: http://$(hostname -I | awk '{print $1}')$ui_path${NC}"
        else
            echo -e "${GREEN}2. Access web interface: http://$(hostname -I | awk '{print $1}')${NC}"
        fi
        echo -e "${GREEN}3. Login with credentials from: $INSTALL_DIR/credentials.txt${NC}"
    else
        if [[ -n "$ui_path" ]]; then
            echo -e "${GREEN}2. Complete setup wizard: http://$(hostname -I | awk '{print $1}')$ui_path${NC}"
        else
            echo -e "${GREEN}2. Complete setup wizard: http://$(hostname -I | awk '{print $1}')${NC}"
        fi
        echo -e "${GREEN}3. Use pre-generated credentials from: $INSTALL_DIR/credentials.txt${NC}"
        echo ""
        echo -e "${BLUE}Wizard Setup Information:${NC}"
        echo -e "${GREEN}• Username: $ADMIN_USERNAME${NC}"
        echo -e "${GREEN}• Password: $ADMIN_PASSWORD${NC}"
        if [[ -n "$ui_path" ]]; then
            echo -e "${GREEN}• UI Access Path: $ui_path (secure random path)${NC}"
        fi
        echo -e "${YELLOW}• The setup wizard will guide you through initial configuration${NC}"
        echo -e "${YELLOW}• All necessary credentials are pre-generated and ready to use${NC}"
    fi
    
    if [[ -n "$AUTO_CERT_TYPE" ]]; then
        echo ""
        echo -e "${BLUE}SSL Certificate Information:${NC}"
        echo -e "${GREEN}• Let's Encrypt will automatically generate certificates for: $FQDN${NC}"
        echo -e "${GREEN}• Challenge type: ${LETS_ENCRYPT_CHALLENGE:-"http"}${NC}"
        echo -e "${GREEN}• Staging mode: ${LETS_ENCRYPT_STAGING:-"yes"}${NC}"
        echo -e "${GREEN}• Certificate profile: ${LETS_ENCRYPT_PROFILE:-"shortlived"} (7-day validity for enhanced security)${NC}"
        echo -e "${GREEN}• Max retries: ${LETS_ENCRYPT_MAX_RETRIES:-"0"} (retries disabled)${NC}"
        echo -e "${GREEN}• Monitor certificate generation: docker compose logs -f bw-scheduler | grep -i cert${NC}"
        echo -e "${GREEN}• Check certificate status after a few minutes${NC}"
        if [[ "$LETS_ENCRYPT_PROFILE" == "shortlived" ]]; then
            echo -e "${YELLOW}• Note: Shortlived certificates expire every 7 days but provide enhanced security${NC}"
        fi
    fi
    
    if [[ "$DEMOSITE" == "yes" ]]; then
        echo ""
        echo -e "${BLUE}Demo Site Information:${NC}"
        echo -e "${GREEN}• Demo site enabled with nginx-hello container${NC}"
        echo -e "${GREEN}• Access demo at: http://$FQDN/demo${NC}"
        echo -e "${GREEN}• Demo shows nginx information and request details${NC}"
        echo -e "${YELLOW}• Demo site is for testing purposes only${NC}"
    fi
    
    if [[ "$USE_BLACKLIST" == "yes" ]]; then
        echo ""
        echo -e "${BLUE}Blacklist Protection Information:${NC}"
        echo -e "${GREEN}• External IP blacklists enabled for enhanced security${NC}"
        if [[ -n "$BLACKLIST_IP_URLS" ]]; then
            echo -e "${GREEN}• TOR exit nodes and FireHOL Level 3 threats blocked${NC}"
        fi
        if [[ -n "$BLACKLIST_RDNS" ]]; then
            echo -e "${GREEN}• Scanning services (Shodan, Censys) blocked by rDNS${NC}"
        fi
        if [[ -n "$BLACKLIST_USER_AGENT_URLS" ]]; then
            echo -e "${GREEN}• Malicious user agents and bad bots blocked${NC}"
        fi
        echo -e "${GREEN}• Blacklists are automatically updated from external sources${NC}"
        echo -e "${YELLOW}• Monitor logs for blocked IPs and adjust whitelist as needed${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}Setup completed successfully!${NC}"
    echo ""
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                    QUICK ACCESS CREDENTIALS                    ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    local creds_file="$INSTALL_DIR/credentials.txt"
    if [[ -f "$creds_file" ]]; then
        echo -e "${CYAN}Quick Access Information:${NC}"
        cat "$creds_file" | grep "Full UI URL:" || echo -e "${YELLOW}Full UI URL: Not configured${NC}"
        cat "$creds_file" | grep "Admin Username:" || echo -e "${YELLOW}Admin Username: Not found${NC}"
        cat "$creds_file" | grep "Admin Password:" || echo -e "${YELLOW}Admin Password: Not found${NC}"
        echo ""
        echo -e "${GREEN}Complete credentials available in: $creds_file${NC}"
    else
        echo -e "${YELLOW}Credentials file not found: $creds_file${NC}"
    fi
    echo ""
}

# Main execution function coordinating all setup phases using helper modules
main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}      BunkerWeb Setup Script${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    
    if [[ $EUID -ne 0 ]]; then
       echo -e "${RED}This script must be run as root${NC}"
       echo -e "${YELLOW}Please run: sudo $0 --type <autoconf|basic|integrated>${NC}"
       exit 1
    fi
    
    parse_arguments "$@"
    
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
    
    if [[ ! -f "$template_path" ]]; then
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
    echo -e "${GREEN}• FQDN Detection Method: $(get_detection_method)${NC}"
    echo -e "${GREEN}• DNS Resolvers: ${DNS_RESOLVERS:-"127.0.0.11"}${NC}"
    echo -e "${GREEN}• HTTP/3 Enabled: ${HTTP3:-"yes"}${NC}"
    echo -e "${GREEN}• Multisite Mode: ${MULTISITE:-"yes"}${NC}"
    echo -e "${GREEN}• ModSecurity Global CRS: ${USE_MODSECURITY_GLOBAL_CRS:-"yes"}${NC}"
    echo -e "${GREEN}• SSL Protocols: ${SSL_PROTOCOLS:-"TLSv1.2 TLSv1.3"}${NC}"
    echo -e "${GREEN}• Log Level: $FQDN_LOG_LEVEL${NC}"
    echo -e "${GREEN}• Debug Mode: ${DEBUG:-"no"}${NC}"
    echo -e "${GREEN}• Allowlist Enabled: $USE_ALLOWLIST${NC}"
    echo -e "${GREEN}• Blacklist Enabled: $USE_BLACKLIST${NC}"
    echo -e "${GREEN}• Greylist Enabled: $USE_GREYLIST${NC}"
    echo -e "${GREEN}• Redis Enabled: $REDIS_ENABLED${NC}"
    echo -e "${GREEN}• Demo Site: $DEMOSITE${NC}"
    echo -e "${GREEN}• Network Detection: $AUTO_DETECT_NETWORK_CONFLICTS${NC}"
    echo ""
    
    echo -e "${BLUE}Step 1: Network Configuration${NC}"
    local docker_subnet=$(simple_network_detection)
    echo -e "${GREEN}✓ Using subnet: $docker_subnet${NC}"
    
    echo -e "${BLUE}Step 2: NAT Detection and API Whitelist Configuration${NC}"
    local api_whitelist=$(detect_nat_and_build_whitelist "$docker_subnet")
    
    echo -e "${BLUE}Step 3: Enhanced Credential Management with Release Channel${NC}"
    if ! manage_credentials "$creds_file" "$REDIS_ENABLED" "$DEPLOYMENT_NAME" "$TEMPLATE_FILE" \
                           "$SETUP_MODE" "$FQDN" "$SERVER_NAME" "$docker_subnet" \
                           "$PRIVATE_NETWORKS_ALREADY_IN_USE" "$RELEASE_CHANNEL"; then
        echo -e "${RED}✗ Credential management failed${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Step 4: Template Processing with Release Channel${NC}"
    
    local image_tag=$(get_image_tag_for_channel "$RELEASE_CHANNEL")
    if [[ -z "$image_tag" ]]; then
        echo -e "${RED}✗ Failed to get image tag for release channel: $RELEASE_CHANNEL${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Release channel: $RELEASE_CHANNEL → Docker image tag: $image_tag${NC}"
    
    if ! process_template_with_release_channel "$template_path" "$compose_file" "$MYSQL_PASSWORD" \
                                              "$REDIS_PASSWORD" "$TOTP_SECRET" "$ADMIN_PASSWORD" \
                                              "$FLASK_SECRET" "$ADMIN_USERNAME" "$AUTO_CERT_TYPE" \
                                              "$AUTO_CERT_CONTACT" "$FQDN" "$SERVER_NAME" \
                                              "$docker_subnet" "$SETUP_MODE" "$REDIS_ENABLED" \
                                              "$RELEASE_CHANNEL" "$image_tag"; then
        echo -e "${RED}✗ Template processing failed${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Step 5: API Whitelist Configuration${NC}"
    if ! update_api_whitelist "$compose_file" "$api_whitelist"; then
        echo -e "${RED}✗ API whitelist update failed${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Step 6: Allowlist Configuration${NC}"
    if ! manage_allowlist_configuration "$ALLOWLIST_IP" "$ALLOWLIST_COUNTRY" "$BLACKLIST_COUNTRY" \
                                       "$ALLOWLIST_DNS" "$USE_ALLOWLIST" "$ALLOWLIST_MODE" \
                                       "$ALLOWLIST_STATUS_CODE" "$compose_file" "$creds_file" "$FQDN"; then
        echo -e "${RED}✗ Allowlist configuration failed${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Step 7: Greylist Configuration${NC}"
    if ! manage_greylist_configuration "$GREYLIST_IP" "$GREYLIST_DNS" "$USE_GREYLIST" \
                                      "$compose_file" "$creds_file" "$FQDN"; then
        echo -e "${RED}✗ Greylist configuration failed${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Step 8: Directory Setup${NC}"
    setup_directories
    
    show_setup_summary
}

main "$@"