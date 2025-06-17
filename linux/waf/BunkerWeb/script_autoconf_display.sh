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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}

# Function to add BunkerWeb labels to bw-ui service
add_bw_ui_labels() {
    local compose_file="$1"
    local fqdn="$2"
    
    echo -e "${BLUE}Adding BunkerWeb labels to bw-ui service...${NC}"
    
    # Generate random 8-character path for UI access
    local random_ui_path=$(generate_random_ui_path)
    
    # Create the labels block
    local labels_block="    labels:
      - \"bunkerweb.SERVER_NAME=$fqdn\"
      - \"bunkerweb.USE_TEMPLATE=ui\"
      - \"bunkerweb.USE_REVERSE_PROXY=yes\"
      - \"bunkerweb.REVERSE_PROXY_URL=/$random_ui_path\"
      - \"bunkerweb.REVERSE_PROXY_HOST=http://bw-ui:7000\""
    
    # Find the bw-ui service and add labels after the image line
    if grep -q "bw-ui:" "$compose_file"; then
        # Use awk to insert labels after the image line in bw-ui service
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
        echo -e "${GREEN}✓ UI access path: /$random_ui_path${NC}"
        echo -e "${GREEN}✓ Server name: $fqdn${NC}"
        
        # Update credentials file with UI path information
        if [[ -f "${compose_file%/*}/credentials.txt" ]]; then
            echo "" >> "${compose_file%/*}/credentials.txt"
            echo "# BunkerWeb UI Access Information" >> "${compose_file%/*}/credentials.txt"
            echo "UI Access Path: /$random_ui_path" >> "${compose_file%/*}/credentials.txt"
            echo "Full UI URL: http://$fqdn/$random_ui_path" >> "${compose_file%/*}/credentials.txt"
            echo "Direct Access: http://$(hostname -I | awk '{print $1}')/$random_ui_path" >> "${compose_file%/*}/credentials.txt"
        fi
        
        return 0
    else
        echo -e "${YELLOW}⚠ bw-ui service not found in compose file${NC}"
        return 1
    fi
}")" && pwd)"
INSTALL_DIR="/data/BunkerWeb"
SETUP_MODE="wizard"  # Default to wizard mode (changed from automated)

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

# Enhanced password generation function for admin password
generate_secure_admin_password() {
    # Generate a 12-character password with mixed case, numbers, and special characters
    # Pattern: 3 uppercase + 3 lowercase + 3 numbers + 3 special chars, then shuffle
    
    local uppercase="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local lowercase="abcdefghijklmnopqrstuvwxyz"
    local numbers="0123456789"
    local special_chars="#$@!%*+=?"
    
    local password=""
    
    # Add 3 uppercase letters
    for i in {1..3}; do
        password+="${uppercase:$((RANDOM % ${#uppercase})):1}"
    done
    
    # Add 3 lowercase letters
    for i in {1..3}; do
        password+="${lowercase:$((RANDOM % ${#lowercase})):1}"
    done
    
    # Add 3 numbers
    for i in {1..3}; do
        password+="${numbers:$((RANDOM % ${#numbers})):1}"
    done
    
    # Add 3 special characters
    for i in {1..3}; do
        password+="${special_chars:$((RANDOM % ${#special_chars})):1}"
    done
    
    # Shuffle the password characters
    echo "$password" | fold -w1 | shuf | tr -d '\n'
}

# Function to generate random 8-character string for UI path
generate_random_ui_path() {
    # Generate a random 8-character string using letters and numbers
    local chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local random_path=""
    
    for i in {1..8}; do
        random_path+="${chars:$((RANDOM % ${#chars})):1}"
    done
    
    echo "$random_path"
}

# Source the modular scripts
source_modules() {
    local modules=(
        "helper_password_manager.sh"
        "helper_network_detection.sh" 
        "helper_template_processor.sh"
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

# Function to detect and build comprehensive API whitelist (FIXED VERSION)
build_comprehensive_api_whitelist() {
    local docker_subnet="$1"
    local api_whitelist="127.0.0.0/8"  # Always include localhost
    
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo -e "${BLUE}                    API WHITELIST AUTO-DETECTION                    ${NC}" >&2
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo "" >&2
    
    echo -e "${BLUE}Building comprehensive API whitelist for Docker networks...${NC}" >&2
    
    # Add the main Docker subnet
    if [[ -n "$docker_subnet" ]]; then
        api_whitelist="$api_whitelist $docker_subnet"
        echo -e "${GREEN}• Added main subnet: $docker_subnet${NC}" >&2
    fi
    
    # Add comprehensive Docker Compose network ranges
    echo -e "${BLUE}Adding Docker Compose network ranges...${NC}" >&2
    
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
            echo -e "${GREEN}• Added Docker range: $range${NC}" >&2
        fi
    done
    
    # Detect existing Docker networks if Docker is available
    if command -v docker >/dev/null 2>&1; then
        echo -e "${BLUE}Detecting existing Docker networks...${NC}" >&2
        
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
                    echo -e "${GREEN}• Added existing Docker network: $network${NC}" >&2
                fi
            fi
        done
    fi
    
    # Add broader ranges for safety
    echo -e "${BLUE}Adding broader private network ranges for safety...${NC}" >&2
    local broad_ranges=(
        "10.0.0.0/8"      # Class A private networks
        "192.168.0.0/16"  # Class C private networks
    )
    
    for range in "${broad_ranges[@]}"; do
        if [[ ! "$api_whitelist" =~ $range ]]; then
            api_whitelist="$api_whitelist $range"
            echo -e "${GREEN}• Added private range: $range${NC}" >&2
        fi
    done
    
    echo "" >&2
    echo -e "${GREEN}Final comprehensive API whitelist:${NC}" >&2
    echo -e "${GREEN}$api_whitelist${NC}" >&2
    echo "" >&2
    
    # CRITICAL: Only output the final whitelist to stdout (not stderr)
    # This prevents debug output from being included in the YAML
    echo "$api_whitelist"
}

# Function to update API whitelist in docker-compose file
update_api_whitelist() {
    local compose_file="$1"
    local api_whitelist="$2"
    
    echo -e "${BLUE}Updating API whitelist in docker-compose.yml...${NC}" >&2
    
    # Escape special characters for sed
    local escaped_whitelist=$(printf '%s\n' "$api_whitelist" | sed 's/[[\.*^$()+?{|]/\\&/g')
    
    # Use sed to replace API_WHITELIST_IP lines
    if sed -i "s|API_WHITELIST_IP: \".*\"|API_WHITELIST_IP: \"$escaped_whitelist\"|g" "$compose_file"; then
        echo -e "${GREEN}✓ API whitelist updated successfully${NC}" >&2
        
        # Verify the replacement worked
        local updated_count=$(grep -c "API_WHITELIST_IP:" "$compose_file" || echo "0")
        echo -e "${GREEN}✓ Updated $updated_count API_WHITELIST_IP entries${NC}" >&2
        
        # Show the updated entries for verification (truncated for readability)
        echo -e "${BLUE}Verification - Updated API whitelist entries:${NC}" >&2
        grep "API_WHITELIST_IP:" "$compose_file" | sed 's/^\s*/  /' | cut -c1-100 | sed 's/$/.../' >&2
        
        return 0
    else
        echo -e "${RED}✗ Failed to update API whitelist${NC}" >&2
        return 1
    fi
}

# Function to configure automated vs wizard setup
configure_setup_mode() {
    local compose_file="$1"
    local setup_mode="$2"
    local admin_username="$3"
    local admin_password="$4"
    local flask_secret="$5"
    
    echo -e "${BLUE}Configuring setup mode: $setup_mode${NC}"
    
    if [[ "$setup_mode" == "automated" ]]; then
        echo -e "${BLUE}Configuring automated setup with credentials...${NC}"
        
        # Enable automated setup in docker-compose.yml (uncomment the lines)
        sed -i 's|# OVERRIDE_ADMIN_CREDS: "no"|OVERRIDE_ADMIN_CREDS: "yes"|' "$compose_file"
        sed -i 's|# # OVERRIDE_ADMIN_CREDS: "no"|OVERRIDE_ADMIN_CREDS: "yes"|' "$compose_file"
        sed -i 's|# ADMIN_USERNAME: "admin"|ADMIN_USERNAME: "'$admin_username'"|' "$compose_file"
        sed -i 's|# # ADMIN_USERNAME: "admin"|ADMIN_USERNAME: "'$admin_username'"|' "$compose_file"
        sed -i 's|# ADMIN_PASSWORD: "'$admin_password'"|ADMIN_PASSWORD: "'$admin_password'"|' "$compose_file"
        sed -i 's|# FLASK_SECRET: "'$flask_secret'"|FLASK_SECRET: "'$flask_secret'"|' "$compose_file"
        
        echo -e "${GREEN}✓ Automated setup configured and enabled${NC}"
        echo -e "${GREEN}✓ Admin credentials activated${NC}"
        return 0
    else
        echo -e "${BLUE}Configuring setup wizard mode...${NC}"
        
        # Ensure OVERRIDE_ADMIN_CREDS is commented out
        sed -i 's|OVERRIDE_ADMIN_CREDS: "yes"|# OVERRIDE_ADMIN_CREDS: "no"|' "$compose_file"
        
        # Comment out admin credentials but keep the values for reference
        sed -i 's|^[[:space:]]*ADMIN_USERNAME: "'$admin_username'"|      # ADMIN_USERNAME: "'$admin_username'"|' "$compose_file"
        sed -i 's|^[[:space:]]*ADMIN_PASSWORD: "'$admin_password'"|      # ADMIN_PASSWORD: "'$admin_password'"|' "$compose_file"
        sed -i 's|^[[:space:]]*FLASK_SECRET: "'$flask_secret'"|      # FLASK_SECRET: "'$flask_secret'"|' "$compose_file"
        
        echo -e "${GREEN}✓ Setup wizard mode enabled${NC}"
        echo -e "${GREEN}✓ Credentials commented out but available for reference${NC}"
        return 0
    fi
}

# Enhanced template processing function
process_template_enhanced() {
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
    
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                        ENHANCED TEMPLATE PROCESSING                        ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    # Validate inputs
    if [[ ! -f "$template_file" ]]; then
        echo -e "${RED}✗ Template file not found: $template_file${NC}"
        return 1
    fi
    
    # Copy template to compose file
    echo -e "${BLUE}Copying template to docker-compose.yml...${NC}"
    if cp "$template_file" "$compose_file"; then
        echo -e "${GREEN}✓ Template copied: $(basename "$template_file") → $(basename "$compose_file")${NC}"
    else
        echo -e "${RED}✗ Failed to copy template${NC}"
        return 1
    fi
    
    # Create backup
    local backup_file="$compose_file.backup.$(date +%Y%m%d_%H%M%S)"
    if cp "$compose_file" "$backup_file"; then
        echo -e "${GREEN}✓ Backup created: $backup_file${NC}"
    else
        echo -e "${RED}✗ Failed to create backup${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Processing template placeholders...${NC}"
    
    # Process all placeholders
    local processing_errors=0
    
    # 1. Replace credential placeholders
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
    
    # 2. Handle network configuration
    if [[ -n "$docker_subnet" ]]; then
        local default_subnet="10.20.30.0/24"
        if [[ "$docker_subnet" != "$default_subnet" ]]; then
            sed -i "s|$default_subnet|$docker_subnet|g" "$compose_file"
            echo -e "${GREEN}✓ Docker subnet updated to: $docker_subnet${NC}"
        fi
    fi
    
    # 3. Handle SSL configuration
    if [[ -n "$auto_cert_type" ]]; then
        sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|yes|g" "$compose_file"
        sed -i "s|REPLACEME_EMAIL_LETS_ENCRYPT|$auto_cert_contact|g" "$compose_file"
        echo -e "${GREEN}✓ SSL certificates configured ($auto_cert_type)${NC}"
    else
        sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|no|g" "$compose_file"
        echo -e "${GREEN}✓ SSL certificates disabled${NC}"
    fi
    
    # 4. Replace ALL REPLACEME placeholders first (including admin credentials)
    if [[ -n "$admin_password" ]]; then
        sed -i "s|REPLACEME_ADMIN|$admin_password|g" "$compose_file"
        echo -e "${GREEN}✓ Admin password placeholder updated${NC}"
    fi
    
    if [[ -n "$flask_secret" ]]; then
        sed -i "s|REPLACEME_FLASK|$flask_secret|g" "$compose_file"
        echo -e "${GREEN}✓ Flask secret placeholder updated${NC}"
    fi
    
    # 5. Handle domain configuration
    if [[ -n "$fqdn" ]]; then
        sed -i "s|REPLACEME_DOMAIN|$fqdn|g" "$compose_file"
        # Also update SERVER_NAME environment variable
        sed -i "s|SERVER_NAME: \"\"|SERVER_NAME: \"$fqdn\"|g" "$compose_file"
        echo -e "${GREEN}✓ Domain configured: $fqdn${NC}"
    fi
    
    # 6. Configure setup mode and credentials (after placeholders are replaced)
    configure_setup_mode "$compose_file" "$setup_mode" "$admin_username" "$admin_password" "$flask_secret"
    
    # 7. Add BunkerWeb labels to bw-ui service for reverse proxy configuration
    add_bw_ui_labels "$compose_file" "$fqdn"
    
    # 8. Verify all placeholders are replaced
    local remaining_placeholders=$(grep -o "REPLACEME_[A-Z_]*" "$compose_file" || true)
    if [[ -n "$remaining_placeholders" ]]; then
        echo -e "${YELLOW}⚠ Some placeholders remain: $remaining_placeholders${NC}"
    else
        echo -e "${GREEN}✓ All placeholders processed${NC}"
    fi
    
    # 9. Validate Docker Compose syntax
    local current_dir=$(pwd)
    cd "$(dirname "$compose_file")"
    if docker compose config >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Docker Compose syntax is valid${NC}"
        cd "$current_dir"
    else
        echo -e "${RED}✗ Docker Compose syntax error detected${NC}"
        cd "$current_dir"
        ((processing_errors++))
    fi
    
    echo ""
    if [[ $processing_errors -eq 0 ]]; then
        echo -e "${GREEN}✓ Enhanced template processing completed successfully${NC}"
        return 0
    else
        echo -e "${RED}✗ Template processing completed with $processing_errors errors${NC}"
        return 1
    fi
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
    echo -e "  --automated         Enable automated setup (skip wizard)"
    echo -e "  --wizard            Enable setup wizard mode (default)"
    echo -e "  --admin-name NAME   Set admin username"
    echo -e "  --FQDN DOMAIN       Set Fully Qualified Domain Name"
    echo -e "  --force             Skip configuration validation"
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
    echo -e "  sudo $0 --type autoconf                                    # Setup wizard mode"
    echo -e "  sudo $0 --type autoconf --automated                       # Automated setup"
    echo -e "  sudo $0 --type autoconf --private-networks \"192.168.1.0/24\""
    echo -e "  sudo $0 --type autoconf --FQDN bunkerweb.example.com"
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

# Enhanced credential management
manage_enhanced_credentials() {
    local creds_file="$1"
    local redis_enabled="$2"
    local deployment_name="$3"
    local template_file="$4"
    local setup_mode="$5"
    local fqdn="$6"
    local server_name="$7"
    local docker_subnet="$8"
    local networks_avoided="$9"
    
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                        ENHANCED CREDENTIAL MANAGEMENT                        ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    # Global credential variables
    local mysql_password=""
    local redis_password=""
    local totp_secret=""
    local admin_password=""
    local flask_secret=""
    local admin_username="$ADMIN_USERNAME"
    
    # Try to load existing credentials
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
    
    # Generate missing credentials
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
        echo -e "${GREEN}✓ Generated secure admin password (12 chars with mixed case, numbers, special chars)${NC}"
    fi
    
    if [[ -z "$flask_secret" ]]; then
        flask_secret=$(openssl rand -base64 33)
        echo -e "${GREEN}✓ Generated Flask secret${NC}"
    fi
    
    # Save credentials
    echo -e "${BLUE}Saving credentials to: $creds_file${NC}"
    
    cat > "$creds_file" << EOF
# BunkerWeb Generated Credentials
# Deployment Type: ${deployment_name:-"Unknown"}
# Template Used: ${template_file:-"Unknown"}
# Setup Mode: ${setup_mode:-"Unknown"}
# Generated on: $(date)
# Keep this file secure and backed up!

MySQL Database Password: $mysql_password
TOTP Secret Key: $totp_secret
$(if [[ "$redis_enabled" == "yes" ]]; then echo "Redis Password: $redis_password"; fi)

# Web UI Setup
Admin Username: $admin_username
Admin Password: $admin_password
Flask Secret: $flask_secret

# Domain Configuration
FQDN: ${fqdn:-"localhost"}
Server Name: ${server_name:-"$fqdn"}

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

# Security Information:
# MySQL passwords: 264-bit entropy (~44 characters)
# Admin password: 12 characters with uppercase, lowercase, numbers, and special characters
# All other secrets: 264-bit entropy for maximum security
EOF
    
    chmod 600 "$creds_file"
    echo -e "${GREEN}✓ Credentials saved successfully${NC}"
    
    # Export credentials for use in template processing
    export MYSQL_PASSWORD="$mysql_password"
    export REDIS_PASSWORD="$redis_password"
    export TOTP_SECRET="$totp_secret"
    export ADMIN_PASSWORD="$admin_password"
    export FLASK_SECRET="$flask_secret"
    export ADMIN_USERNAME="$admin_username"
    
    # Show summary
    echo -e "${BLUE}Credential Summary:${NC}"
    echo -e "${GREEN}• Admin Username: $admin_username${NC}"
    echo -e "${GREEN}• Admin Password: ${admin_password:0:4}... (${#admin_password} chars)${NC}"
    echo -e "${GREEN}• MySQL Password: ${mysql_password:0:8}... (${#mysql_password} chars)${NC}"
    echo -e "${GREEN}• TOTP Secret: ${totp_secret:0:8}... (${#totp_secret} chars)${NC}"
    echo -e "${GREEN}• Flask Secret: ${flask_secret:0:8}... (${#flask_secret} chars)${NC}"
    
    if [[ "$redis_enabled" == "yes" ]]; then
        echo -e "${GREEN}• Redis Password: ${redis_password:0:8}... (${#redis_password} chars)${NC}"
    fi
    
    echo ""
    return 0
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
    echo -e "${YELLOW}Redis Enabled:${NC} $REDIS_ENABLED"
    echo -e "${YELLOW}Network Detection:${NC} $AUTO_DETECT_NETWORK_CONFLICTS"
    
    local detected_subnet=$(get_detected_subnet 2>/dev/null || echo "Default")
    if [[ -n "$detected_subnet" && "$detected_subnet" != "Default" ]]; then
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
    
    # Get the UI path from credentials file if it exists
    local ui_path=""
    local creds_file="$INSTALL_DIR/credentials.txt"
    if [[ -f "$creds_file" ]]; then
        ui_path=$(grep "UI Access Path:" "$creds_file" 2>/dev/null | cut -d' ' -f4 || echo "")
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
        echo -e "${GREEN}• Monitor certificate generation: docker compose logs -f bw-scheduler | grep -i cert${NC}"
        echo -e "${GREEN}• Check certificate status after a few minutes${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}Troubleshooting:${NC}"
    echo -e "${GREEN}• Check logs: docker compose logs -f${NC}"
    echo -e "${GREEN}• Check API connectivity: docker compose logs bunkerweb | grep API${NC}"
    echo -e "${GREEN}• Monitor Let's Encrypt: docker compose logs bw-scheduler | grep -i lets${NC}"
    echo -e "${GREEN}• View credentials: cat $INSTALL_DIR/credentials.txt${NC}"
    
    echo ""
    echo -e "${GREEN}Setup completed successfully!${NC}"
}

# Main execution function
main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}      BunkerWeb Enhanced Setup Script${NC}"
    echo -e "${BLUE}     with Secure Password Generation${NC}"
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
    echo -e "${GREEN}• Redis Enabled: $REDIS_ENABLED${NC}"
    echo -e "${GREEN}• Network Detection: $AUTO_DETECT_NETWORK_CONFLICTS${NC}"
    echo ""
    
    # 1. Network Conflict Detection
    echo -e "${BLUE}Step 1: Network Conflict Detection${NC}"
    if ! detect_network_conflicts "$AUTO_DETECT_NETWORK_CONFLICTS" "$PRIVATE_NETWORKS_ALREADY_IN_USE" "$PREFERRED_DOCKER_SUBNET" 2>/dev/null; then
        echo -e "${RED}✗ Network detection failed${NC}"
        exit 1
    fi
    local docker_subnet=$(get_detected_subnet 2>/dev/null || echo "")
    
    # 2. Build Comprehensive API Whitelist
    echo -e "${BLUE}Step 2: API Whitelist Auto-Detection${NC}"
    local api_whitelist=$(build_comprehensive_api_whitelist "$docker_subnet")
    
    # 3. Enhanced Credential Management  
    echo -e "${BLUE}Step 3: Enhanced Credential Management${NC}"
    if ! manage_enhanced_credentials "$creds_file" "$REDIS_ENABLED" "$DEPLOYMENT_NAME" "$TEMPLATE_FILE" "$SETUP_MODE" "$FQDN" "$SERVER_NAME" "$docker_subnet" "$PRIVATE_NETWORKS_ALREADY_IN_USE"; then
        echo -e "${RED}✗ Credential management failed${NC}"
        exit 1
    fi
    
    # 4. Enhanced Template Processing
    echo -e "${BLUE}Step 4: Enhanced Template Processing${NC}"
    if ! process_template_enhanced "$template_path" "$compose_file" "$MYSQL_PASSWORD" "$REDIS_PASSWORD" "$TOTP_SECRET" "$ADMIN_PASSWORD" "$FLASK_SECRET" "$ADMIN_USERNAME" "$AUTO_CERT_TYPE" "$AUTO_CERT_CONTACT" "$FQDN" "$SERVER_NAME" "$docker_subnet" "$SETUP_MODE" "$REDIS_ENABLED"; then
        echo -e "${RED}✗ Template processing failed${NC}"
        exit 1
    fi
    
    # 5. Update API Whitelist
    echo -e "${BLUE}Step 5: API Whitelist Configuration${NC}"
    if ! update_api_whitelist "$compose_file" "$api_whitelist"; then
        echo -e "${RED}✗ API whitelist update failed${NC}"
        exit 1
    fi
    
    # 6. Directory Setup
    echo -e "${BLUE}Step 6: Directory Setup${NC}"
    setup_directories
    
    # 7. Final Summary
    show_setup_summary
}

# Run main function with all arguments
main "$@"