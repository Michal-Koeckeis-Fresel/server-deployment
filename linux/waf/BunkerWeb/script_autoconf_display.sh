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

# BunkerWeb Setup Script with Network Conflict Detection
# This script generates random passwords and replaces placeholders in docker-compose.yml
# MUST BE RUN AS ROOT: sudo ./setup-bunkerweb.sh --type <autoconf|basic|integrated>

set -e

INSTALL_DIR="/data/BunkerWeb"
SETUP_MODE="automated"  # Default to automated mode

# Default values (can be overridden by BunkerWeb.conf or command line)
ADMIN_USERNAME="admin"  # Default admin username
AUTO_CERT_TYPE=""       # Certificate type: LE or ZeroSSL (ZeroSSL is draft - not yet implemented)
AUTO_CERT_CONTACT=""    # Contact email for certificates
AUTO_CERT_ZSSL_API=""   # ZeroSSL API key
FQDN=""                 # Fully Qualified Domain Name for SSL certificates
LETS_ENCRYPT_CHALLENGE="http"  # Challenge type: http or dns
LETS_ENCRYPT_STAGING="yes"     # Use staging environment for testing (default: yes for safety)
LETS_ENCRYPT_WILDCARD="no"     # Enable wildcard certificates (DNS only, default: no)
MULTISITE="yes"         # Enable multisite mode by default
SERVER_NAME=""          # Primary domain name (same as FQDN in single domain setups)
BUNKERWEB_INSTANCES="127.0.0.1"  # List of BunkerWeb instances
SECURITY_MODE="block"   # Security level: detect or block
SERVER_TYPE="http"      # Server type: http or stream
USE_GREYLIST="no"       # Enable greylist for admin interface
GREYLIST_IP=""          # IP addresses or networks to greylist
GREYLIST_RDNS=""        # Reverse DNS suffixes to greylist

# Network Configuration
PRIVATE_NETWORKS_ALREADY_IN_USE=""  # User-specified networks to avoid
AUTO_DETECT_NETWORK_CONFLICTS="yes"  # Auto-detect conflicts
PREFERRED_DOCKER_SUBNET=""           # Preferred subnet for Docker

# Redis Configuration (enabled by default)
REDIS_ENABLED="yes"     # Enable Redis support: yes or no (default: yes)
REDIS_PASSWORD=""       # Redis password (auto-generated if Redis enabled)

# Syslog Configuration (enabled by default)
SYSLOG_ENABLED="yes"    # Enable external syslog: yes or no (default: yes)
SYSLOG_ADDRESS="127.0.0.1"  # Syslog server address (default: localhost)
SYSLOG_PORT="514"       # Syslog port (default: 514)
SYSLOG_NETWORK="127.0.0.1/32"  # Syslog network (default: localhost only)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Network utility functions
check_command() {
    command -v "$1" >/dev/null 2>&1
}

# Function to validate CIDR format
is_valid_cidr() {
    local cidr="$1"
    [[ "$cidr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]
}

# Function to convert CIDR to decimal for comparison
cidr_to_decimal() {
    local cidr="$1"
    
    # Validate input format
    if ! is_valid_cidr "$cidr"; then
        echo "0/32"  # Return invalid network that won't match anything
        return 1
    fi
    
    local ip="${cidr%/*}"
    local prefix="${cidr#*/}"
    
    # Validate prefix length
    if [[ $prefix -lt 0 || $prefix -gt 32 ]]; then
        echo "0/32"
        return 1
    fi
    
    # Convert IP to decimal
    local a b c d
    IFS=. read -r a b c d <<< "$ip"
    
    # Validate IP octets
    if [[ $a -gt 255 || $b -gt 255 || $c -gt 255 || $d -gt 255 ]]; then
        echo "0/32"
        return 1
    fi
    
    local ip_decimal=$((a * 256**3 + b * 256**2 + c * 256 + d))
    
    # Calculate network address
    local mask=$((0xFFFFFFFF << (32 - prefix)))
    local network=$((ip_decimal & mask))
    
    echo "$network/$prefix"
}

# Function to check if two networks overlap
networks_overlap() {
    local net1="$1"
    local net2="$2"
    
    # Validate both inputs
    if ! is_valid_cidr "$net1" || ! is_valid_cidr "$net2"; then
        return 1  # No overlap if either is invalid
    fi
    
    # Convert to comparable format
    local net1_dec=$(cidr_to_decimal "$net1")
    local net2_dec=$(cidr_to_decimal "$net2")
    
    local net1_addr="${net1_dec%/*}"
    local net1_prefix="${net1_dec#*/}"
    local net2_addr="${net2_dec%/*}"
    local net2_prefix="${net2_dec#*/}"
    
    # Check if networks overlap
    local smaller_prefix=$((net1_prefix < net2_prefix ? net1_prefix : net2_prefix))
    local mask=$((0xFFFFFFFF << (32 - smaller_prefix)))
    
    local net1_masked=$((net1_addr & mask))
    local net2_masked=$((net2_addr & mask))
    
    [[ $net1_masked -eq $net2_masked ]]
}

# Function to get existing network routes
get_existing_networks() {
    local networks=()
    
    # Method 1: Get routes from 'ip route'
    if check_command ip; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+) ]]; then
                local network="${BASH_REMATCH[1]}"
                # Skip default routes and host routes (/32)
                if [[ "$network" != "0.0.0.0/0" && "$network" != *"/32" ]]; then
                    networks+=("$network")
                fi
            fi
        done < <(ip route show 2>/dev/null | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+" || true)
    fi
    
    # Method 2: Get interfaces from 'ip addr'
    if check_command ip; then
        while IFS= read -r line; do
            if [[ "$line" =~ inet[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+) ]]; then
                local network="${BASH_REMATCH[1]}"
                # Skip loopback and host routes
                if [[ "$network" != "127."* && "$network" != *"/32" ]]; then
                    networks+=("$network")
                fi
            fi
        done < <(ip addr show 2>/dev/null || true)
    fi
    
    # Method 3: Fallback to ifconfig if available
    if check_command ifconfig && [[ ${#networks[@]} -eq 0 ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ inet[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*netmask[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
                local ip="${BASH_REMATCH[1]}"
                local netmask="${BASH_REMATCH[2]}"
                # Convert netmask to CIDR
                local cidr=$(netmask_to_cidr "$netmask")
                if [[ "$ip" != "127."* && "$cidr" != "32" ]]; then
                    networks+=("$ip/$cidr")
                fi
            fi
        done < <(ifconfig 2>/dev/null || true)
    fi
    
    # Method 4: Check existing Docker networks
    if check_command docker; then
        while IFS= read -r line; do
            if [[ "$line" =~ \"Subnet\":[[:space:]]*\"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+)\" ]]; then
                local network="${BASH_REMATCH[1]}"
                networks+=("$network")
            fi
        done < <(docker network ls -q | xargs -I {} docker network inspect {} 2>/dev/null | grep -E "\"Subnet\":" || true)
    fi
    
    # Remove duplicates and return
    printf '%s\n' "${networks[@]}" | sort -u
}

# Function to convert netmask to CIDR prefix
netmask_to_cidr() {
    local netmask="$1"
    local a b c d
    IFS=. read -r a b c d <<< "$netmask"
    local mask=$((a * 256**3 + b * 256**2 + c * 256 + d))
    
    local cidr=0
    for ((i=31; i>=0; i--)); do
        if (( (mask >> i) & 1 )); then
            ((cidr++))
        else
            break
        fi
    done
    echo "$cidr"
}

# Function to suggest safe Docker subnets
suggest_safe_subnet() {
    local existing_networks=("$@")
    
    # Common safe subnets to try (in order of preference)
    local candidate_subnets=(
        "10.20.30.0/24"    # Default BunkerWeb subnet
        "172.20.0.0/24"    # Docker default range
        "172.21.0.0/24"
        "172.22.0.0/24"
        "10.10.10.0/24"
        "10.50.0.0/24"
        "10.100.0.0/24"
        "192.168.200.0/24"
        "192.168.100.0/24"
        "192.168.50.0/24"
    )
    
    # Test each candidate subnet
    for subnet in "${candidate_subnets[@]}"; do
        local conflict=false
        
        for existing in "${existing_networks[@]}"; do
            if is_valid_cidr "$existing" && networks_overlap "$subnet" "$existing"; then
                conflict=true
                break
            fi
        done
        
        if [[ "$conflict" == "false" ]]; then
            echo "$subnet"
            return 0
        fi
    done
    
    # If no predefined subnet works, generate one
    # Try different ranges in RFC1918 space
    for base_range in "10" "172" "192"; do
        case "$base_range" in
            "10")
                # Try 10.x.0.0/24 where x is 50-254
                for ((i=50; i<=254; i++)); do
                    local test_subnet="10.$i.0.0/24"
                    local conflict=false
                    for existing in "${existing_networks[@]}"; do
                        if is_valid_cidr "$existing" && networks_overlap "$test_subnet" "$existing"; then
                            conflict=true
                            break
                        fi
                    done
                    if [[ "$conflict" == "false" ]]; then
                        echo "$test_subnet"
                        return 0
                    fi
                done
                ;;
            "172")
                # Try 172.x.0.0/24 where x is 16-31
                for ((i=20; i<=31; i++)); do
                    local test_subnet="172.$i.0.0/24"
                    local conflict=false
                    for existing in "${existing_networks[@]}"; do
                        if is_valid_cidr "$existing" && networks_overlap "$test_subnet" "$existing"; then
                            conflict=true
                            break
                        fi
                    done
                    if [[ "$conflict" == "false" ]]; then
                        echo "$test_subnet"
                        return 0
                    fi
                done
                ;;
            "192")
                # Try 192.168.x.0/24 where x is 100-254
                for ((i=100; i<=254; i++)); do
                    local test_subnet="192.168.$i.0/24"
                    local conflict=false
                    for existing in "${existing_networks[@]}"; do
                        if is_valid_cidr "$existing" && networks_overlap "$test_subnet" "$existing"; then
                            conflict=true
                            break
                        fi
                    done
                    if [[ "$conflict" == "false" ]]; then
                        echo "$test_subnet"
                        return 0
                    fi
                done
                ;;
        esac
    done
    
    # Fallback - this should rarely happen
    echo "10.240.0.0/24"
}

# Function to perform network conflict detection
detect_network_conflicts() {
    if [[ "$AUTO_DETECT_NETWORK_CONFLICTS" != "yes" ]]; then
        echo -e "${BLUE}Network conflict detection disabled${NC}" >&2
        return 0
    fi
    
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo -e "${BLUE}                    NETWORK CONFLICT DETECTION                    ${NC}" >&2
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo "" >&2
    
    echo -e "${BLUE}Scanning existing network configurations...${NC}" >&2
    
    # Get existing networks from system
    local existing_networks=()
    echo -e "${CYAN}• Checking routing table...${NC}" >&2
    echo -e "${CYAN}• Checking network interfaces...${NC}" >&2
    echo -e "${CYAN}• Checking existing Docker networks...${NC}" >&2
    
    # Capture only valid CIDR networks
    while IFS= read -r network; do
        if [[ -n "$network" ]] && is_valid_cidr "$network"; then
            existing_networks+=("$network")
        fi
    done < <(get_existing_networks)
    
    # Add user-specified networks
    if [[ -n "$PRIVATE_NETWORKS_ALREADY_IN_USE" ]]; then
        echo -e "${BLUE}User-specified networks to avoid: $PRIVATE_NETWORKS_ALREADY_IN_USE${NC}" >&2
        IFS=' ' read -ra user_networks <<< "$PRIVATE_NETWORKS_ALREADY_IN_USE"
        for network in "${user_networks[@]}"; do
            # Validate CIDR format
            if is_valid_cidr "$network"; then
                existing_networks+=("$network")
            else
                echo -e "${YELLOW}⚠ Invalid network format ignored: $network${NC}" >&2
            fi
        done
    fi
    
    if [[ ${#existing_networks[@]} -eq 0 ]]; then
        echo -e "${YELLOW}⚠ No existing networks detected - using default configuration${NC}" >&2
        DOCKER_SUBNET="10.20.30.0/24"
        SYSLOG_SUBNET="10.20.30.0/24"
        return 0
    fi
    
    echo -e "${GREEN}Detected existing networks:${NC}" >&2
    for network in "${existing_networks[@]}"; do
        echo -e "${GREEN}  • $network${NC}" >&2
    done
    echo "" >&2
    
    # Check for conflicts with default BunkerWeb subnet
    local default_subnet="10.20.30.0/24"
    local conflict_found=false
    local conflicting_networks=()
    
    for existing in "${existing_networks[@]}"; do
        if networks_overlap "$default_subnet" "$existing"; then
            conflict_found=true
            conflicting_networks+=("$existing")
        fi
    done
    
    if [[ "$conflict_found" == "true" ]]; then
        echo -e "${RED}⚠ NETWORK CONFLICT DETECTED!${NC}" >&2
        echo -e "${RED}Default BunkerWeb subnet $default_subnet conflicts with:${NC}" >&2
        for conflicting in "${conflicting_networks[@]}"; do
            echo -e "${RED}  • $conflicting${NC}" >&2
        done
        echo "" >&2
        
        # Suggest safe subnet
        echo -e "${BLUE}Finding safe Docker subnet...${NC}" >&2
        local safe_subnet=$(suggest_safe_subnet "${existing_networks[@]}")
        
        # Check if we had to use a custom subnet
        local is_custom=true
        local predefined_subnets=("10.20.30.0/24" "172.20.0.0/24" "172.21.0.0/24" "172.22.0.0/24" "10.10.10.0/24" "10.50.0.0/24" "10.100.0.0/24" "192.168.200.0/24" "192.168.100.0/24" "192.168.50.0/24")
        for predefined in "${predefined_subnets[@]}"; do
            if [[ "$safe_subnet" == "$predefined" ]]; then
                is_custom=false
                break
            fi
        done
        
        if [[ "$is_custom" == "true" ]]; then
            echo -e "${YELLOW}⚠ No predefined safe subnet found, generated custom subnet${NC}" >&2
        fi
        
        echo -e "${GREEN}✓ Suggested safe subnet: $safe_subnet${NC}" >&2
        DOCKER_SUBNET="$safe_subnet"
        
        # Calculate syslog subnet in same range
        local base_ip="${safe_subnet%.*}"
        SYSLOG_SUBNET="${base_ip}.0/24"
        
    else
        echo -e "${GREEN}✓ No conflicts detected with default subnet $default_subnet${NC}" >&2
        DOCKER_SUBNET="$default_subnet"
        SYSLOG_SUBNET="10.20.30.0/24"
    fi
    
    # Use user-preferred subnet if specified and safe
    if [[ -n "$PREFERRED_DOCKER_SUBNET" ]]; then
        if is_valid_cidr "$PREFERRED_DOCKER_SUBNET"; then
            local preferred_conflict=false
            for existing in "${existing_networks[@]}"; do
                if networks_overlap "$PREFERRED_DOCKER_SUBNET" "$existing"; then
                    preferred_conflict=true
                    break
                fi
            done
            
            if [[ "$preferred_conflict" == "false" ]]; then
                echo -e "${GREEN}✓ Using preferred subnet: $PREFERRED_DOCKER_SUBNET${NC}" >&2
                DOCKER_SUBNET="$PREFERRED_DOCKER_SUBNET"
            else
                echo -e "${RED}⚠ Preferred subnet $PREFERRED_DOCKER_SUBNET conflicts with existing networks${NC}" >&2
                echo -e "${BLUE}ℹ Using auto-detected safe subnet: $DOCKER_SUBNET${NC}" >&2
            fi
        else
            echo -e "${YELLOW}⚠ Invalid preferred subnet format: $PREFERRED_DOCKER_SUBNET${NC}" >&2
        fi
    fi
    
    echo "" >&2
    echo -e "${GREEN}Final Docker network configuration:${NC}" >&2
    echo -e "${GREEN}  • Main subnet: $DOCKER_SUBNET${NC}" >&2
    echo -e "${GREEN}  • Syslog subnet: $SYSLOG_SUBNET${NC}" >&2
    echo "" >&2
}

# Load configuration from BunkerWeb.conf if it exists
CONFIG_FILE="$INSTALL_DIR/BunkerWeb.conf"
if [[ -f "$CONFIG_FILE" ]]; then
    echo -e "${BLUE}Loading configuration from $CONFIG_FILE...${NC}"
    source "$CONFIG_FILE"
    echo -e "${GREEN}✓ Configuration loaded${NC}"
    
    # Check if user has edited the default configuration
    echo -e "${BLUE}Validating configuration...${NC}"
    CONFIG_NEEDS_EDITING=false
    
    # Create a hash of the critical default values to detect if user made changes
    DEFAULT_HASH=$(echo -n "AUTO_CERT_TYPE=LE;AUTO_CERT_CONTACT=me@example.com;MULTISITE=yes" | sha256sum | cut -d' ' -f1)
    CURRENT_HASH=""
    if [[ -n "$AUTO_CERT_TYPE" && -n "$AUTO_CERT_CONTACT" ]]; then
        CURRENT_HASH=$(echo -n "AUTO_CERT_TYPE=$AUTO_CERT_TYPE;AUTO_CERT_CONTACT=$AUTO_CERT_CONTACT;MULTISITE=$MULTISITE" | sha256sum | cut -d' ' -f1)
    fi
    
    # Check for specific default/example values that need to be changed
    if [[ "$AUTO_CERT_CONTACT" == "me@example.com" ]]; then
        echo -e "${RED}⚠ Default contact email detected: $AUTO_CERT_CONTACT${NC}"
        CONFIG_NEEDS_EDITING=true
    fi
    
    # Check for other example values in the contact email
    if [[ "$AUTO_CERT_CONTACT" == *"@example.com"* || "$AUTO_CERT_CONTACT" == *"@yourdomain.com"* ]]; then
        echo -e "${RED}⚠ Example contact email detected: $AUTO_CERT_CONTACT${NC}"
        CONFIG_NEEDS_EDITING=true
    fi
    
    # Check for example FQDN values
    if [[ "$FQDN" == *"example.com"* || "$FQDN" == *"yourdomain.com"* ]]; then
        echo -e "${RED}⚠ Example domain detected: $FQDN${NC}"
        CONFIG_NEEDS_EDITING=true
    fi
    
    # Check if configuration is exactly the default (using hash comparison)
    if [[ -n "$CURRENT_HASH" && "$DEFAULT_HASH" == "$CURRENT_HASH" && -n "$AUTO_CERT_TYPE" ]]; then
        echo -e "${RED}⚠ Configuration file appears unchanged from defaults${NC}"
        CONFIG_NEEDS_EDITING=true
    fi
    
    # If SSL certificates are enabled but using default values, stop installation
    if [[ -n "$AUTO_CERT_TYPE" && "$CONFIG_NEEDS_EDITING" == "true" && "$FORCE_INSTALL" != "yes" ]]; then
        echo ""
        echo -e "${RED}=================================================================================${NC}"
        echo -e "${RED}                    CONFIGURATION VALIDATION FAILED                    ${NC}"
        echo -e "${RED}=================================================================================${NC}"
        echo ""
        echo -e "${YELLOW}SSL certificates are enabled but the configuration contains default/example values.${NC}"
        echo -e "${YELLOW}This will cause SSL certificate enrollment to fail.${NC}"
        echo ""
        echo -e "${BLUE}Configuration file: $CONFIG_FILE${NC}"
        echo ""
        echo -e "${YELLOW}Issues detected:${NC}"
        if [[ "$AUTO_CERT_CONTACT" == "me@example.com" ]]; then
            echo -e "${RED}• Contact email is still the default: me@example.com${NC}"
        fi
        if [[ "$AUTO_CERT_CONTACT" == *"@example.com"* || "$AUTO_CERT_CONTACT" == *"@yourdomain.com"* ]]; then
            echo -e "${RED}• Contact email contains example domain: $AUTO_CERT_CONTACT${NC}"
        fi
        if [[ "$FQDN" == *"example.com"* || "$FQDN" == *"yourdomain.com"* ]]; then
            echo -e "${RED}• Domain contains example values: $FQDN${NC}"
        fi
        if [[ -n "$CURRENT_HASH" && "$DEFAULT_HASH" == "$CURRENT_HASH" ]]; then
            echo -e "${RED}• Configuration appears to be completely unchanged from defaults${NC}"
        fi
        echo ""
        echo -e "${GREEN}Required fixes:${NC}"
        echo -e "${GREEN}1. Edit the configuration file:${NC}"
        echo -e "${BLUE}   nano $CONFIG_FILE${NC}"
        echo -e "${GREEN}2. Change the contact email:${NC}"
        echo -e "${BLUE}   AUTO_CERT_CONTACT=\"your-real-email@your-domain.com\"${NC}"
        echo -e "${GREEN}3. Optionally set your domain:${NC}"
        echo -e "${BLUE}   FQDN=\"your-actual-domain.com\"${NC}"
        echo -e "${GREEN}4. Run the script again${NC}"
        echo ""
        echo -e "${YELLOW}Alternative - disable SSL certificates:${NC}"
        echo -e "${BLUE}Comment out AUTO_CERT_TYPE by adding # at the beginning:${NC}"
        echo -e "${BLUE}# AUTO_CERT_TYPE=\"LE\"${NC}"
        echo ""
        echo -e "${RED}To bypass this validation (NOT RECOMMENDED): add --force${NC}"
        echo ""
        exit 1
    elif [[ "$CONFIG_NEEDS_EDITING" == "true" && "$FORCE_INSTALL" == "yes" ]]; then
        echo -e "${YELLOW}⚠ Example values detected but --force specified${NC}"
        echo -e "${RED}⚠ Proceeding with potentially invalid configuration${NC}"
        echo -e "${RED}⚠ SSL certificate enrollment may fail${NC}"
    elif [[ "$CONFIG_NEEDS_EDITING" == "true" ]]; then
        echo -e "${YELLOW}⚠ Example values detected but SSL certificates disabled${NC}"
        echo -e "${BLUE}ℹ Continuing with manual SSL configuration${NC}"
    else
        echo -e "${GREEN}✓ Configuration validation passed${NC}"
    fi
    
else
    echo -e "${YELLOW}Configuration file not found, creating default BunkerWeb.conf...${NC}"
    mkdir -p "$INSTALL_DIR"
    cat > "$CONFIG_FILE" << 'EOF'
#!/bin/bash
#
# BunkerWeb Configuration File
# This file contains default settings for the BunkerWeb setup script
# Command line arguments will override these values
#
# IMPORTANT: Edit the values below before running the setup script!
#

# Default admin username
ADMIN_USERNAME="admin"

# Domain Configuration
# FQDN=""                        # Fully Qualified Domain Name (auto-detected if not set)
# SERVER_NAME=""                 # Primary domain name (same as FQDN in single domain setups)

# Network Configuration
# IMPORTANT: Specify existing private networks in your infrastructure to avoid conflicts
# Format: Space-separated list of CIDR networks (e.g., "10.0.0.0/8 172.16.0.0/12 192.168.1.0/24")
# This helps the setup script automatically choose non-conflicting Docker subnets
PRIVATE_NETWORKS_ALREADY_IN_USE=""  # Add your existing networks here

# Examples of networks you might want to reserve:
# PRIVATE_NETWORKS_ALREADY_IN_USE="192.168.1.0/24 10.0.0.0/16"  # Home network + corporate VPN
# PRIVATE_NETWORKS_ALREADY_IN_USE="172.16.0.0/12"                # Corporate VPN range
# PRIVATE_NETWORKS_ALREADY_IN_USE="10.0.0.0/8 192.168.0.0/24"   # Corporate network + local

# Docker Network Configuration
AUTO_DETECT_NETWORK_CONFLICTS="yes"  # Auto-detect and avoid network conflicts (default: yes)
# PREFERRED_DOCKER_SUBNET=""           # Preferred subnet for Docker (auto-selected if empty)

# BunkerWeb Instance Configuration
BUNKERWEB_INSTANCES="127.0.0.1" # List of BunkerWeb instances separated by spaces

# Multisite Configuration
MULTISITE="yes"                  # Enable multisite mode (supports multiple domains)

# Security Configuration
SECURITY_MODE="block"            # Security level: detect or block (default: block)
SERVER_TYPE="http"               # Server type: http or stream (default: http)

# Greylist Configuration (Admin Interface Protection)
USE_GREYLIST="no"                # Enable greylist for admin interface (default: no)
# GREYLIST_IP=""                 # IP addresses/networks to greylist (auto-detected from SSH)
# GREYLIST_RDNS=""               # Reverse DNS suffixes to greylist

# Redis Configuration (Enabled by Default)
REDIS_ENABLED="yes"              # Enable Redis support: yes or no (default: yes)
# REDIS_PASSWORD=""              # Redis password (auto-generated if Redis enabled)

# Syslog Configuration (Enabled by Default)
SYSLOG_ENABLED="yes"             # Enable external syslog: yes or no (default: yes)
# SYSLOG_ADDRESS="127.0.0.1"     # Syslog server address (default: localhost)
# SYSLOG_PORT="514"              # Syslog port (default: 514)
# SYSLOG_NETWORK="127.0.0.1/32"  # Syslog network (default: localhost only)

# SSL Certificate Configuration
AUTO_CERT_TYPE="LE"              # Certificate type: LE or ZeroSSL (Note: ZeroSSL is draft - not yet implemented)
AUTO_CERT_CONTACT="me@example.com"  # Contact email for certificates (CHANGE THIS!)
# AUTO_CERT_ZSSL_API=""          # ZeroSSL API key (draft feature)

# Let's Encrypt Advanced Options
# LETS_ENCRYPT_CHALLENGE="http"  # Challenge type: http or dns
# LETS_ENCRYPT_STAGING="yes"     # Use staging environment: yes or no (default: yes for safety)
# LETS_ENCRYPT_WILDCARD="no"     # Enable wildcard certificates: yes or no (DNS only)

# NETWORK CONFIGURATION GUIDE:
# ============================
# 
# RFC 1918 Private Address Ranges (the only ones you should use):
# • 10.0.0.0/8        (10.0.0.0 - 10.255.255.255)     - Large corporate networks
# • 172.16.0.0/12     (172.16.0.0 - 172.31.255.255)   - Medium networks, VPNs
# • 192.168.0.0/16    (192.168.0.0 - 192.168.255.255) - Small networks, home use
#
# EXAMPLES OF NETWORK CONFIGURATION:
# 
# Home network with router on 192.168.1.x:
# PRIVATE_NETWORKS_ALREADY_IN_USE="192.168.1.0/24"
#
# Corporate environment with VPN:
# PRIVATE_NETWORKS_ALREADY_IN_USE="10.0.0.0/8 172.16.0.0/12"
#
# Multiple specific networks:
# PRIVATE_NETWORKS_ALREADY_IN_USE="192.168.1.0/24 192.168.2.0/24 10.10.0.0/16"
#
# TO AUTOMATICALLY DETECT CONFLICTS:
# The setup script will automatically scan your system for existing networks
# and combine them with PRIVATE_NETWORKS_ALREADY_IN_USE to suggest safe subnets.
#
# NETWORK CONFLICT PREVENTION:
# • The setup script will check existing routes and interfaces
# • It will avoid subnets that conflict with your specified networks
# • It will suggest the safest available private subnet
# • Docker networks will be configured to avoid all conflicts

# TO ENABLE SSL CERTIFICATES:
# 1. Change AUTO_CERT_CONTACT above from me@example.com to your real email address
# 2. Optionally set FQDN to your domain name
# 3. Run the script
#
# TO DISABLE SSL CERTIFICATES:
# 1. Comment out AUTO_CERT_TYPE (add # at the beginning)
# 2. Run the script
#
# MULTISITE MODE:
# Multisite is enabled by default, allowing you to host multiple domains.
# Each domain can have individual configurations using SERVER_NAME prefixes.
# Example: www.example.com_USE_ANTIBOT=captcha
#
# GREYLIST PROTECTION:
# Enable USE_GREYLIST=yes to protect admin interface with IP restrictions.
# GREYLIST_IP will be auto-populated with SSH connection IPs during setup.
# GREYLIST_RDNS can be used to allow access from specific domain suffixes.

# Uncomment and configure the settings below as needed:

# Example domain configuration:
# FQDN="bunkerweb.yourdomain.com"
# SERVER_NAME="bunkerweb.yourdomain.com"

# Example network configuration for home environment:
# PRIVATE_NETWORKS_ALREADY_IN_USE="192.168.1.0/24"

# Example network configuration for corporate environment:
# PRIVATE_NETWORKS_ALREADY_IN_USE="10.0.0.0/8 172.16.0.0/12"

# Example greylist configuration:
# USE_GREYLIST="yes"
# GREYLIST_IP="192.168.1.0/24 10.0.0.1"
# GREYLIST_RDNS="yourdomain.com yourcompany.com"

# Example Let's Encrypt HTTP Challenge (staging by default for safety):
# AUTO_CERT_TYPE="LE"
# AUTO_CERT_CONTACT="admin@yourdomain.com"
# FQDN="bunkerweb.yourdomain.com"
# LETS_ENCRYPT_CHALLENGE="http"
# LETS_ENCRYPT_STAGING="yes"

# Example Let's Encrypt Production (disable staging):
# AUTO_CERT_TYPE="LE"
# AUTO_CERT_CONTACT="admin@yourdomain.com"
# FQDN="bunkerweb.yourdomain.com"
# LETS_ENCRYPT_CHALLENGE="http"
# LETS_ENCRYPT_STAGING="no"

# Example Let's Encrypt DNS Challenge with Wildcard:
# AUTO_CERT_TYPE="LE"
# AUTO_CERT_CONTACT="admin@yourdomain.com"
# FQDN="yourdomain.com"
# LETS_ENCRYPT_CHALLENGE="dns"
# LETS_ENCRYPT_WILDCARD="yes"

# Example Let's Encrypt Staging (for testing):
# AUTO_CERT_TYPE="LE"
# AUTO_CERT_CONTACT="admin@yourdomain.com"
# FQDN="test.yourdomain.com"
# LETS_ENCRYPT_STAGING="yes"

# Example ZeroSSL configuration (DRAFT - NOT YET IMPLEMENTED):
# AUTO_CERT_TYPE="ZeroSSL" 
# AUTO_CERT_CONTACT="admin@yourdomain.com"
# AUTO_CERT_ZSSL_API="your-zerossl-api-key"
# FQDN="bunkerweb.yourdomain.com"

EOF
    chmod 644 "$CONFIG_FILE"
    echo -e "${GREEN}✓ Default configuration created at: $CONFIG_FILE${NC}"
    echo ""
    echo -e "${RED}=================================================================================${NC}"
    echo -e "${RED}                         IMPORTANT - READ THIS                         ${NC}"
    echo -e "${RED}=================================================================================${NC}"
    echo -e "${YELLOW}SSL certificates are ENABLED by default with placeholder values.${NC}"
    echo -e "${YELLOW}The script will STOP if you run it again without editing the config file.${NC}"
    echo ""
    echo -e "${BLUE}Network Configuration:${NC}"
    echo -e "${GREEN}• Auto-detection enabled for network conflicts${NC}"
    echo -e "${GREEN}• Specify existing networks in PRIVATE_NETWORKS_ALREADY_IN_USE to avoid conflicts${NC}"
    echo ""
    echo -e "${BLUE}Required steps before running again:${NC}"
    echo -e "${YELLOW}  1. Edit: $CONFIG_FILE${NC}"
    echo -e "${YELLOW}  2. Change: AUTO_CERT_CONTACT=\"me@example.com\"${NC}"
    echo -e "${YELLOW}  3. To: AUTO_CERT_CONTACT=\"your-real-email@domain.com\"${NC}"
    echo -e "${YELLOW}  4. Optionally set: PRIVATE_NETWORKS_ALREADY_IN_USE=\"your-existing-networks\"${NC}"
    echo -e "${YELLOW}  5. Run this script again${NC}"
    echo ""
    echo -e "${BLUE}Optional - disable services:${NC}"
    echo -e "${BLUE}  Set REDIS_ENABLED=\"no\" to disable Redis caching${NC}"
    echo -e "${BLUE}  Set SYSLOG_ENABLED=\"no\" to disable centralized logging${NC}"
    echo -e "${BLUE}  Set AUTO_DETECT_NETWORK_CONFLICTS=\"no\" to disable network checking${NC}"
    echo ""
    echo -e "${BLUE}Alternative - to disable SSL certificates:${NC}"
    echo -e "${BLUE}  Comment out AUTO_CERT_TYPE (add # at the beginning)${NC}"
    echo ""
    echo -e "${RED}=================================================================================${NC}"
fi

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
    echo -e "  --admin-name NAME   Set admin username (overrides config file)"
    echo -e "  --FQDN DOMAIN       Set Fully Qualified Domain Name (overrides auto-detection)"
    echo -e "  --force             Skip configuration validation (not recommended)"
    echo ""
    echo -e "${YELLOW}Network Configuration:${NC}"
    echo -e "  --private-networks \"NET1 NET2\"  Specify existing networks to avoid"
    echo -e "  --preferred-subnet SUBNET       Preferred Docker subnet"
    echo -e "  --no-network-check              Disable network conflict detection"
    echo ""
    echo -e "${YELLOW}Redis Configuration:${NC}"
    echo -e "  --redis-enabled yes|no       Enable Redis support (default: yes)"
    echo -e "  --redis-password PASS        Set custom Redis password"
    echo ""
    echo -e "${YELLOW}Syslog Configuration:${NC}"
    echo -e "  --syslog-enabled yes|no      Enable external syslog (default: yes)"
    echo -e "  --syslog-address ADDRESS     Syslog server address (default: 127.0.0.1)"
    echo -e "  --syslog-port PORT           Syslog port (default: 514)"
    echo -e "  --syslog-network NETWORK     Syslog network (default: 127.0.0.1/32)"
    echo ""
    echo -e "${YELLOW}SSL Certificate Options:${NC}"
    echo -e "  --AUTO_CERT LE|ZeroSSL       Enable automatic certificates (overrides config file)"
    echo -e "  --AUTO_CERT_CONTACT EMAIL    Contact email for certificate registration"
    echo -e "  --AUTO_CERT_ZSSL_API KEY     ZeroSSL API key (required when using ZeroSSL)"
    echo ""
    echo -e "${YELLOW}Let's Encrypt Advanced Options:${NC}"
    echo -e "  --LE_CHALLENGE http|dns      Challenge method (default: http)"
    echo -e "  --LE_STAGING yes|no          Use staging environment (default: yes for safety)"
    echo -e "  --LE_WILDCARD yes|no         Enable wildcard certificates (default: no, DNS only)"
    echo ""
    echo -e "${YELLOW}Help:${NC}"
    echo -e "  -h, --help          Show this help message"
    echo ""
    echo -e "${BLUE}Configuration File:${NC}"
    echo -e "  Default settings are loaded from: $INSTALL_DIR/BunkerWeb.conf"
    echo -e "  Command line arguments override config file values"
    echo -e "  ${RED}IMPORTANT: SSL is ENABLED by default with example values${NC}"
    echo -e "  ${YELLOW}You MUST edit the config file to use real email addresses${NC}"
    echo -e "  Script will stop if example values are detected in SSL configuration"
    echo ""
    echo -e "${BLUE}Network Examples:${NC}"
    echo -e "  sudo $0 --type autoconf --private-networks \"192.168.1.0/24\""
    echo -e "  sudo $0 --type autoconf --private-networks \"10.0.0.0/8 172.16.0.0/12\""
    echo -e "  sudo $0 --type autoconf --preferred-subnet \"172.20.0.0/24\""
    echo -e "  sudo $0 --type autoconf --no-network-check  # Skip network detection"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo -e "  sudo $0 --type autoconf"
    echo -e "  sudo $0 --type basic --wizard"
    echo -e "  sudo $0 --type integrated --admin-name myuser"
    echo -e "  sudo $0 --type autoconf --redis-enabled no  # Disable Redis"
    echo -e "  sudo $0 --type autoconf --syslog-enabled no  # Disable Syslog"
    echo -e "  sudo $0 --type autoconf --FQDN bunkerweb.example.com --AUTO_CERT LE --AUTO_CERT_CONTACT admin@example.com"
    echo ""
    echo -e "${BLUE}Note:${NC} Existing credentials are preserved. Delete credentials.txt to regenerate passwords."
    echo -e "${RED}Note:${NC} SSL certificates are ENABLED by default with placeholder values!"
    echo -e "${YELLOW}Note:${NC} Edit BunkerWeb.conf with real email/domain before running, or script will stop."
    echo ""
}

# Parse command line arguments
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
        --syslog-enabled)
            SYSLOG_ENABLED="$2"
            shift 2
            ;;
        --syslog-address)
            SYSLOG_ADDRESS="$2"
            shift 2
            ;;
        --syslog-port)
            SYSLOG_PORT="$2"
            shift 2
            ;;
        --syslog-network)
            SYSLOG_NETWORK="$2"
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
        --AUTO_CERT_ZSSL_API)
            AUTO_CERT_ZSSL_API="$2"
            shift 2
            ;;
        --LE_CHALLENGE)
            LETS_ENCRYPT_CHALLENGE="$2"
            shift 2
            ;;
        --LE_STAGING)
            LETS_ENCRYPT_STAGING="$2"
            shift 2
            ;;
        --LE_WILDCARD)
            LETS_ENCRYPT_WILDCARD="$2"
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

# Validate configuration parameters
case "$REDIS_ENABLED" in
    yes|no) ;;
    *)
        echo -e "${RED}Error: Invalid REDIS_ENABLED value '$REDIS_ENABLED'${NC}"
        echo -e "${YELLOW}Valid values: yes, no${NC}"
        exit 1
        ;;
esac

case "$SYSLOG_ENABLED" in
    yes|no) ;;
    *)
        echo -e "${RED}Error: Invalid SYSLOG_ENABLED value '$SYSLOG_ENABLED'${NC}"
        echo -e "${YELLOW}Valid values: yes, no${NC}"
        exit 1
        ;;
esac

case "$AUTO_DETECT_NETWORK_CONFLICTS" in
    yes|no) ;;
    *)
        echo -e "${RED}Error: Invalid AUTO_DETECT_NETWORK_CONFLICTS value '$AUTO_DETECT_NETWORK_CONFLICTS'${NC}"
        echo -e "${YELLOW}Valid values: yes, no${NC}"
        exit 1
        ;;
esac

# Validate that --type was provided
if [[ -z "$DEPLOYMENT_TYPE" ]]; then
    echo -e "${RED}Error: --type parameter is required${NC}"
    echo ""
    show_usage
    exit 1
fi

# Perform network conflict detection
detect_network_conflicts

# Auto-detect FQDN if not provided
if [[ -z "$FQDN" ]]; then
    echo -e "${BLUE}Auto-detecting FQDN...${NC}"
    
    # Try multiple methods to get FQDN
    DETECTED_FQDN=""
    
    # Method 1: hostname -f
    if check_command hostname; then
        DETECTED_FQDN=$(hostname -f 2>/dev/null || echo "")
    fi
    
    # Method 2: dnsdomainname + hostname
    if [[ -z "$DETECTED_FQDN" ]] && check_command dnsdomainname; then
        DOMAIN=$(dnsdomainname 2>/dev/null || echo "")
        HOSTNAME=$(hostname 2>/dev/null || echo "")
        if [[ -n "$DOMAIN" && -n "$HOSTNAME" ]]; then
            DETECTED_FQDN="$HOSTNAME.$DOMAIN"
        fi
    fi
    
    # Method 3: Check /etc/hostname and /etc/hosts
    if [[ -z "$DETECTED_FQDN" && -f "/etc/hostname" ]]; then
        HOSTNAME=$(cat /etc/hostname 2>/dev/null | head -1)
        if [[ "$HOSTNAME" == *.* ]]; then
            DETECTED_FQDN="$HOSTNAME"
        fi
    fi
    
    # Validate detected FQDN
    if [[ -n "$DETECTED_FQDN" && "$DETECTED_FQDN" == *.* && "$DETECTED_FQDN" != "localhost."* ]]; then
        FQDN="$DETECTED_FQDN"
        echo -e "${GREEN}✓ FQDN auto-detected: $FQDN${NC}"
    else
        echo -e "${YELLOW}⚠ Could not auto-detect valid FQDN${NC}"
        echo -e "${BLUE}Detected: ${DETECTED_FQDN:-'none'}${NC}"
        
        if [[ -n "$AUTO_CERT_TYPE" ]]; then
            echo -e "${RED}Error: FQDN is required for SSL certificate enrollment${NC}"
            echo -e "${YELLOW}Please specify FQDN using: --FQDN your-domain.com${NC}"
            exit 1
        else
            echo -e "${BLUE}ℹ SSL certificates disabled - FQDN not required${NC}"
            FQDN="localhost"
        fi
    fi
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
        echo ""
        show_usage
        exit 1
        ;;
esac

# Validate SSL certificate options
if [[ -n "$AUTO_CERT_TYPE" ]]; then
    case "$AUTO_CERT_TYPE" in
        LE|LetsEncrypt)
            AUTO_CERT_TYPE="LE"
            if [[ -z "$AUTO_CERT_CONTACT" ]]; then
                echo -e "${RED}Error: --AUTO_CERT_CONTACT email is required when using Let's Encrypt${NC}"
                exit 1
            fi
            if [[ -z "$FQDN" || "$FQDN" == "localhost" ]]; then
                echo -e "${RED}Error: Valid FQDN is required for Let's Encrypt certificates${NC}"
                echo -e "${YELLOW}Please specify FQDN using: --FQDN your-domain.com${NC}"
                exit 1
            fi
            
            # Validate Let's Encrypt specific options
            case "$LETS_ENCRYPT_CHALLENGE" in
                http|dns) ;;
                *)
                    echo -e "${RED}Error: Invalid challenge type '$LETS_ENCRYPT_CHALLENGE'${NC}"
                    echo -e "${YELLOW}Valid types: http, dns${NC}"
                    exit 1
                    ;;
            esac
            
            case "$LETS_ENCRYPT_STAGING" in
                yes|no) ;;
                *)
                    echo -e "${RED}Error: Invalid staging value '$LETS_ENCRYPT_STAGING'${NC}"
                    echo -e "${YELLOW}Valid values: yes, no${NC}"
                    exit 1
                    ;;
            esac
            
            case "$LETS_ENCRYPT_WILDCARD" in
                yes|no) ;;
                *)
                    echo -e "${RED}Error: Invalid wildcard value '$LETS_ENCRYPT_WILDCARD'${NC}"
                    echo -e "${YELLOW}Valid values: yes, no${NC}"
                    exit 1
                    ;;
            esac
            
            # Wildcard certificates require DNS challenge
            if [[ "$LETS_ENCRYPT_WILDCARD" == "yes" && "$LETS_ENCRYPT_CHALLENGE" != "dns" ]]; then
                echo -e "${RED}Error: Wildcard certificates require DNS challenge${NC}"
                echo -e "${YELLOW}Please set: --LE_CHALLENGE dns${NC}"
                exit 1
            fi
            ;;
        ZeroSSL)
            if [[ -z "$AUTO_CERT_CONTACT" ]]; then
                echo -e "${RED}Error: --AUTO_CERT_CONTACT email is required when using ZeroSSL${NC}"
                exit 1
            fi
            if [[ -z "$AUTO_CERT_ZSSL_API" ]]; then
                echo -e "${RED}Error: --AUTO_CERT_ZSSL_API key is required when using ZeroSSL${NC}"
                exit 1
            fi
            if [[ -z "$FQDN" || "$FQDN" == "localhost" ]]; then
                echo -e "${RED}Error: Valid FQDN is required for ZeroSSL certificates${NC}"
                echo -e "${YELLOW}Please specify FQDN using: --FQDN your-domain.com${NC}"
                exit 1
            fi
            ;;
        *)
            echo -e "${RED}Error: Invalid certificate type '$AUTO_CERT_TYPE'${NC}"
            echo -e "${YELLOW}Valid types: LE, ZeroSSL${NC}"
            exit 1
            ;;
    esac
fi

# Set compose file path
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"
TEMPLATE_PATH="$INSTALL_DIR/$TEMPLATE_FILE"
BACKUP_FILE="$INSTALL_DIR/docker-compose.yml.backup"

echo ""
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}          BunkerWeb Setup Script${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""
echo -e "${GREEN}Deployment Type:${NC} $DEPLOYMENT_NAME"
echo -e "${GREEN}Template File:${NC} $TEMPLATE_FILE"
echo -e "${GREEN}Setup Mode:${NC} $(if [[ $SETUP_MODE == "automated" ]]; then echo "Automated"; else echo "Setup Wizard"; fi)"
echo -e "${GREEN}Admin Username:${NC} $ADMIN_USERNAME"
echo -e "${GREEN}Domain (FQDN):${NC} $FQDN"
echo -e "${GREEN}Multisite Mode:${NC} $MULTISITE"
echo -e "${GREEN}Network Conflicts:${NC} $(if [[ $AUTO_DETECT_NETWORK_CONFLICTS == "yes" ]]; then echo "Auto-detected"; else echo "Disabled"; fi)"
if [[ -n "$DOCKER_SUBNET" ]]; then
    echo -e "${GREEN}Docker Subnet:${NC} $DOCKER_SUBNET"
fi
echo -e "${GREEN}Redis Enabled:${NC} $REDIS_ENABLED"
echo -e "${GREEN}Syslog Enabled:${NC} $SYSLOG_ENABLED"
echo -e "${GREEN}Config File:${NC} $(if [[ -f "$CONFIG_FILE" ]]; then echo "Loaded"; else echo "Created default"; fi)"
if [[ -n "$AUTO_CERT_TYPE" ]]; then
    echo -e "${GREEN}SSL Certificates:${NC} $AUTO_CERT_TYPE"
    echo -e "${GREEN}Contact Email:${NC} $AUTO_CERT_CONTACT"
    if [[ "$AUTO_CERT_TYPE" == "LE" ]]; then
        echo -e "${GREEN}Challenge Type:${NC} $LETS_ENCRYPT_CHALLENGE"
        echo -e "${GREEN}Staging Mode:${NC} $LETS_ENCRYPT_STAGING $(if [[ "$LETS_ENCRYPT_STAGING" == "yes" ]]; then echo "(default for safety)"; fi)"
        echo -e "${GREEN}Wildcard Certs:${NC} $LETS_ENCRYPT_WILDCARD"
    elif [[ "$AUTO_CERT_TYPE" == "ZeroSSL" ]]; then
        echo -e "${GREEN}ZeroSSL API:${NC} ${AUTO_CERT_ZSSL_API:0:8}..."
    fi
else
    echo -e "${GREEN}SSL Certificates:${NC} Manual configuration"
fi
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   echo -e "${YELLOW}Please run: sudo $0 --type $DEPLOYMENT_TYPE${NC}"
   exit 1
fi

# Check if template file exists
if [[ ! -f "$TEMPLATE_PATH" ]]; then
    echo -e "${RED}Error: Template file not found at $TEMPLATE_PATH${NC}"
    echo -e "${YELLOW}Available templates should be:${NC}"
    echo -e "  - $INSTALL_DIR/template_autoconf_display.yml"
    echo -e "  - $INSTALL_DIR/template_basic_display.yml"
    echo -e "  - $INSTALL_DIR/template_ui_integrated_display.yml"
    exit 1
fi

# Copy template to docker-compose.yml
echo -e "${BLUE}Copying template to docker-compose.yml...${NC}"
cp "$TEMPLATE_PATH" "$COMPOSE_FILE"
echo -e "${GREEN}✓ Template copied: $TEMPLATE_FILE → docker-compose.yml${NC}"

# Create backup
echo -e "${BLUE}Creating backup...${NC}"
cp "$COMPOSE_FILE" "$BACKUP_FILE"
echo -e "${GREEN}Backup created: $BACKUP_FILE${NC}"

# Update Docker network subnets if conflicts were detected
if [[ -n "$DOCKER_SUBNET" && "$DOCKER_SUBNET" != "10.20.30.0/24" ]]; then
    echo -e "${BLUE}Updating Docker network configuration to avoid conflicts...${NC}"
    
    # Escape special characters for sed
    local escaped_subnet=$(printf '%s\n' "$DOCKER_SUBNET" | sed 's/[[\.*^$()+?{|]/\\&/g')
    
    # Update the main universe subnet
    sed -i "s|10\.20\.30\.0/24|${escaped_subnet}|g" "$COMPOSE_FILE"
    echo -e "${GREEN}✓ Main subnet updated to: $DOCKER_SUBNET${NC}"
    
    # Update syslog subnet if needed
    if [[ -n "$SYSLOG_SUBNET" && "$SYSLOG_SUBNET" != "$SYSLOG_NETWORK" ]]; then
        # Calculate a suitable syslog subnet from the Docker subnet
        local base_ip="${DOCKER_SUBNET%.*}"
        local syslog_cidr="${base_ip}.0/24"
        SYSLOG_NETWORK="$syslog_cidr"
        echo -e "${GREEN}✓ Syslog subnet will be: $SYSLOG_NETWORK${NC}"
    fi
fi

# Generate passwords function - Admin password only (12 characters for human use)
generate_admin_password() {
    openssl rand -base64 33 | head -c 12 && echo
}

# Generate secure passwords function (full entropy for system passwords)
generate_secure_password() {
    openssl rand -base64 33
}

# Check if credentials already exist
CREDS_FILE="$INSTALL_DIR/credentials.txt"

if [[ -f "$CREDS_FILE" ]]; then
    echo -e "${BLUE}Found existing credentials file, loading existing passwords...${NC}"
    
    # Extract existing passwords from credentials file
    MYSQL_PASSWORD=$(grep "MySQL Database Password:" "$CREDS_FILE" | cut -d' ' -f4 || echo "")
    TOTP_SECRET=$(grep "TOTP Secret Key:" "$CREDS_FILE" | cut -d' ' -f4 || echo "")
    ADMIN_PASSWORD=$(grep "Admin Password:" "$CREDS_FILE" | cut -d' ' -f3 || echo "")
    FLASK_SECRET=$(grep "Flask Secret:" "$CREDS_FILE" | cut -d' ' -f3 || echo "")
    
    # Load existing Redis password if available
    EXISTING_REDIS_PASSWORD=$(grep "Redis Password:" "$CREDS_FILE" | cut -d' ' -f3 || echo "")
    if [[ "$REDIS_ENABLED" == "yes" ]]; then
        if [[ -n "$EXISTING_REDIS_PASSWORD" ]]; then
            REDIS_PASSWORD="$EXISTING_REDIS_PASSWORD"
        elif [[ -z "$REDIS_PASSWORD" ]]; then
            REDIS_PASSWORD=$(generate_secure_password)
        fi
    fi
    
    # Verify we got all passwords
    if [[ -n "$MYSQL_PASSWORD" && -n "$TOTP_SECRET" && -n "$ADMIN_PASSWORD" && -n "$FLASK_SECRET" ]]; then
        echo -e "${GREEN}✓ Existing MySQL password loaded${NC}"
        echo -e "${GREEN}✓ Existing TOTP secret loaded${NC}"
        echo -e "${GREEN}✓ Existing admin password loaded${NC}"
        echo -e "${GREEN}✓ Existing Flask secret loaded${NC}"
        if [[ "$REDIS_ENABLED" == "yes" ]]; then
            echo -e "${GREEN}✓ Redis password loaded/generated${NC}"
        fi
        echo -e "${YELLOW}Note: Using existing credentials. Delete $CREDS_FILE to regenerate passwords.${NC}"
    else
        echo -e "${YELLOW}Warning: Could not load all credentials from existing file.${NC}"
        echo -e "${BLUE}Generating missing credentials...${NC}"
        
        # Generate any missing passwords
        [[ -z "$MYSQL_PASSWORD" ]] && MYSQL_PASSWORD=$(generate_secure_password) && echo -e "${GREEN}✓ New MySQL password generated${NC}"
        [[ -z "$TOTP_SECRET" ]] && TOTP_SECRET=$(generate_secure_password) && echo -e "${GREEN}✓ New TOTP secret generated${NC}"
        [[ -z "$ADMIN_PASSWORD" ]] && ADMIN_PASSWORD=$(generate_admin_password) && echo -e "${GREEN}✓ New admin password generated${NC}"
        [[ -z "$FLASK_SECRET" ]] && FLASK_SECRET=$(generate_secure_password) && echo -e "${GREEN}✓ New Flask secret generated${NC}"
        if [[ "$REDIS_ENABLED" == "yes" && -z "$REDIS_PASSWORD" ]]; then
            REDIS_PASSWORD=$(generate_secure_password)
            echo -e "${GREEN}✓ New Redis password generated${NC}"
        fi
    fi
else
    echo -e "${BLUE}No existing credentials found, generating new secure passwords...${NC}"
    
    # Generate MySQL password (used for both DATABASE_URI and MYSQL_PASSWORD)
    MYSQL_PASSWORD=$(generate_secure_password)
    echo -e "${GREEN}✓ MySQL password generated${NC}"

    # Generate TOTP secret
    TOTP_SECRET=$(generate_secure_password)
    echo -e "${GREEN}✓ TOTP secret generated${NC}"

    # Generate admin password and Flask secret (always generated for both modes)
    ADMIN_PASSWORD=$(generate_admin_password)
    echo -e "${GREEN}✓ Admin password generated (12 chars - human friendly)${NC}"

    FLASK_SECRET=$(generate_secure_password)
    echo -e "${GREEN}✓ Flask secret generated${NC}"
    
    # Generate Redis password if enabled
    if [[ "$REDIS_ENABLED" == "yes" && -z "$REDIS_PASSWORD" ]]; then
        REDIS_PASSWORD=$(generate_secure_password)
        echo -e "${GREEN}✓ Redis password generated${NC}"
    fi
fi

# Create/update credentials file
if [[ -f "$CREDS_FILE" ]]; then
    echo -e "${BLUE}Updating existing credentials file...${NC}"
    # Create backup of existing credentials
    cp "$CREDS_FILE" "$CREDS_FILE.backup.$(date +%Y%m%d_%H%M%S)"
    echo -e "${GREEN}✓ Existing credentials backed up${NC}"
else
    echo -e "${BLUE}Creating new credentials file...${NC}"
fi

cat > "$CREDS_FILE" << EOF
# BunkerWeb Generated Credentials
# Deployment Type: $DEPLOYMENT_NAME
# Template Used: $TEMPLATE_FILE
# Setup Mode: $(if [[ $SETUP_MODE == "automated" ]]; then echo "Automated"; else echo "Setup Wizard"; fi)
# Generated on: $(date)
# Keep this file secure and backed up!

MySQL Database Password: $MYSQL_PASSWORD
TOTP Secret Key: $TOTP_SECRET
$(if [[ "$REDIS_ENABLED" == "yes" ]]; then echo "Redis Password: $REDIS_PASSWORD"; fi)

# Web UI Setup (passwords always generated)
Admin Username: $ADMIN_USERNAME
Admin Password: $ADMIN_PASSWORD
Flask Secret: $FLASK_SECRET

# Domain Configuration
FQDN: $FQDN
Server Name: $(if [[ -n "$SERVER_NAME" ]]; then echo "$SERVER_NAME"; else echo "$FQDN"; fi)

# Network Configuration
Network Conflict Detection: $AUTO_DETECT_NETWORK_CONFLICTS
$(if [[ -n "$DOCKER_SUBNET" ]]; then echo "Docker Subnet: $DOCKER_SUBNET"; fi)
$(if [[ -n "$PRIVATE_NETWORKS_ALREADY_IN_USE" ]]; then echo "Private Networks Avoided: $PRIVATE_NETWORKS_ALREADY_IN_USE"; fi)

# BunkerWeb Configuration
Multisite Mode: $MULTISITE
BunkerWeb Instances: $BUNKERWEB_INSTANCES
Security Mode: $SECURITY_MODE
Server Type: $SERVER_TYPE
Redis Enabled: $REDIS_ENABLED
Syslog Enabled: $SYSLOG_ENABLED
$(if [[ "$SYSLOG_ENABLED" == "yes" ]]; then echo "Syslog Server: $SYSLOG_ADDRESS:$SYSLOG_PORT"; fi)

# Greylist Configuration (Admin Interface Protection)
Use Greylist: $USE_GREYLIST
$(if [[ "$USE_GREYLIST" == "yes" ]]; then
echo "Greylist IPs: $GREYLIST_IP"
echo "Greylist RDNS: $GREYLIST_RDNS"
fi)

# SSL Certificate Configuration
Certificate Type: $(if [[ -n "$AUTO_CERT_TYPE" ]]; then echo "$AUTO_CERT_TYPE"; else echo "Manual"; fi)
Contact Email: $AUTO_CERT_CONTACT
$(if [[ "$AUTO_CERT_TYPE" == "LE" ]]; then
echo "Challenge Type: $LETS_ENCRYPT_CHALLENGE"
echo "Staging Mode: $LETS_ENCRYPT_STAGING"
echo "Wildcard Certificates: $LETS_ENCRYPT_WILDCARD"
fi)
$(if [[ "$AUTO_CERT_TYPE" == "ZeroSSL" ]]; then echo "ZeroSSL API Key: $AUTO_CERT_ZSSL_API (NOTE: ZeroSSL is draft - not yet implemented)"; fi)

# Network Information:
# Network conflict detection automatically scans system routes and interfaces
# to avoid conflicts with existing networks. This ensures Docker containers
# can start without IP address conflicts.

# Database Connection String:
# mariadb+pymysql://bunkerweb:$MYSQL_PASSWORD@bw-db:3306/db

$(if [[ "$REDIS_ENABLED" == "yes" ]]; then
echo "# Redis Connection String:"
echo "# redis://:$REDIS_PASSWORD@bw-redis:6379/0"
echo "# Redis CLI Access: docker exec -it bw-redis redis-cli -a '$REDIS_PASSWORD'"
fi)

$(if [[ "$SYSLOG_ENABLED" == "yes" ]]; then
echo "# Syslog Information:"
echo "# Syslog Server: $SYSLOG_ADDRESS:$SYSLOG_PORT"
echo "# Log Files: $INSTALL_DIR/logs/"
echo "# Syslog Access: docker exec -it bw-syslog tail -f /var/log/messages"
fi)
EOF

if [[ $SETUP_MODE == "automated" ]]; then
    # Automated setup - enable automated configuration
    echo -e "${BLUE}Configuring automated setup...${NC}"
    
    # Enable automated setup in docker-compose.yml (uncomment the lines)
    sed -i 's|# OVERRIDE_ADMIN_CREDS: "yes"|OVERRIDE_ADMIN_CREDS: "yes"|' "$COMPOSE_FILE"
    sed -i 's|# ADMIN_USERNAME: "admin"|ADMIN_USERNAME: "'$ADMIN_USERNAME'"|' "$COMPOSE_FILE"
    sed -i 's|# ADMIN_PASSWORD: "REPLACEME_ADMIN"|ADMIN_PASSWORD: "'$ADMIN_PASSWORD'"|' "$COMPOSE_FILE"
    sed -i 's|# FLASK_SECRET: "REPLACEME_FLASK"|FLASK_SECRET: "'$FLASK_SECRET'"|' "$COMPOSE_FILE"
    
    echo -e "${GREEN}✓ Automated setup configured and enabled${NC}"
    echo -e "${GREEN}✓ Admin credentials activated${NC}"
else
    echo -e "${BLUE}Configuring setup wizard mode...${NC}"
    echo -e "${BLUE}Admin credentials generated but setup wizard enabled${NC}"
fi

# Secure the credentials file
chmod 600 "$CREDS_FILE"
if [[ -f "$CREDS_FILE.backup."* ]]; then
    echo -e "${GREEN}✓ Credentials updated in: $CREDS_FILE${NC}"
else
    echo -e "${GREEN}✓ Credentials saved to: $CREDS_FILE${NC}"
fi

# Replace placeholders in docker-compose.yml
echo -e "${BLUE}Updating docker-compose.yml...${NC}"

# Replace REPLACEME_MYSQL (both in DATABASE_URI and MYSQL_PASSWORD)
sed -i "s|REPLACEME_MYSQL|$MYSQL_PASSWORD|g" "$COMPOSE_FILE"
echo -e "${GREEN}✓ MySQL passwords updated${NC}"

# Replace REPLACEME_DEFAULT (TOTP_SECRETS)
sed -i "s|REPLACEME_DEFAULT|$TOTP_SECRET|g" "$COMPOSE_FILE"
echo -e "${GREEN}✓ TOTP secret updated${NC}"

# Always replace admin password and Flask secret placeholders
sed -i "s|REPLACEME_ADMIN|$ADMIN_PASSWORD|g" "$COMPOSE_FILE"
sed -i "s|REPLACEME_FLASK|$FLASK_SECRET|g" "$COMPOSE_FILE"
echo -e "${GREEN}✓ Admin password updated${NC}"
echo -e "${GREEN}✓ Flask secret updated${NC}"

# Handle additional placeholders that may exist in templates
echo -e "${BLUE}Processing additional template placeholders...${NC}"

# Handle Redis password placeholder
if grep -q "REPLACEME_REDIS_PASSWORD" "$COMPOSE_FILE"; then
    if [[ "$REDIS_ENABLED" == "yes" && -n "$REDIS_PASSWORD" ]]; then
        sed -i "s|REPLACEME_REDIS_PASSWORD|$REDIS_PASSWORD|g" "$COMPOSE_FILE"
        echo -e "${GREEN}✓ Redis password updated${NC}"
    else
        # Redis disabled - use a placeholder value
        sed -i "s|REPLACEME_REDIS_PASSWORD|disabled|g" "$COMPOSE_FILE"
        echo -e "${BLUE}✓ Redis password placeholder set to 'disabled'${NC}"
    fi
fi

# Handle Syslog placeholders
if grep -q "REPLACEME_SYSLOG_ADDRESS" "$COMPOSE_FILE"; then
    sed -i "s|REPLACEME_SYSLOG_ADDRESS|$SYSLOG_ADDRESS|g" "$COMPOSE_FILE"
    echo -e "${GREEN}✓ Syslog address updated to: $SYSLOG_ADDRESS${NC}"
fi

if grep -q "REPLACEME_SYSLOG_PORT" "$COMPOSE_FILE"; then
    sed -i "s|REPLACEME_SYSLOG_PORT|$SYSLOG_PORT|g" "$COMPOSE_FILE"
    echo -e "${GREEN}✓ Syslog port updated to: $SYSLOG_PORT${NC}"
fi

if grep -q "REPLACEME_SYSLOG_NETWORK" "$COMPOSE_FILE"; then
    sed -i "s|REPLACEME_SYSLOG_NETWORK|$SYSLOG_NETWORK|g" "$COMPOSE_FILE"
    echo -e "${GREEN}✓ Syslog network updated to: $SYSLOG_NETWORK${NC}"
fi

# Add Redis and Syslog containers if they don't exist and are enabled
if [[ "$REDIS_ENABLED" == "yes" ]]; then
    if ! grep -q "bw-redis:" "$COMPOSE_FILE"; then
        echo -e "${BLUE}Adding Redis container to docker-compose.yml...${NC}"
        cat >> "$COMPOSE_FILE" << EOF

  bw-redis:
    image: redis:7-alpine
    command: >
      redis-server
      --requirepass "$REDIS_PASSWORD"
      --maxmemory 256mb
      --maxmemory-policy allkeys-lru
      --save 900 1 300 10 60 10000
      --appendonly yes
      --appendfsync everysec
      --auto-aof-rewrite-percentage 100
      --auto-aof-rewrite-min-size 64mb
      --tcp-keepalive 300
      --timeout 300
    volumes:
      - /data/BunkerWeb/redis:/data
    restart: unless-stopped
    networks:
      - bw-redis
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
EOF
        echo -e "${GREEN}✓ Redis container added to compose file${NC}"
    else
        echo -e "${GREEN}✓ Redis container already exists in compose file${NC}"
    fi
fi

# Handle syslog configuration
if [[ "$SYSLOG_ENABLED" == "yes" ]]; then
    echo -e "${GREEN}✓ Syslog service configured in template${NC}"
elif [[ "$SYSLOG_ENABLED" == "no" ]]; then
    # Remove syslog service if disabled
    if grep -q "bw-syslog:" "$COMPOSE_FILE"; then
        echo -e "${BLUE}Removing syslog service (disabled)...${NC}"
        # Remove the entire bw-syslog service section
        sed -i '/bw-syslog:/,/^  [a-zA-Z]/{ /^  [a-zA-Z]/!d; }' "$COMPOSE_FILE"
        # Remove syslog dependencies
        sed -i '/- bw-syslog/d' "$COMPOSE_FILE"
        # Remove syslog networks
        sed -i '/bw-syslog$/d' "$COMPOSE_FILE"
        echo -e "${GREEN}✓ Syslog service removed${NC}"
    fi
fi

# Handle SSL certificate configuration
if [[ -n "$AUTO_CERT_TYPE" ]]; then
    echo -e "${BLUE}Configuring SSL certificates ($AUTO_CERT_TYPE) for domain: $FQDN...${NC}"
    
    if [[ "$AUTO_CERT_TYPE" == "LE" ]]; then
        # Let's Encrypt configuration
        sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|yes|g" "$COMPOSE_FILE" 2>/dev/null || true
        sed -i "s|REPLACEME_EMAIL_LETS_ENCRYPT|$AUTO_CERT_CONTACT|g" "$COMPOSE_FILE" 2>/dev/null || true
        
        # Set email and other options
        if grep -q "EMAIL_LETS_ENCRYPT:" "$COMPOSE_FILE"; then
            sed -i "s|EMAIL_LETS_ENCRYPT: \".*\"|EMAIL_LETS_ENCRYPT: \"$AUTO_CERT_CONTACT\"|g" "$COMPOSE_FILE"
        fi
        
        echo -e "${GREEN}✓ Let's Encrypt enabled${NC}"
        echo -e "${GREEN}✓ Contact email: $AUTO_CERT_CONTACT${NC}"
        
    elif [[ "$AUTO_CERT_TYPE" == "ZeroSSL" ]]; then
        # ZeroSSL configuration
        sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|yes|g" "$COMPOSE_FILE" 2>/dev/null || true
        sed -i "s|REPLACEME_EMAIL_LETS_ENCRYPT|$AUTO_CERT_CONTACT|g" "$COMPOSE_FILE" 2>/dev/null || true
        echo -e "${GREEN}✓ Contact email: $AUTO_CERT_CONTACT${NC}"
    fi
    
    # Set domain/server name for SSL certificates
    sed -i "s|SERVER_NAME: \"\"|SERVER_NAME: \"$FQDN\"|g" "$COMPOSE_FILE"
    sed -i "s|REPLACEME_DOMAIN|$FQDN|g" "$COMPOSE_FILE"
    echo -e "${GREEN}✓ Domain configured: $FQDN${NC}"
    
else
    # No automatic certificates - ensure Let's Encrypt is disabled
    sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|no|g" "$COMPOSE_FILE" 2>/dev/null || true
    sed -i "s|AUTO_LETS_ENCRYPT: \"yes\"|AUTO_LETS_ENCRYPT: \"no\"|g" "$COMPOSE_FILE" 2>/dev/null || true
    sed -i "s|SERVER_NAME: \"\"|SERVER_NAME: \"$FQDN\"|g" "$COMPOSE_FILE"
    sed -i "s|REPLACEME_DOMAIN|$FQDN|g" "$COMPOSE_FILE"
    echo -e "${BLUE}✓ SSL certificates set to manual configuration${NC}"
    echo -e "${BLUE}✓ Domain configured: $FQDN${NC}"
fi

# Verify replacements
echo -e "${BLUE}Verifying configuration...${NC}"

# Check for any remaining placeholders (all should be replaced now)
REMAINING_PLACEHOLDERS=$(grep -o "REPLACEME_[A-Z_]*" "$COMPOSE_FILE" || true)

if [[ -n "$REMAINING_PLACEHOLDERS" ]]; then
    echo -e "${RED}Error: Some placeholders were not replaced!${NC}"
    echo "Remaining placeholders: $REMAINING_PLACEHOLDERS"
    echo -e "${YELLOW}Restoring backup...${NC}"
    cp "$BACKUP_FILE" "$COMPOSE_FILE"
    exit 1
else
    echo -e "${GREEN}✓ All placeholders successfully replaced${NC}"
fi

# Create required directories
echo -e "${BLUE}Creating directories...${NC}"
mkdir -p "$INSTALL_DIR/storage"
mkdir -p "$INSTALL_DIR/database"
mkdir -p "$INSTALL_DIR/apps"

# Create syslog directory if enabled
if [[ "$SYSLOG_ENABLED" == "yes" ]]; then
    mkdir -p "$INSTALL_DIR/logs"
    echo -e "${GREEN}✓ Syslog directory created: $INSTALL_DIR/logs${NC}"
fi

# Create Redis directory if enabled  
if [[ "$REDIS_ENABLED" == "yes" ]]; then
    mkdir -p "$INSTALL_DIR/redis"
    echo -e "${GREEN}✓ Redis directory created: $INSTALL_DIR/redis${NC}"
fi

# Set proper ownership and permissions for BunkerWeb containers
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

# Set ownership for Syslog directory if enabled
if [[ "$SYSLOG_ENABLED" == "yes" ]]; then
    chown -R 101:101 "$INSTALL_DIR/logs"
    chmod -R 755 "$INSTALL_DIR/logs"
    echo -e "${GREEN}✓ Syslog directory ownership set to syslog (101:101)${NC}"
fi

# Set general ownership for other files
if [[ -n "$SUDO_USER" ]]; then
    OWNER_USER="$SUDO_USER"
    OWNER_GROUP=$(id -gn "$SUDO_USER")
    echo -e "${GREEN}Setting general ownership to: $OWNER_USER:$OWNER_GROUP${NC}"
    
    # Set ownership for compose files and scripts, but preserve container-specific directories
    chown "$OWNER_USER:$OWNER_GROUP" "$INSTALL_DIR"
    chown "$OWNER_USER:$OWNER_GROUP" "$INSTALL_DIR"/*.yml 2>/dev/null || true
    chown "$OWNER_USER:$OWNER_GROUP" "$INSTALL_DIR"/*.sh 2>/dev/null || true
    chown "$OWNER_USER:$OWNER_GROUP" "$INSTALL_DIR/apps"
else
    echo -e "${YELLOW}Running as root directly, keeping root ownership for config files${NC}"
fi

chmod 755 "$INSTALL_DIR"
chmod 600 "$CREDS_FILE"  # Keep credentials file secure
chmod 755 "$INSTALL_DIR/apps"
echo -e "${GREEN}✓ All directories created and permissions properly set${NC}"

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}          Setup Complete!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${YELLOW}Deployment Type:${NC} $DEPLOYMENT_NAME"
echo -e "${YELLOW}Installation Directory:${NC} $INSTALL_DIR"
echo -e "${YELLOW}Credentials File:${NC} $CREDS_FILE"
echo -e "${YELLOW}Network Conflict Detection:${NC} $AUTO_DETECT_NETWORK_CONFLICTS"
if [[ -n "$DOCKER_SUBNET" ]]; then
    echo -e "${YELLOW}Docker Subnet:${NC} $DOCKER_SUBNET"
fi
echo -e "${YELLOW}Redis Enabled:${NC} $REDIS_ENABLED"
echo -e "${YELLOW}Syslog Enabled:${NC} $SYSLOG_ENABLED"
echo ""

if [[ $SETUP_MODE == "automated" ]]; then
    echo -e "${BLUE}🚀 Configuration completed with network conflict detection!${NC}"
    echo -e "${GREEN}You can now start BunkerWeb with: cd $INSTALL_DIR && docker compose up -d${NC}"
else
    echo -e "${BLUE}🔧 Setup wizard mode configured with safe network settings!${NC}"
fi

echo -e "${GREEN}Setup script completed successfully!${NC}"