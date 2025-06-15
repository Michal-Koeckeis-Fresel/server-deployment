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

# BunkerWeb Auto-Configuration Script
# This script automatically detects FQDN, verifies DNS records, and configures SSL
# It will prompt for email address unless provided via --email option

set -e

INSTALL_DIR="/data/BunkerWeb"
CONFIG_FILE="$INSTALL_DIR/BunkerWeb.conf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display usage
show_usage() {
    echo -e "${BLUE}Usage: $0 [OPTIONS]${NC}"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  --fqdn DOMAIN       Specify FQDN instead of auto-detection"
    echo -e "  --email EMAIL       Set contact email for SSL certificates"
    echo -e "  --staging yes|no    Use Let's Encrypt staging (default: yes)"
    echo -e "  --production        Use Let's Encrypt production (same as --staging no)"
    echo -e "  --verify-only       Only verify DNS without configuring"
    echo -e "  --force-ip IP       Use specific IP instead of auto-detection"
    echo -e "  -h, --help          Show this help message"
    echo ""
    echo -e "${YELLOW}Configuration File:${NC}"
    echo -e "  If /root/BunkerWeb.conf exists, values will be loaded as defaults"
    echo -e "  Command line arguments override configuration file values"
    echo -e "  Supported config variables: FQDN, AUTO_CERT_CONTACT, LETS_ENCRYPT_STAGING,"
    echo -e "  ADMIN_USERNAME, GREYLIST_IP, GREYLIST_RDNS"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo -e "  $0                                    # Auto-detect, will prompt for email"
    echo -e "  $0 --email admin@example.com         # Specify email on command line"
    echo -e "  $0 --fqdn bunkerweb.example.com --email admin@example.com"
    echo -e "  $0 --fqdn example.com --email admin@example.com --production"
    echo -e "  $0 --verify-only                     # Just check DNS (no email needed)"
    echo ""
    echo -e "${BLUE}Description:${NC}"
    echo -e "  This script automatically:"
    echo -e "  1. Loads configuration from /root/BunkerWeb.conf (if exists)"
    echo -e "  2. Detects your server's external IP address"
    echo -e "  3. Detects or uses provided FQDN"
    echo -e "  4. Prompts for email address (unless --email provided)"
    echo -e "  5. Checks if DNS A record points to your IP"
    echo -e "  6. Configures BunkerWeb.conf if DNS is correct"
    echo ""
    echo -e "${YELLOW}Note: Email is required for SSL certificate registration with Let's Encrypt${NC}"
    echo -e "${YELLOW}Note: Email domain will be verified to ensure it exists${NC}"
    echo ""
}

# Function to get external IP address
get_external_ip() {
    local ip=""
    local services=(
        "https://ipinfo.io/ip"
        "https://ifconfig.me"
        "https://api.ipify.org"
        "https://checkip.amazonaws.com"
        "https://icanhazip.com"
    )
    
    echo -e "${BLUE}Detecting external IP address...${NC}" >&2
    
    for service in "${services[@]}"; do
        echo -e "${YELLOW}Trying: $service${NC}" >&2
        if ip=$(curl -s --connect-timeout 5 --max-time 10 "$service" 2>/dev/null); then
            # Validate IP format
            if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                echo -e "${GREEN}✓ External IP detected: $ip${NC}" >&2
                echo "$ip"
                return 0
            fi
        fi
    done
    
    echo -e "${RED}✗ Failed to detect external IP address${NC}" >&2
    echo -e "${YELLOW}Please ensure internet connectivity and try again${NC}" >&2
    return 1
}

# Function to detect FQDN
detect_fqdn() {
    local fqdn=""
    
    echo -e "${BLUE}Auto-detecting FQDN...${NC}" >&2
    
    # Method 1: hostname -f
    if command -v hostname &> /dev/null; then
        fqdn=$(hostname -f 2>/dev/null || echo "")
        if [[ -n "$fqdn" && "$fqdn" == *.* && "$fqdn" != "localhost."* ]]; then
            echo -e "${GREEN}✓ FQDN detected via hostname: $fqdn${NC}" >&2
            echo "$fqdn"
            return 0
        fi
    fi
    
    # Method 2: dnsdomainname + hostname
    if command -v dnsdomainname &> /dev/null; then
        local domain=$(dnsdomainname 2>/dev/null || echo "")
        local hostname=$(hostname 2>/dev/null || echo "")
        if [[ -n "$domain" && -n "$hostname" ]]; then
            fqdn="$hostname.$domain"
            if [[ "$fqdn" == *.* && "$fqdn" != "localhost."* ]]; then
                echo -e "${GREEN}✓ FQDN constructed: $fqdn${NC}" >&2
                echo "$fqdn"
                return 0
            fi
        fi
    fi
    
    # Method 3: Check /etc/hostname
    if [[ -f "/etc/hostname" ]]; then
        fqdn=$(cat /etc/hostname 2>/dev/null | head -1)
        if [[ -n "$fqdn" && "$fqdn" == *.* && "$fqdn" != "localhost."* ]]; then
            echo -e "${GREEN}✓ FQDN from /etc/hostname: $fqdn${NC}" >&2
            echo "$fqdn"
            return 0
        fi
    fi
    
    echo -e "${YELLOW}⚠ Could not auto-detect valid FQDN${NC}" >&2
    return 1
}

# Function to lookup DNS A record
lookup_dns_record() {
    local domain="$1"
    local ip=""
    
    echo -e "${BLUE}Looking up DNS A record for: $domain${NC}" >&2
    
    # Try different DNS lookup methods
    if command -v dig &> /dev/null; then
        ip=$(dig +short A "$domain" | head -1)
    elif command -v nslookup &> /dev/null; then
        ip=$(nslookup "$domain" | grep -A1 "Name:" | grep "Address:" | awk '{print $2}' | head -1)
    elif command -v host &> /dev/null; then
        ip=$(host "$domain" | grep "has address" | awk '{print $4}' | head -1)
    else
        echo -e "${RED}✗ No DNS lookup tools available (dig, nslookup, host)${NC}" >&2
        return 1
    fi
    
    # Validate IP format
    if [[ -n "$ip" && $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo -e "${GREEN}✓ DNS A record: $domain → $ip${NC}" >&2
        echo "$ip"
        return 0
    else
        echo -e "${RED}✗ No valid A record found for: $domain${NC}" >&2
        return 1
    fi
}

# Function to check if domain exists
check_domain_exists() {
    local domain="$1"
    local has_records=false
    local debug_info=""
    
    echo -e "${BLUE}Verifying domain exists: $domain${NC}" >&2
    
    # Try to find any DNS records for the domain (A, MX, or NS records)
    if command -v dig &> /dev/null; then
        # Check for A records
        local a_record=$(dig +short A "$domain" 2>/dev/null | head -1)
        # Check for MX records  
        local mx_record=$(dig +short MX "$domain" 2>/dev/null | head -1)
        # Check for NS records
        local ns_record=$(dig +short NS "$domain" 2>/dev/null | head -1)
        
        debug_info="A: ${a_record:-none}, MX: ${mx_record:-none}, NS: ${ns_record:-none}"
        
        if [[ -n "$a_record" || -n "$mx_record" || -n "$ns_record" ]]; then
            has_records=true
        fi
        
    elif command -v nslookup &> /dev/null; then
        # Try nslookup for any record type
        if nslookup "$domain" >/dev/null 2>&1; then
            has_records=true
            debug_info="nslookup successful"
        else
            debug_info="nslookup failed"
        fi
        
    elif command -v host &> /dev/null; then
        # Try host command
        if host "$domain" >/dev/null 2>&1; then
            has_records=true
            debug_info="host command successful"
        else
            debug_info="host command failed"
        fi
    else
        echo -e "${YELLOW}⚠ No DNS tools available (dig, nslookup, host), skipping domain verification${NC}" >&2
        return 0  # Allow if we can't verify
    fi
    
    if [[ "$has_records" == "true" ]]; then
        echo -e "${GREEN}✓ Domain verified: $domain exists${NC}" >&2
        return 0
    else
        echo -e "${RED}✗ Domain does not exist: $domain${NC}" >&2
        echo -e "${YELLOW}DNS lookup details: $debug_info${NC}" >&2
        echo -e "${YELLOW}Common causes:${NC}" >&2
        echo -e "${BLUE}• Domain name is misspelled${NC}" >&2
        echo -e "${BLUE}• Domain has not been registered${NC}" >&2
        echo -e "${BLUE}• Domain DNS is not properly configured${NC}" >&2
        echo -e "${BLUE}• DNS propagation is still in progress${NC}" >&2
        return 1
    fi
}

# Function to load configuration from /root/BunkerWeb.conf
load_root_config() {
    local root_config="/root/BunkerWeb.conf"
    
    if [[ -f "$root_config" ]]; then
        echo -e "${BLUE}Found configuration file: $root_config${NC}" >&2
        echo -e "${BLUE}Loading default values...${NC}" >&2
        
        # Source the configuration file safely
        if source "$root_config" 2>/dev/null; then
            echo -e "${GREEN}✓ Configuration loaded from $root_config${NC}" >&2
            
            # Display loaded values (only if they're set)
            [[ -n "$FQDN" ]] && echo -e "${YELLOW}  Default FQDN: $FQDN${NC}" >&2
            [[ -n "$AUTO_CERT_CONTACT" ]] && echo -e "${YELLOW}  Default Email: $AUTO_CERT_CONTACT${NC}" >&2
            [[ -n "$LETS_ENCRYPT_STAGING" ]] && echo -e "${YELLOW}  Default Staging: $LETS_ENCRYPT_STAGING${NC}" >&2
            [[ -n "$ADMIN_USERNAME" ]] && echo -e "${YELLOW}  Default Admin: $ADMIN_USERNAME${NC}" >&2
            [[ -n "$GREYLIST_IP" ]] && echo -e "${YELLOW}  Default Greylist IPs: $GREYLIST_IP${NC}" >&2
            [[ -n "$GREYLIST_RDNS" ]] && echo -e "${YELLOW}  Default Greylist RDNS: $GREYLIST_RDNS${NC}" >&2
            
            echo -e "${BLUE}Note: Command line arguments will override these defaults${NC}" >&2
        else
            echo -e "${YELLOW}⚠ Could not load $root_config (syntax error?)${NC}" >&2
            echo -e "${YELLOW}Continuing with built-in defaults...${NC}" >&2
        fi
        echo ""
    else
        echo -e "${BLUE}No configuration file found at $root_config${NC}" >&2
        echo -e "${BLUE}Using built-in defaults...${NC}" >&2
    fi
}

# Function to validate email address
validate_email() {
    local email="$1"
    
    if [[ -z "$email" ]]; then
        return 1
    fi
    
    # Basic email validation - must contain @ and at least one dot after @
    if [[ "$email" =~ ^[^@]+@[^@]+\.[^@]+$ ]]; then
        # Extract domain part (everything after @)
        local domain="${email##*@}"
        
        # Check for common example domains first
        if [[ "$email" =~ @(example\.com|test\.com|localhost|domain\.com|sample\.com|demo\.com)$ ]]; then
            echo -e "${RED}✗ '$email' uses an example domain${NC}" >&2
            echo -e "${YELLOW}Please use your real email address for SSL certificate notifications${NC}" >&2
            return 1
        fi
        
        # Check if the domain actually exists
        if ! check_domain_exists "$domain"; then
            echo -e "${RED}✗ Email domain '$domain' does not exist${NC}" >&2
            echo -e "${YELLOW}Please use an email address with a valid, existing domain${NC}" >&2
            echo -e "${YELLOW}Make sure the domain '$domain' is correctly spelled and accessible${NC}" >&2
            return 1
        fi
        
        return 0
    else
        echo -e "${RED}✗ Invalid email format: $email${NC}" >&2
        echo -e "${YELLOW}Please use format: user@domain.com${NC}" >&2
        return 1
    fi
}

# Function to prompt for email address
prompt_for_email() {
    local email=""
    local attempts=0
    local max_attempts=3
    
    echo ""
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}           EMAIL ADDRESS REQUIRED${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    echo -e "${YELLOW}An email address is required for SSL certificate registration.${NC}"
    echo -e "${YELLOW}Let's Encrypt will use this email to:${NC}"
    echo -e "${BLUE}• Send certificate expiration notifications${NC}"
    echo -e "${BLUE}• Contact you about important security updates${NC}"
    echo -e "${BLUE}• Recover your account if needed${NC}"
    echo ""
    echo -e "${YELLOW}Requirements:${NC}"
    echo -e "${BLUE}• Must be a valid email format (user@domain.com)${NC}"
    echo -e "${BLUE}• Domain must exist and be accessible via DNS${NC}"
    echo -e "${BLUE}• Cannot use example domains (example.com, test.com, etc.)${NC}"
    echo ""
    
    while [[ $attempts -lt $max_attempts ]]; do
        echo -e "${BLUE}Enter your email address:${NC}"
        read -p "Email: " email
        
        echo ""
        if validate_email "$email"; then
            echo -e "${GREEN}✓ Email address accepted: $email${NC}"
            echo "$email"
            return 0
        else
            attempts=$((attempts + 1))
            if [[ $attempts -lt $max_attempts ]]; then
                echo -e "${YELLOW}Please try again (attempt $attempts/$max_attempts)${NC}"
                echo ""
            fi
        fi
    done
    
    echo -e "${RED}Failed to get valid email address after $max_attempts attempts${NC}"
    echo -e "${YELLOW}Common issues:${NC}"
    echo -e "${BLUE}• Typos in domain name (check spelling)${NC}"
    echo -e "${BLUE}• Using non-existent domains${NC}"
    echo -e "${BLUE}• Using example/test domains${NC}"
    echo -e "${BLUE}• Domain not yet propagated in DNS${NC}"
    return 1
}

# Function to detect SSH connection IPs for greylist
detect_ssh_ips() {
    local ssh_ips=""
    local current_ssh_ip=""
    
    # Get current SSH connection IP
    if [[ -n "$SSH_CLIENT" ]]; then
        current_ssh_ip=$(echo "$SSH_CLIENT" | awk '{print $1}')
        echo -e "${BLUE}Detected SSH connection from: $current_ssh_ip${NC}" >&2
        ssh_ips="$current_ssh_ip"
    fi
    
    # Check recent SSH connections from auth logs
    if [[ -f "/var/log/auth.log" ]]; then
        local recent_ips=$(grep "Accepted publickey\|Accepted password" /var/log/auth.log 2>/dev/null | \
                          tail -20 | \
                          grep -oE 'from [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
                          awk '{print $2}' | \
                          sort -u | \
                          head -5)
        
        if [[ -n "$recent_ips" ]]; then
            echo -e "${BLUE}Found recent SSH login IPs:${NC}" >&2
            for ip in $recent_ips; do
                echo -e "${YELLOW}  - $ip${NC}" >&2
                if [[ -n "$ssh_ips" ]]; then
                    ssh_ips="$ssh_ips $ip"
                else
                    ssh_ips="$ip"
                fi
            done
        fi
    fi
    
    # Remove duplicates and return
    if [[ -n "$ssh_ips" ]]; then
        ssh_ips=$(echo "$ssh_ips" | tr ' ' '\n' | sort -u | tr '\n' ' ' | xargs)
        echo -e "${GREEN}✓ SSH IPs for greylist: $ssh_ips${NC}" >&2
        echo "$ssh_ips"
    else
        echo -e "${YELLOW}⚠ No SSH IPs detected${NC}" >&2
        return 1
    fi
}

configure_bunkerweb() {
    local fqdn="$1"
    local email="$2"
    local staging="$3"
    local greylist_rdns="$4"
    local greylist_ips="$5"
    
    echo -e "${BLUE}Configuring BunkerWeb...${NC}"
    
    # Create directory if it doesn't exist
    mkdir -p "$INSTALL_DIR"
    
    # Create or update configuration file
    cat > "$CONFIG_FILE" << EOF
#!/bin/bash
#
# BunkerWeb Configuration File
# This file was automatically configured by autoconf.sh
# Generated on: $(date)
#

# Default admin username
ADMIN_USERNAME="admin"

# Domain Configuration (auto-configured)
FQDN="$fqdn"

# SSL Certificate Configuration (auto-configured)
AUTO_CERT_TYPE="LE"
AUTO_CERT_CONTACT="$email"

# Let's Encrypt Advanced Options
LETS_ENCRYPT_CHALLENGE="http"
LETS_ENCRYPT_STAGING="$staging"
LETS_ENCRYPT_WILDCARD="no"

# Greylist Configuration
USE_GREYLIST="$(if [[ -n "$greylist_ips" || -n "$greylist_rdns" ]]; then echo "yes"; else echo "no"; fi)"
$(if [[ -n "$greylist_ips" ]]; then echo "GREYLIST_IP=\"$greylist_ips\""; fi)
$(if [[ -n "$greylist_rdns" ]]; then echo "GREYLIST_RDNS=\"$greylist_rdns\""; fi)

# DNS verification passed:
# Domain: $fqdn
# External IP: $(cat /tmp/bw_external_ip 2>/dev/null || echo "detected")
# DNS A Record: $(cat /tmp/bw_dns_ip 2>/dev/null || echo "verified")
# Verification Date: $(date)

EOF

    chmod 644 "$CONFIG_FILE"
    echo -e "${GREEN}✓ BunkerWeb configuration updated: $CONFIG_FILE${NC}"
}

# Main function
main() {
    local FQDN=""
    local EMAIL=""
    local STAGING="yes"
    local VERIFY_ONLY="no"
    local FORCE_IP=""
    local GREYLIST_RDNS_LIST=()
    
    # Load configuration from /root/BunkerWeb.conf if it exists
    load_root_config
    
    # Use loaded config values as defaults if they exist and weren't set above
    [[ -n "$FQDN" ]] && local FQDN="$FQDN"
    [[ -n "$AUTO_CERT_CONTACT" ]] && local EMAIL="$AUTO_CERT_CONTACT"
    [[ -n "$LETS_ENCRYPT_STAGING" ]] && local STAGING="$LETS_ENCRYPT_STAGING"
    
    # Parse command line arguments (these will override config file values)
    while [[ $# -gt 0 ]]; do
        case $1 in
            --fqdn)
                FQDN="$2"
                shift 2
                ;;
            --email)
                EMAIL="$2"
                shift 2
                ;;
            --staging)
                STAGING="$2"
                shift 2
                ;;
            --production)
                STAGING="no"
                shift
                ;;
            --greylist_rdns)
                GREYLIST_RDNS_LIST+=("$2")
                shift 2
                ;;
            --verify-only)
                VERIFY_ONLY="yes"
                shift
                ;;
            --force-ip)
                FORCE_IP="$2"
                shift 2
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
    
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}        BunkerWeb Auto-Configuration${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    
    # Get email address first (unless verify-only mode)
    if [[ "$VERIFY_ONLY" != "yes" ]]; then
        if [[ -z "$EMAIL" ]]; then
            EMAIL=$(prompt_for_email)
            if [[ -z "$EMAIL" ]]; then
                echo -e "${RED}Email address is required for SSL certificate setup${NC}"
                echo -e "${YELLOW}Options:${NC}"
                echo -e "${YELLOW}• Use --email option: $0 --email your@email.com${NC}"
                echo -e "${YELLOW}• Use --verify-only to skip configuration: $0 --verify-only${NC}"
                exit 1
            fi
        else
            echo -e "${BLUE}Email address provided: $EMAIL${NC}"
            echo ""
            if ! validate_email "$EMAIL"; then
                echo ""
                echo -e "${RED}Invalid email address provided: $EMAIL${NC}"
                echo -e "${YELLOW}Requirements for email address:${NC}"
                echo -e "${BLUE}• Must be valid format (user@domain.com)${NC}"
                echo -e "${BLUE}• Domain must exist and be accessible via DNS${NC}"
                echo -e "${BLUE}• Cannot use example domains${NC}"
                echo -e "${YELLOW}Example of valid email: admin@yourdomain.com${NC}"
                exit 1
            fi
            echo -e "${GREEN}✓ Email address validated: $EMAIL${NC}"
        fi
        echo ""
    else
        echo -e "${BLUE}Verify-only mode: Skipping email collection${NC}"
        echo -e "${YELLOW}(Email not needed for DNS verification only)${NC}"
        echo ""
    fi
    
    # Get external IP
    if [[ -n "$FORCE_IP" ]]; then
        echo -e "${BLUE}Using forced IP: $FORCE_IP${NC}"
        EXTERNAL_IP="$FORCE_IP"
    else
        EXTERNAL_IP=$(get_external_ip)
        if [[ -z "$EXTERNAL_IP" ]]; then
            echo -e "${RED}Failed to detect external IP address${NC}"
            exit 1
        fi
    fi
    
    # Store for later use
    echo "$EXTERNAL_IP" > /tmp/bw_external_ip
    
    # Get FQDN
    if [[ -z "$FQDN" ]]; then
        FQDN=$(detect_fqdn)
        if [[ -z "$FQDN" ]]; then
            echo -e "${RED}Could not detect FQDN. Please specify with --fqdn${NC}"
            echo -e "${YELLOW}Example: $0 --fqdn your-domain.com${NC}"
            exit 1
        fi
    else
        echo -e "${BLUE}Using specified FQDN: $FQDN${NC}"
    fi
    
    # Detect SSH IPs for greylist (unless verify-only mode)
    GREYLIST_IPS=""
    if [[ "$VERIFY_ONLY" != "yes" ]]; then
        # Use greylist IPs from config file if available
        if [[ -n "$GREYLIST_IP" ]]; then
            GREYLIST_IPS="$GREYLIST_IP"
            echo -e "${GREEN}✓ Using greylist IPs from config: $GREYLIST_IPS${NC}"
        fi
        
        # Detect additional SSH IPs and add them
        local detected_ssh_ips=$(detect_ssh_ips || echo "")
        if [[ -n "$detected_ssh_ips" ]]; then
            if [[ -n "$GREYLIST_IPS" ]]; then
                # Combine and deduplicate
                GREYLIST_IPS="$GREYLIST_IPS $detected_ssh_ips"
                GREYLIST_IPS=$(echo "$GREYLIST_IPS" | tr ' ' '\n' | sort -u | tr '\n' ' ' | xargs)
                echo -e "${GREEN}✓ Combined greylist IPs: $GREYLIST_IPS${NC}"
            else
                GREYLIST_IPS="$detected_ssh_ips"
            fi
        fi
    fi
    
    # Process greylist RDNS list
    GREYLIST_RDNS_FROM_CONFIG=""
    if [[ -n "$GREYLIST_RDNS" ]]; then
        GREYLIST_RDNS_FROM_CONFIG="$GREYLIST_RDNS"
        echo -e "${GREEN}✓ Using greylist RDNS from config: $GREYLIST_RDNS_FROM_CONFIG${NC}"
    fi
    
    # Combine RDNS from config and command line
    GREYLIST_RDNS_FINAL=""
    if [[ ${#GREYLIST_RDNS_LIST[@]} -gt 0 ]]; then
        local greylist_rdns_cmdline=$(IFS=' '; echo "${GREYLIST_RDNS_LIST[*]}")
        if [[ -n "$GREYLIST_RDNS_FROM_CONFIG" ]]; then
            GREYLIST_RDNS_FINAL="$GREYLIST_RDNS_FROM_CONFIG $greylist_rdns_cmdline"
        else
            GREYLIST_RDNS_FINAL="$greylist_rdns_cmdline"
        fi
        echo -e "${GREEN}✓ Final greylist RDNS domains: $GREYLIST_RDNS_FINAL${NC}"
    elif [[ -n "$GREYLIST_RDNS_FROM_CONFIG" ]]; then
        GREYLIST_RDNS_FINAL="$GREYLIST_RDNS_FROM_CONFIG"
    fi
    
    # Lookup DNS record
    DNS_IP=$(lookup_dns_record "$FQDN")
    if [[ -z "$DNS_IP" ]]; then
        echo ""
        echo -e "${RED}================================================${NC}"
        echo -e "${RED}           DNS VERIFICATION FAILED${NC}"
        echo -e "${RED}================================================${NC}"
        echo ""
        echo -e "${YELLOW}Domain: $FQDN${NC}"
        echo -e "${YELLOW}Your IP: $EXTERNAL_IP${NC}"
        echo -e "${RED}DNS Status: No A record found${NC}"
        echo ""
        echo -e "${BLUE}Required actions:${NC}"
        echo -e "${YELLOW}1. Add DNS A record for $FQDN pointing to $EXTERNAL_IP${NC}"
        echo -e "${YELLOW}2. Wait for DNS propagation (5-30 minutes)${NC}"
        echo -e "${YELLOW}3. Run this script again:${NC}"
        if [[ -n "$EMAIL" ]]; then
            echo -e "${BLUE}   $0 --fqdn $FQDN --email $EMAIL${NC}"
        else
            echo -e "${BLUE}   $0 --fqdn $FQDN --email your@email.com${NC}"
        fi
        echo ""
        exit 1
    fi
    
    # Store for later use
    echo "$DNS_IP" > /tmp/bw_dns_ip
    
    # Compare IPs
    if [[ "$EXTERNAL_IP" == "$DNS_IP" ]]; then
        echo ""
        echo -e "${GREEN}================================================${NC}"
        echo -e "${GREEN}          DNS VERIFICATION SUCCESS${NC}"
        echo -e "${GREEN}================================================${NC}"
        echo ""
        echo -e "${GREEN}Domain: $FQDN${NC}"
        echo -e "${GREEN}Your IP: $EXTERNAL_IP${NC}"
        echo -e "${GREEN}DNS A Record: $DNS_IP${NC}"
        echo -e "${GREEN}Status: ✓ DNS correctly configured${NC}"
        echo ""
        
        if [[ "$VERIFY_ONLY" == "yes" ]]; then
            echo -e "${BLUE}Verification complete (--verify-only specified)${NC}"
            exit 0
        fi
        
        # Email should already be validated at this point
        if [[ -z "$EMAIL" ]]; then
            echo -e "${RED}Error: Email address required but not provided${NC}"
            exit 1
        fi
        
        # Configure BunkerWeb
        configure_bunkerweb "$FQDN" "$EMAIL" "$STAGING" "$GREYLIST_RDNS_FINAL" "$GREYLIST_IPS"
        
        echo ""
        echo -e "${GREEN}================================================${NC}"
        echo -e "${GREEN}        AUTO-CONFIGURATION COMPLETE${NC}"
        echo -e "${GREEN}================================================${NC}"
        echo ""
        echo -e "${BLUE}Configuration Summary:${NC}"
        echo -e "${GREEN}Domain (FQDN): $FQDN${NC}"
        echo -e "${GREEN}Email Address: $EMAIL${NC}"
        echo -e "${GREEN}Let's Encrypt: $STAGING environment${NC}"
        echo -e "${GREEN}Security Mode: block${NC}"
        echo -e "${GREEN}Server Type: http${NC}"
        echo -e "${GREEN}Multisite: yes${NC}"
        if [[ -n "$GREYLIST_IPS" || -n "$GREYLIST_RDNS_FINAL" ]]; then
            echo -e "${GREEN}Greylist: enabled${NC}"
            if [[ -n "$GREYLIST_IPS" ]]; then
                echo -e "${GREEN}Greylist IPs: $GREYLIST_IPS${NC}"
            fi
            if [[ -n "$GREYLIST_RDNS_FINAL" ]]; then
                echo -e "${GREEN}Greylist RDNS: $GREYLIST_RDNS_FINAL${NC}"
            fi
        else
            echo -e "${GREEN}Greylist: disabled${NC}"
        fi
        echo -e "${GREEN}Config File: $CONFIG_FILE${NC}"
        echo ""
        echo -e "${BLUE}Next Steps:${NC}"
        echo -e "${YELLOW}1. Run the main setup script:${NC}"
        echo -e "${BLUE}   sudo ./script_autoconf_display.sh --type autoconf${NC}"
        echo -e "${YELLOW}2. Your SSL certificates will be automatically issued to: $EMAIL${NC}"
        echo ""
        if [[ "$STAGING" == "yes" ]]; then
            echo -e "${YELLOW}Note: Using Let's Encrypt staging environment (safe for testing)${NC}"
            echo -e "${YELLOW}Staging certificates are not trusted by browsers${NC}"
            echo -e "${YELLOW}For production certificates, run:${NC}"
            echo -e "${BLUE}   $0 --fqdn $FQDN --email $EMAIL --production${NC}"
            echo ""
        else
            echo -e "${GREEN}Note: Using Let's Encrypt production environment${NC}"
            echo -e "${GREEN}Production certificates will be trusted by browsers${NC}"
            echo ""
        fi
        
    else
        echo ""
        echo -e "${RED}================================================${NC}"
        echo -e "${RED}            DNS MISMATCH ERROR${NC}"
        echo -e "${RED}================================================${NC}"
        echo ""
        echo -e "${YELLOW}Domain: $FQDN${NC}"
        echo -e "${YELLOW}Your IP: $EXTERNAL_IP${NC}"
        echo -e "${RED}DNS A Record: $DNS_IP${NC}"
        echo -e "${RED}Status: ✗ DNS points to wrong IP${NC}"
        echo ""
        echo -e "${BLUE}Required actions:${NC}"
        echo -e "${YELLOW}1. Update DNS A record for $FQDN${NC}"
        echo -e "${YELLOW}2. Change it from $DNS_IP to $EXTERNAL_IP${NC}"
        echo -e "${YELLOW}3. Wait for DNS propagation (5-30 minutes)${NC}"
        echo -e "${YELLOW}4. Run this script again:${NC}"
        if [[ -n "$EMAIL" ]]; then
            echo -e "${BLUE}   $0 --fqdn $FQDN --email $EMAIL${NC}"
        else
            echo -e "${BLUE}   $0 --fqdn $FQDN --email your@email.com${NC}"
        fi
        echo ""
        echo -e "${BLUE}Common DNS providers:${NC}"
        echo -e "${BLUE}• Cloudflare: DNS tab in your domain dashboard${NC}"
        echo -e "${BLUE}• Namecheap: Advanced DNS settings${NC}"
        echo -e "${BLUE}• GoDaddy: DNS Management${NC}"
        echo -e "${BLUE}• Route53: Hosted Zone A records${NC}"
        echo ""
        exit 1
    fi
    
    # Cleanup temp files
    rm -f /tmp/bw_external_ip /tmp/bw_dns_ip
}

# Run main function with all arguments
main "$@"