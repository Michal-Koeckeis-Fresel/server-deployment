#!/bin/bash
# Copyright (c) 2025 Michal Koeckeis-Fresel
# This software is dual-licensed under your choice of:
# - MIT License (see LICENSE-MIT)
# - GNU Affero General Public License v3.0 (see LICENSE-AGPL)
# SPDX-License-Identifier: MIT OR AGPL-3.0-or-later

# BunkerWeb FQDN Lookup Helper Script
# Handles FQDN detection and validation

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variable for detected FQDN
DETECTED_FQDN=""

# Function to check if a hostname is valid FQDN format
is_valid_fqdn() {
    local hostname="$1"
    
    if [[ -z "$hostname" ]]; then
        return 1
    fi
    
    # Must contain at least one dot
    if [[ "$hostname" != *.* ]]; then
        return 1
    fi
    
    # Should not start with localhost
    if [[ "$hostname" == "localhost."* ]]; then
        return 1
    fi
    
    # Should not be just an IP address
    if [[ "$hostname" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 1
    fi
    
    # Basic hostname validation - alphanumeric, dots, and hyphens
    if [[ ! "$hostname" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        return 1
    fi
    
    # Should not start or end with a dot or hyphen
    if [[ "$hostname" =~ ^[.-] ]] || [[ "$hostname" =~ [.-]$ ]]; then
        return 1
    fi
    
    return 0
}

# Function to detect FQDN using hostname command
detect_fqdn_hostname() {
    local detected=""
    
    if command -v hostname &> /dev/null; then
        detected=$(hostname -f 2>/dev/null || echo "")
        if is_valid_fqdn "$detected"; then
            echo "$detected"
            return 0
        fi
    fi
    
    return 1
}

# Function to detect FQDN using dnsdomainname + hostname
detect_fqdn_dns_domain() {
    local detected=""
    
    if command -v dnsdomainname &> /dev/null && command -v hostname &> /dev/null; then
        local domain=$(dnsdomainname 2>/dev/null || echo "")
        local hostname=$(hostname 2>/dev/null || echo "")
        
        if [[ -n "$domain" && -n "$hostname" ]]; then
            detected="$hostname.$domain"
            if is_valid_fqdn "$detected"; then
                echo "$detected"
                return 0
            fi
        fi
    fi
    
    return 1
}

# Function to detect FQDN from /etc/hostname
detect_fqdn_etc_hostname() {
    local detected=""
    
    if [[ -f "/etc/hostname" ]]; then
        detected=$(cat /etc/hostname 2>/dev/null | head -1 | tr -d '\n\r')
        if is_valid_fqdn "$detected"; then
            echo "$detected"
            return 0
        fi
    fi
    
    return 1
}

# Function to detect FQDN from /etc/hosts
detect_fqdn_etc_hosts() {
    local detected=""
    
    if [[ -f "/etc/hosts" ]]; then
        # Look for entries that are not localhost or 127.0.0.1
        while IFS= read -r line; do
            # Skip comments and empty lines
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue
            
            # Parse the line
            local ip=$(echo "$line" | awk '{print $1}')
            local hostnames=$(echo "$line" | awk '{for(i=2;i<=NF;i++) print $i}')
            
            # Skip localhost entries
            if [[ "$ip" == "127.0.0.1" || "$ip" == "::1" ]]; then
                continue
            fi
            
            # Check each hostname
            for hostname in $hostnames; do
                if is_valid_fqdn "$hostname"; then
                    echo "$hostname"
                    return 0
                fi
            done
        done < /etc/hosts
    fi
    
    return 1
}

# Function to detect FQDN using systemd hostnamectl
detect_fqdn_hostnamectl() {
    local detected=""
    
    if command -v hostnamectl &> /dev/null; then
        # Try to get the static hostname
        detected=$(hostnamectl --static 2>/dev/null || echo "")
        if is_valid_fqdn "$detected"; then
            echo "$detected"
            return 0
        fi
        
        # Try to get the pretty hostname
        detected=$(hostnamectl --pretty 2>/dev/null || echo "")
        if is_valid_fqdn "$detected"; then
            echo "$detected"
            return 0
        fi
    fi
    
    return 1
}

# Function to detect FQDN using reverse DNS lookup
detect_fqdn_reverse_dns() {
    local detected=""
    
    # Get the primary IP address (excluding localhost)
    local primary_ip=""
    if command -v hostname &> /dev/null; then
        primary_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "")
    fi
    
    if [[ -z "$primary_ip" ]] && command -v ip &> /dev/null; then
        primary_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[^ ]+' || echo "")
    fi
    
    if [[ -n "$primary_ip" && "$primary_ip" != "127.0.0.1" ]]; then
        # Try reverse DNS lookup
        if command -v nslookup &> /dev/null; then
            detected=$(nslookup "$primary_ip" 2>/dev/null | grep "name =" | awk '{print $4}' | sed 's/\.$//' || echo "")
        elif command -v dig &> /dev/null; then
            detected=$(dig +short -x "$primary_ip" 2>/dev/null | sed 's/\.$//' || echo "")
        elif command -v host &> /dev/null; then
            detected=$(host "$primary_ip" 2>/dev/null | awk '{print $NF}' | sed 's/\.$//' || echo "")
        fi
        
        if is_valid_fqdn "$detected"; then
            echo "$detected"
            return 0
        fi
    fi
    
    return 1
}

# Main function to auto-detect FQDN using multiple methods
auto_detect_fqdn() {
    local provided_fqdn="$1"
    local require_ssl="${2:-no}"
    
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo -e "${BLUE}                        FQDN DETECTION                        ${NC}" >&2
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo "" >&2
    
    # If FQDN is provided, validate and use it
    if [[ -n "$provided_fqdn" ]]; then
        if is_valid_fqdn "$provided_fqdn"; then
            echo -e "${GREEN}✓ Using provided FQDN: $provided_fqdn${NC}" >&2
            DETECTED_FQDN="$provided_fqdn"
            echo "$provided_fqdn"
            return 0
        else
            echo -e "${RED}✗ Provided FQDN is invalid: $provided_fqdn${NC}" >&2
            if [[ "$require_ssl" == "yes" ]]; then
                echo -e "${RED}Error: Valid FQDN is required for SSL certificate enrollment${NC}" >&2
                return 1
            fi
        fi
    fi
    
    echo -e "${BLUE}Auto-detecting FQDN using multiple methods...${NC}" >&2
    
    # Array of detection methods to try
    local methods=(
        "detect_fqdn_hostname:hostname -f command"
        "detect_fqdn_hostnamectl:systemd hostnamectl"
        "detect_fqdn_dns_domain:dnsdomainname + hostname"
        "detect_fqdn_etc_hostname:/etc/hostname file"
        "detect_fqdn_etc_hosts:/etc/hosts file"
        "detect_fqdn_reverse_dns:reverse DNS lookup"
    )
    
    for method_info in "${methods[@]}"; do
        local method_func="${method_info%%:*}"
        local method_desc="${method_info#*:}"
        
        echo -e "${CYAN}• Trying $method_desc...${NC}" >&2
        
        if detected_fqdn=$($method_func); then
            echo -e "${GREEN}✓ FQDN detected via $method_desc: $detected_fqdn${NC}" >&2
            DETECTED_FQDN="$detected_fqdn"
            echo "$detected_fqdn"
            return 0
        else
            echo -e "${YELLOW}⚠ No valid FQDN found via $method_desc${NC}" >&2
        fi
    done
    
    # No valid FQDN found
    echo -e "${YELLOW}⚠ Could not auto-detect valid FQDN using any method${NC}" >&2
    
    if [[ "$require_ssl" == "yes" ]]; then
        echo -e "${RED}Error: FQDN is required for SSL certificate enrollment${NC}" >&2
        echo -e "${YELLOW}Please provide a valid FQDN using --FQDN parameter${NC}" >&2
        return 1
    else
        echo -e "${BLUE}ℹ Using localhost as fallback${NC}" >&2
        DETECTED_FQDN="localhost"
        echo "localhost"
        return 0
    fi
}

# Function to get the detected FQDN
get_detected_fqdn() {
    echo "$DETECTED_FQDN"
}

# Function to validate an FQDN and check if it resolves
validate_fqdn() {
    local fqdn="$1"
    local check_dns="${2:-yes}"
    
    echo -e "${BLUE}Validating FQDN: $fqdn${NC}" >&2
    
    # Basic format validation
    if ! is_valid_fqdn "$fqdn"; then
        echo -e "${RED}✗ Invalid FQDN format${NC}" >&2
        return 1
    fi
    
    echo -e "${GREEN}✓ FQDN format is valid${NC}" >&2
    
    # DNS resolution check (optional)
    if [[ "$check_dns" == "yes" ]]; then
        echo -e "${BLUE}Checking DNS resolution...${NC}" >&2
        
        local resolved=false
        
        # Try nslookup
        if command -v nslookup &> /dev/null; then
            if nslookup "$fqdn" &>/dev/null; then
                resolved=true
            fi
        # Try dig
        elif command -v dig &> /dev/null; then
            if dig +short "$fqdn" &>/dev/null; then
                resolved=true
            fi
        # Try host
        elif command -v host &> /dev/null; then
            if host "$fqdn" &>/dev/null; then
                resolved=true
            fi
        # Try ping
        elif command -v ping &> /dev/null; then
            if ping -c 1 -W 3 "$fqdn" &>/dev/null; then
                resolved=true
            fi
        fi
        
        if [[ "$resolved" == "true" ]]; then
            echo -e "${GREEN}✓ FQDN resolves to an IP address${NC}" >&2
        else
            echo -e "${YELLOW}⚠ FQDN does not resolve (this may be expected for new domains)${NC}" >&2
        fi
    fi
    
    return 0
}

# Function to show FQDN detection summary
show_fqdn_summary() {
    local fqdn="$1"
    
    echo -e "${BLUE}FQDN Detection Summary:${NC}" >&2
    echo -e "${GREEN}• Detected FQDN: ${fqdn:-"Not detected"}${NC}" >&2
    
    if [[ -n "$fqdn" && "$fqdn" != "localhost" ]]; then
        echo -e "${GREEN}• SSL Ready: Yes${NC}" >&2
        echo -e "${GREEN}• Domain Configuration: Ready${NC}" >&2
    else
        echo -e "${YELLOW}• SSL Ready: No (localhost or invalid FQDN)${NC}" >&2
        echo -e "${YELLOW}• Domain Configuration: Manual setup required${NC}" >&2
    fi
}

# If script is run directly, show usage or run tests
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ "$1" == "test" ]]; then
        echo "Testing FQDN detection functions..."
        echo ""
        
        # Test FQDN validation
        echo "Testing FQDN validation:"
        local test_fqdns=("example.com" "sub.example.com" "localhost" "192.168.1.1" "invalid" "test.")
        for fqdn in "${test_fqdns[@]}"; do
            if is_valid_fqdn "$fqdn"; then
                echo "  ✓ $fqdn - Valid"
            else
                echo "  ✗ $fqdn - Invalid"
            fi
        done
        echo ""
        
        # Test auto-detection
        echo "Testing auto-detection:"
        detected=$(auto_detect_fqdn "" "no")
        echo "  Detected FQDN: $detected"
        
    else
        echo "BunkerWeb FQDN Lookup Helper Script"
        echo ""
        echo "This script is designed to be sourced by other scripts."
        echo ""
        echo "Available functions:"
        echo "  auto_detect_fqdn [provided_fqdn] [require_ssl]"
        echo "  get_detected_fqdn"
        echo "  validate_fqdn <fqdn> [check_dns]"
        echo "  show_fqdn_summary [fqdn]"
        echo "  is_valid_fqdn <fqdn>"
        echo ""
        echo "Example usage:"
        echo "  source helper_fqdn_lookup.sh"
        echo "  FQDN=\$(auto_detect_fqdn \"\" \"no\")"
        echo "  validate_fqdn \"\$FQDN\""
        echo ""
        echo "Run with 'test' argument to run diagnostic tests:"
        echo "  $0 test"
    fi
fi