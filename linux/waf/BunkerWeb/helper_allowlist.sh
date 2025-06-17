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

# BunkerWeb Allowlist Management Script
# Handles allowlist detection, validation, and configuration
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables
DETECTED_ALLOWLIST_IP=""
DETECTED_ALLOWLIST_DNS=""
ALLOWLIST_DETECTION_METHOD=""

# Function to validate IP address or CIDR notation
validate_ip_or_cidr() {
    local ip="$1"
    
    # Check if it's a valid IPv4 address
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        local -a octets=($ip)
        for octet in "${octets[@]}"; do
            if (( octet > 255 )); then
                return 1
            fi
        done
        return 0
    fi
    
    # Check if it's a valid CIDR notation
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        local network="${ip%/*}"
        local prefix="${ip#*/}"
        
        # Validate network part
        if ! validate_ip_or_cidr "$network"; then
            return 1
        fi
        
        # Validate prefix length
        if (( prefix < 0 || prefix > 32 )); then
            return 1
        fi
        
        return 0
    fi
    
    return 1
}

# Function to validate country code (ISO 3166-1 alpha-2)
validate_country_code() {
    local country="$1"
    
    # Check if it's exactly 2 uppercase letters
    if [[ "$country" =~ ^[A-Z]{2}$ ]]; then
        # List of common valid country codes (not exhaustive but covers most cases)
        local valid_codes=(
            "AD" "AE" "AF" "AG" "AI" "AL" "AM" "AO" "AQ" "AR" "AS" "AT" "AU" "AW" "AX" "AZ"
            "BA" "BB" "BD" "BE" "BF" "BG" "BH" "BI" "BJ" "BL" "BM" "BN" "BO" "BQ" "BR" "BS"
            "BT" "BV" "BW" "BY" "BZ" "CA" "CC" "CD" "CF" "CG" "CH" "CI" "CK" "CL" "CM" "CN"
            "CO" "CR" "CU" "CV" "CW" "CX" "CY" "CZ" "DE" "DJ" "DK" "DM" "DO" "DZ" "EC" "EE"
            "EG" "EH" "ER" "ES" "ET" "FI" "FJ" "FK" "FM" "FO" "FR" "GA" "GB" "GD" "GE" "GF"
            "GG" "GH" "GI" "GL" "GM" "GN" "GP" "GQ" "GR" "GS" "GT" "GU" "GW" "GY" "HK" "HM"
            "HN" "HR" "HT" "HU" "ID" "IE" "IL" "IM" "IN" "IO" "IQ" "IR" "IS" "IT" "JE" "JM"
            "JO" "JP" "KE" "KG" "KH" "KI" "KM" "KN" "KP" "KR" "KW" "KY" "KZ" "LA" "LB" "LC"
            "LI" "LK" "LR" "LS" "LT" "LU" "LV" "LY" "MA" "MC" "MD" "ME" "MF" "MG" "MH" "MK"
            "ML" "MM" "MN" "MO" "MP" "MQ" "MR" "MS" "MT" "MU" "MV" "MW" "MX" "MY" "MZ" "NA"
            "NC" "NE" "NF" "NG" "NI" "NL" "NO" "NP" "NR" "NU" "NZ" "OM" "PA" "PE" "PF" "PG"
            "PH" "PK" "PL" "PM" "PN" "PR" "PS" "PT" "PW" "PY" "QA" "RE" "RO" "RS" "RU" "RW"
            "SA" "SB" "SC" "SD" "SE" "SG" "SH" "SI" "SJ" "SK" "SL" "SM" "SN" "SO" "SR" "SS"
            "ST" "SV" "SX" "SY" "SZ" "TC" "TD" "TF" "TG" "TH" "TJ" "TK" "TL" "TM" "TN" "TO"
            "TR" "TT" "TV" "TW" "TZ" "UA" "UG" "UM" "US" "UY" "UZ" "VA" "VC" "VE" "VG" "VI"
            "VN" "VU" "WF" "WS" "YE" "YT" "ZA" "ZM" "ZW"
        )
        
        for valid in "${valid_codes[@]}"; do
            if [[ "$country" == "$valid" ]]; then
                return 0
            fi
        done
    fi
    
    return 1
}

# Function to validate DNS suffix
validate_dns_suffix() {
    local dns="$1"
    
    # Check if it's a valid domain name format
    if [[ "$dns" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]] && [[ "$dns" == *.* ]]; then
        # Check for valid characters and structure
        if [[ ! "$dns" =~ \.\. ]] && [[ ! "$dns" =~ ^- ]] && [[ ! "$dns" =~ -$ ]]; then
            return 0
        fi
    fi
    
    return 1
}

# Function to detect current SSH connection IP
detect_ssh_connection_ip() {
    local ssh_ips=()
    
    echo -e "${BLUE}Detecting SSH connection IP addresses...${NC}" >&2
    
    # Method 1: Check SSH_CLIENT environment variable
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        local ssh_ip=$(echo "$SSH_CLIENT" | cut -d' ' -f1)
        if validate_ip_or_cidr "$ssh_ip"; then
            ssh_ips+=("$ssh_ip")
            echo -e "${GREEN}✓ SSH_CLIENT IP detected: $ssh_ip${NC}" >&2
        fi
    fi
    
    # Method 2: Check SSH_CONNECTION environment variable
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        local ssh_ip=$(echo "$SSH_CONNECTION" | cut -d' ' -f1)
        if validate_ip_or_cidr "$ssh_ip" && [[ ! " ${ssh_ips[*]} " =~ " $ssh_ip " ]]; then
            ssh_ips+=("$ssh_ip")
            echo -e "${GREEN}✓ SSH_CONNECTION IP detected: $ssh_ip${NC}" >&2
        fi
    fi
    
    # Method 3: Check who/w command for current session
    if command -v who >/dev/null 2>&1; then
        local current_tty=$(tty 2>/dev/null | sed 's|/dev/||')
        if [[ -n "$current_tty" ]]; then
            local who_ip=$(who | grep "$current_tty" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
            if [[ -n "$who_ip" ]] && validate_ip_or_cidr "$who_ip" && [[ ! " ${ssh_ips[*]} " =~ " $who_ip " ]]; then
                ssh_ips+=("$who_ip")
                echo -e "${GREEN}✓ Current session IP detected: $who_ip${NC}" >&2
            fi
        fi
    fi
    
    # Method 4: Check netstat for established SSH connections
    if command -v netstat >/dev/null 2>&1; then
        while IFS= read -r line; do
            if [[ "$line" =~ ([0-9]{1,3}\.){3}[0-9]{1,3}:22.*ESTABLISHED ]]; then
                local connection_ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
                if [[ -n "$connection_ip" ]] && validate_ip_or_cidr "$connection_ip" && [[ ! " ${ssh_ips[*]} " =~ " $connection_ip " ]]; then
                    ssh_ips+=("$connection_ip")
                    echo -e "${GREEN}✓ Netstat SSH IP detected: $connection_ip${NC}" >&2
                fi
            fi
        done < <(netstat -tn 2>/dev/null | grep ":22 ")
    fi
    
    # Output results
    if [[ ${#ssh_ips[@]} -gt 0 ]]; then
        printf '%s\n' "${ssh_ips[@]}"
        return 0
    else
        echo -e "${YELLOW}⚠ No SSH connection IPs detected${NC}" >&2
        return 1
    fi
}

# Function to auto-detect allowlist configuration
auto_detect_allowlist() {
    local user_allowlist_ip="$1"
    local user_allowlist_dns="$2"
    
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo -e "${BLUE}                    ALLOWLIST AUTO-DETECTION                    ${NC}" >&2
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo "" >&2
    
    ALLOWLIST_DETECTION_METHOD="auto-detection"
    
    # Start with user-provided values
    local final_allowlist_ip="$user_allowlist_ip"
    local final_allowlist_dns="$user_allowlist_dns"
    
    # Auto-detect SSH connection IPs
    local ssh_ips=()
    if mapfile -t ssh_ips < <(detect_ssh_connection_ip); then
        echo -e "${GREEN}✓ Detected ${#ssh_ips[@]} SSH connection IP(s)${NC}" >&2
        
        # Add SSH IPs directly to allowlist (no network generation)
        for ip in "${ssh_ips[@]}"; do
            if [[ ! "$final_allowlist_ip" =~ $ip ]]; then
                if [[ -n "$final_allowlist_ip" ]]; then
                    final_allowlist_ip="$final_allowlist_ip $ip"
                else
                    final_allowlist_ip="$ip"
                fi
                echo -e "${GREEN}✓ Added SSH IP to allowlist: $ip${NC}" >&2
            fi
        done
    else
        echo -e "${YELLOW}⚠ SSH IP auto-detection failed${NC}" >&2
        ALLOWLIST_DETECTION_METHOD="manual"
    fi
    
    # Set global variables
    DETECTED_ALLOWLIST_IP="$final_allowlist_ip"
    DETECTED_ALLOWLIST_DNS="$final_allowlist_dns"
    
    # Show results
    echo "" >&2
    echo -e "${GREEN}Allowlist Auto-Detection Results:${NC}" >&2
    echo -e "${GREEN}• IP Allowlist: ${DETECTED_ALLOWLIST_IP:-"(none)"}${NC}" >&2
    echo -e "${GREEN}• DNS Allowlist: ${DETECTED_ALLOWLIST_DNS:-"(none)"}${NC}" >&2
    echo -e "${GREEN}• Detection Method: $ALLOWLIST_DETECTION_METHOD${NC}" >&2
    echo "" >&2
    
    return 0
}

# Function to validate allowlist configuration
validate_allowlist_config() {
    local allowlist_ip="$1"
    local allowlist_country="$2"
    local blacklist_country="$3"
    local allowlist_dns="$4"
    local allowlist_mode="$5"
    local allowlist_status="$6"
    
    echo -e "${BLUE}Validating allowlist configuration...${NC}" >&2
    
    local validation_errors=0
    
    # Validate IP allowlist
    if [[ -n "$allowlist_ip" ]]; then
        local invalid_ips=()
        for ip in $allowlist_ip; do
            if ! validate_ip_or_cidr "$ip"; then
                invalid_ips+=("$ip")
                ((validation_errors++))
            fi
        done
        
        if [[ ${#invalid_ips[@]} -gt 0 ]]; then
            echo -e "${RED}✗ Invalid IP addresses/networks: ${invalid_ips[*]}${NC}" >&2
        else
            echo -e "${GREEN}✓ IP allowlist validation passed${NC}" >&2
        fi
    fi
    
    # Validate allowlist country codes
    if [[ -n "$allowlist_country" ]]; then
        local invalid_countries=()
        for country in $allowlist_country; do
            if ! validate_country_code "$country"; then
                invalid_countries+=("$country")
                ((validation_errors++))
            fi
        done
        
        if [[ ${#invalid_countries[@]} -gt 0 ]]; then
            echo -e "${RED}✗ Invalid allowlist country codes: ${invalid_countries[*]}${NC}" >&2
        else
            echo -e "${GREEN}✓ Allowlist country validation passed${NC}" >&2
        fi
    fi
    
    # Validate blacklist country codes
    if [[ -n "$blacklist_country" ]]; then
        local invalid_countries=()
        for country in $blacklist_country; do
            if ! validate_country_code "$country"; then
                invalid_countries+=("$country")
                ((validation_errors++))
            fi
        done
        
        if [[ ${#invalid_countries[@]} -gt 0 ]]; then
            echo -e "${RED}✗ Invalid blacklist country codes: ${invalid_countries[*]}${NC}" >&2
        else
            echo -e "${GREEN}✓ Blacklist country validation passed${NC}" >&2
        fi
    fi
    
    # Validate DNS suffixes
    if [[ -n "$allowlist_dns" ]]; then
        local invalid_dns=()
        for dns in $allowlist_dns; do
            if ! validate_dns_suffix "$dns"; then
                invalid_dns+=("$dns")
                ((validation_errors++))
            fi
        done
        
        if [[ ${#invalid_dns[@]} -gt 0 ]]; then
            echo -e "${RED}✗ Invalid DNS suffixes: ${invalid_dns[*]}${NC}" >&2
        else
            echo -e "${GREEN}✓ DNS allowlist validation passed${NC}" >&2
        fi
    fi
    
    # Validate allowlist mode
    if [[ -n "$allowlist_mode" ]]; then
        if [[ "$allowlist_mode" != "block" && "$allowlist_mode" != "deny" ]]; then
            echo -e "${RED}✗ Invalid allowlist mode: $allowlist_mode (must be 'block' or 'deny')${NC}" >&2
            ((validation_errors++))
        else
            echo -e "${GREEN}✓ Allowlist mode validation passed${NC}" >&2
        fi
    fi
    
    # Validate status code
    if [[ -n "$allowlist_status" ]]; then
        if [[ ! "$allowlist_status" =~ ^[0-9]{3}$ ]] || (( allowlist_status < 100 || allowlist_status > 599 )); then
            echo -e "${RED}✗ Invalid HTTP status code: $allowlist_status${NC}" >&2
            ((validation_errors++))
        else
            echo -e "${GREEN}✓ Status code validation passed${NC}" >&2
        fi
    fi
    
    if [[ $validation_errors -eq 0 ]]; then
        echo -e "${GREEN}✓ Allowlist configuration validation completed successfully${NC}" >&2
        return 0
    else
        echo -e "${RED}✗ Allowlist configuration validation failed with $validation_errors errors${NC}" >&2
        return 1
    fi
}

# Function to configure allowlist in docker-compose.yml
configure_allowlist_in_compose() {
    local compose_file="$1"
    local use_allowlist="$2"
    local allowlist_ip="$3"
    local allowlist_country="$4"
    local blacklist_country="$5"
    local allowlist_dns="$6"
    local allowlist_mode="$7"
    local allowlist_status="$8"
    
    echo -e "${BLUE}Configuring allowlist in docker-compose.yml...${NC}" >&2
    
    if [[ "$use_allowlist" == "yes" ]]; then
        echo -e "${BLUE}Enabling allowlist protection...${NC}" >&2
        
        # Add allowlist environment variables to bunkerweb service
        local allowlist_env=""
        
        if [[ -n "$allowlist_ip" ]]; then
            allowlist_env="${allowlist_env}      WHITELIST_IP: \"$allowlist_ip\"\n"
            echo -e "${GREEN}✓ Added IP allowlist: $allowlist_ip${NC}" >&2
        fi
        
        if [[ -n "$allowlist_country" ]]; then
            allowlist_env="${allowlist_env}      WHITELIST_COUNTRY: \"$allowlist_country\"\n"
            allowlist_env="${allowlist_env}      USE_GEOIP: \"yes\"\n"
            echo -e "${GREEN}✓ Added country allowlist: $allowlist_country${NC}" >&2
        fi
        
        if [[ -n "$blacklist_country" ]]; then
            allowlist_env="${allowlist_env}      BLACKLIST_COUNTRY: \"$blacklist_country\"\n"
            allowlist_env="${allowlist_env}      USE_GEOIP: \"yes\"\n"
            echo -e "${GREEN}✓ Added country blacklist: $blacklist_country${NC}" >&2
        fi
        
        if [[ -n "$allowlist_dns" ]]; then
            allowlist_env="${allowlist_env}      WHITELIST_RDNS: \"$allowlist_dns\"\n"
            echo -e "${GREEN}✓ Added DNS allowlist: $allowlist_dns${NC}" >&2
        fi
        
        if [[ -n "$allowlist_mode" ]]; then
            if [[ "$allowlist_mode" == "deny" ]]; then
                allowlist_env="${allowlist_env}      DENY_NOT_WHITELISTED: \"yes\"\n"
            fi
            echo -e "${GREEN}✓ Set allowlist mode: $allowlist_mode${NC}" >&2
        fi
        
        if [[ -n "$allowlist_status" ]]; then
            allowlist_env="${allowlist_env}      WHITELIST_STATUS_CODE: \"$allowlist_status\"\n"
            echo -e "${GREEN}✓ Set allowlist status code: $allowlist_status${NC}" >&2
        fi
        
        # Insert allowlist configuration into bunkerweb service environment
        if [[ -n "$allowlist_env" ]]; then
            # Use awk to insert allowlist environment variables
            awk -v allowlist_env="$allowlist_env" '
            /^  bunkerweb:/ { in_bunkerweb = 1 }
            in_bunkerweb && /^    environment:/ {
                print $0
                printf "%s", allowlist_env
                next
            }
            /^  [a-zA-Z]/ && !/^  bunkerweb:/ { in_bunkerweb = 0 }
            { print }
            ' "$compose_file" > "$compose_file.tmp" && mv "$compose_file.tmp" "$compose_file"
            
            echo -e "${GREEN}✓ Allowlist configuration added to docker-compose.yml${NC}" >&2
        fi
        
    else
        echo -e "${BLUE}Allowlist protection disabled${NC}" >&2
    fi
    
    return 0
}

# Function to manage allowlist configuration (main function)
manage_allowlist_configuration() {
    local user_allowlist_ip="$1"
    local user_allowlist_country="$2"
    local user_allowlist_dns="$3"
    local use_allowlist="$4"
    local allowlist_mode="$5"
    local allowlist_status="$6"