#!/bin/bash
# Copyright (c) 2025 Michal Koeckeis-Fresel
# This software is dual-licensed under your choice of:
# - MIT License (see LICENSE-MIT)
# - GNU Affero General Public License v3.0 (see LICENSE-AGPL)
# SPDX-License-Identifier: MIT OR AGPL-3.0-or-later

# BunkerWeb Allowlist Management Script
# Handles allowlist detection, validation, and configuration

# Load debug configuration if available
if [[ -f "/data/BunkerWeb/BunkerWeb.conf" ]]; then
    source "/data/BunkerWeb/BunkerWeb.conf" 2>/dev/null || true
elif [[ -f "/root/BunkerWeb.conf" ]]; then
    source "/root/BunkerWeb.conf" 2>/dev/null || true
fi

# Enable debug mode if requested
if [[ "${DEBUG:-no}" == "yes" ]]; then
    set -x
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global variables
DETECTED_ALLOWLIST_IP=""
DETECTED_ALLOWLIST_DNS=""
ALLOWLIST_DETECTION_METHOD=""

# Function to validate IP address or CIDR notation
validate_ip_or_cidr() {
    local ip="$1"
    
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
    
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        local network="${ip%/*}"
        local prefix="${ip#*/}"
        
        if ! validate_ip_or_cidr "$network"; then
            return 1
        fi
        
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
    
    if [[ "$country" =~ ^[A-Z]{2}$ ]]; then
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
    
    if [[ "$dns" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]] && [[ "$dns" == *.* ]]; then
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
    
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        local ssh_ip=$(echo "$SSH_CLIENT" | cut -d' ' -f1)
        if validate_ip_or_cidr "$ssh_ip"; then
            ssh_ips+=("$ssh_ip")
            echo -e "${GREEN}✓ SSH_CLIENT IP detected: $ssh_ip${NC}" >&2
        fi
    fi
    
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        local ssh_ip=$(echo "$SSH_CONNECTION" | cut -d' ' -f1)
        if validate_ip_or_cidr "$ssh_ip" && [[ ! " ${ssh_ips[*]} " =~ " $ssh_ip " ]]; then
            ssh_ips+=("$ssh_ip")
            echo -e "${GREEN}✓ SSH_CONNECTION IP detected: $ssh_ip${NC}" >&2
        fi
    fi
    
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
    local add_ssh_to_trusted="${3:-yes}"
    local ssh_trusted="$4"
    
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo -e "${BLUE}                    ALLOWLIST AUTO-DETECTION                    ${NC}" >&2
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo "" >&2
    
    ALLOWLIST_DETECTION_METHOD="auto-detection"
    
    local final_allowlist_ip="$user_allowlist_ip"
    local final_allowlist_dns="$user_allowlist_dns"
    
    # Add SSH_TRUSTED IPs if specified
    if [[ -n "$ssh_trusted" ]]; then
        echo -e "${BLUE}Adding SSH trusted IP addresses/networks: $ssh_trusted${NC}" >&2
        if [[ -n "$final_allowlist_ip" ]]; then
            final_allowlist_ip="$final_allowlist_ip $ssh_trusted"
        else
            final_allowlist_ip="$ssh_trusted"
        fi
        echo -e "${GREEN}✓ Added SSH trusted networks to allowlist${NC}" >&2
    fi
    
    # Auto-detect SSH connections if enabled
    if [[ "$add_ssh_to_trusted" == "yes" ]]; then
        echo -e "${BLUE}SSH auto-detection enabled - detecting current SSH connections...${NC}" >&2
        
        local ssh_ips=()
        if mapfile -t ssh_ips < <(detect_ssh_connection_ip); then
            echo -e "${GREEN}✓ Detected ${#ssh_ips[@]} SSH connection IP(s)${NC}" >&2
            
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
    else
        echo -e "${BLUE}SSH auto-detection disabled - skipping SSH IP detection${NC}" >&2
        ALLOWLIST_DETECTION_METHOD="manual"
    fi
    
    DETECTED_ALLOWLIST_IP="$final_allowlist_ip"
    DETECTED_ALLOWLIST_DNS="$final_allowlist_dns"
    
    echo "" >&2
    echo -e "${GREEN}Allowlist Auto-Detection Results:${NC}" >&2
    echo -e "${GREEN}• IP Allowlist: ${DETECTED_ALLOWLIST_IP:-"(none)"}${NC}" >&2
    echo -e "${GREEN}• DNS Allowlist: ${DETECTED_ALLOWLIST_DNS:-"(none)"}${NC}" >&2
    echo -e "${GREEN}• Detection Method: $ALLOWLIST_DETECTION_METHOD${NC}" >&2
    echo -e "${GREEN}• SSH Auto-Detection: $add_ssh_to_trusted${NC}" >&2
    if [[ -n "$ssh_trusted" ]]; then
        echo -e "${GREEN}• SSH Trusted Networks: $ssh_trusted${NC}" >&2
    fi
    echo "" >&2
    
    return 0
}

# Function to validate user-provided networks
validate_user_networks() {
    local networks_string="$1"
    local valid_networks=()
    local invalid_networks=()
    
    if [[ -z "$networks_string" ]]; then
        return 0
    fi
    
    IFS=' ' read -ra user_networks <<< "$networks_string"
    for network in "${user_networks[@]}"; do
        if validate_ip_or_cidr "$network"; then
            valid_networks+=("$network")
        else
            invalid_networks+=("$network")
        fi
    done
    
    if [[ ${#invalid_networks[@]} -gt 0 ]]; then
        echo -e "${YELLOW}⚠ Invalid network formats ignored: ${invalid_networks[*]}${NC}" >&2
    fi
    
    if [[ ${#valid_networks[@]} -gt 0 ]]; then
        printf '%s\n' "${valid_networks[@]}"
        return 0
    else
        return 1
    fi
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
    
    if [[ -n "$allowlist_mode" ]]; then
        if [[ "$allowlist_mode" != "block" && "$allowlist_mode" != "deny" ]]; then
            echo -e "${RED}✗ Invalid allowlist mode: $allowlist_mode (must be 'block' or 'deny')${NC}" >&2
            ((validation_errors++))
        else
            echo -e "${GREEN}✓ Allowlist mode validation passed${NC}" >&2
        fi
    fi
    
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
        
        if [[ -n "$allowlist_env" ]]; then
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

# Function to save allowlist configuration to credentials file
save_allowlist_to_credentials() {
    local creds_file="$1"
    local allowlist_ip="$2"
    local allowlist_country="$3"
    local blacklist_country="$4"
    local allowlist_dns="$5"
    local use_allowlist="$6"
    local allowlist_mode="$7"
    local allowlist_status="$8"
    local detection_method="$9"
    
    if [[ ! -f "$creds_file" ]]; then
        echo -e "${YELLOW}⚠ Credentials file not found: $creds_file${NC}" >&2
        return 1
    fi
    
    echo -e "${BLUE}Saving allowlist configuration to credentials file...${NC}" >&2
    
    cat >> "$creds_file" << EOF

# Allowlist Configuration (Global Access Control)
Allowlist Enabled: $use_allowlist
$(if [[ "$use_allowlist" == "yes" ]]; then
    if [[ -n "$allowlist_ip" ]]; then
        echo "Allowlist IP/Networks: $allowlist_ip"
    fi
    if [[ -n "$allowlist_country" ]]; then
        echo "Allowlist Countries: $allowlist_country"
    fi
    if [[ -n "$blacklist_country" ]]; then
        echo "Blacklist Countries: $blacklist_country"
    fi
    if [[ -n "$allowlist_dns" ]]; then
        echo "Allowlist DNS Suffixes: $allowlist_dns"
    fi
    if [[ -n "$allowlist_mode" ]]; then
        echo "Allowlist Mode: $allowlist_mode"
    fi
    if [[ -n "$allowlist_status" ]]; then
        echo "HTTP Status Code: $allowlist_status"
    fi
    echo "Detection Method: ${detection_method:-"manual"}"
fi)

# Allowlist Management Commands:
$(if [[ "$use_allowlist" == "yes" ]]; then
    echo "# Test allowlist: curl -I http://$(hostname -I | awk '{print $1}')"
    echo "# Check logs: docker compose logs bunkerweb | grep -i whitelist"
    echo "# Check blocked requests: docker compose logs bunkerweb | grep -i blocked"
    echo "# Emergency disable: Edit BunkerWeb.conf, set USE_ALLOWLIST=\"no\", restart"
    echo "# Modify allowlist: Edit BunkerWeb.conf and restart containers"
fi)
EOF
    
    echo -e "${GREEN}✓ Allowlist configuration saved to credentials file${NC}" >&2
    return 0
}

# Function to show allowlist summary
show_allowlist_summary() {
    local allowlist_ip="$1"
    local allowlist_country="$2"
    local blacklist_country="$3"
    local allowlist_dns="$4"
    local use_allowlist="$5"
    
    echo -e "${BLUE}Allowlist Configuration Summary:${NC}" >&2
    echo -e "${GREEN}• Allowlist Enabled: $use_allowlist${NC}" >&2
    
    if [[ "$use_allowlist" == "yes" ]]; then
        echo -e "${GREEN}• Detection Method: ${ALLOWLIST_DETECTION_METHOD:-"manual"}${NC}" >&2
        
        if [[ -n "$allowlist_ip" ]]; then
            local ip_count=$(echo "$allowlist_ip" | wc -w)
            echo -e "${GREEN}• IP/Network Entries: $ip_count${NC}" >&2
        fi
        
        if [[ -n "$allowlist_country" ]]; then
            local country_count=$(echo "$allowlist_country" | wc -w)
            echo -e "${GREEN}• Allowed Countries: $country_count${NC}" >&2
        fi
        
        if [[ -n "$blacklist_country" ]]; then
            local blacklist_count=$(echo "$blacklist_country" | wc -w)
            echo -e "${GREEN}• Blocked Countries: $blacklist_count${NC}" >&2
        fi
        
        if [[ -n "$allowlist_dns" ]]; then
            local dns_count=$(echo "$allowlist_dns" | wc -w)
            echo -e "${GREEN}• DNS Suffixes: $dns_count${NC}" >&2
        fi
        
        echo -e "${RED}• WARNING: Controls access to ENTIRE application${NC}" >&2
    else
        echo -e "${YELLOW}• Global access control is disabled${NC}" >&2
        echo -e "${YELLOW}• All visitors can access the application${NC}" >&2
    fi
}

# Main function to manage allowlist configuration
manage_allowlist_configuration() {
    local user_allowlist_ip="$1"
    local user_allowlist_country="$2"
    local blacklist_country="$3"
    local user_allowlist_dns="$4"
    local use_allowlist="$5"
    local allowlist_mode="$6"
    local allowlist_status="$7"
    local compose_file="$8"
    local creds_file="$9"
    local fqdn="${10}"
    local add_ssh_to_trusted="${11:-yes}"
    local ssh_trusted="${12}"
    
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo -e "${BLUE}                    ALLOWLIST CONFIGURATION MANAGEMENT                    ${NC}" >&2
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo "" >&2
    
    if [[ "$use_allowlist" != "yes" ]]; then
        echo -e "${YELLOW}⚠ Allowlist disabled in configuration${NC}" >&2
        echo -e "${BLUE}ℹ Skipping allowlist configuration${NC}" >&2
        
        if [[ -n "$creds_file" ]]; then
            save_allowlist_to_credentials "$creds_file" "" "" "" "" "$use_allowlist" "" "" "disabled"
        fi
        
        show_allowlist_summary "" "" "" "" "$use_allowlist"
        return 0
    fi
    
    echo -e "${BLUE}Configuring allowlist protection...${NC}" >&2
    echo -e "${RED}WARNING: This will control access to your ENTIRE application!${NC}" >&2
    echo "" >&2
    
    auto_detect_allowlist "$user_allowlist_ip" "$user_allowlist_dns" "$add_ssh_to_trusted" "$ssh_trusted"
    
    local final_allowlist_ip="${DETECTED_ALLOWLIST_IP:-$user_allowlist_ip}"
    local final_allowlist_dns="${DETECTED_ALLOWLIST_DNS:-$user_allowlist_dns}"
    
    if ! validate_allowlist_config "$final_allowlist_ip" "$user_allowlist_country" "$blacklist_country" "$final_allowlist_dns" "$allowlist_mode" "$allowlist_status"; then
        echo -e "${RED}✗ Allowlist validation failed${NC}" >&2
        return 1
    fi
    
    if [[ -n "$compose_file" ]]; then
        configure_allowlist_in_compose "$compose_file" "$use_allowlist" "$final_allowlist_ip" "$user_allowlist_country" "$blacklist_country" "$final_allowlist_dns" "$allowlist_mode" "$allowlist_status"
    fi
    
    if [[ -n "$creds_file" ]]; then
        save_allowlist_to_credentials "$creds_file" "$final_allowlist_ip" "$user_allowlist_country" "$blacklist_country" "$final_allowlist_dns" "$use_allowlist" "$allowlist_mode" "$allowlist_status" "$ALLOWLIST_DETECTION_METHOD"
    fi
    
    show_allowlist_summary "$final_allowlist_ip" "$user_allowlist_country" "$blacklist_country" "$final_allowlist_dns" "$use_allowlist"
    
    echo "" >&2
    echo -e "${GREEN}✓ Allowlist configuration completed successfully${NC}" >&2
    echo "" >&2
    
    return 0
}

# Function to get detected allowlist IP
get_detected_allowlist_ip() {
    echo "$DETECTED_ALLOWLIST_IP"
}

# Function to get detected allowlist DNS
get_detected_allowlist_dns() {
    echo "$DETECTED_ALLOWLIST_DNS"
}

# Function to get allowlist detection method
get_allowlist_detection_method() {
    echo "$ALLOWLIST_DETECTION_METHOD"
}

# If script is run directly, show usage or run tests
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "BunkerWeb Allowlist Management Script"
    echo ""
    echo "This script is designed to be sourced by other scripts."
    echo ""
    echo "Available functions:"
    echo "  manage_allowlist_configuration <ip> <country> <blacklist_country> <dns> <use> <mode> <status> <compose_file> <creds_file> <fqdn>"
    echo "  auto_detect_allowlist <ip> <dns>"
    echo "  validate_allowlist_config <ip> <country> <blacklist_country> <dns> <mode> <status>"
    echo "  configure_allowlist_in_compose <compose_file> <use> <ip> <country> <blacklist_country> <dns> <mode> <status>"
    echo "  get_detected_allowlist_ip"
    echo "  get_detected_allowlist_dns"
    echo "  get_allowlist_detection_method"
    echo "  show_allowlist_summary <ip> <country> <blacklist_country> <dns> <use>"
    
    # Handle test commands
    if [[ "$1" == "test-detect" ]]; then
        echo ""
        echo "=== Testing SSH IP Detection ==="
        detect_ssh_connection_ip
        auto_detect_allowlist "" ""
        show_allowlist_summary "$DETECTED_ALLOWLIST_IP" "" "" "$DETECTED_ALLOWLIST_DNS" "yes"
    elif [[ "$1" == "test-validate" ]]; then
        echo ""
        echo "=== Testing Validation Functions ==="
        validate_allowlist_config "192.168.1.0/24 10.0.0.1 invalid.ip" "US CA XX" "CN RU YY" "example.com invalid..domain" "invalid_mode" "999"
    fi
fi