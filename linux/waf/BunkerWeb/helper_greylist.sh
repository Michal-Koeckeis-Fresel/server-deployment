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

# BunkerWeb Greylist Configuration Helper Script
# Handles greylist detection, SSH IP discovery, and greylist configuration
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables for greylist configuration
DETECTED_SSH_IPS=()
DETECTED_SSH_NETWORKS=()
ENHANCED_GREYLIST_IP=""
GREYLIST_DETECTION_METHOD=""

# Utility functions
check_command() {
    command -v "$1" >/dev/null 2>&1
}

# Function to validate IP address format
is_valid_ip() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && {
        local IFS='.'
        set -- $ip
        [[ $1 -le 255 && $2 -le 255 && $3 -le 255 && $4 -le 255 ]]
    }
}

# Function to validate CIDR format
is_valid_cidr() {
    local cidr="$1"
    [[ "$cidr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] && {
        local ip="${cidr%/*}"
        local prefix="${cidr#*/}"
        is_valid_ip "$ip" && [[ $prefix -ge 0 && $prefix -le 32 ]]
    }
}

# Function to convert IP to network (for /24 networks)
ip_to_network() {
    local ip="$1"
    local prefix="${2:-24}"
    
    if ! is_valid_ip "$ip"; then
        return 1
    fi
    
    local IFS='.'
    set -- $ip
    
    case "$prefix" in
        8)
            echo "$1.0.0.0/$prefix"
            ;;
        16)
            echo "$1.$2.0.0/$prefix"
            ;;
        24)
            echo "$1.$2.$3.0/$prefix"
            ;;
        32)
            echo "$ip/$prefix"
            ;;
        *)
            # For other prefixes, return as /32
            echo "$ip/32"
            ;;
    esac
}

# Function to detect current SSH connection IP
detect_current_ssh_ip() {
    local current_ssh_ip=""
    
    # Method 1: Check SSH_CLIENT environment variable
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        current_ssh_ip=$(echo "$SSH_CLIENT" | awk '{print $1}')
        if is_valid_ip "$current_ssh_ip"; then
            echo -e "${GREEN}✓ Current SSH connection detected: $current_ssh_ip${NC}" >&2
            GREYLIST_DETECTION_METHOD="SSH_CLIENT"
            echo "$current_ssh_ip"
            return 0
        fi
    fi
    
    # Method 2: Check SSH_CONNECTION environment variable
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        current_ssh_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}')
        if is_valid_ip "$current_ssh_ip"; then
            echo -e "${GREEN}✓ Current SSH connection detected: $current_ssh_ip${NC}" >&2
            GREYLIST_DETECTION_METHOD="SSH_CONNECTION"
            echo "$current_ssh_ip"
            return 0
        fi
    fi
    
    # Method 3: Check who command for current session
    if check_command who; then
        local current_tty=$(tty 2>/dev/null | sed 's|/dev/||')
        if [[ -n "$current_tty" ]]; then
            current_ssh_ip=$(who | grep "$current_tty" | awk '{print $5}' | tr -d '()')
            if is_valid_ip "$current_ssh_ip"; then
                echo -e "${GREEN}✓ Current SSH connection detected via who: $current_ssh_ip${NC}" >&2
                GREYLIST_DETECTION_METHOD="who"
                echo "$current_ssh_ip"
                return 0
            fi
        fi
    fi
    
    # Method 4: Check netstat for current SSH connection
    if check_command netstat; then
        local ssh_port="${SSH_PORT:-22}"
        current_ssh_ip=$(netstat -tn | grep ":$ssh_port " | awk '{print $5}' | cut -d: -f1 | head -1)
        if is_valid_ip "$current_ssh_ip"; then
            echo -e "${GREEN}✓ Current SSH connection detected via netstat: $current_ssh_ip${NC}" >&2
            GREYLIST_DETECTION_METHOD="netstat"
            echo "$current_ssh_ip"
            return 0
        fi
    fi
    
    echo -e "${YELLOW}⚠ Could not detect current SSH connection IP${NC}" >&2
    GREYLIST_DETECTION_METHOD="none"
    return 1
}

# Function to detect recent SSH connection IPs
detect_recent_ssh_ips() {
    local ssh_ips=()
    
    echo -e "${BLUE}Detecting recent SSH connection IPs...${NC}" >&2
    
    # Method 1: Check auth.log for recent SSH connections (last 24 hours)
    local auth_logs=("/var/log/auth.log" "/var/log/secure" "/var/log/authentication.log")
    
    for log_file in "${auth_logs[@]}"; do
        if [[ -f "$log_file" && -r "$log_file" ]]; then
            echo -e "${CYAN}• Checking $log_file...${NC}" >&2
            
            # Extract successful SSH connections from last 24 hours
            local recent_ips=$(grep "Accepted" "$log_file" 2>/dev/null | \
                              grep "$(date +'%b %d')" | \
                              awk '{print $(NF-3)}' | \
                              grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
                              sort -u)
            
            while IFS= read -r ip; do
                if [[ -n "$ip" ]] && is_valid_ip "$ip"; then
                    ssh_ips+=("$ip")
                    echo -e "${GREEN}  Found recent SSH IP: $ip${NC}" >&2
                fi
            done <<< "$recent_ips"
            
            break  # Use first available log file
        fi
    done
    
    # Method 2: Check journalctl for SSH connections (if available and no auth.log found)
    if [[ ${#ssh_ips[@]} -eq 0 ]] && check_command journalctl; then
        echo -e "${CYAN}• Checking journalctl for SSH connections...${NC}" >&2
        
        local journal_ips=$(journalctl -u ssh -u sshd --since "24 hours ago" 2>/dev/null | \
                           grep "Accepted" | \
                           awk '{print $(NF-3)}' | \
                           grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
                           sort -u)
        
        while IFS= read -r ip; do
            if [[ -n "$ip" ]] && is_valid_ip "$ip"; then
                ssh_ips+=("$ip")
                echo -e "${GREEN}  Found recent SSH IP: $ip${NC}" >&2
            fi
        done <<< "$journal_ips"
    fi
    
    # Method 3: Check last command for recent logins
    if [[ ${#ssh_ips[@]} -eq 0 ]] && check_command last; then
        echo -e "${CYAN}• Checking last command for recent logins...${NC}" >&2
        
        local last_ips=$(last -i | head -20 | awk '/pts|tty/ {print $3}' | \
                        grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
                        sort -u)
        
        while IFS= read -r ip; do
            if [[ -n "$ip" ]] && is_valid_ip "$ip"; then
                ssh_ips+=("$ip")
                echo -e "${GREEN}  Found login IP: $ip${NC}" >&2
            fi
        done <<< "$last_ips"
    fi
    
    # Store results in global array
    DETECTED_SSH_IPS=("${ssh_ips[@]}")
    
    if [[ ${#DETECTED_SSH_IPS[@]} -gt 0 ]]; then
        echo -e "${GREEN}✓ Detected ${#DETECTED_SSH_IPS[@]} recent SSH connection IPs${NC}" >&2
        return 0
    else
        echo -e "${YELLOW}⚠ No recent SSH connection IPs found${NC}" >&2
        return 1
    fi
}

# Function to convert SSH IPs to networks (intelligent network detection)
convert_ips_to_networks() {
    local ips=("$@")
    local networks=()
    
    echo -e "${BLUE}Converting SSH IPs to networks for greylist...${NC}" >&2
    
    for ip in "${ips[@]}"; do
        if ! is_valid_ip "$ip"; then
            continue
        fi
        
        # Determine appropriate network size based on IP classification
        local network=""
        local ip_class=""
        
        # Check if it's a private IP (RFC 1918)
        if [[ "$ip" =~ ^10\. ]]; then
            # Class A private - use /16 for office networks, /24 for small networks
            if [[ "$ip" =~ ^10\.0\. ]]; then
                network=$(ip_to_network "$ip" 16)
                ip_class="Private Class A (large network)"
            else
                network=$(ip_to_network "$ip" 24)
                ip_class="Private Class A (subnet)"
            fi
        elif [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
            # Class B private - use /24
            network=$(ip_to_network "$ip" 24)
            ip_class="Private Class B"
        elif [[ "$ip" =~ ^192\.168\. ]]; then
            # Class C private - use /24
            network=$(ip_to_network "$ip" 24)
            ip_class="Private Class C"
        elif [[ "$ip" =~ ^127\. ]]; then
            # Loopback - use /8
            network=$(ip_to_network "$ip" 8)
            ip_class="Loopback"
        else
            # Public IP - be more restrictive, use /32 (exact IP) or /28 for small office
            # Check if it looks like a small office range (ending in common patterns)
            local last_octet="${ip##*.}"
            if [[ $last_octet -ge 1 && $last_octet -le 10 ]] || [[ $last_octet -ge 250 && $last_octet -le 254 ]]; then
                # Likely small office - use /28 (16 IPs)
                local base_ip=$(echo "$ip" | sed 's/\.[0-9]*$//')
                local subnet_start=$(( (last_octet / 16) * 16 ))
                network="$base_ip.$subnet_start/28"
                ip_class="Public IP (small range)"
            else
                # Use exact IP for public addresses
                network="$ip/32"
                ip_class="Public IP (exact)"
            fi
        fi
        
        if [[ -n "$network" ]]; then
            networks+=("$network")
            echo -e "${GREEN}  $ip → $network ($ip_class)${NC}" >&2
        fi
    done
    
    # Remove duplicates and store in global array
    DETECTED_SSH_NETWORKS=($(printf '%s\n' "${networks[@]}" | sort -u))
    
    echo -e "${GREEN}✓ Generated ${#DETECTED_SSH_NETWORKS[@]} network ranges from SSH IPs${NC}" >&2
    return 0
}

# Function to enhance greylist configuration with detected IPs
enhance_greylist_configuration() {
    local existing_greylist_ip="$1"
    local use_greylist="$2"
    
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo -e "${BLUE}                    GREYLIST CONFIGURATION ENHANCEMENT                    ${NC}" >&2
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo "" >&2
    
    if [[ "$use_greylist" != "yes" ]]; then
        echo -e "${YELLOW}⚠ Greylist disabled in configuration${NC}" >&2
        echo -e "${BLUE}ℹ Skipping greylist IP detection${NC}" >&2
        ENHANCED_GREYLIST_IP=""
        return 0
    fi
    
    echo -e "${BLUE}Enhancing greylist configuration with SSH connection detection...${NC}" >&2
    
    # Start with existing configuration
    local enhanced_ips="$existing_greylist_ip"
    
    # Detect current SSH IP
    echo -e "${BLUE}Step 1: Detecting current SSH connection...${NC}" >&2
    local current_ssh_ip
    if current_ssh_ip=$(detect_current_ssh_ip); then
        # Convert current IP to appropriate network
        local current_networks=()
        convert_ips_to_networks "$current_ssh_ip"
        current_networks=("${DETECTED_SSH_NETWORKS[@]}")
        
        # Add current SSH networks to enhanced list
        for network in "${current_networks[@]}"; do
            if [[ ! "$enhanced_ips" =~ $network ]]; then
                enhanced_ips="$enhanced_ips $network"
                echo -e "${GREEN}✓ Added current SSH network: $network${NC}" >&2
            fi
        done
    fi
    
    # Detect recent SSH IPs
    echo -e "${BLUE}Step 2: Detecting recent SSH connections...${NC}" >&2
    if detect_recent_ssh_ips; then
        # Convert recent IPs to networks
        convert_ips_to_networks "${DETECTED_SSH_IPS[@]}"
        
        # Add recent SSH networks to enhanced list
        for network in "${DETECTED_SSH_NETWORKS[@]}"; do
            if [[ ! "$enhanced_ips" =~ $network ]]; then
                enhanced_ips="$enhanced_ips $network"
                echo -e "${GREEN}✓ Added recent SSH network: $network${NC}" >&2
            fi
        done
    fi
    
    # Clean up the enhanced IP list (remove extra spaces, duplicates)
    enhanced_ips=$(echo "$enhanced_ips" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ' | sed 's/^ *//;s/ *$//')
    
    # Store result
    ENHANCED_GREYLIST_IP="$enhanced_ips"
    
    echo "" >&2
    echo -e "${GREEN}Greylist Enhancement Summary:${NC}" >&2
    echo -e "${GREEN}• Detection Method: ${GREYLIST_DETECTION_METHOD:-"multiple"}${NC}" >&2
    echo -e "${GREEN}• Current SSH IPs: ${#DETECTED_SSH_IPS[@]}${NC}" >&2
    echo -e "${GREEN}• Generated Networks: ${#DETECTED_SSH_NETWORKS[@]}${NC}" >&2
    echo -e "${GREEN}• Enhanced Greylist:${NC}" >&2
    
    # Display enhanced greylist in readable format
    if [[ -n "$ENHANCED_GREYLIST_IP" ]]; then
        echo "$ENHANCED_GREYLIST_IP" | tr ' ' '\n' | while read -r entry; do
            if [[ -n "$entry" ]]; then
                echo -e "${GREEN}  • $entry${NC}" >&2
            fi
        done
    else
        echo -e "${YELLOW}  • No greylist entries configured${NC}" >&2
    fi
    
    echo "" >&2
    return 0
}

# Function to apply greylist configuration to docker-compose file
apply_greylist_to_compose() {
    local compose_file="$1"
    local enhanced_greylist_ip="$2"
    local greylist_dns="$3"
    local use_greylist="$4"
    local fqdn="$5"
    
    echo -e "${BLUE}Applying greylist configuration to docker-compose.yml...${NC}" >&2
    
    if [[ "$use_greylist" != "yes" ]]; then
        echo -e "${YELLOW}⚠ Greylist disabled - skipping greylist configuration${NC}" >&2
        return 0
    fi
    
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${RED}✗ Docker compose file not found: $compose_file${NC}" >&2
        return 1
    fi
    
    # Apply greylist settings based on the deployment type
    echo -e "${BLUE}Configuring greylist for admin interface protection...${NC}" >&2
    
    # For UI-integrated deployments, configure domain-specific greylist
    if grep -q "USE_TEMPLATE.*ui" "$compose_file"; then
        echo -e "${BLUE}Detected UI-integrated deployment - configuring domain-specific greylist${NC}" >&2
        
        # Add greylist configuration for the specific domain
        if [[ -n "$fqdn" && "$fqdn" != "localhost" ]]; then
            local greylist_vars=""
            
            # Add IP-based greylist
            if [[ -n "$enhanced_greylist_ip" ]]; then
                greylist_vars+="      ${fqdn}_GREYLIST_IP: \"$enhanced_greylist_ip\"\n"
                echo -e "${GREEN}✓ Configured IP greylist for domain: $fqdn${NC}" >&2
            fi
            
            # Add DNS-based greylist
            if [[ -n "$greylist_dns" ]]; then
                greylist_vars+="      ${fqdn}_GREYLIST_RDNS: \"$greylist_dns\"\n"
                echo -e "${GREEN}✓ Configured DNS greylist for domain: $fqdn${NC}" >&2
            fi
            
            # Insert greylist variables into scheduler environment
            if [[ -n "$greylist_vars" ]]; then
                # Find the scheduler service and add greylist environment variables
                awk -v vars="$greylist_vars" '
                /^  bw-scheduler:/ { in_scheduler = 1 }
                in_scheduler && /^    environment:/ { 
                    print $0
                    printf "%s", vars
                    next
                }
                /^  [a-zA-Z]/ && !/^  bw-scheduler:/ { in_scheduler = 0 }
                { print }
                ' "$compose_file" > "$compose_file.tmp" && mv "$compose_file.tmp" "$compose_file"
                
                echo -e "${GREEN}✓ Greylist environment variables added to scheduler${NC}" >&2
            fi
        fi
    fi
    
    # For autoconf deployments, configure global greylist
    if grep -q "AUTOCONF_MODE.*yes" "$compose_file"; then
        echo -e "${BLUE}Detected autoconf deployment - configuring global greylist${NC}" >&2
        
        # Add greylist to scheduler environment variables
        if [[ -n "$enhanced_greylist_ip" || -n "$greylist_dns" ]]; then
            local global_greylist_vars=""
            
            if [[ -n "$enhanced_greylist_ip" ]]; then
                global_greylist_vars+="      GREYLIST_IP: \"$enhanced_greylist_ip\"\n"
            fi
            
            if [[ -n "$greylist_dns" ]]; then
                global_greylist_vars+="      GREYLIST_RDNS: \"$greylist_dns\"\n"
            fi
            
            # Insert into scheduler environment
            if [[ -n "$global_greylist_vars" ]]; then
                awk -v vars="$global_greylist_vars" '
                /^  bw-scheduler:/ { in_scheduler = 1 }
                in_scheduler && /^    environment:/ { 
                    print $0
                    printf "%s", vars
                    next
                }
                /^  [a-zA-Z]/ && !/^  bw-scheduler:/ { in_scheduler = 0 }
                { print }
                ' "$compose_file" > "$compose_file.tmp" && mv "$compose_file.tmp" "$compose_file"
                
                echo -e "${GREEN}✓ Global greylist environment variables added${NC}" >&2
            fi
        fi
    fi
    
    echo -e "${GREEN}✓ Greylist configuration applied successfully${NC}" >&2
    return 0
}

# Function to validate greylist configuration
validate_greylist_configuration() {
    local greylist_ip="$1"
    local greylist_dns="$2"
    
    echo -e "${BLUE}Validating greylist configuration...${NC}" >&2
    
    local validation_errors=0
    
    # Validate IP addresses and networks
    if [[ -n "$greylist_ip" ]]; then
        echo -e "${BLUE}Validating greylist IP addresses/networks...${NC}" >&2
        
        while IFS= read -r entry; do
            if [[ -n "$entry" ]]; then
                if [[ "$entry" =~ / ]]; then
                    # CIDR notation
                    if is_valid_cidr "$entry"; then
                        echo -e "${GREEN}  ✓ Valid network: $entry${NC}" >&2
                    else
                        echo -e "${RED}  ✗ Invalid network: $entry${NC}" >&2
                        ((validation_errors++))
                    fi
                else
                    # Single IP
                    if is_valid_ip "$entry"; then
                        echo -e "${GREEN}  ✓ Valid IP: $entry${NC}" >&2
                    else
                        echo -e "${RED}  ✗ Invalid IP: $entry${NC}" >&2
                        ((validation_errors++))
                    fi
                fi
            fi
        done <<< "$(echo "$greylist_ip" | tr ' ' '\n')"
    fi
    
    # Validate DNS suffixes
    if [[ -n "$greylist_dns" ]]; then
        echo -e "${BLUE}Validating greylist DNS suffixes...${NC}" >&2
        
        while IFS= read -r domain; do
            if [[ -n "$domain" ]]; then
                # Basic domain validation
                if [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$ ]]; then
                    echo -e "${GREEN}  ✓ Valid DNS suffix: $domain${NC}" >&2
                else
                    echo -e "${RED}  ✗ Invalid DNS suffix: $domain${NC}" >&2
                    ((validation_errors++))
                fi
            fi
        done <<< "$(echo "$greylist_dns" | tr ' ' '\n')"
    fi
    
    if [[ $validation_errors -eq 0 ]]; then
        echo -e "${GREEN}✓ Greylist configuration validation passed${NC}" >&2
        return 0
    else
        echo -e "${RED}✗ Greylist configuration validation failed with $validation_errors errors${NC}" >&2
        return 1
    fi
}

# Function to save greylist configuration to credentials file
save_greylist_to_credentials() {
    local creds_file="$1"
    local enhanced_greylist_ip="$2"
    local greylist_dns="$3"
    local use_greylist="$4"
    local detection_method="$5"
    
    if [[ ! -f "$creds_file" ]]; then
        echo -e "${YELLOW}⚠ Credentials file not found: $creds_file${NC}" >&2
        return 1
    fi
    
    echo -e "${BLUE}Saving greylist configuration to credentials file...${NC}" >&2
    
    # Add greylist section to credentials file
    cat >> "$creds_file" << EOF

# Greylist Configuration
Greylist Enabled: $use_greylist
$(if [[ "$use_greylist" == "yes" ]]; then
    echo "Greylist IP/Networks: $enhanced_greylist_ip"
    if [[ -n "$greylist_dns" ]]; then
        echo "Greylist DNS Suffixes: $greylist_dns"
    fi
    echo "Detection Method: ${detection_method:-"manual"}"
    echo ""
    echo "# Greylist Security Information:"
    echo "# Only the above IP addresses/networks can access the admin interface"
    echo "# SSH connections were automatically detected and added to the greylist"
    echo "# Additional trusted networks should be added before deployment"
    echo "# Test greylist access before removing alternative access methods"
fi)

# Greylist Testing Commands:
$(if [[ "$use_greylist" == "yes" ]]; then
    echo "# Test greylist: curl -I http://$(hostname -I | awk '{print $1}')/admin"
    echo "# Check logs: docker compose logs bunkerweb | grep -i greylist"
    echo "# Modify greylist: Edit BunkerWeb.conf and restart containers"
fi)
EOF
    
    echo -e "${GREEN}✓ Greylist configuration saved to credentials file${NC}" >&2
    return 0
}

# Function to show greylist summary
show_greylist_summary() {
    local enhanced_greylist_ip="$1"
    local greylist_dns="$2"
    local use_greylist="$3"
    
    echo -e "${BLUE}Greylist Configuration Summary:${NC}" >&2
    echo -e "${GREEN}• Greylist Enabled: $use_greylist${NC}" >&2
    
    if [[ "$use_greylist" == "yes" ]]; then
        echo -e "${GREEN}• Detection Method: ${GREYLIST_DETECTION_METHOD:-"manual"}${NC}" >&2
        echo -e "${GREEN}• SSH IPs Detected: ${#DETECTED_SSH_IPS[@]}${NC}" >&2
        echo -e "${GREEN}• Networks Generated: ${#DETECTED_SSH_NETWORKS[@]}${NC}" >&2
        
        if [[ -n "$enhanced_greylist_ip" ]]; then
            local ip_count=$(echo "$enhanced_greylist_ip" | wc -w)
            echo -e "${GREEN}• Total Greylist Entries: $ip_count${NC}" >&2
        fi
        
        if [[ -n "$greylist_dns" ]]; then
            local dns_count=$(echo "$greylist_dns" | wc -w)
            echo -e "${GREEN}• DNS Suffixes: $dns_count${NC}" >&2
        fi
    else
        echo -e "${YELLOW}• Greylist protection is disabled${NC}" >&2
        echo -e "${YELLOW}• Admin interface accessible from any IP${NC}" >&2
    fi
}

# Main function to manage greylist configuration
manage_greylist_configuration() {
    local existing_greylist_ip="$1"
    local greylist_dns="$2"
    local use_greylist="$3"
    local compose_file="$4"
    local creds_file="$5"
    local fqdn="$6"
    
    # Enhance greylist with SSH detection
    enhance_greylist_configuration "$existing_greylist_ip" "$use_greylist"
    
    # Validate configuration
    if [[ "$use_greylist" == "yes" ]]; then
        if ! validate_greylist_configuration "$ENHANCED_GREYLIST_IP" "$greylist_dns"; then
            echo -e "${RED}✗ Greylist validation failed${NC}" >&2
            return 1
        fi
    fi
    
    # Apply to docker-compose file
    if [[ -n "$compose_file" ]]; then
        apply_greylist_to_compose "$compose_file" "$ENHANCED_GREYLIST_IP" "$greylist_dns" "$use_greylist" "$fqdn"
    fi
    
    # Save to credentials file
    if [[ -n "$creds_file" ]]; then
        save_greylist_to_credentials "$creds_file" "$ENHANCED_GREYLIST_IP" "$greylist_dns" "$use_greylist" "$GREYLIST_DETECTION_METHOD"
    fi
    
    # Show summary
    show_greylist_summary "$ENHANCED_GREYLIST_IP" "$greylist_dns" "$use_greylist"
    
    return 0
}

# Function to get enhanced greylist IP
get_enhanced_greylist_ip() {
    echo "$ENHANCED_GREYLIST_IP"
}

# Function to get detected SSH IPs
get_detected_ssh_ips() {
    printf '%s\n' "${DETECTED_SSH_IPS[@]}"
}

# Function to get detection method
get_greylist_detection_method() {
    echo "$GREYLIST_DETECTION_METHOD"
}

# If script is run directly, show usage or run tests
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "BunkerWeb Greylist Configuration Helper Script"
    echo ""
    echo "This script is designed to be sourced by other scripts."
    echo ""
    echo "Available functions:"
    echo "  manage_greylist_configuration <existing_ip> <dns> <use_greylist> <compose_file> <creds_file> <fqdn>"
    echo "  enhance_greylist_configuration <existing_greylist_ip> <use_greylist>"
    echo "  detect_current_ssh_ip"
    echo "  detect_recent_ssh_ips"
    echo "  apply_greylist_to_compose <compose_file> <greylist_ip> <greylist_dns> <use_greylist> <fqdn>"
    echo "  validate_greylist_configuration <greylist_ip> <greylist_dns>"
    echo "  get_enhanced_greylist_ip"
    echo "  get_detected_ssh_ips"
    echo "  show_greylist_summary <greylist_ip> <greylist_dns> <use_greylist>"
    echo ""
    echo "Example usage:"
    echo "  source helper_greylist.sh"
    echo "  manage_greylist_configuration \"192.168.1.0/24\" \"\" \"yes\" \"docker-compose.yml\" \"credentials.txt\" \"example.com\""
    echo ""
    echo "Test functions:"
    echo "  $0 test-detect    # Test SSH IP detection"
    echo "  $0 test-validate  # Test validation functions"
    
    # Handle test commands
    if [[ "$1" == "test-detect" ]]; then
        echo ""
        echo "=== Testing SSH IP Detection ==="
        detect_current_ssh_ip
        detect_recent_ssh_ips
        convert_ips_to_networks "${DETECTED_SSH_IPS[@]}"
        show_greylist_summary "$ENHANCED_GREYLIST_IP" "" "yes"
    elif [[ "$1" == "test-validate" ]]; then
        echo ""
        echo "=== Testing Validation Functions ==="
        validate_greylist_configuration "192.168.1.0/24 10.0.0.1 invalid.ip" "example.com invalid..domain"
    fi
fi