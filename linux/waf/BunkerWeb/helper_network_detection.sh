#!/bin/bash
# Copyright (c) 2025 Michal Koeckeis-Fresel
# This software is dual-licensed under your choice of:
# - MIT License (see LICENSE-MIT)
# - GNU Affero General Public License v3.0 (see LICENSE-AGPL)
# SPDX-License-Identifier: MIT OR AGPL-3.0-or-later

# BunkerWeb Network Conflict Detection Script
# Handles network scanning, conflict detection, and safe subnet suggestion

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
DETECTED_DOCKER_SUBNET=""
DETECTED_CONFLICTS=()

# Utility functions
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
    
    if ! is_valid_cidr "$cidr"; then
        echo "0/32"
        return 1
    fi
    
    local ip="${cidr%/*}"
    local prefix="${cidr#*/}"
    
    if [[ $prefix -lt 0 || $prefix -gt 32 ]]; then
        echo "0/32"
        return 1
    fi
    
    local a b c d
    IFS=. read -r a b c d <<< "$ip"
    
    if [[ $a -gt 255 || $b -gt 255 || $c -gt 255 || $d -gt 255 ]]; then
        echo "0/32"
        return 1
    fi
    
    local ip_decimal=$((a * 256**3 + b * 256**2 + c * 256 + d))
    local mask=$((0xFFFFFFFF << (32 - prefix)))
    local network=$((ip_decimal & mask))
    
    echo "$network/$prefix"
}

# Function to check if two networks overlap
networks_overlap() {
    local net1="$1"
    local net2="$2"
    
    if ! is_valid_cidr "$net1" || ! is_valid_cidr "$net2"; then
        return 1
    fi
    
    local net1_dec=$(cidr_to_decimal "$net1")
    local net2_dec=$(cidr_to_decimal "$net2")
    
    local net1_addr="${net1_dec%/*}"
    local net1_prefix="${net1_dec#*/}"
    local net2_addr="${net2_dec%/*}"
    local net2_prefix="${net2_dec#*/}"
    
    local smaller_prefix=$((net1_prefix < net2_prefix ? net1_prefix : net2_prefix))
    local mask=$((0xFFFFFFFF << (32 - smaller_prefix)))
    
    local net1_masked=$((net1_addr & mask))
    local net2_masked=$((net2_addr & mask))
    
    [[ $net1_masked -eq $net2_masked ]]
}

# Function to get existing network routes from system
get_existing_networks() {
    local networks=()
    
    if check_command ip; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+) ]]; then
                local network="${BASH_REMATCH[1]}"
                if [[ "$network" != "0.0.0.0/0" && "$network" != *"/32" ]]; then
                    networks+=("$network")
                fi
            fi
        done < <(ip route show 2>/dev/null | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+" || true)
    fi
    
    if check_command ip; then
        while IFS= read -r line; do
            if [[ "$line" =~ inet[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+) ]]; then
                local network="${BASH_REMATCH[1]}"
                if [[ "$network" != "127."* && "$network" != *"/32" ]]; then
                    networks+=("$network")
                fi
            fi
        done < <(ip addr show 2>/dev/null || true)
    fi
    
    if check_command ifconfig && [[ ${#networks[@]} -eq 0 ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ inet[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*netmask[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
                local ip="${BASH_REMATCH[1]}"
                local netmask="${BASH_REMATCH[2]}"
                local cidr=$(netmask_to_cidr "$netmask")
                if [[ "$ip" != "127."* && "$cidr" != "32" ]]; then
                    networks+=("$ip/$cidr")
                fi
            fi
        done < <(ifconfig 2>/dev/null || true)
    fi
    
    if check_command docker; then
        while IFS= read -r line; do
            if [[ "$line" =~ \"Subnet\":[[:space:]]*\"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+)\" ]]; then
                local network="${BASH_REMATCH[1]}"
                networks+=("$network")
            fi
        done < <(docker network ls -q 2>/dev/null | xargs -I {} docker network inspect {} 2>/dev/null | grep -E "\"Subnet\":" || true)
    fi
    
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
    
    local candidate_subnets=(
        "10.20.30.0/24"
        "172.20.0.0/24"
        "172.21.0.0/24"
        "172.22.0.0/24"
        "10.10.10.0/24"
        "10.50.0.0/24"
        "10.100.0.0/24"
        "192.168.200.0/24"
        "192.168.100.0/24"
        "192.168.50.0/24"
    )
    
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
    
    for base_range in "10" "172" "192"; do
        case "$base_range" in
            "10")
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
    
    echo "10.240.0.0/24"
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
        if is_valid_cidr "$network"; then
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

# Function to perform comprehensive network conflict detection
detect_network_conflicts() {
    local auto_detect="${1:-yes}"
    local user_networks_string="$2"
    local preferred_subnet="$3"
    local default_subnet="${4:-10.20.30.0/24}"
    
    DETECTED_DOCKER_SUBNET=""
    DETECTED_CONFLICTS=()
    
    if [[ "$auto_detect" != "yes" ]]; then
        echo -e "${BLUE}Network conflict detection disabled${NC}" >&2
        DETECTED_DOCKER_SUBNET="$default_subnet"
        return 0
    fi
    
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo -e "${BLUE}                    NETWORK CONFLICT DETECTION                    ${NC}" >&2
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo "" >&2
    
    echo -e "${BLUE}Scanning existing network configurations...${NC}" >&2
    
    local existing_networks=()
    echo -e "${CYAN}• Checking routing table...${NC}" >&2
    echo -e "${CYAN}• Checking network interfaces...${NC}" >&2
    echo -e "${CYAN}• Checking existing Docker networks...${NC}" >&2
    
    while IFS= read -r network; do
        if [[ -n "$network" ]] && is_valid_cidr "$network"; then
            existing_networks+=("$network")
        fi
    done < <(get_existing_networks)
    
    if [[ -n "$user_networks_string" ]]; then
        echo -e "${BLUE}User-specified networks to avoid: $user_networks_string${NC}" >&2
        while IFS= read -r network; do
            existing_networks+=("$network")
        done < <(validate_user_networks "$user_networks_string")
    fi
    
    if [[ ${#existing_networks[@]} -eq 0 ]]; then
        echo -e "${YELLOW}⚠ No existing networks detected - using default configuration${NC}" >&2
        DETECTED_DOCKER_SUBNET="$default_subnet"
        return 0
    fi
    
    echo -e "${GREEN}Detected existing networks:${NC}" >&2
    for network in "${existing_networks[@]}"; do
        echo -e "${GREEN}  • $network${NC}" >&2
    done
    echo "" >&2
    
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
        echo -e "${RED}Default subnet $default_subnet conflicts with:${NC}" >&2
        for conflicting in "${conflicting_networks[@]}"; do
            echo -e "${RED}  • $conflicting${NC}" >&2
            DETECTED_CONFLICTS+=("$conflicting")
        done
        echo "" >&2
        
        echo -e "${BLUE}Finding safe Docker subnet...${NC}" >&2
        local safe_subnet=$(suggest_safe_subnet "${existing_networks[@]}")
        
        echo -e "${GREEN}✓ Suggested safe subnet: $safe_subnet${NC}" >&2
        DETECTED_DOCKER_SUBNET="$safe_subnet"
        
    else
        echo -e "${GREEN}✓ No conflicts detected with default subnet $default_subnet${NC}" >&2
        DETECTED_DOCKER_SUBNET="$default_subnet"
    fi
    
    if [[ -n "$preferred_subnet" ]]; then
        if is_valid_cidr "$preferred_subnet"; then
            local preferred_conflict=false
            for existing in "${existing_networks[@]}"; do
                if networks_overlap "$preferred_subnet" "$existing"; then
                    preferred_conflict=true
                    break
                fi
            done
            
            if [[ "$preferred_conflict" == "false" ]]; then
                echo -e "${GREEN}✓ Using preferred subnet: $preferred_subnet${NC}" >&2
                DETECTED_DOCKER_SUBNET="$preferred_subnet"
            else
                echo -e "${RED}⚠ Preferred subnet $preferred_subnet conflicts with existing networks${NC}" >&2
                echo -e "${BLUE}ℹ Using auto-detected safe subnet: $DETECTED_DOCKER_SUBNET${NC}" >&2
            fi
        else
            echo -e "${YELLOW}⚠ Invalid preferred subnet format: $preferred_subnet${NC}" >&2
        fi
    fi
    
    echo "" >&2
    echo -e "${GREEN}Final Docker network configuration:${NC}" >&2
    echo -e "${GREEN}  • Main subnet: $DETECTED_DOCKER_SUBNET${NC}" >&2
    echo "" >&2
    
    return 0
}

# Function to get the detected subnet
get_detected_subnet() {
    echo "$DETECTED_DOCKER_SUBNET"
}

# Function to get detected conflicts
get_detected_conflicts() {
    printf '%s\n' "${DETECTED_CONFLICTS[@]}"
}

# Function to display network detection summary
show_network_summary() {
    echo -e "${BLUE}Network Detection Summary:${NC}" >&2
    echo -e "${GREEN}• Detected Subnet: ${DETECTED_DOCKER_SUBNET:-"Not detected"}${NC}" >&2
    
    if [[ ${#DETECTED_CONFLICTS[@]} -gt 0 ]]; then
        echo -e "${YELLOW}• Conflicts Found: ${#DETECTED_CONFLICTS[@]}${NC}" >&2
        for conflict in "${DETECTED_CONFLICTS[@]}"; do
            echo -e "${YELLOW}  - $conflict${NC}" >&2
        done
    else
        echo -e "${GREEN}• Conflicts Found: None${NC}" >&2
    fi
}

# Function to test network functions (for debugging)
test_network_functions() {
    echo "Testing network utility functions..."
    echo ""
    
    echo "Testing CIDR validation:"
    local test_cidrs=("192.168.1.0/24" "10.0.0.0/8" "invalid" "256.1.1.1/24" "192.168.1.0/33")
    for cidr in "${test_cidrs[@]}"; do
        if is_valid_cidr "$cidr"; then
            echo "  ✓ $cidr - Valid"
        else
            echo "  ✗ $cidr - Invalid"
        fi
    done
    echo ""
    
    echo "Testing network overlap detection:"
    local test_pairs=(
        "192.168.1.0/24 192.168.1.100/32"
        "10.0.0.0/8 172.16.0.0/12"
        "192.168.1.0/24 192.168.2.0/24"
        "10.20.30.0/24 10.20.0.0/16"
    )
    
    for pair in "${test_pairs[@]}"; do
        read -r net1 net2 <<< "$pair"
        if networks_overlap "$net1" "$net2"; then
            echo "  ✓ $net1 overlaps with $net2"
        else
            echo "  ✗ $net1 does not overlap with $net2"
        fi
    done
    echo ""
    
    echo "Testing existing network detection:"
    local existing_nets=()
    while IFS= read -r network; do
        existing_nets+=("$network")
    done < <(get_existing_networks)
    
    echo "  Found ${#existing_nets[@]} existing networks:"
    for net in "${existing_nets[@]}"; do
        echo "    • $net"
    done
}

# If script is run directly, show usage or run tests
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ "$1" == "test" ]]; then
        test_network_functions
    else
        echo "BunkerWeb Network Conflict Detection Script"
        echo ""
        echo "This script is designed to be sourced by other scripts."
        echo ""
        echo "Available functions:"
        echo "  detect_network_conflicts [auto_detect] [user_networks] [preferred_subnet] [default_subnet]"
        echo "  get_detected_subnet"
        echo "  get_detected_conflicts"
        echo "  show_network_summary"
        echo "  is_valid_cidr <cidr>"
        echo "  networks_overlap <net1> <net2>"
        echo "  suggest_safe_subnet <existing_networks...>"
        echo ""
        echo "Example usage:"
        echo "  source helper_network_detection.sh"
        echo "  detect_network_conflicts \"yes\" \"192.168.1.0/24\" \"\" \"10.20.30.0/24\""
        echo "  SUBNET=\$(get_detected_subnet)"
        echo ""
        echo "Run with 'test' argument to run diagnostic tests:"
        echo "  $0 test"
    fi
fi