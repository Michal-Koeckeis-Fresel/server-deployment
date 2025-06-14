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

# DNS Performance Benchmark Script for Unbound Configuration
# Tests google.com lookup on multiple DNS servers, ranks by performance, and configures DoT/DoH encryption
# Features: Performance testing, DoT/DoH support detection, encryption-aware Unbound configuration



# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration files
DNS_SERVERS_FILE="/root/unbound-dns-servers.txt"
DNS_SERVERS_URL="https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/configs/unbound/dns_servers_list.txt"
UNBOUND_CONFIG="/etc/unbound/unbound.conf"
BACKUP_CONFIG="/etc/unbound/unbound.conf.backup.$(date +%Y%m%d_%H%M%S)"

# DNS servers arrays (will be populated from external file)
declare -A DNS_SERVERS=()
declare -A DOH_ENDPOINTS=()
declare -A DOT_HOSTNAMES=()

# Test domain
TEST_DOMAIN="google.com"

# Results array
declare -a RESULTS=()

# IPv6 availability flag
IPV6_AVAILABLE=false

# Encryption support tracking
declare -A DOH_SUPPORT=()
declare -A DOT_SUPPORT=()

# Function to download DNS servers list from GitHub
download_dns_servers_file() {
    echo "Downloading DNS servers list from GitHub repository..."
    
    if command -v curl >/dev/null 2>&1; then
        if curl -s -f -o "$DNS_SERVERS_FILE" "$DNS_SERVERS_URL"; then
            echo -e "${GREEN}✓ Successfully downloaded DNS servers list${NC}"
            return 0
        else
            echo -e "${RED}✗ Failed to download with curl${NC}"
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -q -O "$DNS_SERVERS_FILE" "$DNS_SERVERS_URL"; then
            echo -e "${GREEN}✓ Successfully downloaded DNS servers list${NC}"
            return 0
        else
            echo -e "${RED}✗ Failed to download with wget${NC}"
        fi
    else
        echo -e "${RED}✗ Neither curl nor wget found${NC}"
    fi
    
    echo -e "${YELLOW}Please download manually:${NC}"
    echo "curl -o $DNS_SERVERS_FILE $DNS_SERVERS_URL"
    echo "or"
    echo "wget -O $DNS_SERVERS_FILE $DNS_SERVERS_URL"
    return 1
}

# Function to load DNS servers from external file
load_dns_servers() {
    if [ ! -f "$DNS_SERVERS_FILE" ]; then
        echo -e "${YELLOW}DNS servers file not found at $DNS_SERVERS_FILE${NC}"
        echo "Attempting to download from GitHub repository..."
        
        if download_dns_servers_file; then
            echo "Download successful, proceeding with DNS server loading..."
        else
            echo -e "${RED}ERROR: Could not download DNS servers file${NC}"
            echo "Please manually download the file with:"
            echo "curl -o $DNS_SERVERS_FILE $DNS_SERVERS_URL"
            exit 1
        fi
    fi
    
    echo "Loading DNS servers from: $DNS_SERVERS_FILE"
    
    local count=0
    while IFS='|' read -r ip name doh_endpoint dot_hostname || [ -n "$ip" ]; do
        # Skip empty lines and comments
        [[ -z "$ip" || "$ip" =~ ^[[:space:]]*# ]] && continue
        
        # Trim whitespace
        ip=$(echo "$ip" | xargs)
        name=$(echo "$name" | xargs)
        doh_endpoint=$(echo "$doh_endpoint" | xargs)
        dot_hostname=$(echo "$dot_hostname" | xargs)
        
        # Skip if IP is empty after trimming
        [ -z "$ip" ] && continue
        
        # Populate arrays
        DNS_SERVERS["$ip"]="$name"
        [ -n "$doh_endpoint" ] && DOH_ENDPOINTS["$ip"]="$doh_endpoint"
        [ -n "$dot_hostname" ] && DOT_HOSTNAMES["$ip"]="$dot_hostname"
        
        ((count++))
    done < "$DNS_SERVERS_FILE"
    
    if [ $count -eq 0 ]; then
        echo -e "${RED}ERROR: No valid DNS servers found in $DNS_SERVERS_FILE${NC}"
        exit 1
    fi
    
    echo "Loaded $count DNS servers from configuration file"
    echo "Source: $DNS_SERVERS_URL"
}

echo -e "${BLUE}=== DNS Performance Benchmark for ${TEST_DOMAIN} ===${NC}"

# Handle command line arguments
if [ "$1" = "--update-servers" ] || [ "$1" = "-u" ]; then
    echo "Force updating DNS servers list from GitHub repository..."
    if download_dns_servers_file; then
        echo -e "${GREEN}DNS servers list updated successfully${NC}"
        echo "You can now run the script again without the --update-servers flag"
        exit 0
    else
        echo -e "${RED}Failed to update DNS servers list${NC}"
        exit 1
    fi
fi

if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  -u, --update-servers    Download/update DNS servers list from GitHub"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "DNS servers source: $DNS_SERVERS_URL"
    echo "Local file: $DNS_SERVERS_FILE"
    exit 0
fi

# Load DNS servers from external file
load_dns_servers

# Count IPv6 servers
ipv6_count=0
for server in "${!DNS_SERVERS[@]}"; do
    if [[ "$server" == *":"* ]]; then
        ((ipv6_count++))
    fi
done

echo "Available: ${#DNS_SERVERS[@]} total DNS servers ($ipv6_count IPv6, $((${#DNS_SERVERS[@]} - ipv6_count)) IPv4)"
echo "Features: Performance benchmarking + DoT/DoH testing + Encryption-based grouping"
echo "Note: Each server gets a cache-warming lookup before performance measurement"
echo ""

# Test IPv6 connectivity first
echo -e "${YELLOW}=== Checking IPv6 Connectivity ===${NC}"
printf "Testing IPv6 connectivity... "

if ping6 -c 1 -W 3 2001:4860:4860::8888 >/dev/null 2>&1; then
    echo -e "${GREEN}✓ IPv6 working - testing all $((${#DNS_SERVERS[@]})) servers${NC}"
    IPV6_AVAILABLE=true
else
    echo -e "${RED}✗ IPv6 not available - skipping $ipv6_count IPv6 servers, testing $((${#DNS_SERVERS[@]} - ipv6_count)) IPv4 servers${NC}"
    IPV6_AVAILABLE=false
fi
echo ""

# Function to test DoT support
test_dot_support() {
    local server=$1
    local hostname=${DOT_HOSTNAMES[$server]}
    
    if [ -z "$hostname" ]; then
        return 1
    fi
    
    # Test DoT connection with timeout
    if timeout 3 openssl s_client -connect "${server}:853" -servername "$hostname" </dev/null >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to test DoH support
test_doh_support() {
    local server=$1
    local endpoint=${DOH_ENDPOINTS[$server]}
    
    if [ -z "$endpoint" ]; then
        return 1
    fi
    
    # Test DoH endpoint with timeout
    if timeout 3 curl -s -H "Accept: application/dns-json" "${endpoint}?name=google.com&type=A" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Test encryption support for all servers
echo -e "${YELLOW}=== Testing DNS Encryption Support ===${NC}"
echo "Checking DoT (port 853) and DoH (port 443) support..."
echo ""

for server in "${!DNS_SERVERS[@]}"; do
    # Skip IPv6 servers if IPv6 is not available
    if [[ "$server" == *":"* ]] && [ "$IPV6_AVAILABLE" = false ]; then
        continue
    fi
    
    printf "Testing %-25s " "$server"
    
    dot_status="✗"
    doh_status="✗"
    
    # Test DoT support
    if test_dot_support "$server"; then
        dot_status="✓"
        DOT_SUPPORT[$server]=true
    else
        DOT_SUPPORT[$server]=false
    fi
    
    # Test DoH support
    if test_doh_support "$server"; then
        doh_status="✓"
        DOH_SUPPORT[$server]=true
    else
        DOH_SUPPORT[$server]=false
    fi
    
    printf "DoT: ${dot_status}  DoH: ${doh_status}\n"
done

echo ""

# Function to test DNS server performance
test_dns_server() {
    local server=$1
    local name=$2
    local total_time=0
    local successful_queries=0
    local attempts=3
    
    # Build encryption support indicator
    local encryption_info=""
    if [ "${DOT_SUPPORT[$server]}" = true ] && [ "${DOH_SUPPORT[$server]}" = true ]; then
        encryption_info=" ${GREEN}[DoT+DoH]${NC}"
    elif [ "${DOT_SUPPORT[$server]}" = true ]; then
        encryption_info=" ${BLUE}[DoT]${NC}"
    elif [ "${DOH_SUPPORT[$server]}" = true ]; then
        encryption_info=" ${BLUE}[DoH]${NC}"
    fi

    printf "Testing %-25s %-30s" "$server" "($name)"

    # Cache warming lookup (not measured)
    dig @$server +time=3 +tries=1 +short $TEST_DOMAIN >/dev/null 2>&1
    sleep 0.5 # Allow cache to settle

    for i in $(seq 1 $attempts); do
        # Use dig with timeout and measure response time
        local start_time=$(date +%s%N)
        local result=$(dig @$server +time=2 +tries=1 +short $TEST_DOMAIN 2>/dev/null)
        local end_time=$(date +%s%N)
        
        if [ $? -eq 0 ] && [ ! -z "$result" ]; then
            local query_time=$((($end_time - $start_time) / 1000000)) # Convert to milliseconds
            total_time=$(($total_time + $query_time))
            successful_queries=$(($successful_queries + 1))
        fi
        
        sleep 0.2 # Small delay between attempts
    done

    if [ $successful_queries -gt 0 ]; then
        local avg_time=$(($total_time / $successful_queries))
        printf "${GREEN}%4d ms${NC} (${successful_queries}/${attempts} success)$encryption_info\n" $avg_time
        
        # Include encryption support in results
        local encryption_tag=""
        if [ "${DOT_SUPPORT[$server]}" = true ] && [ "${DOH_SUPPORT[$server]}" = true ]; then
            encryption_tag=" [DoT+DoH]"
        elif [ "${DOT_SUPPORT[$server]}" = true ]; then
            encryption_tag=" [DoT]"
        elif [ "${DOH_SUPPORT[$server]}" = true ]; then
            encryption_tag=" [DoH]"
        fi
        
        RESULTS+=("$avg_time|$server|$name$encryption_tag")
    else
        printf "${RED}FAILED${NC} (0/${attempts} success)$encryption_info\n"
    fi
}

# Test all DNS servers
for server in "${!DNS_SERVERS[@]}"; do
    # Skip IPv6 servers if IPv6 is not available
    if [[ "$server" == *":"* ]] && [ "$IPV6_AVAILABLE" = false ]; then
        printf "Skipping %-25s %-30s ${YELLOW}IPv6 not available${NC}\n" "$server" "(${DNS_SERVERS[$server]})"
        continue
    fi
    
    test_dns_server "$server" "${DNS_SERVERS[$server]}"
done

echo ""
echo -e "${YELLOW}=== Results Summary ===${NC}"

# Sort results by response time (ascending)
IFS=$'\n'
SORTED_RESULTS=($(sort -n <<<"${RESULTS[*]}"))
unset IFS

if [ ${#SORTED_RESULTS[@]} -eq 0 ]; then
    echo -e "${RED}ERROR: No DNS servers responded successfully!${NC}"
    exit 1
fi

echo "Ranked by performance (fastest first):"
echo ""

counter=1
declare -a TOP_SERVERS=()
encrypted_count=0
total_tested=0

for result in "${SORTED_RESULTS[@]}"; do
    IFS='|' read -r time server name <<< "$result"
    
    # Count encryption support
    if [[ "$name" == *"[DoT"* ]] || [[ "$name" == *"[DoH"* ]]; then
        encrypted_count=$((encrypted_count + 1))
    fi
    total_tested=$((total_tested + 1))
    
    printf "%2d. %-25s %-30s %s ms\n" $counter "$server" "($name)" "$time"
    TOP_SERVERS+=("$server")
    counter=$((counter + 1))
done

echo ""
echo -e "${BLUE}Encryption Support Summary:${NC}"
echo "$encrypted_count of $total_tested tested servers support DoT and/or DoH encryption"

echo ""
echo -e "${YELLOW}=== Updating Unbound Configuration ===${NC}"

# Backup current configuration
if [ -f "$UNBOUND_CONFIG" ]; then
    cp "$UNBOUND_CONFIG" "$BACKUP_CONFIG"
    echo "Backup created: $BACKUP_CONFIG"
fi

# Generate new forward-zone section with encryption capability grouping
echo "Generating optimized forward-zone configuration by encryption capability..."

# Group servers by encryption support and get top 3 from each
declare -A ENCRYPTION_GROUPS

# Group results by encryption capability
for result in "${SORTED_RESULTS[@]}"; do
    IFS='|' read -r time server name <<< "$result"
    
    # Determine encryption group
    if [ "${DOH_SUPPORT[$server]}" = true ]; then
        encryption_type="doh"
    elif [ "${DOT_SUPPORT[$server]}" = true ]; then
        encryption_type="dot"
    else
        encryption_type="regular"
    fi
    
    # Add to encryption group (max 3 per group)
    if [[ ! ${ENCRYPTION_GROUPS[$encryption_type]} ]]; then
        ENCRYPTION_GROUPS[$encryption_type]="$result"
    else
        count=$(echo "${ENCRYPTION_GROUPS[$encryption_type]}" | tr ';' '\n' | wc -l)
        if [ $count -lt 3 ]; then
            ENCRYPTION_GROUPS[$encryption_type]="${ENCRYPTION_GROUPS[$encryption_type]};$result"
        fi
    fi
done

# Build server lists by encryption capability
DOH_SERVERS=""
DOT_SERVERS=""
REGULAR_SERVERS=""

echo "Selected top 3 performers per encryption group:"

# Process DoH group (highest priority) - Note: DoH forwarding in Unbound is limited
if [[ ${ENCRYPTION_GROUPS[doh]} ]]; then
    echo ""
    echo "DoH (DNS-over-HTTPS) - Top 3 performers:"
    echo "Note: DoH forwarding support in Unbound is limited. These will be configured as DoT where supported."
    IFS=';' read -ra SERVERS <<< "${ENCRYPTION_GROUPS[doh]}"
    for server_result in "${SERVERS[@]}"; do
        IFS='|' read -r time server name <<< "$server_result"
        clean_name=$(echo "$name" | sed 's/ \[DoT[^]]*\]//g')
        echo "  $server - $time ms - $clean_name"
        
        # For DoH-capable servers, use DoT if available, otherwise regular DNS
        if [ "${DOT_SUPPORT[$server]}" = true ]; then
            if [ -n "$DOT_SERVERS" ]; then
                DOT_SERVERS+="\n"
            fi
            DOT_SERVERS+="    forward-addr: $server@853#${DOT_HOSTNAMES[$server]}            # $clean_name (DoT - DoH capable)"
        else
            if [ -n "$REGULAR_SERVERS" ]; then
                REGULAR_SERVERS+="\n"
            fi
            REGULAR_SERVERS+="    forward-addr: $server            # $clean_name (DoH capable - using regular DNS)"
        fi
    done
fi

# Process DoT group (secondary priority)
if [[ ${ENCRYPTION_GROUPS[dot]} ]]; then
    echo ""
    echo "DoT (DNS-over-TLS) - Top 3 performers:"
    IFS=';' read -ra SERVERS <<< "${ENCRYPTION_GROUPS[dot]}"
    for server_result in "${SERVERS[@]}"; do
        IFS='|' read -r time server name <<< "$server_result"
        clean_name=$(echo "$name" | sed 's/ \[DoT[^]]*\]//g')
        echo "  $server - $time ms - $clean_name"
        
        if [ -n "$DOT_SERVERS" ]; then
            DOT_SERVERS+="\n"
        fi
        DOT_SERVERS+="    forward-addr: $server@853#${DOT_HOSTNAMES[$server]}            # $clean_name (DoT)"
    done
fi

# Process Regular DNS group (fallback priority)
if [[ ${ENCRYPTION_GROUPS[regular]} ]]; then
    echo ""
    echo "Regular DNS - Top 3 performers:"
    IFS=';' read -ra SERVERS <<< "${ENCRYPTION_GROUPS[regular]}"
    for server_result in "${SERVERS[@]}"; do
        IFS='|' read -r time server name <<< "$server_result"
        clean_name=$(echo "$name" | sed 's/ \[DoT[^]]*\]//g')
        echo "  $server - $time ms - $clean_name"
        
        if [ -n "$REGULAR_SERVERS" ]; then
            REGULAR_SERVERS+="\n"
        fi
        REGULAR_SERVERS+="    forward-addr: $server            # $clean_name (Regular DNS)"
    done
fi

# Build complete forward-zone configuration with encryption hierarchy
FORWARD_ZONE="# Auto-generated DNS configuration by encryption capability
# Generated on: $(date)
# Test domain: $TEST_DOMAIN (with cache warming and encryption testing)
# Configuration: Top 3 performers per encryption group
# Priority order: DoT (port 853) > Regular DNS (port 53)
# Note: DoH servers are configured as DoT where supported due to Unbound limitations
# DNS servers loaded from: $DNS_SERVERS_FILE

forward-zone:
    name: \".\"
    
    # DNS-over-TLS (DoT) - Encrypted Priority - Port 853
$DOT_SERVERS
    
    # Regular DNS - Fallback Priority - Port 53
$REGULAR_SERVERS"

echo ""
echo -e "${GREEN}New forward-zone configuration:${NC}"
echo -e "$FORWARD_ZONE"

# Create new configuration file
if [ -f "$UNBOUND_CONFIG" ]; then
    # Remove ALL existing forward-zone sections and auto-generated comments
    awk '
    /^# Auto-generated DNS configuration/ { skip_comments=1; next }
    /^# Generated on:/ && skip_comments { next }
    /^# Test domain:/ && skip_comments { next }
    /^# Configuration:/ && skip_comments { next }
    /^# Priority:/ && skip_comments { next }
    /^# Note:/ && skip_comments { next }
    /^# DNS servers loaded from:/ && skip_comments { next }
    /^# Simplified DNS configuration/ { next }
    /^forward-zone:/ { in_forward=1; skip_comments=0; next }
    in_forward && /^[[:space:]]/ { next }
    in_forward && !/^[[:space:]]/ { in_forward=0; skip_comments=0 }
    /^[[:space:]]*$/ && skip_comments { next }
    !in_forward && !skip_comments { print }
    ' "$UNBOUND_CONFIG" > "${UNBOUND_CONFIG}.tmp"
    
    # Add TLS support to server section if not already present (for DoT)
    if ! grep -q "tls-cert-bundle:" "${UNBOUND_CONFIG}.tmp"; then
        sed -i '/^server:$/a\    # TLS settings for DoT support\n    tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"' "${UNBOUND_CONFIG}.tmp"
    fi
    
    echo -e "\n$FORWARD_ZONE" >> "${UNBOUND_CONFIG}.tmp"
    mv "${UNBOUND_CONFIG}.tmp" "$UNBOUND_CONFIG"
else
    echo -e "${RED}ERROR: Unbound configuration file not found at $UNBOUND_CONFIG${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}=== Testing Configuration ===${NC}"

# Test the new configuration
if unbound-checkconf "$UNBOUND_CONFIG" >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Configuration syntax is valid${NC}"
    
    echo "Restarting Unbound with new DNS server configuration..."
    
    if systemctl restart unbound; then
        echo -e "${GREEN}✓ Unbound restarted successfully${NC}"
        
        # Test the new configuration
        echo "Testing new configuration..."
        sleep 2
        
        test_result=$(dig @127.0.0.1 +time=5 +short $TEST_DOMAIN 2>/dev/null)
        if [ $? -eq 0 ] && [ ! -z "$test_result" ]; then
            echo -e "${GREEN}✓ DNS resolution working: $test_result${NC}"
            
            # Remove debug logging and restore normal verbosity
            echo "Disabling debug logging and restoring normal verbosity..."
            sed -i 's/verbosity: 3/verbosity: 1/' "$UNBOUND_CONFIG"
            sed -i '/log-queries:/d; /log-replies:/d; /log-tag-queryreply:/d; /log-time-ascii:/d; /logfile:/d' "$UNBOUND_CONFIG"
            
            # Clean up debug log file
            if [ -f "/var/log/unbound-debug.log" ]; then
                rm -f "/var/log/unbound-debug.log"
                echo "Debug log file removed"
            fi
            
            # Final restart with clean logging
            systemctl restart unbound
            echo -e "${GREEN}✓ Debug logging disabled, normal operation restored${NC}"
        else
            echo -e "${RED}✗ DNS resolution test failed${NC}"
        fi
    else
        echo -e "${RED}✗ Failed to restart Unbound${NC}"
        echo "Restoring backup configuration..."
        cp "$BACKUP_CONFIG" "$UNBOUND_CONFIG"
        
        # Clean up debug logging from backup too
        sed -i 's/verbosity: 3/verbosity: 1/' "$UNBOUND_CONFIG"
        sed -i '/log-queries:/d; /log-replies:/d; /log-tag-queryreply:/d; /log-time-ascii:/d; /logfile:/d' "$UNBOUND_CONFIG"
        rm -f "/var/log/unbound-debug.log"
        
        systemctl restart unbound
    fi
else
    echo -e "${RED}✗ Configuration syntax error${NC}"
    echo "Restoring backup configuration..."
    cp "$BACKUP_CONFIG" "$UNBOUND_CONFIG"
    
    # Clean up debug logging from backup
    sed -i 's/verbosity: 3/verbosity: 1/' "$UNBOUND_CONFIG"
    sed -i '/log-queries:/d; /log-replies:/d; /log-tag-queryreply:/d; /log-time-ascii:/d; /logfile:/d' "$UNBOUND_CONFIG"
    rm -f "/var/log/unbound-debug.log"
    
    systemctl restart unbound
    exit 1
fi

echo ""
echo -e "${BLUE}=== DNS Encryption & Performance Optimization Complete ===${NC}"
echo "Configuration created with top 3 performers per encryption group"
echo "Encryption priority: DoT (including DoH-capable servers) > Regular DNS"
echo "Note: DoH servers configured as DoT due to Unbound forwarding limitations"
echo "Backup saved as: $BACKUP_CONFIG"
echo "DNS servers loaded from: $DNS_SERVERS_FILE"

echo ""
echo -e "${YELLOW}Configuration Summary:${NC}"

# Count servers by encryption type
dot_count=$(echo -e "$DOT_SERVERS" | grep -c "forward-addr:" || echo "0")
regular_count=$(echo -e "$REGULAR_SERVERS" | grep -c "forward-addr:" || echo "0")

echo "DoT (DNS-over-TLS) servers: $dot_count (includes DoH-capable servers)"
echo "Regular DNS servers: $regular_count"
echo "Total configured servers: $((dot_count + regular_count))"

# Optional: Show performance comparison by encryption capability
echo ""
echo -e "${YELLOW}Encryption Group Performance Summary:${NC}"

# Show best server from each encryption group
for encryption_type in doh dot regular; do
    if [[ ${ENCRYPTION_GROUPS[$encryption_type]} ]]; then
        # Get first (fastest) server from this encryption group
        first_result=$(echo "${ENCRYPTION_GROUPS[$encryption_type]}" | cut -d';' -f1)
        IFS='|' read -r time server name <<< "$first_result"
        
        # Clean name and show encryption type
        clean_name=$(echo "$name" | sed 's/ \[DoT[^]]*\]//g')
        
        case $encryption_type in
            doh) 
                echo -e "${GREEN}DoH fastest:${NC} $server - $time ms ($clean_name)"
                ;;
            dot) 
                echo -e "${BLUE}DoT fastest:${NC} $server - $time ms ($clean_name)"
                ;;
            regular) 
                echo -e "${YELLOW}Regular fastest:${NC} $server - $time ms ($clean_name)"
                ;;
        esac
    fi
done

echo ""
echo -e "${BLUE}DNS Encryption Configuration Hierarchy:${NC}"
echo -e "${GREEN}1. DoT (DNS-over-TLS):${NC} Port 853 - Highest priority, encrypted DNS"
echo -e "${BLUE}   • Includes DoH-capable servers configured as DoT${NC}"
echo -e "${YELLOW}2. Regular DNS:${NC} Port 53 - Fallback priority, unencrypted but fast"
echo ""
echo -e "${BLUE}Note on DoH:${NC} Unbound has limited DoH forwarding support."
echo -e "DoH-capable servers are configured as DoT for better compatibility."
echo ""
echo -e "${YELLOW}To update DNS servers list:${NC} Run script with --update-servers flag"
echo -e "${YELLOW}Manual update:${NC} curl -o $DNS_SERVERS_FILE $DNS_SERVERS_URL"
echo -e "${YELLOW}Edit local file:${NC} $DNS_SERVERS_FILE"
echo -e "${YELLOW}File format:${NC} IP_ADDRESS|NAME|DOH_ENDPOINT|DOT_HOSTNAME"