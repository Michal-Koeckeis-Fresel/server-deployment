#!/bin/bash

# DNS Performance Benchmark Script for Unbound Configuration
# Tests google.com lookup on multiple DNS servers, ranks by performance, and configures DoT/DoH encryption
# Features: Performance testing, DoT/DoH support detection, encryption-aware Unbound configuration
# Author: Michal Koeckeis-Fresel
# License: MIT

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# DNS servers to test with DoH/DoT endpoints
declare -A DNS_SERVERS=(
    ["185.12.64.1"]="Hetzner IPv4 Primary"
    ["185.12.64.2"]="Hetzner IPv4 Secondary"
    ["2a01:4ff:ff00::add:1"]="Hetzner IPv6 Primary"
    ["2a01:4ff:ff00::add:2"]="Hetzner IPv6 Secondary"
    ["9.9.9.9"]="Quad9 IPv4 Primary"
    ["149.112.112.112"]="Quad9 IPv4 Secondary"
    ["1.1.1.1"]="Cloudflare IPv4 Primary"
    ["1.0.0.1"]="Cloudflare IPv4 Secondary"
    ["1.1.1.2"]="Cloudflare Family IPv4 Primary"
    ["1.0.0.2"]="Cloudflare Family IPv4 Secondary"
    ["1.1.1.3"]="Cloudflare for Families IPv4 Primary"
    ["1.0.0.3"]="Cloudflare for Families IPv4 Secondary"
    ["8.8.8.8"]="Google IPv4 Primary"
    ["8.8.4.4"]="Google IPv4 Secondary"
    ["2620:fe::fe"]="Quad9 IPv6 Primary"
    ["2620:fe::9"]="Quad9 IPv6 Secondary"
    ["2606:4700:4700::1111"]="Cloudflare IPv6"
    ["2001:4860:4860::8888"]="Google IPv6 Primary"
    ["2001:4860:4860::8844"]="Google IPv6 Secondary"
)

# DoH endpoints for supported servers
declare -A DOH_ENDPOINTS=(
    ["1.1.1.1"]="https://cloudflare-dns.com/dns-query"
    ["1.0.0.1"]="https://cloudflare-dns.com/dns-query"
    ["1.1.1.2"]="https://security.cloudflare-dns.com/dns-query"
    ["1.0.0.2"]="https://security.cloudflare-dns.com/dns-query"
    ["1.1.1.3"]="https://family.cloudflare-dns.com/dns-query"
    ["1.0.0.3"]="https://family.cloudflare-dns.com/dns-query"
    ["2606:4700:4700::1111"]="https://cloudflare-dns.com/dns-query"
    ["8.8.8.8"]="https://dns.google/dns-query"
    ["8.8.4.4"]="https://dns.google/dns-query"
    ["2001:4860:4860::8888"]="https://dns.google/dns-query"
    ["2001:4860:4860::8844"]="https://dns.google/dns-query"
    ["9.9.9.9"]="https://dns.quad9.net/dns-query"
    ["149.112.112.112"]="https://dns.quad9.net/dns-query"
    ["2620:fe::fe"]="https://dns.quad9.net/dns-query"
    ["2620:fe::9"]="https://dns.quad9.net/dns-query"
)

# DoT hostnames for supported servers
declare -A DOT_HOSTNAMES=(
    ["1.1.1.1"]="cloudflare-dns.com"
    ["1.0.0.1"]="cloudflare-dns.com"
    ["1.1.1.2"]="security.cloudflare-dns.com"
    ["1.0.0.2"]="security.cloudflare-dns.com"
    ["1.1.1.3"]="family.cloudflare-dns.com"
    ["1.0.0.3"]="family.cloudflare-dns.com"
    ["2606:4700:4700::1111"]="cloudflare-dns.com"
    ["8.8.8.8"]="dns.google"
    ["8.8.4.4"]="dns.google"
    ["2001:4860:4860::8888"]="dns.google"
    ["2001:4860:4860::8844"]="dns.google"
    ["9.9.9.9"]="dns.quad9.net"
    ["149.112.112.112"]="dns.quad9.net"
    ["2620:fe::fe"]="dns.quad9.net"
    ["2620:fe::9"]="dns.quad9.net"
)

# Test domain
TEST_DOMAIN="google.com"
UNBOUND_CONFIG="/etc/unbound/unbound.conf"
BACKUP_CONFIG="/etc/unbound/unbound.conf.backup.$(date +%Y%m%d_%H%M%S)"

# Results array
declare -a RESULTS=()

# IPv6 availability flag
IPV6_AVAILABLE=false

# Encryption support tracking
declare -A DOH_SUPPORT=()
declare -A DOT_SUPPORT=()

echo -e "${BLUE}=== DNS Performance Benchmark for ${TEST_DOMAIN} ===${NC}"

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
IFS=

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
    systemctl restart unbound
    
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
echo -e "DoH-capable servers are configured as DoT for better compatibility."\n' SORTED_RESULTS=($(sort -n <<<"${RESULTS[*]}"))
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

# Generate new forward-zone section
echo "Generating optimized forward-zone configuration..."

FORWARD_ZONE="# Auto-generated DNS configuration based on cache-warmed performance test
# Generated on: $(date)
# Test domain: $TEST_DOMAIN (with cache warming)
# Note: Temporary debug logging will be automatically removed after testing
forward-zone:
    name: \".\""

counter=1
for server in "${TOP_SERVERS[@]}"; do
    name="${DNS_SERVERS[$server]}"
    if [ $counter -le 3 ]; then
        priority="primary"
    elif [ $counter -le 6 ]; then
        priority="secondary"
    else
        priority="fallback"
    fi
    
    FORWARD_ZONE+="\n    forward-addr: $server            # $name ($priority)"
    counter=$((counter + 1))
done

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
    /^# Note:/ && skip_comments { next }
    /^# Simplified DNS configuration/ { next }
    /^forward-zone:/ { in_forward=1; skip_comments=0; next }
    in_forward && /^[[:space:]]/ { next }
    in_forward && !/^[[:space:]]/ { in_forward=0; skip_comments=0 }
    /^[[:space:]]*$/ && skip_comments { next }
    !in_forward && !skip_comments { print }
    ' "$UNBOUND_CONFIG" > "${UNBOUND_CONFIG}.tmp"
    
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
    systemctl restart unbound
    
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
echo -e "${BLUE}=== Performance Optimization Complete ===${NC}"
echo "Top 3 fastest servers are now prioritized in Unbound configuration"
echo "Backup saved as: $BACKUP_CONFIG"

# Optional: Show performance comparison
echo ""
echo -e "${YELLOW}Performance Summary:${NC}"
echo "Fastest server: ${TOP_SERVERS[0]} (${DNS_SERVERS[${TOP_SERVERS[0]}]})"
if [ ${#TOP_SERVERS[@]} -gt 1 ]; then
    echo "Second fastest: ${TOP_SERVERS[1]} (${DNS_SERVERS[${TOP_SERVERS[1]}]})"
fi
if [ ${#TOP_SERVERS[@]} -gt 2 ]; then
    echo "Third fastest: ${TOP_SERVERS[2]} (${DNS_SERVERS[${TOP_SERVERS[2]}]})"
fi