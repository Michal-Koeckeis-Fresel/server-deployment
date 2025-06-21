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

# Check if server is behind NAT for IPv4 and IPv6

check_ipv4_private() {
    local ip="$1"
    
    if [[ "$ip" =~ ^10\. ]] || \
       [[ "$ip" =~ ^192\.168\. ]] || \
       [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || \
       [[ "$ip" =~ ^127\. ]] || \
       [[ "$ip" =~ ^169\.254\. ]]; then
        return 0
    fi
    return 1
}

check_ipv6_private() {
    local ip="$1"
    
    if [[ "$ip" =~ ^fe80: ]] || \
       [[ "$ip" =~ ^fc[0-9a-f][0-9a-f]: ]] || \
       [[ "$ip" =~ ^fd[0-9a-f][0-9a-f]: ]] || \
       [[ "$ip" =~ ^::1$ ]]; then
        return 0
    fi
    return 1
}

get_local_ipv4() {
    ip -4 route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1
}

get_local_ipv6() {
    ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1
}

get_public_ipv4() {
    curl -s --connect-timeout 5 ipv4.icanhazip.com 2>/dev/null || \
    curl -s --connect-timeout 5 ifconfig.me/ip 2>/dev/null || \
    echo "Unable to determine"
}

get_public_ipv6() {
    curl -s --connect-timeout 5 ipv6.icanhazip.com 2>/dev/null || \
    curl -s --connect-timeout 5 -6 ifconfig.me/ip 2>/dev/null || \
    echo "Unable to determine"
}

show_network_path() {
    echo "=== Network Path (first 3 hops to Google) ==="
    
    echo "IPv4 path to 8.8.8.8 (Google DNS):"
    if command -v traceroute >/dev/null 2>&1; then
        traceroute -m 3 8.8.8.8 2>/dev/null || echo "IPv4 traceroute failed"
    else
        echo "Traceroute not available"
    fi
    
    echo
    echo "IPv6 path to 2001:4860:4860::8888 (Google DNS):"
    if command -v traceroute6 >/dev/null 2>&1; then
        traceroute6 -m 3 2001:4860:4860::8888 2>/dev/null || echo "IPv6 traceroute failed"
    elif command -v traceroute >/dev/null 2>&1; then
        traceroute -6 -m 3 2001:4860:4860::8888 2>/dev/null || echo "IPv6 traceroute failed"
    else
        echo "IPv6 traceroute not available"
    fi
    echo
}

show_gateways() {
    echo "=== Default Gateways ==="
    
    echo "IPv4 Default Routes:"
    default_routes=$(ip -4 route show default 2>/dev/null)
    if [[ -n "$default_routes" ]]; then
        echo "$default_routes"
    else
        echo "No IPv4 default gateway found"
    fi
    
    echo
    echo "IPv6 Default Routes:"
    default_routes_v6=$(ip -6 route show default 2>/dev/null)
    if [[ -n "$default_routes_v6" ]]; then
        echo "$default_routes_v6"
    else
        echo "No IPv6 default gateway found"
    fi
    
    echo
    echo "=== All Gateway Routes ==="
    echo "IPv4 Routes:"
    ip -4 route show 2>/dev/null | head -10
    
    echo
    echo "IPv6 Routes (first 10):"
    ip -6 route show 2>/dev/null | head -10
    echo
}

check_nat_status() {
    echo "=== NAT Detection Report ==="
    echo
    
    local_ipv4=$(get_local_ipv4)
    if [[ -n "$local_ipv4" ]]; then
        echo "Source IPv4: $local_ipv4"
        
        public_ipv4=$(get_public_ipv4)
        if [[ "$public_ipv4" != "Unable to determine" ]]; then
            echo "Public IPv4: $public_ipv4"
        fi
        
        if check_ipv4_private "$local_ipv4"; then
            echo "IPv4 Status: Behind NAT (private source address)"
            if [[ "$public_ipv4" != "Unable to determine" && "$local_ipv4" != "$public_ipv4" ]]; then
                echo "IPv4 NAT: Confirmed (source != public)"
            fi
        else
            echo "IPv4 Status: Direct connection (public source address)"
            if [[ "$public_ipv4" != "Unable to determine" && "$local_ipv4" == "$public_ipv4" ]]; then
                echo "IPv4 NAT: Not detected (source == public)"
            elif [[ "$public_ipv4" != "Unable to determine" && "$local_ipv4" != "$public_ipv4" ]]; then
                echo "IPv4 Note: Source and public IPs differ (possible load balancer/proxy)"
            fi
        fi
    else
        echo "IPv4: Not available"
    fi
    
    echo
    
    local_ipv6=$(get_local_ipv6)
    if [[ -n "$local_ipv6" ]]; then
        echo "Source IPv6: $local_ipv6"
        
        public_ipv6=$(get_public_ipv6)
        if [[ "$public_ipv6" != "Unable to determine" ]]; then
            echo "Public IPv6: $public_ipv6"
        fi
        
        if check_ipv6_private "$local_ipv6"; then
            echo "IPv6 Status: Private/Local source address"
            if [[ "$public_ipv6" != "Unable to determine" && "$local_ipv6" != "$public_ipv6" ]]; then
                echo "IPv6 Translation: Detected (source != public)"
            fi
        else
            echo "IPv6 Status: Global unicast source address"
            if [[ "$public_ipv6" != "Unable to determine" && "$local_ipv6" == "$public_ipv6" ]]; then
                echo "IPv6 Translation: Not detected (source == public)"
            elif [[ "$public_ipv6" != "Unable to determine" && "$local_ipv6" != "$public_ipv6" ]]; then
                echo "IPv6 Note: Source and public IPs differ (possible load balancer/proxy)"
            fi
        fi
    else
        echo "IPv6: Not available"
    fi
    
    echo
    show_gateways
    
    show_network_path
    
    echo "=== All Network Interfaces ==="
    ip addr show | while IFS= read -r line; do
        if [[ "$line" =~ ^[0-9]+:[[:space:]]*([^:]+): ]]; then
            interface="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ inet[[:space:]]+([0-9.]+) ]]; then
            addr="${BASH_REMATCH[1]}"
            if [[ "$addr" != "127.0.0.1" ]]; then
                if check_ipv4_private "$addr"; then
                    echo "[$interface] IPv4: $addr (private)"
                else
                    echo "[$interface] IPv4: $addr (public)"
                fi
            fi
        elif [[ "$line" =~ inet6[[:space:]]+([a-f0-9:]+) ]]; then
            addr="${BASH_REMATCH[1]}"
            if [[ "$addr" != "::1" ]]; then
                if check_ipv6_private "$addr"; then
                    echo "[$interface] IPv6: $addr (private/local)"
                else
                    echo "[$interface] IPv6: $addr (global)"
                fi
            fi
        fi
    done
}

main() {
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        echo "Usage: $0 [--help]"
        echo "Check if server is behind NAT for IPv4 and IPv6"
        exit 0
    fi
    
    check_nat_status
}

main "$@"