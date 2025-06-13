#!/bin/bash

# Author: Michal Koeckeis-Fresel
# License: MIT

set -e

echo "Starting Unbound DNS resolver deployment..."

# Install DNS utilities for testing
echo "Installing DNS utilities..."
apt update
apt install -y dnsutils

# Test if DNS lookups are working
echo "Testing DNS resolution before installation..."
if nslookup google.com > /dev/null 2>&1; then
    echo "✓ DNS resolution is working"
else
    echo "✗ DNS resolution failed - cannot proceed"
    exit 1
fi

# Create backup of original resolv.conf
echo "Creating backup of original resolv.conf..."
RESOLV_BACKUP="/etc/resolv.conf.backup.$(date +%Y%m%d_%H%M%S)"
cp -f /etc/resolv.conf "$RESOLV_BACKUP"

# Prepare unbound directory and download root hints
echo "Preparing unbound directory and downloading root hints..."
mkdir -p /var/lib/unbound
curl -o /var/lib/unbound/root.key https://www.internic.net/domain/named.root
chown unbound:unbound /var/lib/unbound/root.key 2>/dev/null || chown root:root /var/lib/unbound/root.key
chmod 644 /var/lib/unbound/root.key

# Install unbound package
echo "Installing unbound package..."
apt update
apt install -y unbound unbound-anchor

# Check if resolv.conf only contains localhost nameservers and fix temporarily
echo "Checking resolv.conf for localhost-only nameservers..."
NON_LOCALHOST_DNS=$(grep "^nameserver" /etc/resolv.conf | grep -v "^nameserver 127\.0\.0\." | wc -l)
LOCALHOST_DNS=$(grep "^nameserver 127\.0\.0\." /etc/resolv.conf | wc -l)

if [ "$LOCALHOST_DNS" -gt 0 ] && [ "$NON_LOCALHOST_DNS" -eq 0 ]; then
    echo "Found localhost-only nameservers, setting temporary external DNS..."
    cat > /etc/resolv.conf << EOF
nameserver 9.9.9.9
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
    echo "✓ Temporary external DNS configured"
fi

# Create backup of original unbound configuration
echo "Creating backup of original unbound configuration..."
cp -f /etc/unbound/unbound.conf /etc/unbound/unbound.conf.backup.$(date +%Y%m%d_%H%M%S)

# Download optimized unbound configuration
echo "Downloading optimized unbound configuration..."
curl -o /etc/unbound/unbound.conf https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/main/linux/unbound/unbound_optimized_config.conf

# Setup unbound control
echo "Setting up unbound control..."
unbound-control-setup

# Enable and start unbound service
echo "Enabling and starting unbound service..."
systemctl enable unbound
systemctl start unbound

# Configure system to use local unbound resolver only if config is valid
echo "Validating unbound configuration..."
if unbound-checkconf; then
    echo "Unbound configuration valid - updating resolv.conf to use local resolver"
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    echo "✓ System configured to use local unbound resolver"
else
    echo "✗ Unbound configuration invalid - restoring original resolv.conf"
    cp -f "$RESOLV_BACKUP" /etc/resolv.conf
    echo "✓ Original resolv.conf restored"
    exit 1
fi

# Download and run DNS benchmark script
echo "Downloading and running DNS benchmark script..."
curl -o /tmp/dns_benchmark_script.sh https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/main/linux/unbound/dns_benchmark_script.sh
chmod +x /tmp/dns_benchmark_script.sh
/tmp/dns_benchmark_script.sh

echo "✓ Unbound DNS resolver deployment completed successfully!"