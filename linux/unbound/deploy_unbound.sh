#!/bin/bash

# Author: Michal Koeckeis-Fresel
# License: MIT

set -e

echo "Starting Unbound DNS resolver deployment..."

# Install unbound package
echo "Installing unbound package..."
apt update

mkdir -p /var/lib/unbound
#unbound-anchor -a /var/lib/unbound/root.key
curl -o /var/lib/unbound/root.key https://www.internic.net/domain/named.root

# Create backup of original unbound configuration
echo "Creating backup of original unbound configuration..."
cp /etc/unbound/unbound.conf /etc/unbound/unbound.conf.backup.$(date +%Y%m%d_%H%M%S)

# Download optimized unbound configuration
echo "Downloading optimized unbound configuration..."
curl -o /tmp/unbound.conf https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/main/linux/unbound/unbound_optimized_config.conf



apt install -y unbound unbound-anchor

cp /tmp/unbound.conf /etc/unbound/unbound.conf
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
    echo "✗ Unbound configuration invalid - keeping original resolv.conf"
    exit 1
fi

# Download and run DNS benchmark script
echo "Downloading and running DNS benchmark script..."
curl -o /tmp/dns_benchmark_script.sh https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/main/linux/unbound/dns_benchmark_script.sh
chmod +x /tmp/dns_benchmark_script.sh
/tmp/dns_benchmark_script.sh

echo "✓ Unbound DNS resolver deployment completed successfully!"