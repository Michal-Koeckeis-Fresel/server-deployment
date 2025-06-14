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

# SafeLine WAF System Preparation Script
# This script prepares a Linux system for SafeLine WAF installation
# Includes Docker installation and all prerequisites
# Compatible with: Ubuntu, Fedora, Debian, CentOS, Rocky Linux, AlmaLinux, openSUSE


set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global variables
OS_TYPE=""
OS_NAME=""
OS_VERSION=""
OS_CODENAME=""
PACKAGE_MANAGER=""
ARCH=""

# Configuration variables
SAFELINE_MGT_PORT="9443"
MIN_MEMORY_GB=1
MIN_DISK_GB=5

# Logging functions
log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS and set global variables
detect_os() {
    log_step "Detecting operating system..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=$NAME
        OS_VERSION=$VERSION_ID
        OS_CODENAME=${VERSION_CODENAME:-""}
        
        case $ID in
            ubuntu)
                OS_TYPE="debian"
                PACKAGE_MANAGER="apt"
                log_info "Ubuntu detected - optimized configuration applied"
                ;;
            debian)
                OS_TYPE="debian"
                PACKAGE_MANAGER="apt"
                ;;
            fedora)
                OS_TYPE="rhel"
                PACKAGE_MANAGER="dnf"
                log_info "Fedora detected - using modern DNF package manager"
                ;;
            centos|rhel|rocky|almalinux)
                OS_TYPE="rhel"
                PACKAGE_MANAGER="yum"
                # Check if dnf is available (CentOS 8+, RHEL 8+)
                if command_exists dnf; then
                    PACKAGE_MANAGER="dnf"
                fi
                ;;
            opensuse-leap|opensuse-tumbleweed|opensuse)
                OS_TYPE="suse"
                PACKAGE_MANAGER="zypper"
                log_info "openSUSE detected - using zypper package manager"
                ;;
            *)
                log_error "Unsupported operating system: $ID"
                log_info "This script supports: Ubuntu, Fedora, Debian, CentOS, RHEL, Rocky Linux, AlmaLinux, openSUSE"
                exit 1
                ;;
        esac
        
        log_success "Detected: $OS_NAME $OS_VERSION"
        log_info "Package manager: $PACKAGE_MANAGER"
    else
        log_error "Cannot determine operating system"
        exit 1
    fi
    
    # Set architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            if [ "$OS_TYPE" = "debian" ]; then
                ARCH_DOCKER="amd64"
            else
                ARCH_DOCKER="x86_64"
            fi
            ;;
        aarch64)
            if [ "$OS_TYPE" = "debian" ]; then
                ARCH_DOCKER="arm64"
            else
                ARCH_DOCKER="aarch64"
            fi
            ;;
        armv7l)
            if [ "$OS_TYPE" = "debian" ]; then
                ARCH_DOCKER="armhf"
            else
                log_error "ARM 32-bit not supported on $OS_TYPE systems"
                exit 1
            fi
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
}

# Function to display banner
show_banner() {
    echo -e "${GREEN}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                SafeLine WAF System Preparation              ║
║                     Multi-Platform Installer                ║
║  Ubuntu • Fedora • Debian • CentOS • Rocky • Alma • SUSE   ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo "This script will prepare your Linux system for SafeLine WAF installation."
    echo "It includes Docker installation and all necessary prerequisites."
    echo
}

# Enhanced system requirements check
check_system_requirements() {
    log_step "Performing comprehensive system requirements check..."
    
    local failed=0
    
    # Root check
    if [ "$EUID" -ne 0 ]; then
        log_error "Must run as root. Use: sudo $0"
        exit 1
    fi
    log_success "✓ Running as root"
    
    log_success "✓ $OS_NAME $OS_VERSION detected"
    log_success "✓ Architecture: $ARCH (supported)"
    
    # SSSE3 check for x86_64
    if [ "$ARCH" == "x86_64" ]; then
        if grep -q ssse3 /proc/cpuinfo; then
            log_success "✓ SSSE3 instruction set supported"
        else
            log_error "✗ SSSE3 instruction set not supported"
            failed=1
        fi
    fi
    
    # Memory check
    local mem_kb=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    local mem_gb=$((mem_kb / 1024 / 1024))
    if [ $mem_gb -ge $MIN_MEMORY_GB ]; then
        log_success "✓ Memory: ${mem_gb}GB available (minimum: ${MIN_MEMORY_GB}GB)"
    else
        log_error "✗ Insufficient memory: ${mem_gb}GB (minimum: ${MIN_MEMORY_GB}GB required)"
        failed=1
    fi
    
    # Disk space check for root and target directory
    local root_space_kb=$(df / | tail -1 | awk '{print $4}')
    local root_space_gb=$((root_space_kb / 1024 / 1024))
    if [ $root_space_gb -ge $MIN_DISK_GB ]; then
        log_success "✓ Root disk space: ${root_space_gb}GB available"
    else
        log_error "✗ Insufficient root disk space: ${root_space_gb}GB (minimum: ${MIN_DISK_GB}GB)"
        failed=1
    fi
    
    # Network connectivity check
    log_info "Checking network connectivity..."
    if ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        log_success "✓ Internet connectivity verified"
    else
        log_error "✗ No internet connectivity"
        failed=1
    fi
    
    # Python version check
    if command_exists python3; then
        local python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        local python_major=$(echo $python_version | cut -d. -f1)
        local python_minor=$(echo $python_version | cut -d. -f2)
        if [ $python_major -eq 3 ] && [ $python_minor -ge 5 ]; then
            log_success "✓ Python $python_version (compatible)"
        else
            log_error "✗ Python version too old: $python_version (need 3.5+)"
            failed=1
        fi
    else
        log_warning "⚠ Python3 not found - will install"
    fi
    
    if [ $failed -eq 1 ]; then
        log_error "System requirements check failed"
        exit 1
    fi
    
    log_success "All system requirements met!"
}

# Function to update system packages
update_system() {
    log_step "Updating system packages..."
    
    case $PACKAGE_MANAGER in
        apt)
            apt-get update -qq
            log_success "Package index updated"
            ;;
        yum)
            yum update -y -q
            log_success "System packages updated"
            ;;
        dnf)
            dnf update -y -q
            log_success "System packages updated"
            ;;
        zypper)
            zypper refresh -q
            log_success "Package repositories refreshed"
            ;;
    esac
}

# Install Docker using the official method
install_docker_official() {
    log_step "Installing Docker from official repository..."
    
    # Check if Docker is already installed
    if command_exists docker; then
        local docker_version=$(docker --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
        local docker_major=$(echo $docker_version | cut -d. -f1)
        if [ "$docker_major" -ge 20 ]; then
            log_success "✓ Docker $docker_version already installed"
            configure_docker_service
            return 0
        else
            log_warning "⚠ Docker $docker_version is too old (need 20+), upgrading..."
        fi
    fi
    
    # Remove old installations
    log_info "Removing old Docker installations..."
    case $OS_TYPE in
        debian)
            apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
            ;;
        rhel)
            OLD_PACKAGES="docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine"
            for package in $OLD_PACKAGES; do
                $PACKAGE_MANAGER remove -y $package 2>/dev/null || true
            done
            ;;
        suse)
            OLD_PACKAGES="docker docker-runc containerd"
            for package in $OLD_PACKAGES; do
                zypper remove -y $package 2>/dev/null || true
            done
            ;;
    esac
    
    # Update package index
    update_system
    
    # Install dependencies and Docker
    case $OS_TYPE in
        debian)
            # Install dependencies
            apt-get install -y \
                apt-transport-https \
                ca-certificates \
                curl \
                gnupg \
                lsb-release \
                python3 \
                python3-pip \
                net-tools
            
            # Add Docker's GPG key
            curl -fsSL https://download.docker.com/linux/$ID/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
            chmod a+r /usr/share/keyrings/docker-archive-keyring.gpg
            
            # Add Docker repository
            echo "deb [arch=$ARCH_DOCKER signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/$ID $VERSION_CODENAME stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
            
            # Update package index
            apt-get update -qq
            
            # Install Docker
            apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
        rhel)
            # Install dependencies
            case $PACKAGE_MANAGER in
                yum)
                    yum install -y yum-utils device-mapper-persistent-data lvm2 curl python3 python3-pip net-tools
                    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
                    ;;
                dnf)
                    dnf install -y dnf-plugins-core curl python3 python3-pip net-tools
                    dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
                    ;;
            esac
            
            # Install Docker
            $PACKAGE_MANAGER install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
        suse)
            # Install dependencies
            zypper install -y curl ca-certificates python3 python3-pip net-tools-deprecated
            
            # Add Docker's GPG key
            rpm --import https://download.docker.com/linux/sles/gpg
            
            # Add Docker repository
            zypper addrepo https://download.docker.com/linux/sles/docker-ce.repo
            zypper refresh
            
            # Install Docker
            zypper install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
    esac
    
    configure_docker_service
    log_success "✓ Docker installed and started"
}

# Function to configure Docker service
configure_docker_service() {
    log_step "Configuring Docker service..."
    
    # Enable and start Docker
    systemctl enable docker
    systemctl start docker
    
    # Check if Docker service is running
    if systemctl is-active --quiet docker; then
        log_success "✓ Docker service is running"
    else
        log_error "✗ Docker service failed to start"
        return 1
    fi
    
    # Configure firewall based on OS type
    case $OS_TYPE in
        debian)
            # Ubuntu/Debian typically use UFW, but may have iptables
            if command_exists ufw; then
                log_info "UFW firewall detected"
            fi
            ;;
        rhel)
            if systemctl is-active --quiet firewalld; then
                log_info "Configuring firewalld for Docker..."
                firewall-cmd --permanent --zone=trusted --add-interface=docker0 2>/dev/null || true
                firewall-cmd --permanent --zone=trusted --add-masquerade 2>/dev/null || true
                firewall-cmd --reload 2>/dev/null || true
                log_success "✓ Firewalld configured for Docker"
            fi
            
            # Check SELinux
            if command_exists getenforce && [ "$(getenforce)" = "Enforcing" ]; then
                log_warning "⚠ SELinux is enforcing - may require additional configuration"
                log_info "Consider running: setsebool -P container_manage_cgroup on"
            fi
            ;;
        suse)
            if systemctl is-active --quiet firewalld; then
                log_info "Configuring firewalld for Docker..."
                firewall-cmd --permanent --zone=trusted --add-interface=docker0 2>/dev/null || true
                firewall-cmd --permanent --zone=trusted --add-masquerade 2>/dev/null || true
                firewall-cmd --reload 2>/dev/null || true
                log_success "✓ Firewalld configured for Docker"
            elif systemctl is-active --quiet SuSEfirewall2; then
                log_warning "⚠ SuSEfirewall2 detected - manual configuration may be required"
                log_info "Consider switching to firewalld for better Docker integration"
            fi
            
            # Check AppArmor
            if command_exists aa-status && aa-status >/dev/null 2>&1; then
                log_info "AppArmor detected - Docker profiles should be automatically loaded"
            fi
            ;;
    esac
}

# Verify Docker installation
verify_docker_installation() {
    log_step "Verifying Docker installation..."
    
    # Check Docker version
    local docker_version=$(docker --version)
    log_info "Docker: $docker_version"
    
    # Check Docker Compose
    if docker compose version >/dev/null 2>&1; then
        local compose_version=$(docker compose version)
        log_info "Docker Compose: $compose_version"
        log_success "✓ Docker Compose plugin available"
    elif command_exists docker-compose; then
        local compose_version=$(docker-compose version)
        log_info "Docker Compose: $compose_version"
        log_success "✓ Docker Compose standalone available"
    else
        log_error "✗ Docker Compose not available"
        return 1
    fi
    
    # Test Docker
    if docker run --rm hello-world >/dev/null 2>&1; then
        log_success "✓ Docker test successful"
    else
        log_error "✗ Docker test failed"
        return 1
    fi
}

# Configure system for SafeLine
configure_system_for_safeline() {
    log_step "Configuring system for SafeLine..."
    
    # Check if management port is available
    if command_exists netstat; then
        if netstat -tuln | grep -q ":$SAFELINE_MGT_PORT "; then
            log_warning "⚠ Port $SAFELINE_MGT_PORT is already in use"
            log_info "SafeLine installer will prompt for an alternative port"
        else
            log_success "✓ Management port $SAFELINE_MGT_PORT is available"
        fi
    fi
    
    # Check and fix DNS configuration
    local resolv_conf="/etc/resolv.conf"
    if [ -f "$resolv_conf" ]; then
        if grep -q "nameserver.*%.*" "$resolv_conf"; then
            log_warning "⚠ IPv6 nameservers with scope found in $resolv_conf"
            log_info "SafeLine installer will offer to fix this automatically"
        fi
    fi
    
    # Configure firewall based on OS
    case $OS_TYPE in
        debian)
            if command_exists ufw; then
                log_info "UFW firewall detected"
                if ufw status | grep -q "Status: active"; then
                    log_warning "⚠ UFW is active - you may need to allow SafeLine ports"
                    echo "  Suggested commands after SafeLine installation:"
                    echo "  ufw allow $SAFELINE_MGT_PORT/tcp  # Management interface"
                    echo "  ufw allow 80/tcp                 # HTTP traffic"
                    echo "  ufw allow 443/tcp                # HTTPS traffic"
                fi
            fi
            ;;
        rhel)
            if systemctl is-active --quiet firewalld; then
                log_info "Firewalld detected and active"
                log_warning "⚠ You may need to configure firewall rules for SafeLine"
                echo "  Suggested commands after SafeLine installation:"
                echo "  firewall-cmd --permanent --add-port=$SAFELINE_MGT_PORT/tcp"
                echo "  firewall-cmd --permanent --add-service=http"
                echo "  firewall-cmd --permanent --add-service=https"
                echo "  firewall-cmd --reload"
            fi
            ;;
        suse)
            if systemctl is-active --quiet firewalld; then
                log_info "Firewalld detected and active"
                log_warning "⚠ You may need to configure firewall rules for SafeLine"
                echo "  Suggested commands after SafeLine installation:"
                echo "  firewall-cmd --permanent --add-port=$SAFELINE_MGT_PORT/tcp"
                echo "  firewall-cmd --permanent --add-service=http"
                echo "  firewall-cmd --permanent --add-service=https"
                echo "  firewall-cmd --reload"
            elif systemctl is-active --quiet SuSEfirewall2; then
                log_warning "⚠ SuSEfirewall2 detected - manual configuration required"
                echo "  Consider switching to firewalld:"
                echo "  systemctl disable SuSEfirewall2"
                echo "  systemctl enable firewalld"
                echo "  systemctl start firewalld"
            fi
            ;;
    esac
}

# Add user to docker group
configure_docker_user_access() {
    if [ -n "$SUDO_USER" ]; then
        log_step "Configuring Docker user access..."
        
        read -p "Add user '$SUDO_USER' to docker group? (Y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            usermod -aG docker "$SUDO_USER"
            log_success "✓ User '$SUDO_USER' added to docker group"
            log_warning "⚠ User needs to log out/in for group changes to take effect"
        fi
    fi
}

# Show SafeLine installation instructions
show_safeline_installation_instructions() {
    log_step "SafeLine WAF Installation Instructions"
    
    echo
    log_info "Your system is now ready for SafeLine WAF installation."
    echo
    echo -e "${YELLOW}To install SafeLine WAF, run the following command:${NC}"
    echo
    echo -e "   ${GREEN}bash -c \"\$(curl -fsSLk https://waf.chaitin.com/release/latest/manager.sh)\" -- --en${NC}"
    echo
    log_info "This will download and run the official SafeLine installer with English interface."
    echo
}

# Show final instructions
show_final_instructions() {
    echo
    log_success "🎉 System preparation completed successfully!"
    echo
    echo -e "${CYAN}System Information:${NC}"
    echo "• OS: $OS_NAME $OS_VERSION"
    echo "• Package Manager: $PACKAGE_MANAGER"
    echo "• Architecture: $ARCH"
    echo "• Docker: Installed and running"
    echo
    echo -e "${CYAN}Your system is now ready for SafeLine WAF installation.${NC}"
    echo
    echo -e "${YELLOW}To install SafeLine WAF:${NC}"
    echo -e "   ${GREEN}bash -c \"\$(curl -fsSLk https://waf.chaitin.com/release/latest/manager.sh)\" -- --en${NC}"
    echo
    echo -e "${YELLOW}Configuration details:${NC}"
    echo "• Default management port: $SAFELINE_MGT_PORT"
    echo "• Docker service: Active"
    echo
    echo -e "${YELLOW}OS-specific notes:${NC}"
    case $OS_TYPE in
        debian)
            echo "• Debian/Ubuntu: All prerequisites installed"
            if [ "$ID" = "ubuntu" ]; then
                echo "• Ubuntu: Snap Docker conflicts avoided by using official repository"
            fi
            if [ -n "$SUDO_USER" ]; then
                echo "• Log out and back in to use Docker without sudo"
            fi
            ;;
        rhel)
            echo "• RHEL-based: All prerequisites installed"
            if [ "$ID" = "fedora" ]; then
                echo "• Fedora: Using DNF for package management"
            fi
            if systemctl is-active --quiet firewalld; then
                echo "• Firewalld: Configure ports after SafeLine installation"
            fi
            if command_exists getenforce && [ "$(getenforce)" = "Enforcing" ]; then
                echo "• SELinux: May require additional container policies"
            fi
            if [ -n "$SUDO_USER" ]; then
                echo "• Log out and back in to use Docker without sudo"
            fi
            ;;
        suse)
            echo "• openSUSE: All prerequisites installed"
            if systemctl is-active --quiet firewalld; then
                echo "• Firewalld: Configure ports after SafeLine installation"
            elif systemctl is-active --quiet SuSEfirewall2; then
                echo "• SuSEfirewall2: Consider migrating to firewalld"
            fi
            if command_exists aa-status; then
                echo "• AppArmor: Docker profiles should be automatically loaded"
            fi
            if [ -n "$SUDO_USER" ]; then
                echo "• Log out and back in to use Docker without sudo"
            fi
            ;;
    esac
    echo
    echo -e "${YELLOW}Important notes:${NC}"
    echo "• SafeLine will create its own Docker network"
    echo "• Ensure ports 80, 443, and $SAFELINE_MGT_PORT are accessible"
    echo "• For remote management, configure firewall accordingly"
    echo "• SafeLine supports both HTTP and HTTPS traffic protection"
    echo
    echo -e "${CYAN}Platform-specific documentation:${NC}"
    case $OS_TYPE in
        debian)
            if [ "$ID" = "ubuntu" ]; then
                echo "• Ubuntu Docker: https://docs.docker.com/engine/install/ubuntu/"
            else
                echo "• Debian Docker: https://docs.docker.com/engine/install/debian/"
            fi
            ;;
        rhel)
            if [ "$ID" = "fedora" ]; then
                echo "• Fedora Docker: https://docs.docker.com/engine/install/fedora/"
            else
                echo "• CentOS Docker: https://docs.docker.com/engine/install/centos/"
            fi
            ;;
        suse)
            echo "• openSUSE Docker: https://en.opensuse.org/Docker"
            echo "• SUSE Enterprise: https://documentation.suse.com/sles/15-SP3/html/SLES-all/cha-docker.html"
            ;;
    esac
    echo
}

# Main function
main() {
    show_banner
    
    detect_os
    check_system_requirements
    update_system
    install_docker_official
    verify_docker_installation
    configure_system_for_safeline
    configure_docker_user_access
    show_safeline_installation_instructions
    show_final_instructions
}

# Always run main function when script is executed
# This script is designed to be run directly, not sourced
main "$@"