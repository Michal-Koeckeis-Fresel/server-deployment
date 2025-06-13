#!/bin/bash

# Author: Michal Koeckeis-Fresel
# License: MIT

# Deploy Docker - Install Docker from official repository

set -e  # Exit on any error

# Logging functions
log_info() {
    echo -e "\033[34m[INFO]\033[0m $1"
}

log_success() {
    echo -e "\033[32m[SUCCESS]\033[0m $1"
}

log_warning() {
    echo -e "\033[33m[WARNING]\033[0m $1"
}

log_error() {
    echo -e "\033[31m[ERROR]\033[0m $1"
}

log_step() {
    echo -e "\033[36m[STEP]\033[0m $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect OS and package manager
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_TYPE=""
        case $ID in
            ubuntu|debian|linuxmint|pop)
                OS_TYPE="debian"
                PACKAGE_MANAGER="apt-get"
                ;;
            centos|rhel|fedora|rocky|almalinux)
                OS_TYPE="rhel"
                if command_exists dnf; then
                    PACKAGE_MANAGER="dnf"
                else
                    PACKAGE_MANAGER="yum"
                fi
                ;;
            opensuse*|sles)
                OS_TYPE="suse"
                PACKAGE_MANAGER="zypper"
                ;;
            *)
                log_error "Unsupported operating system: $ID"
                exit 1
                ;;
        esac
        
        # Set architecture for Docker
        case $(uname -m) in
            x86_64)
                ARCH_DOCKER="amd64"
                ;;
            aarch64)
                ARCH_DOCKER="arm64"
                ;;
            *)
                log_error "Unsupported architecture: $(uname -m)"
                exit 1
                ;;
        esac
    else
        log_error "Cannot detect operating system"
        exit 1
    fi
}

# Update system packages
update_system() {
    log_info "Updating system packages..."
    case $OS_TYPE in
        debian)
            apt-get update -qq
            ;;
        rhel)
            $PACKAGE_MANAGER update -y -q
            ;;
        suse)
            zypper refresh
            ;;
    esac
}

# Configure Docker service
configure_docker_service() {
    log_info "Configuring Docker service..."
    
    # Enable and start Docker service
    systemctl enable docker
    systemctl start docker
    
    # Add user to docker group if not root
    if [ "$EUID" -ne 0 ] && [ -n "$SUDO_USER" ]; then
        usermod -aG docker $SUDO_USER
        log_info "Added $SUDO_USER to docker group"
        log_warning "Please log out and back in for group changes to take effect"
    elif [ "$EUID" -ne 0 ]; then
        usermod -aG docker $USER
        log_info "Added $USER to docker group"
        log_warning "Please log out and back in for group changes to take effect"
    fi
    
    # Test Docker installation
    if docker --version >/dev/null 2>&1; then
        log_success "Docker is working correctly"
    else
        log_error "Docker installation failed"
        return 1
    fi
}

install_docker() {
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

# Main execution
main() {
    log_step "Starting Docker deployment..."
    
    # Check if running as root or with sudo
    if [ "$EUID" -ne 0 ]; then
        log_error "This script requires root privileges. Please run with sudo."
        exit 1
    fi
    
    # Detect operating system
    detect_os
    log_info "Detected OS: $ID $VERSION_ID ($OS_TYPE)"
    
    # Install Docker
    install_docker
    
    log_success "Docker deployment completed successfully!"
    echo ""
    echo "🐳 Docker installed and ready"
    echo "📋 Docker version: $(docker --version)"
    echo ""
    log_info "Docker is now ready for use."
    if [ -n "$SUDO_USER" ]; then
        log_info "Remember to log out and back in for docker group permissions to take effect."
    fi
}

# Run main function
main "$@"