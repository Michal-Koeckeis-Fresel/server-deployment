#!/bin/bash

# Author: Michal Koeckeis-Fresel
# License: MIT

# Deploy BunkerWeb - Install Docker and download project files

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

install_nginx() {
    log_step "Installing NGINX from official repository..."
    
    # Check if NGINX is already installed
    if command_exists nginx; then
        local nginx_version=$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        log_success "✓ NGINX $nginx_version already installed"
        configure_nginx_service
        return 0
    fi
    
    # Install NGINX based on OS type
    case $OS_TYPE in
        debian)
            log_info "Installing NGINX dependencies..."
            apt-get install -y curl gnupg2 ca-certificates lsb-release debian-archive-keyring
            
            log_info "Adding NGINX GPG key..."
            curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
            
            log_info "Adding NGINX repository..."
            echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/debian $(lsb_release -cs) nginx" | tee /etc/apt/sources.list.d/nginx.list >/dev/null
            
            # Set repository priority
            echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | tee /etc/apt/preferences.d/99nginx >/dev/null
            
            log_info "Updating package list..."
            apt-get update -qq
            
            log_info "Installing NGINX..."
            apt-get install -y nginx
            ;;
        rhel)
            log_info "Installing NGINX dependencies..."
            $PACKAGE_MANAGER install -y curl ca-certificates
            
            log_info "Adding NGINX repository..."
            case $ID in
                centos|rhel)
                    cat > /etc/yum.repos.d/nginx.repo << 'EOF'
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
                    ;;
                fedora)
                    cat > /etc/yum.repos.d/nginx.repo << 'EOF'
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/fedora/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
                    ;;
                rocky|almalinux)
                    cat > /etc/yum.repos.d/nginx.repo << 'EOF'
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
                    ;;
            esac
            
            log_info "Installing NGINX..."
            $PACKAGE_MANAGER install -y nginx
            ;;
        suse)
            log_info "Installing NGINX dependencies..."
            zypper install -y curl ca-certificates
            
            log_info "Adding NGINX repository..."
            case $ID in
                opensuse-leap)
                    zypper addrepo -G -t yum -c 'http://nginx.org/packages/sles/15' nginx-stable
                    ;;
                opensuse-tumbleweed)
                    zypper addrepo -G -t yum -c 'http://nginx.org/packages/opensuse/tumbleweed' nginx-stable
                    ;;
                sles)
                    zypper addrepo -G -t yum -c "http://nginx.org/packages/sles/$VERSION_ID" nginx-stable
                    ;;
            esac
            
            log_info "Installing NGINX..."
            zypper install -y nginx
            ;;
    esac
    
    configure_nginx_service
    log_success "✓ NGINX installed and started"
}

# Configure NGINX service
configure_nginx_service() {
    log_info "Configuring NGINX service..."
    
    # Enable and start NGINX service
    systemctl enable nginx
    systemctl start nginx
    
    # Test NGINX installation
    if nginx -t >/dev/null 2>&1; then
        log_success "NGINX configuration is valid"
    else
        log_error "NGINX configuration test failed"
        return 1
    fi
    
    # Check if NGINX is running
    if systemctl is-active --quiet nginx; then
        log_success "NGINX is running correctly"
    else
        log_error "NGINX failed to start"
        return 1
    fi
}
# Main execution
main() {
    log_step "Starting BunkerWeb deployment..."
    
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
    
    # Install NGINX
    install_nginx
    
    # Create the BunkerWeb directory
    log_step "Creating BunkerWeb directory..."
    mkdir -p "/data/BunkerWeb"
    
    # Change to the target directory
    cd "/data/BunkerWeb"
    
    # Base URL for the repository
    BASE_URL="https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/waf/BunkerWeb"
    
    # Array of files to download
    FILES=(
        "script_autoconf_display.sh"
        "script_password_reset_display.sh"
        "template_autoconf_display.yml"
        "template_basic_display.yml"
        "template_ui_integrated_display.yml"
    )
    
    # Download each file
    log_step "Downloading BunkerWeb project files..."
    for file in "${FILES[@]}"; do
        log_info "Downloading $file..."
        if command_exists wget; then
            wget -q "$BASE_URL/$file" -O "$file"
        elif command_exists curl; then
            curl -s "$BASE_URL/$file" -o "$file"
        else
            log_error "Neither wget nor curl is available. Please install one of them."
            exit 1
        fi
        
        if [ $? -eq 0 ]; then
            log_success "✓ Successfully downloaded $file"
        else
            log_error "✗ Failed to download $file"
            exit 1
        fi
    done
    
    # Make shell scripts executable
    log_step "Setting executable permissions on shell scripts..."
    chmod +x script_autoconf_display.sh
    chmod +x script_password_reset_display.sh
    
    log_success "BunkerWeb deployment completed successfully!"
    echo ""
    echo "📁 Files downloaded to: /data/BunkerWeb"
    echo "🐳 Docker installed and ready"
    echo "🌐 NGINX installed and running"
    echo ""
    echo "Downloaded files:"
    ls -la /data/BunkerWeb/
    echo ""
    log_info "You can now proceed with BunkerWeb configuration and deployment."
}

# Run main function
main "$@"