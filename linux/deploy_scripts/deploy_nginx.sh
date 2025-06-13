#!/bin/bash

# Author: Michal Koeckeis-Fresel
# License: MIT

# Deploy NGINX - Install NGINX from official repository

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

install_nginx() {
    log_step "Installing NGINX from official repository..."
    
    # Check if NGINX is already installed
    if command_exists nginx; then
        local nginx_version=$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        log_success "✓ NGINX $nginx_version already installed"
        configure_nginx_service
        return 0
    fi
    
    # Update package index first
    update_system
    
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

# Main execution
main() {
    log_step "Starting NGINX deployment..."
    
    # Check if running as root or with sudo
    if [ "$EUID" -ne 0 ]; then
        log_error "This script requires root privileges. Please run with sudo."
        exit 1
    fi
    
    # Detect operating system
    detect_os
    log_info "Detected OS: $ID $VERSION_ID ($OS_TYPE)"
    
    # Install NGINX
    install_nginx
    
    log_success "NGINX deployment completed successfully!"
    echo ""
    echo "🌐 NGINX installed and running"
    echo "📋 NGINX version: $(nginx -v 2>&1)"
    echo "🔧 Configuration file: /etc/nginx/nginx.conf"
    echo "📁 Document root: /usr/share/nginx/html"
    echo ""
    log_info "NGINX is now ready to serve web content."
    log_info "You can test it by visiting http://localhost or your server's IP address."
}

# Run main function
main "$@"