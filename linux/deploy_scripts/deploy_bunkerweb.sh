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

# Deploy BunkerWeb - Download project files with Fluent Bit support

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

# Main execution
main() {
    log_step "Starting BunkerWeb deployment with Fluent Bit support..."
    
    # Create the BunkerWeb directory
    log_step "Creating BunkerWeb directory structure..."
    mkdir -p "/data/BunkerWeb"
    mkdir -p "/data/BunkerWeb/fluent-config"
    mkdir -p "/data/BunkerWeb/logs"
    
    # Change to the target directory
    cd "/data/BunkerWeb"
    
    # Base URL for the repository
    BASE_URL="https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/waf/BunkerWeb"
    
    # Array of main files to download (excluding BunkerWeb.conf - handled separately)
    FILES=(
        "script_autoconf_display.sh"
        "script_password_reset_display.sh"
        "template_autoconf_display.yml"
        "template_basic_display.yml"
        "template_ui_integrated_display.yml"
        "template_sample_app_display.yml"
        "helper_password_manager.sh"
        "helper_network_detection.sh"
        "helper_template_processor.sh"
        "helper_release_channel_manager.sh"
        "helper_bunkerweb_config_checker.sh"
        "uninstall_BunkerWeb.sh"
    )
    
    # Array of Fluent Bit configuration files to download to fluent-config directory
    FLUENT_FILES=(
        "fluent-bit.conf"
        "fluent_bit_parsers.txt"
    )
    
    # Check if wget or curl is available
    if ! command_exists wget && ! command_exists curl; then
        log_error "Neither wget nor curl is available. Please install one of them."
        exit 1
    fi
    
    # Handle BunkerWeb.conf separately
    log_step "Checking for BunkerWeb.conf..."
    if [[ -f "/root/BunkerWeb.conf" ]]; then
        log_info "Found existing /root/BunkerWeb.conf - skipping download"
    else
        log_info "Creating /root/BunkerWeb.conf..."
        touch /root/BunkerWeb.conf
        
        if [[ -f "/root/BunkerWeb.conf" ]]; then
            log_success "✓ Created /root/BunkerWeb.conf"
            log_info "Downloading BunkerWeb.conf to /root/BunkerWeb.conf..."
            
            if command_exists wget; then
                wget -q "$BASE_URL/BunkerWeb.conf" -O "/root/BunkerWeb.conf"
            elif command_exists curl; then
                curl -s "$BASE_URL/BunkerWeb.conf" -o "/root/BunkerWeb.conf"
            fi
            
            if [ $? -eq 0 ]; then
                log_success "✓ Successfully downloaded BunkerWeb.conf to /root/"
            else
                log_error "✗ Failed to download BunkerWeb.conf"
                exit 1
            fi
        else
            log_error "✗ Failed to create /root/BunkerWeb.conf"
            exit 1
        fi
    fi
    
    # Create symbolic link from /data/BunkerWeb/BunkerWeb.conf to /root/BunkerWeb.conf
    log_step "Creating symbolic link for BunkerWeb.conf..."
    if [[ -L "/data/BunkerWeb/BunkerWeb.conf" ]]; then
        log_info "Symbolic link already exists - removing old link"
        rm "/data/BunkerWeb/BunkerWeb.conf"
    elif [[ -f "/data/BunkerWeb/BunkerWeb.conf" ]]; then
        log_warning "Regular file exists at /data/BunkerWeb/BunkerWeb.conf - backing up"
        mv "/data/BunkerWeb/BunkerWeb.conf" "/data/BunkerWeb/BunkerWeb.conf.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    ln -s "/root/BunkerWeb.conf" "/data/BunkerWeb/BunkerWeb.conf"
    
    if [[ -L "/data/BunkerWeb/BunkerWeb.conf" ]]; then
        log_success "✓ Created symbolic link: /data/BunkerWeb/BunkerWeb.conf → /root/BunkerWeb.conf"
    else
        log_error "✗ Failed to create symbolic link"
        exit 1
    fi
    
    # Download main project files to current directory
    log_step "Downloading BunkerWeb project files..."
    for file in "${FILES[@]}"; do
        log_info "Downloading $file..."
        if command_exists wget; then
            wget -q "$BASE_URL/$file" -O "$file"
        elif command_exists curl; then
            curl -s "$BASE_URL/$file" -o "$file"
        fi
        
        if [ $? -eq 0 ]; then
            log_success "✓ Successfully downloaded $file"
        else
            log_error "✗ Failed to download $file"
            exit 1
        fi
    done
    
    # Download Fluent Bit configuration files to fluent-config directory
    log_step "Downloading Fluent Bit configuration files..."
    for file in "${FLUENT_FILES[@]}"; do
        log_info "Downloading $file to fluent-config/..."
        
        # Determine the correct local filename
        if [[ "$file" == "fluent_bit_parsers.txt" ]]; then
            local_filename="parsers.conf"
        else
            local_filename="$file"
        fi
        
        if command_exists wget; then
            wget -q "$BASE_URL/$file" -O "fluent-config/$local_filename"
        elif command_exists curl; then
            curl -s "$BASE_URL/$file" -o "fluent-config/$local_filename"
        fi
        
        if [ $? -eq 0 ]; then
            log_success "✓ Successfully downloaded $file → fluent-config/$local_filename"
        else
            log_error "✗ Failed to download $file"
            exit 1
        fi
    done
    
    # Make shell scripts executable
    log_step "Setting executable permissions on shell scripts..."
    cd /data/BunkerWeb
    chmod +x script_autoconf_display.sh
    chmod +x script_password_reset_display.sh
    chmod +x helper_password_manager.sh
    chmod +x helper_network_detection.sh
    chmod +x helper_template_processor.sh
    chmod +x helper_release_channel_manager.sh
    chmod +x helper_bunkerweb_config_checker.sh
    chmod +x autoconf_script.sh
    chmod +x uninstall_BunkerWeb.sh
    
    # Set proper permissions for Fluent Bit and log directories
    log_step "Setting proper permissions for logging directories..."
    
    # Set ownership for logs directory to be writable by containers
    chown -R 101:101 logs 2>/dev/null || log_warning "Could not set ownership for logs directory (non-root user?)"
    chmod -R 755 logs
    chmod -R 755 fluent-config
    
    log_success "BunkerWeb deployment with Fluent Bit completed successfully!"
    echo ""
    echo "📁 Files downloaded to: /data/BunkerWeb"
    echo "📁 BunkerWeb.conf location: /root/BunkerWeb.conf"
    echo "🔗 Symbolic link: /data/BunkerWeb/BunkerWeb.conf → /root/BunkerWeb.conf"
    echo "📁 Fluent Bit config: /data/BunkerWeb/fluent-config/"
    echo "📁 Log directory: /data/BunkerWeb/logs/"
    echo ""
    
    echo "🔧 Downloaded main files:"
    ls -la /data/BunkerWeb/*.sh /data/BunkerWeb/*.yml /data/BunkerWeb/*.conf 2>/dev/null || true
    echo ""
    
    echo "🚀 Fluent Bit configuration files:"
    ls -la /data/BunkerWeb/fluent-config/
    echo ""
    
    echo "📋 Configuration file:"
    ls -la /root/BunkerWeb.conf
    echo ""
    
    echo "🔧 Next steps:"
    echo "1. Validate configuration: cd /data/BunkerWeb && ./helper_bunkerweb_config_checker.sh"
    echo "2. Edit configuration if needed: nano /root/BunkerWeb.conf"
    echo "3. Configure network settings (edit PRIVATE_NETWORKS_ALREADY_IN_USE if needed)"
    echo "4. Deploy BunkerWeb with Fluent Bit: cd /data/BunkerWeb && sudo ./script_autoconf_display.sh --type autoconf"
    echo ""
    
    echo "🌟 New Features in this deployment:"
    echo "• Fluent Bit integration for modern logging (replaces syslog-ng)"
    echo "• Network conflict detection and automatic subnet selection"
    echo "• Improved SSL certificate management"
    echo "• Enhanced security with proper private subnet usage"
    echo ""
    
    log_info "You can now proceed with BunkerWeb configuration and deployment."
    log_info "Fluent Bit will provide lightweight, high-performance log processing."
}

# Run main function
main "$@"