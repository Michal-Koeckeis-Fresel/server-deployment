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

# Deploy BunkerWeb - Download project files

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
    log_step "Starting BunkerWeb deployment..."
    
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
    
    # Check if wget or curl is available
    if ! command_exists wget && ! command_exists curl; then
        log_error "Neither wget nor curl is available. Please install one of them."
        exit 1
    fi
    
    # Download each file
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
    
    # Make shell scripts executable
    log_step "Setting executable permissions on shell scripts..."
    chmod +x script_autoconf_display.sh
    chmod +x script_password_reset_display.sh
    
    log_success "BunkerWeb deployment completed successfully!"
    echo ""
    echo "📁 Files downloaded to: /data/BunkerWeb"
    echo ""
    echo "Downloaded files:"
    ls -la /data/BunkerWeb/
    echo ""
    log_info "You can now proceed with BunkerWeb configuration and deployment."
}

# Run main function
main "$@"