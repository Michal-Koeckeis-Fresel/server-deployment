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

# Deploy BunkerWeb - Download project files with Release Channel Support

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
    log_step "Starting BunkerWeb deployment with Release Channel Support..."
    
    # Create the BunkerWeb directory
    log_step "Creating BunkerWeb directory..."
    mkdir -p "/data/BunkerWeb"
    
    # Change to the target directory
    cd "/data/BunkerWeb"
    
    # Base URL for the repository
    BASE_URL="https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/waf/BunkerWeb"
    
    # Array of files to download (excluding BunkerWeb.conf - handled separately)
    FILES=(
        "script_autoconf_display.sh"
        "script_password_reset_display.sh"
        "template_autoconf_display.yml"
        "template_basic_display.yml"
        "template_ui_integrated_display.yml"
        "template_sample_app_display.yml"
        "autoconf_script.sh"
        "uninstall_BunkerWeb.sh"
        "syslog-ng.conf"
        "helper_password_manager.sh"
        "helper_network_detection.sh"
        "helper_template_processor.sh"
        "helper_fqdn.sh"
        "helper_greylist.sh"
        "helper_allowlist.sh"
        "helper_release_channel_manager.sh"
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
    
    # Download each file to current directory
    log_step "Downloading BunkerWeb project files..."
    local downloaded_count=0
    local failed_count=0
    
    for file in "${FILES[@]}"; do
        log_info "Downloading $file..."
        if command_exists wget; then
            wget -q "$BASE_URL/$file" -O "$file"
        elif command_exists curl; then
            curl -s "$BASE_URL/$file" -o "$file"
        fi
        
        if [ $? -eq 0 ]; then
            log_success "✓ Successfully downloaded $file"
            ((downloaded_count++))
        else
            log_error "✗ Failed to download $file"
            ((failed_count++))
        fi
    done
    
    # Report download statistics
    log_step "Download Summary"
    log_success "✓ Successfully downloaded: $downloaded_count files"
    if [[ $failed_count -gt 0 ]]; then
        log_warning "⚠ Failed downloads: $failed_count files"
    fi
    
    # Make shell scripts executable
    log_step "Setting executable permissions on shell scripts..."
    local script_files=(
        "script_autoconf_display.sh"
        "script_password_reset_display.sh"
        "autoconf_script.sh"
        "uninstall_BunkerWeb.sh"
        "helper_password_manager.sh"
        "helper_network_detection.sh"
        "helper_template_processor.sh"
        "helper_fqdn.sh"
        "helper_greylist.sh"
        "helper_allowlist.sh"
        "helper_release_channel_manager.sh"
    )
    
    for script in "${script_files[@]}"; do
        if [[ -f "$script" ]]; then
            chmod +x "$script"
            log_success "✓ Made executable: $script"
        else
            log_warning "⚠ Script not found: $script"
        fi
    done
    
    # Verify critical files exist
    log_step "Verifying critical files..."
    local critical_files=(
        "script_autoconf_display.sh"
        "helper_release_channel_manager.sh"
        "template_autoconf_display.yml"
        "BunkerWeb.conf"
    )
    
    local verification_passed=true
    for file in "${critical_files[@]}"; do
        if [[ -f "$file" ]] || [[ -L "$file" ]]; then
            log_success "✓ Verified: $file"
        else
            log_error "✗ Missing critical file: $file"
            verification_passed=false
        fi
    done
    
    if [[ "$verification_passed" != "true" ]]; then
        log_error "✗ Critical files missing - deployment may not work correctly"
        exit 1
    fi
    
    # Test release channel manager
    log_step "Testing Release Channel Manager..."
    if [[ -f "helper_release_channel_manager.sh" && -x "helper_release_channel_manager.sh" ]]; then
        if source helper_release_channel_manager.sh >/dev/null 2>&1; then
            if validate_release_channel "latest" >/dev/null 2>&1; then
                log_success "✓ Release Channel Manager is working correctly"
            else
                log_warning "⚠ Release Channel Manager validation failed"
            fi
        else
            log_warning "⚠ Failed to source Release Channel Manager"
        fi
    else
        log_error "✗ Release Channel Manager not found or not executable"
    fi
    
    log_success "BunkerWeb deployment completed successfully!"
    echo ""
    echo "📁 Files downloaded to: /data/BunkerWeb"
    echo "📁 BunkerWeb.conf location: /root/BunkerWeb.conf"
    echo "🔗 Symbolic link: /data/BunkerWeb/BunkerWeb.conf → /root/BunkerWeb.conf"
    echo ""
    echo "🚀 NEW: Release Channel Support"
    echo "   • Configure RELEASE_CHANNEL in BunkerWeb.conf"
    echo "   • Options: latest, RC, nightly, X.Y.Z (e.g., 1.6.1)"
    echo "   • Default: latest (stable production releases)"
    echo ""
    echo "Downloaded files:"
    ls -la /data/BunkerWeb/ | grep -E '\.(sh|yml|conf)$'
    echo ""
    echo "Configuration file:"
    ls -la /root/BunkerWeb.conf
    echo ""
    echo "🎯 Quick Start Examples:"
    echo "   • Setup with latest stable:     sudo ./script_autoconf_display.sh --type autoconf"
    echo "   • Setup with release candidate: sudo ./script_autoconf_display.sh --type autoconf --release RC"
    echo "   • Setup with specific version:  sudo ./script_autoconf_display.sh --type autoconf --release 1.6.1"
    echo "   • Setup with nightly builds:    sudo ./script_autoconf_display.sh --type autoconf --release nightly"
    echo ""
    echo "📖 Configuration:"
    echo "   • Edit release channel: nano /root/BunkerWeb.conf"
    echo "   • Set RELEASE_CHANNEL=\"latest|RC|nightly|X.Y.Z\""
    echo "   • Configure SSL contact: AUTO_CERT_CONTACT=\"your-email@domain.com\""
    echo ""
    log_info "You can now proceed with BunkerWeb configuration and deployment."
    
    # Show release channel information if available
    if [[ -f "helper_release_channel_manager.sh" ]]; then
        echo ""
        echo "🔄 Available Release Channels:"
        source helper_release_channel_manager.sh >/dev/null 2>&1
        if command -v list_available_channels >/dev/null 2>&1; then
            list_available_channels 2>/dev/null || echo "   • Run ./helper_release_channel_manager.sh for detailed information"
        else
            echo "   • latest   - Stable production releases"
            echo "   • RC       - Release candidates (beta testing)"
            echo "   • nightly  - Development builds (testing only)"
            echo "   • X.Y.Z    - Specific version pinning (e.g., 1.6.1)"
        fi
    fi
}

# Run main function
main "$@"