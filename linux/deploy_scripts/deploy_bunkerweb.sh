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

# Robust download function with timeout and retry logic
download_file() {
    local url="$1"
    local output_file="$2"
    local description="${3:-$output_file}"
    
    log_info "Downloading $description..."
    
    if [[ "$DOWNLOAD_METHOD" == "curl" ]]; then
        # curl with robust options:
        # -s: silent mode
        # -S: show errors even in silent mode
        # --connect-timeout: connection timeout
        # --max-time: maximum time for entire operation
        # --retry: number of retries
        # --retry-delay: delay between retries
        # --retry-max-time: maximum time for retries
        # -L: follow redirects
        # --fail: fail silently on server errors
        if curl -sSL --connect-timeout 10 --max-time 60 --retry 3 --retry-delay 2 --retry-max-time 180 --fail "$url" -o "$output_file"; then
            return 0
        else
            local curl_exit_code=$?
            log_warning "curl failed with exit code $curl_exit_code for $description"
            return 1
        fi
    else
        # wget with timeout options as fallback
        if timeout 60 wget -q --timeout=10 --tries=3 --retry-connrefused --waitretry=2 "$url" -O "$output_file"; then
            return 0
        else
            local wget_exit_code=$?
            log_warning "wget failed with exit code $wget_exit_code for $description"
            return 1
        fi
    fi
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
    
    # Check if curl or wget is available (prefer curl)
    if ! command_exists curl && ! command_exists wget; then
        log_error "Neither curl nor wget is available. Please install one of them."
        log_info "Recommended: apt update && apt install curl"
        exit 1
    fi
    
    # Set download method preference (curl preferred due to better reliability)
    if command_exists curl; then
        DOWNLOAD_METHOD="curl"
        log_info "Using curl for downloads (preferred method)"
    else
        DOWNLOAD_METHOD="wget"
        log_info "Using wget for downloads (fallback method)"
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
            
            if download_file "$BASE_URL/BunkerWeb.conf" "/root/BunkerWeb.conf" "BunkerWeb.conf"; then
                log_success "✓ Successfully downloaded BunkerWeb.conf to /root/"
            else
                log_error "✗ Failed to download BunkerWeb.conf"
                log_info "Attempting alternative download method..."
                
                # Try alternative method if primary failed
                if [[ "$DOWNLOAD_METHOD" == "curl" ]] && command_exists wget; then
                    if timeout 60 wget -q --timeout=15 --tries=2 "$BASE_URL/BunkerWeb.conf" -O "/root/BunkerWeb.conf"; then
                        log_success "✓ Downloaded BunkerWeb.conf with wget (fallback)"
                    else
                        log_error "✗ All download methods failed for BunkerWeb.conf"
                        exit 1
                    fi
                elif [[ "$DOWNLOAD_METHOD" == "wget" ]] && command_exists curl; then
                    if curl -sSL --connect-timeout 15 --max-time 60 --retry 2 --fail "$BASE_URL/BunkerWeb.conf" -o "/root/BunkerWeb.conf"; then
                        log_success "✓ Downloaded BunkerWeb.conf with curl (fallback)"
                    else
                        log_error "✗ All download methods failed for BunkerWeb.conf"
                        exit 1
                    fi
                else
                    exit 1
                fi
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
    
    # Download each file to current directory with robust error handling
    log_step "Downloading BunkerWeb project files with $DOWNLOAD_METHOD..."
    local downloaded_count=0
    local failed_count=0
    local skipped_count=0
    declare -a failed_files=()
    
    for file in "${FILES[@]}"; do
        # Skip if file already exists and is not empty
        if [[ -f "$file" && -s "$file" ]]; then
            log_info "Skipping $file (already exists)"
            ((skipped_count++))
            continue
        fi
        
        if download_file "$BASE_URL/$file" "$file" "$file"; then
            # Verify file was downloaded and is not empty
            if [[ -f "$file" && -s "$file" ]]; then
                log_success "✓ Successfully downloaded $file"
                ((downloaded_count++))
            else
                log_error "✗ Download succeeded but file is empty: $file"
                failed_files+=("$file")
                ((failed_count++))
                rm -f "$file"  # Remove empty file
            fi
        else
            log_error "✗ Failed to download $file"
            failed_files+=("$file")
            ((failed_count++))
            
            # Try alternative download method for failed files
            log_info "Attempting alternative download method for $file..."
            if [[ "$DOWNLOAD_METHOD" == "curl" ]] && command_exists wget; then
                if timeout 60 wget -q --timeout=15 --tries=2 "$BASE_URL/$file" -O "$file"; then
                    if [[ -f "$file" && -s "$file" ]]; then
                        log_success "✓ Downloaded $file with wget (fallback)"
                        ((downloaded_count++))
                        ((failed_count--))
                        # Remove from failed_files array
                        failed_files=("${failed_files[@]/$file}")
                    fi
                fi
            elif [[ "$DOWNLOAD_METHOD" == "wget" ]] && command_exists curl; then
                if curl -sSL --connect-timeout 15 --max-time 60 --retry 2 --fail "$BASE_URL/$file" -o "$file"; then
                    if [[ -f "$file" && -s "$file" ]]; then
                        log_success "✓ Downloaded $file with curl (fallback)"
                        ((downloaded_count++))
                        ((failed_count--))
                        # Remove from failed_files array
                        failed_files=("${failed_files[@]/$file}")
                    fi
                fi
            fi
        fi
    done
    
    # Report download statistics
    log_step "Download Summary"
    log_success "✓ Successfully downloaded: $downloaded_count files"
    if [[ $skipped_count -gt 0 ]]; then
        log_info "ℹ Skipped (already exist): $skipped_count files"
    fi
    if [[ $failed_count -gt 0 ]]; then
        log_warning "⚠ Failed downloads: $failed_count files"
        if [[ ${#failed_files[@]} -gt 0 ]]; then
            log_warning "Failed files: ${failed_files[*]}"
        fi
        
        # Check if critical files failed
        local critical_failed=false
        for failed_file in "${failed_files[@]}"; do
            if [[ "$failed_file" == "script_autoconf_display.sh" ]] || [[ "$failed_file" == "helper_release_channel_manager.sh" ]] || [[ "$failed_file" == "template_autoconf_display.yml" ]]; then
                critical_failed=true
                break
            fi
        done
        
        if [[ "$critical_failed" == "true" ]]; then
            log_error "✗ Critical files failed to download - setup may not work properly"
            log_info "You can try running this script again or download manually"
        fi
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
    
    log_success "BunkerWeb deployment completed!"
    
    # Show manual retry instructions if some downloads failed
    if [[ $failed_count -gt 0 ]] && [[ ${#failed_files[@]} -gt 0 ]]; then
        echo ""
        log_warning "Some files failed to download. You can retry manually:"
        echo ""
        echo "cd /data/BunkerWeb"
        echo "BASE_URL=\"$BASE_URL\""
        echo ""
        for failed_file in "${failed_files[@]}"; do
            if [[ -n "$failed_file" ]]; then  # Skip empty entries
                echo "# Retry $failed_file:"
                if command_exists curl; then
                    echo "curl -sSL --connect-timeout 10 --max-time 60 --retry 3 --fail \"\$BASE_URL/$failed_file\" -o \"$failed_file\""
                else
                    echo "wget -q --timeout=10 --tries=3 \"\$BASE_URL/$failed_file\" -O \"$failed_file\""
                fi
                echo ""
            fi
        done
        echo "# Then make scripts executable:"
        echo "chmod +x *.sh"
        echo ""
    fi
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