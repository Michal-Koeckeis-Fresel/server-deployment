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

set -e

# Load debug configuration if available
if [[ -f "/root/BunkerWeb.conf" ]]; then
    source "/root/BunkerWeb.conf" 2>/dev/null || true
fi

# Enable debug mode if requested
if [[ "${DEBUG:-no}" == "yes" ]]; then
    set -x
    echo "[DEBUG] Debug mode enabled"
fi

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

# Download function with curl (primary) and wget (fallback)
download_file() {
    local url="$1"
    local output_file="$2"
    
    # Try curl first (preferred)
    if command_exists curl; then
        if curl -sSL --connect-timeout 10 --max-time 30 --retry 2 --fail "$url" -o "$output_file" 2>/dev/null; then
            return 0
        fi
    fi
    
    # Fallback to wget
    if command_exists wget; then
        if timeout 30 wget -q --timeout=10 --tries=2 "$url" -O "$output_file" 2>/dev/null; then
            return 0
        fi
    fi
    
    return 1
}

# Process a single file download
process_file() {
    local file="$1"
    local url="$2"
    local force_download="${3:-no}"
    
    echo -n "Processing $file... "
    
    # Skip if file already exists and is not empty (unless force download)
    if [[ "$force_download" != "yes" && -f "$file" && -s "$file" ]]; then
        echo "SKIPPED (exists)"
        return 2  # Return 2 for skipped
    fi
    
    # Download the file
    if download_file "$url" "$file"; then
        if [[ -f "$file" && -s "$file" ]]; then
            echo "SUCCESS"
            return 0  # Success
        else
            echo "FAILED (empty file)"
            rm -f "$file" 2>/dev/null || true
            return 1  # Failed
        fi
    else
        echo "FAILED (download error)"
        return 1  # Failed
    fi
}

# Main execution
main() {
    log_step "Starting BunkerWeb deployment..."
    
    # Create the BunkerWeb directory
    log_step "Creating BunkerWeb directory..."
    mkdir -p "/data/BunkerWeb"
    cd "/data/BunkerWeb"
    
    # Base URL for the repository
    local BASE_URL="https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/waf/BunkerWeb"
    
    # Check download tools
    if ! command_exists curl && ! command_exists wget; then
        log_error "Neither curl nor wget is available. Please install one of them."
        exit 1
    fi
    
    # Handle BunkerWeb.conf separately
    log_step "Checking for BunkerWeb.conf..."
    if [[ -f "/root/BunkerWeb.conf" ]]; then
        # Check if file exists but is empty or contains only whitespace/comments
        local non_empty_content=""
        non_empty_content=$(grep -v '^[[:space:]]*$' /root/BunkerWeb.conf 2>/dev/null | grep -v '^[[:space:]]*#' | head -1 || true)
        if [[ -z "$non_empty_content" ]]; then
            log_info "Found empty BunkerWeb.conf - downloading template"
            if download_file "$BASE_URL/BunkerWeb.conf" "/root/BunkerWeb.conf"; then
                log_success "✓ Downloaded BunkerWeb.conf template"
            else
                log_error "✗ Failed to download BunkerWeb.conf template"
                exit 1
            fi
        else
            log_info "Found existing BunkerWeb.conf - keeping current configuration"
        fi
    else
        log_info "Creating new BunkerWeb.conf..."
        if download_file "$BASE_URL/BunkerWeb.conf" "/root/BunkerWeb.conf"; then
            log_success "✓ Downloaded BunkerWeb.conf template"
        else
            log_error "✗ Failed to download BunkerWeb.conf"
            exit 1
        fi
    fi
    
    # Create symbolic link
    log_step "Creating symbolic link for BunkerWeb.conf..."
    if [[ -L "/data/BunkerWeb/BunkerWeb.conf" ]]; then
        rm "/data/BunkerWeb/BunkerWeb.conf"
    elif [[ -f "/data/BunkerWeb/BunkerWeb.conf" ]]; then
        mv "/data/BunkerWeb/BunkerWeb.conf" "/data/BunkerWeb/BunkerWeb.conf.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    ln -s "/root/BunkerWeb.conf" "/data/BunkerWeb/BunkerWeb.conf"
    log_success "✓ Created symbolic link: /data/BunkerWeb/BunkerWeb.conf → /root/BunkerWeb.conf"
    
    # Download files
    log_step "Downloading BunkerWeb project files..."
    
    # Define files to download from main repository
    declare -a FILES=(
        "script_autoconf_display.sh"
        "script_password_reset_display.sh"
        "template_autoconf_display.yml"
        "template_basic_display.yml"
        "template_ui_integrated_display.yml"
        "template_sample_app_display.yml"
        "uninstall_BunkerWeb.sh"
        "helper_password_manager.sh"
        "helper_network_detection.sh"
        "helper_template_processor.sh"
        "helper_greylist.sh"
        "helper_allowlist.sh"
        "helper_release_channel_manager.sh"
        "helper_directory_layout.sh"
        "helper_bunkerweb_config_checker.sh"
        "helper_fqdn_lookup.sh"
        "fluent-bit.conf"
        "fluent_bit_parsers.txt"
    )
    
    # Special files with different URLs
    declare -A SPECIAL_FILES=(
        ["helper_fqdn.sh"]="https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/deploy_scripts/helper-scripts/helper_fqdn.sh"
    )
    
    local downloaded_count=0
    local failed_count=0
    local skipped_count=0
    
    # Process regular files from main repository
    for file in "${FILES[@]}"; do
        local result=0
        process_file "$file" "$BASE_URL/$file" || result=$?
        
        case $result in
            0) ((downloaded_count++)) ;;
            1) ((failed_count++)) ;;
            2) ((skipped_count++)) ;;
        esac
    done
    
    # Process special files with custom URLs
    for file in "${!SPECIAL_FILES[@]}"; do
        local url="${SPECIAL_FILES[$file]}"
        local result=0
        
        echo -n "Processing $file (special URL)... "
        process_file "$file" "$url" || result=$?
        
        case $result in
            0) 
                echo "SUCCESS"
                ((downloaded_count++)) 
                ;;
            1) 
                echo "FAILED"
                ((failed_count++)) 
                ;;
            2) 
                echo "SKIPPED (exists)"
                ((skipped_count++)) 
                ;;
        esac
    done
    
    # Report statistics
    log_step "Download Summary"
    log_success "✓ Downloaded: $downloaded_count files"
    if [[ $skipped_count -gt 0 ]]; then
        log_info "ℹ Skipped: $skipped_count files (already exist)"
    fi
    if [[ $failed_count -gt 0 ]]; then
        log_warning "⚠ Failed: $failed_count files"
    fi
    
    # Make shell scripts executable
    log_step "Setting executable permissions..."
    find . -name "*.sh" -type f -exec chmod +x {} \; 2>/dev/null || true
    log_success "✓ Made scripts executable"
    
    # Verify critical files
    log_step "Verifying critical files..."
    declare -a critical_files=(
        "script_autoconf_display.sh"
        "helper_release_channel_manager.sh"
        "helper_fqdn.sh"
        "template_autoconf_display.yml"
        "BunkerWeb.conf"
    )
    
    local missing_critical=0
    for file in "${critical_files[@]}"; do
        if [[ -f "$file" ]] || [[ -L "$file" ]]; then
            echo "✓ $file"
        else
            echo "✗ Missing: $file"
            missing_critical=$((missing_critical + 1))
        fi
    done
    
    if [[ $missing_critical -gt 0 ]]; then
        log_error "✗ $missing_critical critical files missing"
        log_info "Try running the script again or check network connection."
        exit 1
    fi
    
    # Test release channel manager
    if [[ -f "helper_release_channel_manager.sh" && -x "helper_release_channel_manager.sh" ]]; then
        if source helper_release_channel_manager.sh >/dev/null 2>&1; then
            if validate_release_channel "latest" >/dev/null 2>&1; then
                log_success "✓ Release channel system ready"
            else
                log_warning "⚠ Release channel validation failed"
            fi
        else
            log_warning "⚠ Release channel manager failed to load"
        fi
    fi
    
    log_success "BunkerWeb deployment completed successfully!"
    echo ""
    echo "Files downloaded to: /data/BunkerWeb"
    echo "Configuration: /root/BunkerWeb.conf"
    echo ""
    echo "Downloaded files:"
    ls -la /data/BunkerWeb/ | grep -v "^total" | grep -v "^d"
    echo ""
    echo "Next steps:"
    echo "  1. Edit configuration: nano /root/BunkerWeb.conf"
    echo "  2. Run setup: sudo ./script_autoconf_display.sh --type autoconf"
    echo ""
    log_info "Setup ready. Edit /root/BunkerWeb.conf if needed before running setup."
}

# Run main function
main "$@"