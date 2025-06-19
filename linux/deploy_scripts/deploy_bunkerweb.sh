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

# Load debug configuration if available
if [ -f "/root/BunkerWeb.conf" ]; then
    source "/root/BunkerWeb.conf" 2>/dev/null || true
fi

# Enable debug mode if requested
if [ "${DEBUG:-no}" = "yes" ]; then
    set -x
    echo "[DEBUG] Debug mode enabled"
fi

# Logging functions
log_info() {
    echo "[INFO] $1"
}

log_success() {
    echo "[SUCCESS] $1"
}

log_warning() {
    echo "[WARNING] $1"
}

log_error() {
    echo "[ERROR] $1"
}

log_step() {
    echo "[STEP] $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install required packages if missing
install_required_packages() {
    log_step "Checking required packages..."
    
    local packages_to_install=""
    local missing_packages=""
    
    # Check for required tools
    for tool in curl wget jq sudo; do
        if ! command_exists "$tool"; then
            missing_packages="$missing_packages $tool"
            packages_to_install="$packages_to_install $tool"
        else
            echo "✓ $tool is available"
        fi
    done
    
    # If no packages are missing, return early
    if [ -z "$packages_to_install" ]; then
        log_success "All required packages are already installed"
        return 0
    fi
    
    log_info "Missing packages:$missing_packages"
    log_step "Installing required packages..."
    
    # Detect package manager and install packages
    if command_exists apt-get; then
        log_info "Using apt package manager"
        apt-get update -qq >/dev/null 2>&1 || log_warning "Failed to update package list"
        if apt-get install -y $packages_to_install >/dev/null 2>&1; then
            log_success "Successfully installed packages via apt"
        else
            log_error "Failed to install packages via apt"
            return 1
        fi
    elif command_exists yum; then
        log_info "Using yum package manager"
        if yum install -y $packages_to_install >/dev/null 2>&1; then
            log_success "Successfully installed packages via yum"
        else
            log_error "Failed to install packages via yum"
            return 1
        fi
    elif command_exists dnf; then
        log_info "Using dnf package manager"
        if dnf install -y $packages_to_install >/dev/null 2>&1; then
            log_success "Successfully installed packages via dnf"
        else
            log_error "Failed to install packages via dnf"
            return 1
        fi
    elif command_exists zypper; then
        log_info "Using zypper package manager"
        if zypper install -y $packages_to_install >/dev/null 2>&1; then
            log_success "Successfully installed packages via zypper"
        else
            log_error "Failed to install packages via zypper"
            return 1
        fi
    elif command_exists pacman; then
        log_info "Using pacman package manager"
        if pacman -S --noconfirm $packages_to_install >/dev/null 2>&1; then
            log_success "Successfully installed packages via pacman"
        else
            log_error "Failed to install packages via pacman"
            return 1
        fi
    elif command_exists apk; then
        log_info "Using apk package manager"
        if apk add $packages_to_install >/dev/null 2>&1; then
            log_success "Successfully installed packages via apk"
        else
            log_error "Failed to install packages via apk"
            return 1
        fi
    else
        log_error "No supported package manager found"
        log_error "Please install manually:$missing_packages"
        return 1
    fi
    
    # Verify installation
    local verification_failed=0
    for tool in $packages_to_install; do
        if command_exists "$tool"; then
            echo "✓ $tool successfully installed"
        else
            echo "✗ $tool installation failed"
            verification_failed=1
        fi
    done
    
    if [ "$verification_failed" -eq 1 ]; then
        log_error "Some packages failed to install properly"
        return 1
    fi
    
    log_success "All required packages installed successfully"
    return 0
}

# Download function with curl (primary) and wget (fallback) - tools are auto-installed if missing
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

# Main execution
main() {
    log_step "Starting BunkerWeb deployment..."
    
    # Check if running as root (required for package installation)
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root for package installation"
        log_info "Please run: sudo $0"
        exit 1
    fi
    
    # Create the BunkerWeb directory
    log_step "Creating BunkerWeb directory..."
    mkdir -p "/data/BunkerWeb"
    
    # Install required packages if missing
    if ! install_required_packages; then
        log_error "Failed to install required packages"
        exit 1
    fi
    
    # Change to BunkerWeb directory
    cd "/data/BunkerWeb"
    log_info "Working in directory: /data/BunkerWeb"
    
    # Base URL for the repository
    BASE_URL="https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/waf/BunkerWeb"
    
    # Handle BunkerWeb.conf separately
    log_step "Checking for BunkerWeb.conf..."
    if [ -f "/root/BunkerWeb.conf" ]; then
        # Check file size - if 0 or 1 byte, replace it
        local file_size
        file_size=$(stat -c%s "/root/BunkerWeb.conf" 2>/dev/null || echo "0")
        
        if [ "$file_size" -le 1 ]; then
            log_info "Found empty/corrupted BunkerWeb.conf (${file_size} bytes) - downloading template"
            if download_file "$BASE_URL/BunkerWeb.conf" "/root/BunkerWeb.conf"; then
                log_success "Downloaded BunkerWeb.conf template"
            else
                log_error "Failed to download BunkerWeb.conf template"
                exit 1
            fi
        else
            # Check if file exists but contains only whitespace/comments
            local non_empty_content
            non_empty_content=$(grep -v '^[[:space:]]*$' /root/BunkerWeb.conf 2>/dev/null | grep -v '^[[:space:]]*#' | head -1 || echo "")
            if [ -z "$non_empty_content" ]; then
                log_info "Found empty BunkerWeb.conf - downloading template"
                if download_file "$BASE_URL/BunkerWeb.conf" "/root/BunkerWeb.conf"; then
                    log_success "Downloaded BunkerWeb.conf template"
                else
                    log_error "Failed to download BunkerWeb.conf template"
                    exit 1
                fi
            else
                log_info "Found existing BunkerWeb.conf - keeping current configuration"
            fi
        fi
    else
        log_info "Creating new BunkerWeb.conf..."
        if download_file "$BASE_URL/BunkerWeb.conf" "/root/BunkerWeb.conf"; then
            log_success "Downloaded BunkerWeb.conf template"
        else
            log_error "Failed to download BunkerWeb.conf"
            exit 1
        fi
    fi
    
    # Create symbolic link
    log_step "Creating symbolic link for BunkerWeb.conf..."
    if [ -L "/data/BunkerWeb/BunkerWeb.conf" ]; then
        rm "/data/BunkerWeb/BunkerWeb.conf"
    elif [ -f "/data/BunkerWeb/BunkerWeb.conf" ]; then
        mv "/data/BunkerWeb/BunkerWeb.conf" "/data/BunkerWeb/BunkerWeb.conf.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    ln -s "/root/BunkerWeb.conf" "/data/BunkerWeb/BunkerWeb.conf"
    log_success "Created symbolic link: /data/BunkerWeb/BunkerWeb.conf -> /root/BunkerWeb.conf"
    
    # Download files
    log_step "Downloading BunkerWeb project files..."
    
    # Initialize counters
    local downloaded_count=0
    local failed_count=0
    local skipped_count=0
    
    # List of files to download from main repository
    echo "Downloading main repository files..."
    
    # Process files one by one to avoid array issues
    for file in script_autoconf_display.sh script_password_reset_display.sh script_template_selector.sh template_autoconf_display.yml template_basic_display.yml template_ui_integrated_display.yml template_sample_app_display.yml uninstall_BunkerWeb.sh helper_password_manager.sh helper_network_detection.sh helper_template_processor.sh helper_greylist.sh helper_allowlist.sh helper_release_channel_manager.sh helper_directory_layout.sh helper_bunkerweb_config_checker.sh helper_fqdn_lookup.sh fluent-bit.conf fluent_bit_parsers.txt; do
        echo -n "Processing $file... "
        
        # Skip if file already exists and is not empty
        if [ -f "$file" ] && [ -s "$file" ]; then
            echo "SKIPPED (exists)"
            skipped_count=$((skipped_count + 1))
            continue
        fi
        
        # Download the file
        if download_file "$BASE_URL/$file" "$file"; then
            if [ -f "$file" ] && [ -s "$file" ]; then
                echo "SUCCESS"
                downloaded_count=$((downloaded_count + 1))
            else
                echo "FAILED (empty file)"
                rm -f "$file" 2>/dev/null || true
                failed_count=$((failed_count + 1))
            fi
        else
            echo "FAILED (download error)"
            failed_count=$((failed_count + 1))
        fi
    done
    
    # Download special files with custom URLs
    echo "Downloading special files..."
    
    # helper_fqdn.sh from different repository
    file="helper_fqdn.sh"
    url="https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/deploy_scripts/helper-scripts/helper_fqdn.sh"
    
    echo -n "Processing $file (special URL)... "
    
    # Skip if file already exists and is not empty
    if [ -f "$file" ] && [ -s "$file" ]; then
        echo "SKIPPED (exists)"
        skipped_count=$((skipped_count + 1))
    else
        # Download the file
        if download_file "$url" "$file"; then
            if [ -f "$file" ] && [ -s "$file" ]; then
                echo "SUCCESS"
                downloaded_count=$((downloaded_count + 1))
            else
                echo "FAILED (empty file)"
                rm -f "$file" 2>/dev/null || true
                failed_count=$((failed_count + 1))
            fi
        else
            echo "FAILED (download error)"
            failed_count=$((failed_count + 1))
        fi
    fi
    
    # Report statistics
    log_step "Download Summary"
    log_success "Downloaded: $downloaded_count files"
    if [ "$skipped_count" -gt 0 ]; then
        log_info "Skipped: $skipped_count files (already exist)"
    fi
    if [ "$failed_count" -gt 0 ]; then
        log_warning "Failed: $failed_count files"
    fi
    
    # Set executable permissions for shell scripts
    log_step "Setting executable permissions..."
    local executable_count=0
    
    for script in script_autoconf_display.sh script_password_reset_display.sh script_template_selector.sh uninstall_BunkerWeb.sh helper_password_manager.sh helper_network_detection.sh helper_template_processor.sh helper_greylist.sh helper_allowlist.sh helper_release_channel_manager.sh helper_directory_layout.sh helper_bunkerweb_config_checker.sh helper_fqdn_lookup.sh helper_fqdn.sh; do
        if [ -f "$script" ]; then
            chmod +x "$script" && executable_count=$((executable_count + 1))
        fi
    done
    
    log_success "Made $executable_count scripts executable"
    
    # Verify critical files
    log_step "Verifying critical files..."
    local missing_critical=0
    
    for file in script_autoconf_display.sh script_template_selector.sh helper_release_channel_manager.sh helper_fqdn.sh template_autoconf_display.yml BunkerWeb.conf; do
        if [ -f "$file" ] || [ -L "$file" ]; then
            echo "✓ $file"
        else
            echo "✗ Missing: $file"
            missing_critical=$((missing_critical + 1))
        fi
    done
    
    if [ "$missing_critical" -gt 0 ]; then
        log_error "$missing_critical critical files missing"
        log_info "Try running the script again or check network connection."
        exit 1
    fi
    
    # Test release channel manager
    if [ -f "helper_release_channel_manager.sh" ] && [ -x "helper_release_channel_manager.sh" ]; then
        if source helper_release_channel_manager.sh >/dev/null 2>&1; then
            if command -v validate_release_channel >/dev/null 2>&1; then
                if validate_release_channel "latest" >/dev/null 2>&1; then
                    log_success "Release channel system ready"
                else
                    log_warning "Release channel validation failed"
                fi
            else
                log_warning "Release channel function not found"
            fi
        else
            log_warning "Release channel manager failed to load"
        fi
    fi
    
    # Show what was downloaded
    log_step "Files in directory:"
    ls -la /data/BunkerWeb/ | grep -v "^total" | grep -v "^d" || true
    
    log_success "BunkerWeb deployment completed successfully!"
    echo ""
    echo "Files downloaded to: /data/BunkerWeb"
    echo "Configuration: /root/BunkerWeb.conf"
    echo ""
    echo "Next steps:"
    echo "  1. Edit configuration: nano /root/BunkerWeb.conf"
    echo "  2. Select template: sudo ./script_template_selector.sh"
    echo "  3. Run setup: sudo ./script_autoconf_display.sh --type autoconf"
    echo ""
    log_info "Setup ready. Edit /root/BunkerWeb.conf if needed before running setup."
}

# Run main function
main "$@"