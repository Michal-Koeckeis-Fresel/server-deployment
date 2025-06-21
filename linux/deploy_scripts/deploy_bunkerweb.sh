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

# Deploy BunkerWeb - Download project files to /data/BunkerWeb

# Load debug configuration if available
if [ -f "/root/BunkerWeb.conf" ]; then
    source "/root/BunkerWeb.conf" 2>/dev/null || true
fi

# Enable debug mode if requested
if [ "${DEBUG:-no}" = "yes" ]; then
    set -x
    echo "[DEBUG] Debug mode enabled"
fi

# Output informational messages
log_info() {
    echo "[INFO] $1"
}

# Output success messages
log_success() {
    echo "[SUCCESS] $1"
}

# Output warning messages
log_warning() {
    echo "[WARNING] $1"
}

# Output error messages
log_error() {
    echo "[ERROR] $1"
}

# Output step messages
log_step() {
    echo "[STEP] $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Get remote file size using curl HEAD request
get_remote_file_size() {
    local url="$1"
    local size=""
    
    if command_exists curl; then
        size=$(curl -sI --connect-timeout 10 --max-time 30 "$url" | \
               grep -i content-length | awk '{print $2}' | tr -d '\r\n' || echo "")
    fi
    
    echo "$size"
}

# Get local file size
get_local_file_size() {
    local file="$1"
    if [ -f "$file" ]; then
        stat -c%s "$file" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# Check if file needs download by comparing sizes
needs_download() {
    local url="$1"
    local file="$2"
    
    # If file doesn't exist, download needed
    if [ ! -f "$file" ]; then
        return 0
    fi
    
    # If file is empty, download needed
    if [ ! -s "$file" ]; then
        return 0
    fi
    
    # Get remote and local file sizes
    local remote_size=$(get_remote_file_size "$url")
    local local_size=$(get_local_file_size "$file")
    
    # If we can't get remote size, assume download is needed
    if [ -z "$remote_size" ] || [ "$remote_size" = "0" ]; then
        return 0
    fi
    
    # Compare sizes
    if [ "$remote_size" != "$local_size" ]; then
        echo "[SIZE MISMATCH] Remote: $remote_size bytes, Local: $local_size bytes"
        return 0
    fi
    
    # File exists and sizes match
    return 1
}

# Install required packages if missing
install_required_packages() {
    log_step "Checking required packages..."
    
    local packages_to_install=""
    local missing_packages=""
    
    # Check for required tools
    for tool in curl wget jq sudo nano vi; do
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
        apt-get update -qq >/dev/null 2>&1 || \
            log_warning "Failed to update package list"
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

# Download files with curl (primary) and wget (fallback) with size verification
download_file() {
    local url="$1"
    local output_file="$2"
    
    # Try curl first (preferred)
    if command_exists curl; then
        if curl -sSL --connect-timeout 10 --max-time 30 --retry 2 --fail "$url" \
                -o "$output_file" 2>/dev/null; then
            return 0
        fi
    fi
    
    # Fallback to wget
    if command_exists wget; then
        if timeout 30 wget -q --timeout=10 --tries=2 "$url" \
                -O "$output_file" 2>/dev/null; then
            return 0
        fi
    fi
    
    return 1
}

# Download file with size comparison and retry logic
download_with_verification() {
    local url="$1"
    local file="$2"
    
    # Check if download is needed
    if ! needs_download "$url" "$file"; then
        echo "UP-TO-DATE (size match)"
        return 2
    fi
    
    # Remove existing file if it exists
    [ -f "$file" ] && rm -f "$file"
    
    # Download the file
    if download_file "$url" "$file"; then
        if [ -f "$file" ] && [ -s "$file" ]; then
            # Verify size after download
            local remote_size=$(get_remote_file_size "$url")
            local local_size=$(get_local_file_size "$file")
            
            if [ -n "$remote_size" ] && [ "$remote_size" != "0" ] && \
               [ "$remote_size" != "$local_size" ]; then
                echo "FAILED (size mismatch after download: expected $remote_size, got $local_size)"
                rm -f "$file" 2>/dev/null || true
                return 1
            fi
            
            echo "SUCCESS"
            return 0
        else
            echo "FAILED (empty file)"
            rm -f "$file" 2>/dev/null || true
            return 1
        fi
    else
        echo "FAILED (download error)"
        return 1
    fi
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
    BASE_URL="https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment"
    BASE_URL+="/refs/heads/main/linux/waf/BunkerWeb"
    
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
            non_empty_content=$(grep -v '^[[:space:]]*$' /root/BunkerWeb.conf 2>/dev/null | \
                              grep -v '^[[:space:]]*#' | head -1 || echo "")
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
    
    # Create symbolic link for BunkerWeb.conf
    log_step "Creating symbolic link for BunkerWeb.conf..."
    
    # Handle existing BunkerWeb.conf in /data/BunkerWeb/ - move to /root/ and create symlink
    if [ -f "/data/BunkerWeb/BunkerWeb.conf" ] && [ ! -L "/data/BunkerWeb/BunkerWeb.conf" ]; then
        log_info "Found existing BunkerWeb.conf in /data/BunkerWeb/ - moving to /root/ and creating symlink"
        
        # Backup existing file in /root/ if it exists
        if [ -f "/root/BunkerWeb.conf" ]; then
            mv "/root/BunkerWeb.conf" "/root/BunkerWeb.conf.backup.$(date +%Y%m%d_%H%M%S)"
            log_info "Backed up existing /root/BunkerWeb.conf"
        fi
        
        # Move file to /root/ and create symlink
        mv "/data/BunkerWeb/BunkerWeb.conf" "/root/BunkerWeb.conf"
        ln -s "/root/BunkerWeb.conf" "/data/BunkerWeb/BunkerWeb.conf"
        log_success "Moved BunkerWeb.conf to /root/ and created symlink"
        
    elif [ -L "/data/BunkerWeb/BunkerWeb.conf" ]; then
        log_info "BunkerWeb.conf symlink already exists"
        
    elif [ -f "/root/BunkerWeb.conf" ] && [ ! -f "/data/BunkerWeb/BunkerWeb.conf" ]; then
        log_info "Found BunkerWeb.conf in /root/ - creating symlink"
        ln -s "/root/BunkerWeb.conf" "/data/BunkerWeb/BunkerWeb.conf"
        log_success "Created symlink for existing /root/BunkerWeb.conf"
        
    else
        ln -s "/root/BunkerWeb.conf" "/data/BunkerWeb/BunkerWeb.conf"
        log_success "Created symbolic link: /data/BunkerWeb/BunkerWeb.conf -> /root/BunkerWeb.conf"
    fi
    
    # Handle credentials.txt if it exists - move to /root/ and create symlink
    log_step "Checking for existing credentials.txt..."
    if [ -f "/data/BunkerWeb/credentials.txt" ] && [ ! -L "/data/BunkerWeb/credentials.txt" ]; then
        log_info "Found existing credentials.txt - moving to /root/ and creating symlink"
        
        # Backup existing file in /root/ if it exists
        if [ -f "/root/BunkerWeb-credentials.txt" ]; then
            mv "/root/BunkerWeb-credentials.txt" \
               "/root/BunkerWeb-credentials.txt.backup.$(date +%Y%m%d_%H%M%S)"
            log_info "Backed up existing /root/BunkerWeb-credentials.txt"
        fi
        
        # Move file to /root/ and create symlink
        mv "/data/BunkerWeb/credentials.txt" "/root/BunkerWeb-credentials.txt"
        ln -s "/root/BunkerWeb-credentials.txt" "/data/BunkerWeb/credentials.txt"
        log_success "Moved credentials.txt to /root/ and created symlink"
    elif [ -f "/root/BunkerWeb-credentials.txt" ] && [ ! -L "/data/BunkerWeb/credentials.txt" ]; then
        log_info "Found BunkerWeb-credentials.txt in /root/ - creating symlink"
        ln -s "/root/BunkerWeb-credentials.txt" "/data/BunkerWeb/credentials.txt"
        log_success "Created symlink for existing /root/BunkerWeb-credentials.txt"
    elif [ -L "/data/BunkerWeb/credentials.txt" ]; then
        log_info "Credentials.txt symlink already exists"
    else
        log_info "Creating empty credentials.txt and linking to /root/BunkerWeb-credentials.txt"
        touch "/root/BunkerWeb-credentials.txt"
        ln -s "/root/BunkerWeb-credentials.txt" "/data/BunkerWeb/credentials.txt"
        log_success "Created empty credentials.txt and symlink"
    fi
    
    # Download files
    log_step "Downloading BunkerWeb project files..."
    
    # Initialize counters
    local downloaded_count=0
    local failed_count=0
    local skipped_count=0
    local uptodate_count=0
    
    # List of files to download from main repository
    echo "Downloading main repository files..."
    
    # Process files one by one to avoid array issues
    for file in script_autoconf_display.sh script_password_reset_display.sh script_template_selector.sh \
                template_autoconf_display.yml template_basic_display.yml template_ui_integrated_display.yml \
                template_sample_app_display.yml uninstall_BunkerWeb.sh helper_password_manager.sh \
                helper_network_detection.sh helper_template_processor.sh helper_greylist.sh \
                helper_allowlist.sh helper_release_channel_manager.sh helper_directory_layout.sh \
                helper_bunkerweb_config_checker.sh helper_fqdn_lookup.sh fluent-bit.conf \
                fluent_bit_parsers.txt; do
        echo -n "Processing $file... "
        
        # Use new download function with verification
        result=$(download_with_verification "$BASE_URL/$file" "$file")
        case $? in
            0) # Downloaded successfully
                downloaded_count=$((downloaded_count + 1))
                ;;
            1) # Download failed
                failed_count=$((failed_count + 1))
                ;;
            2) # File up to date
                uptodate_count=$((uptodate_count + 1))
                ;;
        esac
    done
    
    # Download special files with custom URLs
    echo "Downloading special files..."
    
    # Define helper scripts with custom URLs
    declare -A special_files=(
        ["helper_net_fqdn.sh"]="https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment"
        ["helper_net_nat.sh"]="https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment"
    )
    special_files["helper_net_fqdn.sh"]+="/refs/heads/main/linux/deploy_scripts/helper-scripts/helper_net_fqdn.sh"
    special_files["helper_net_nat.sh"]+="/refs/heads/main/linux/deploy_scripts/helper-scripts/helper_net_nat.sh"
    
    # Download each special file
    for file in "${!special_files[@]}"; do
        url="${special_files[$file]}"
        
        echo -n "Processing $file (special URL)... "
        
        # Use new download function with verification
        result=$(download_with_verification "$url" "$file")
        case $? in
            0) # Downloaded successfully
                downloaded_count=$((downloaded_count + 1))
                ;;
            1) # Download failed
                failed_count=$((failed_count + 1))
                ;;
            2) # File up to date
                uptodate_count=$((uptodate_count + 1))
                ;;
        esac
    done
    
    # Report statistics
    log_step "Download Summary"
    log_success "Downloaded: $downloaded_count files"
    if [ "$uptodate_count" -gt 0 ]; then
        log_info "Up-to-date: $uptodate_count files (size match)"
    fi
    if [ "$failed_count" -gt 0 ]; then
        log_warning "Failed: $failed_count files"
    fi
    
    # Set executable permissions for shell scripts
    log_step "Setting executable permissions..."
    local executable_count=0
    
    for script in script_autoconf_display.sh script_password_reset_display.sh script_template_selector.sh \
                  uninstall_BunkerWeb.sh helper_password_manager.sh helper_network_detection.sh \
                  helper_template_processor.sh helper_greylist.sh helper_allowlist.sh \
                  helper_release_channel_manager.sh helper_directory_layout.sh \
                  helper_bunkerweb_config_checker.sh helper_fqdn_lookup.sh helper_net_fqdn.sh \
                  helper_net_nat.sh; do
        if [ -f "$script" ]; then
            chmod +x "$script" && executable_count=$((executable_count + 1))
        fi
    done
    
    log_success "Made $executable_count scripts executable"
    
    # Verify critical files
    log_step "Verifying critical files..."
    local missing_critical=0
    
    for file in script_autoconf_display.sh script_template_selector.sh helper_release_channel_manager.sh \
                helper_net_fqdn.sh template_autoconf_display.yml BunkerWeb.conf; do
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
    echo "Credentials: /root/BunkerWeb-credentials.txt"
    echo ""
    echo -e "\033[31mWARNING: YOU MUST EDIT THE LINE CONTAINING\033[0m"
    echo -e "\033[31mAUTO_CERT_CONTACT\033[0m"
    echo -e "\033[31min /root/BunkerWeb.conf\033[0m"
    echo ""
    echo "SET IT TO YOUR VALID EMAIL-ADRESS - OTHERWISE THE SCRIPT WILL FAIL"
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