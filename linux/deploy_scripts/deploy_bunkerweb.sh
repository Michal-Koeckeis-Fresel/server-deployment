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
set -x
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

# Function to download a file with error handling
download_file() {
    local url="$1"
    local output_file="$2"
    local description="$3"
    
    log_info "Downloading $description..."
    
    local success=false
    
    if command_exists wget; then
        if wget -q "$url" -O "$output_file"; then
            success=true
        fi
    elif command_exists curl; then
        if curl -s "$url" -o "$output_file"; then
            success=true
        fi
    fi
    
    if [[ "$success" == "true" ]]; then
        log_success "✓ Successfully downloaded $description"
        return 0
    else
        log_error "✗ Failed to download $description"
        return 1
    fi
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
            
            if ! download_file "$BASE_URL/BunkerWeb.conf" "/root/BunkerWeb.conf" "BunkerWeb.conf to /root/"; then
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
    
    # Create symbolic link from /data/BunkerWeb/credentials.txt to /root/BunkerWeb-credentials.txt
    log_step "Creating symbolic link for credentials.txt..."
    if [[ -L "/data/BunkerWeb/credentials.txt" ]]; then
        log_info "Credentials symbolic link already exists - removing old link"
        rm "/data/BunkerWeb/credentials.txt"
    elif [[ -f "/data/BunkerWeb/credentials.txt" ]]; then
        log_warning "Regular credentials file exists at /data/BunkerWeb/credentials.txt - backing up"
        mv "/data/BunkerWeb/credentials.txt" "/data/BunkerWeb/credentials.txt.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Create the target file if it doesn't exist (will be populated by setup script)
    if [[ ! -f "/root/BunkerWeb-credentials.txt" ]]; then
        touch "/root/BunkerWeb-credentials.txt"
        chmod 600 "/root/BunkerWeb-credentials.txt"
        log_success "✓ Created /root/BunkerWeb-credentials.txt"
    fi
    
    ln -s "/root/BunkerWeb-credentials.txt" "/data/BunkerWeb/credentials.txt"
    
    if [[ -L "/data/BunkerWeb/credentials.txt" ]]; then
        log_success "✓ Created symbolic link: /data/BunkerWeb/credentials.txt → /root/BunkerWeb-credentials.txt"
    else
        log_error "✗ Failed to create credentials symbolic link"
        exit 1
    fi
    
    # Array of all files to download
    log_step "Downloading BunkerWeb project files..."
    
    # Main setup scripts
    declare -A MAIN_SCRIPTS=(
        ["script_autoconf_display.sh"]="Main setup script (autoconf display)"
        ["script_password_reset_display.sh"]="Password reset utility"
        ["uninstall_BunkerWeb.sh"]="Uninstall script"
    )
    
    # Helper scripts (modular components)
    declare -A HELPER_SCRIPTS=(
        ["helper_network_detection.sh"]="Network conflict detection helper"
        ["helper_password_mananger.sh"]="Password management helper"
        ["helper_template_processor.sh"]="Template processing helper"
        ["helper_fqdn_lookup.sh"]="FQDN detection helper"
        ["helper_directory_layout.sh"]="Directory layout helper"
    )
    
    # Docker Compose templates
    declare -A TEMPLATES=(
        ["template_autoconf_display.yml"]="Autoconf deployment template"
        ["template_basic_display.yml"]="Basic deployment template"
        ["template_ui_integrated_display.yml"]="UI integrated deployment template"
        ["template_sample_app_display.yml"]="Sample application template"
    )
    
    # Configuration files
    declare -A CONFIG_FILES=(
        ["syslog-ng.conf"]="Syslog-ng configuration"
    )
    
    # Download main scripts
    log_step "Downloading main scripts..."
    local failed_downloads=0
    
    for file in "${!MAIN_SCRIPTS[@]}"; do
        if ! download_file "$BASE_URL/$file" "$file" "${MAIN_SCRIPTS[$file]}"; then
            ((failed_downloads++))
        fi
    done
    
    # Download helper scripts
    log_step "Downloading helper scripts..."
    
    for file in "${!HELPER_SCRIPTS[@]}"; do
        if ! download_file "$BASE_URL/$file" "$file" "${HELPER_SCRIPTS[$file]}"; then
            ((failed_downloads++))
        fi
    done
    
    # Download templates
    log_step "Downloading Docker Compose templates..."
    
    for file in "${!TEMPLATES[@]}"; do
        if ! download_file "$BASE_URL/$file" "$file" "${TEMPLATES[$file]}"; then
            ((failed_downloads++))
        fi
    done
    
    # Download configuration files
    log_step "Downloading configuration files..."
    
    for file in "${!CONFIG_FILES[@]}"; do
        if ! download_file "$BASE_URL/$file" "$file" "${CONFIG_FILES[$file]}"; then
            ((failed_downloads++))
        fi
    done
    
    # Check for download failures
    if [[ $failed_downloads -gt 0 ]]; then
        log_error "✗ $failed_downloads files failed to download"
        log_warning "Some components may not work properly"
        echo ""
        log_info "You can retry downloading individual files manually from:"
        log_info "$BASE_URL"
    fi
    
    # Make shell scripts executable
    log_step "Setting executable permissions on shell scripts..."
    
    # Set permissions for main scripts
    for file in "${!MAIN_SCRIPTS[@]}"; do
        if [[ -f "$file" ]]; then
            chmod +x "$file"
            log_success "✓ Made executable: $file"
        fi
    done
    
    # Set permissions for helper scripts
    for file in "${!HELPER_SCRIPTS[@]}"; do
        if [[ -f "$file" ]]; then
            chmod +x "$file"
            log_success "✓ Made executable: $file"
        fi
    done
    
    # Verify critical files
    log_step "Verifying critical files..."
    
    local critical_files=(
        "script_autoconf_display.sh"
        "helper_password_mananger.sh"
        "helper_network_detection.sh"
        "helper_template_processor.sh"
        "helper_fqdn_lookup.sh"
        "helper_directory_layout.sh"
        "template_autoconf_display.yml"
        "template_basic_display.yml"
        "template_ui_integrated_display.yml"
    )
    
    local missing_critical=0
    for file in "${critical_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_error "✗ Critical file missing: $file"
            ((missing_critical++))
        fi
    done
    
    if [[ $missing_critical -gt 0 ]]; then
        log_error "✗ $missing_critical critical files are missing"
        log_error "BunkerWeb setup may not work properly"
        exit 1
    fi
    
    # Success summary
    log_success "BunkerWeb deployment completed successfully!"
    echo ""
    echo "📁 Files downloaded to: /data/BunkerWeb"
    echo "📁 BunkerWeb.conf location: /root/BunkerWeb.conf"
    echo "📁 Credentials location: /root/BunkerWeb-credentials.txt"
    echo "🔗 Symbolic link: /data/BunkerWeb/BunkerWeb.conf → /root/BunkerWeb.conf"
    echo "🔗 Symbolic link: /data/BunkerWeb/credentials.txt → /root/BunkerWeb-credentials.txt"
    echo ""
    
    # Show downloaded file summary
    echo "📋 Downloaded Components:"
    echo ""
    
    echo "🔧 Main Scripts:"
    for file in "${!MAIN_SCRIPTS[@]}"; do
        if [[ -f "$file" ]]; then
            echo "  ✓ $file - ${MAIN_SCRIPTS[$file]}"
        else
            echo "  ✗ $file - Missing"
        fi
    done
    echo ""
    
    echo "🛠️  Helper Scripts:"
    for file in "${!HELPER_SCRIPTS[@]}"; do
        if [[ -f "$file" ]]; then
            echo "  ✓ $file - ${HELPER_SCRIPTS[$file]}"
        else
            echo "  ✗ $file - Missing"
        fi
    done
    echo ""
    
    echo "📄 Templates:"
    for file in "${!TEMPLATES[@]}"; do
        if [[ -f "$file" ]]; then
            echo "  ✓ $file - ${TEMPLATES[$file]}"
        else
            echo "  ✗ $file - Missing"
        fi
    done
    echo ""
    
    echo "⚙️  Configuration Files:"
    for file in "${!CONFIG_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            echo "  ✓ $file - ${CONFIG_FILES[$file]}"
        else
            echo "  ✗ $file - Missing"
        fi
    done
    echo ""
    
    # Show directory listing
    echo "📂 Complete file listing:"
    ls -la /data/BunkerWeb/ | grep -E '\.(sh|yml|conf)$'
    echo ""
    
    echo "🔧 Configuration file:"
    ls -la /root/BunkerWeb.conf
    echo ""
    echo "🔐 Credentials file (will be populated by setup script):"
    ls -la /root/BunkerWeb-credentials.txt
    echo ""
    echo "🔗 Symbolic links:"
    ls -la /data/BunkerWeb/ | grep -E '\.conf$|credentials\.txt
    
    # Next steps
    echo "🚀 Next Steps:"
    echo "1. Edit configuration: nano /root/BunkerWeb.conf"
    echo "2. Run setup script: sudo /data/BunkerWeb/script_autoconf_display.sh --type autoconf"
    echo "3. Or get help: /data/BunkerWeb/script_autoconf_display.sh --help"
    echo ""
    
    log_info "You can now proceed with BunkerWeb configuration and deployment."
}

# Run main function
main "$@"
    echo ""
    
    # Next steps
    echo "🚀 Next Steps:"
    echo "1. Edit configuration: nano /root/BunkerWeb.conf"
    echo "2. Run setup script: sudo /data/BunkerWeb/script_autoconf_display.sh --type autoconf"
    echo "3. Or get help: /data/BunkerWeb/script_autoconf_display.sh --help"
    echo ""
    
    log_info "You can now proceed with BunkerWeb configuration and deployment."
}

# Run main function
main "$@"
