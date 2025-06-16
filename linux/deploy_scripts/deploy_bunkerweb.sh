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

# BunkerWeb Setup Script - MODULAR VERSION
# This script orchestrates the setup using separate modules for each major function
# MUST BE RUN AS ROOT: sudo ./script_autoconf_display.sh --type <autoconf|basic|integrated>

set -e

# Script directory and installation directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/data/BunkerWeb"
SETUP_MODE="automated"  # Default to automated mode

# Default values (can be overridden by BunkerWeb.conf or command line)
ADMIN_USERNAME="admin"
AUTO_CERT_TYPE=""
AUTO_CERT_CONTACT=""
FQDN=""
MULTISITE="yes"
SERVER_NAME=""
SECURITY_MODE="block"
SERVER_TYPE="http"

# Network Configuration
PRIVATE_NETWORKS_ALREADY_IN_USE=""
AUTO_DETECT_NETWORK_CONFLICTS="yes"
PREFERRED_DOCKER_SUBNET=""

# Service Configuration
REDIS_ENABLED="yes"
REDIS_PASSWORD=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Source the modular scripts
source_modules() {
    local modules=(
        "helper_password_manager.sh"
        "helper_network_detection.sh" 
        "helper_template_processor.sh"
        "helper_fqdn_lookup.sh"
        "helper_directory_layout.sh"
    )
    
    echo -e "${BLUE}Loading BunkerWeb modules...${NC}"
    
    for module in "${modules[@]}"; do
        local module_path="$SCRIPT_DIR/$module"
        
        if [[ -f "$module_path" ]]; then
            if source "$module_path"; then
                echo -e "${GREEN}✓ Loaded: $module${NC}"
            else
                echo -e "${RED}✗ Failed to load: $module${NC}"
                return 1
            fi
        else
            echo -e "${RED}✗ Module not found: $module_path${NC}"
            echo -e "${YELLOW}ℹ Please ensure all modules are in the same directory as this script${NC}"
            return 1
        fi
    done
    
    echo -e "${GREEN}✓ All modules loaded successfully${NC}"
    return 0
}

# Load configuration from BunkerWeb.conf if it exists
load_configuration() {
    local config_file="$INSTALL_DIR/BunkerWeb.conf"
    
    if [[ -f "$config_file" ]]; then
        echo -e "${BLUE}Loading configuration from $config_file...${NC}"
        source "$config_file"
        echo -e "${GREEN}✓ Configuration loaded${NC}"
        
        # Simple validation for SSL configuration
        if [[ -n "$AUTO_CERT_TYPE" ]]; then
            if [[ "$AUTO_CERT_CONTACT" == "me@example.com" ]] || [[ "$AUTO_CERT_CONTACT" == *"@example.com"* ]] || [[ "$AUTO_CERT_CONTACT" == *"@yourdomain.com"* ]]; then
                if [[ "$FORCE_INSTALL" != "yes" ]]; then
                    echo -e "${RED}=================================================================================${NC}"
                    echo -e "${RED}                    CONFIGURATION VALIDATION FAILED                    ${NC}"
                    echo -e "${RED}=================================================================================${NC}"
                    echo ""
                    echo -e "${YELLOW}SSL certificates are enabled but using example email addresses.${NC}"
                    echo -e "${YELLOW}Please edit $config_file and change AUTO_CERT_CONTACT to a real email.${NC}"
                    echo ""
                    echo -e "${GREEN}To fix: nano $config_file${NC}"
                    echo -e "${GREEN}Change: AUTO_CERT_CONTACT=\"your-real-email@your-domain.com\"${NC}"
                    echo ""
                    echo -e "${RED}To bypass validation: add --force${NC}"
                    exit 1
                fi
            fi
        fi
    else
        echo -e "${YELLOW}No configuration file found - using defaults${NC}"
    fi
}

# Function to display usage
show_usage() {
    echo -e "${BLUE}Usage: $0 --type <autoconf|basic|integrated> [OPTIONS]${NC}"
    echo ""
    echo -e "${YELLOW}Required Options:${NC}"
    echo -e "  --type autoconf     Use template_autoconf_display.yml"
    echo -e "  --type basic        Use template_basic_display.yml"
    echo -e "  --type integrated   Use template_ui_integrated_display.yml"
    echo ""
    echo -e "${YELLOW}Optional Parameters:${NC}"
    echo -e "  --wizard            Enable setup wizard mode (default: automated setup)"
    echo -e "  --admin-name NAME   Set admin username"
    echo -e "  --FQDN DOMAIN       Set Fully Qualified Domain Name"
    echo -e "  --force             Skip configuration validation"
    echo ""
    echo -e "${YELLOW}Network Configuration:${NC}"
    echo -e "  --private-networks \"NET1 NET2\"  Specify existing networks to avoid"
    echo -e "  --preferred-subnet SUBNET       Preferred Docker subnet"
    echo -e "  --no-network-check              Disable network conflict detection"
    echo ""
    echo -e "${YELLOW}Service Configuration:${NC}"
    echo -e "  --redis-enabled yes|no       Enable Redis support (default: yes)"
    echo -e "  --redis-password PASS        Set custom Redis password"
    echo ""
    echo -e "${YELLOW}SSL Certificate Options:${NC}"
    echo -e "  --AUTO_CERT LE|ZeroSSL       Enable automatic certificates"
    echo -e "  --AUTO_CERT_CONTACT EMAIL    Contact email for certificate registration"
    echo ""
    echo -e "${YELLOW}Help:${NC}"
    echo -e "  -h, --help          Show this help message"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo -e "  sudo $0 --type autoconf"
    echo -e "  sudo $0 --type autoconf --private-networks \"192.168.1.0/24\""
    echo -e "  sudo $0 --type autoconf --FQDN bunkerweb.example.com"
    echo ""
}

# Parse command line arguments
parse_arguments() {
    DEPLOYMENT_TYPE=""
    FORCE_INSTALL="no"

    while [[ $# -gt 0 ]]; do
        case $1 in
            --type)
                DEPLOYMENT_TYPE="$2"
                shift 2
                ;;
            --wizard)
                SETUP_MODE="wizard"
                shift
                ;;
            --admin-name)
                ADMIN_USERNAME="$2"
                shift 2
                ;;
            --FQDN)
                FQDN="$2"
                shift 2
                ;;
            --private-networks)
                PRIVATE_NETWORKS_ALREADY_IN_USE="$2"
                shift 2
                ;;
            --preferred-subnet)
                PREFERRED_DOCKER_SUBNET="$2"
                shift 2
                ;;
            --no-network-check)
                AUTO_DETECT_NETWORK_CONFLICTS="no"
                shift
                ;;
            --redis-enabled)
                REDIS_ENABLED="$2"
                shift 2
                ;;
            --redis-password)
                REDIS_PASSWORD="$2"
                shift 2
                ;;
            --AUTO_CERT)
                AUTO_CERT_TYPE="$2"
                shift 2
                ;;
            --AUTO_CERT_CONTACT)
                AUTO_CERT_CONTACT="$2"
                shift 2
                ;;
            --force)
                FORCE_INSTALL="yes"
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                echo -e "${RED}Error: Unknown option '$1'${NC}"
                show_usage
                exit 1
                ;;
        esac
    done

    # Validate that --type was provided
    if [[ -z "$DEPLOYMENT_TYPE" ]]; then
        echo -e "${RED}Error: --type parameter is required${NC}"
        echo ""
        show_usage
        exit 1
    fi

    # Validate deployment type and set template file
    case "$DEPLOYMENT_TYPE" in
        autoconf)
            TEMPLATE_FILE="template_autoconf_display.yml"
            DEPLOYMENT_NAME="Autoconf Display"
            ;;
        basic)
            TEMPLATE_FILE="template_basic_display.yml"
            DEPLOYMENT_NAME="Basic Display"
            ;;
        integrated)
            TEMPLATE_FILE="template_ui_integrated_display.yml"
            DEPLOYMENT_NAME="UI Integrated Display"
            ;;
        *)
            echo -e "${RED}Error: Invalid deployment type '$DEPLOYMENT_TYPE'${NC}"
            echo -e "${YELLOW}Valid types: autoconf, basic, integrated${NC}"
            exit 1
            ;;
    esac
}

# Auto-detect FQDN if not provided
detect_fqdn() {
    local require_ssl="no"
    [[ -n "$AUTO_CERT_TYPE" ]] && require_ssl="yes"
    
    FQDN=$(auto_detect_fqdn "$FQDN" "$require_ssl")
    local result=$?
    
    if [[ $result -ne 0 ]]; then
        echo -e "${RED}Error: FQDN detection failed${NC}"
        exit 1
    fi
    
    return 0
}

# Create required directories with proper permissions
setup_directories() {
    local syslog_enabled="no"  # Default for this deployment
    
    if ! setup_directory_structure "$INSTALL_DIR" "$REDIS_ENABLED" "$syslog_enabled"; then
        echo -e "${RED}✗ Directory setup failed${NC}"
        return 1
    fi
    
    return 0
}

# Display setup summary
show_setup_summary() {
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}          Setup Complete!${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    echo -e "${YELLOW}Deployment Type:${NC} $DEPLOYMENT_NAME"
    echo -e "${YELLOW}Installation Directory:${NC} $INSTALL_DIR"
    echo -e "${YELLOW}Template Used:${NC} $TEMPLATE_FILE"
    echo -e "${YELLOW}Setup Mode:${NC} $SETUP_MODE"
    echo -e "${YELLOW}Domain (FQDN):${NC} $FQDN"
    echo -e "${YELLOW}Redis Enabled:${NC} $REDIS_ENABLED"
    echo -e "${YELLOW}Network Detection:${NC} $AUTO_DETECT_NETWORK_CONFLICTS"
    
    local detected_subnet=$(get_detected_subnet)
    if [[ -n "$detected_subnet" ]]; then
        echo -e "${YELLOW}Docker Subnet:${NC} $detected_subnet"
    fi
    
    if [[ -n "$AUTO_CERT_TYPE" ]]; then
        echo -e "${YELLOW}SSL Certificates:${NC} $AUTO_CERT_TYPE ($AUTO_CERT_CONTACT)"
    else
        echo -e "${YELLOW}SSL Certificates:${NC} Manual configuration"
    fi
    
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo -e "${GREEN}1. Start BunkerWeb: cd $INSTALL_DIR && docker compose up -d${NC}"
    
    if [[ $SETUP_MODE == "automated" ]]; then
        echo -e "${GREEN}2. Access web interface: http://$(hostname -I | awk '{print $1}')${NC}"
        echo -e "${GREEN}3. Login with credentials from: $INSTALL_DIR/credentials.txt${NC}"
    else
        echo -e "${GREEN}2. Complete setup wizard: http://$(hostname -I | awk '{print $1}')/setup${NC}"
        echo -e "${GREEN}3. Use pre-generated credentials from: $INSTALL_DIR/credentials.txt${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}Setup completed successfully!${NC}"
}

# Main execution function
main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}      BunkerWeb Modular Setup Script${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
       echo -e "${RED}This script must be run as root${NC}"
       echo -e "${YELLOW}Please run: sudo $0 --type <autoconf|basic|integrated>${NC}"
       exit 1
    fi
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Source modular scripts
    if ! source_modules; then
        echo -e "${RED}✗ Failed to load required modules${NC}"
        exit 1
    fi
    
    # Load configuration
    load_configuration
    
    # Auto-detect FQDN
    detect_fqdn
    
    # Set paths
    local compose_file="$INSTALL_DIR/docker-compose.yml"
    local template_path="$INSTALL_DIR/$TEMPLATE_FILE"
    local creds_file="$INSTALL_DIR/credentials.txt"
    
    # Check if template file exists
    if [[ ! -f "$template_path" ]]; then
        echo -e "${RED}Error: Template file not found at $template_path${NC}"
        echo -e "${YELLOW}Available templates should be in: $INSTALL_DIR${NC}"
        exit 1
    fi
    
    # Display initial configuration
    echo -e "${GREEN}Configuration Summary:${NC}"
    echo -e "${GREEN}• Deployment Type: $DEPLOYMENT_NAME${NC}"
    echo -e "${GREEN}• Template File: $TEMPLATE_FILE${NC}"
    echo -e "${GREEN}• Setup Mode: $SETUP_MODE${NC}"
    echo -e "${GREEN}• Domain (FQDN): $FQDN${NC}"
    echo -e "${GREEN}• Redis Enabled: $REDIS_ENABLED${NC}"
    echo -e "${GREEN}• Network Detection: $AUTO_DETECT_NETWORK_CONFLICTS${NC}"
    echo ""
    
    # 1. Network Conflict Detection
    echo -e "${BLUE}Step 1: Network Conflict Detection${NC}"
    if ! detect_network_conflicts "$AUTO_DETECT_NETWORK_CONFLICTS" "$PRIVATE_NETWORKS_ALREADY_IN_USE" "$PREFERRED_DOCKER_SUBNET"; then
        echo -e "${RED}✗ Network detection failed${NC}"
        exit 1
    fi
    local docker_subnet=$(get_detected_subnet)
    
    # 2. Credential Management  
    echo -e "${BLUE}Step 2: Credential Management${NC}"
    if ! manage_credentials "$creds_file" "$REDIS_ENABLED" "$DEPLOYMENT_NAME" "$TEMPLATE_FILE" "$SETUP_MODE" "$FQDN" "$SERVER_NAME" "$docker_subnet" "$PRIVATE_NETWORKS_ALREADY_IN_USE"; then
        echo -e "${RED}✗ Credential management failed${NC}"
        exit 1
    fi
    
    # Load the generated passwords
    eval "$(get_passwords)"
    
    # 3. Template Processing
    echo -e "${BLUE}Step 3: Template Processing${NC}"
    if ! process_template "$template_path" "$compose_file" "$MYSQL_PASSWORD" "$REDIS_PASSWORD" "$TOTP_SECRET" "$ADMIN_PASSWORD" "$FLASK_SECRET" "$ADMIN_USERNAME" "$AUTO_CERT_TYPE" "$AUTO_CERT_CONTACT" "$FQDN" "$SERVER_NAME" "$docker_subnet" "$SETUP_MODE" "$REDIS_ENABLED"; then
        echo -e "${RED}✗ Template processing failed${NC}"
        exit 1
    fi
    
    # 4. Directory Setup
    echo -e "${BLUE}Step 4: Directory Setup${NC}"
    setup_directories
    
    # 5. Final Summary
    show_setup_summary
}

# Run main function with all arguments
main "$@"
