#!/bin/bash
# Copyright (c) 2025 Michal Koeckeis-Fresel
# This software is dual-licensed under your choice of:
# - MIT License (see LICENSE-MIT)
# - GNU Affero General Public License v3.0 (see LICENSE-AGPL)
# SPDX-License-Identifier: MIT OR AGPL-3.0-or-later

# BunkerWeb Configuration Checker
# Validates critical configuration settings and provides recommendations

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Global variables
INSTALL_DIR="/data/BunkerWeb"
CONFIG_FILE="$INSTALL_DIR/BunkerWeb.conf"
ROOT_CONFIG_FILE="/root/BunkerWeb.conf"

# Validation results
VALIDATION_ERRORS=()
VALIDATION_WARNINGS=()
VALIDATION_INFO=()
VALIDATION_SUCCESS=()

# Configuration values (loaded from config file)
ADMIN_USERNAME=""
RELEASE_CHANNEL=""
AUTO_CERT_TYPE=""
AUTO_CERT_CONTACT=""
FQDN=""
SERVER_NAME=""
PRIVATE_NETWORKS_ALREADY_IN_USE=""
AUTO_DETECT_NETWORK_CONFLICTS=""
PREFERRED_DOCKER_SUBNET=""
BUNKERWEB_INSTANCES=""
MULTISITE=""
SECURITY_MODE=""
SERVER_TYPE=""
USE_GREYLIST=""
GREYLIST_IP=""
GREYLIST_RDNS=""
REDIS_ENABLED=""
REDIS_PASSWORD=""
SYSLOG_ENABLED=""
SYSLOG_ADDRESS=""
SYSLOG_PORT=""
SYSLOG_NETWORK=""
LETS_ENCRYPT_CHALLENGE=""
LETS_ENCRYPT_STAGING=""
LETS_ENCRYPT_WILDCARD=""

# Function to add validation result
add_error() {
    VALIDATION_ERRORS+=("$1")
}

add_warning() {
    VALIDATION_WARNINGS+=("$1")
}

add_info() {
    VALIDATION_INFO+=("$1")
}

add_success() {
    VALIDATION_SUCCESS+=("$1")
}

# Function to find and load configuration file
find_config_file() {
    local config_found=""
    
    # Priority order: 1) /data/BunkerWeb/BunkerWeb.conf, 2) /root/BunkerWeb.conf
    if [[ -f "$CONFIG_FILE" ]]; then
        config_found="$CONFIG_FILE"
    elif [[ -f "$ROOT_CONFIG_FILE" ]]; then
        config_found="$ROOT_CONFIG_FILE"
    fi
    
    if [[ -n "$config_found" ]]; then
        echo "$config_found"
        return 0
    else
        return 1
    fi
}

# Function to load configuration from file
load_configuration() {
    local config_path
    
    if config_path=$(find_config_file); then
        echo -e "${BLUE}Loading configuration from: $config_path${NC}"
        source "$config_path"
        add_success "Configuration file found and loaded: $config_path"
        return 0
    else
        add_error "Configuration file not found (searched: $CONFIG_FILE, $ROOT_CONFIG_FILE)"
        return 1
    fi
}

# Function to validate release channel
validate_release_channel() {
    echo -e "${CYAN}Checking release channel configuration...${NC}"
    
    if [[ -z "$RELEASE_CHANNEL" ]]; then
        add_warning "RELEASE_CHANNEL not set - will use default 'latest'"
        return 0
    fi
    
    # Check if it's a standard channel
    case "$RELEASE_CHANNEL" in
        "latest")
            add_success "Release channel set to 'latest' (stable production releases)"
            ;;
        "RC")
            add_warning "Release channel set to 'RC' (release candidates - use for testing only)"
            ;;
        "nightly")
            add_warning "Release channel set to 'nightly' (development builds - hardcore testers only)"
            ;;
        *)
            # Check if it's a version pattern
            if [[ "$RELEASE_CHANNEL" =~ ^v?[0-9]+\.[0-9]+(\.[0-9]+)?(-[a-zA-Z0-9]+)?$ ]]; then
                add_info "Release channel set to custom version: $RELEASE_CHANNEL (version pinning)"
            else
                add_error "Invalid RELEASE_CHANNEL format: $RELEASE_CHANNEL (valid: latest, RC, nightly, or X.Y.Z)"
            fi
            ;;
    esac
}

# Function to validate SSL/Let's Encrypt configuration
validate_ssl_config() {
    echo -e "${CYAN}Checking SSL/Let's Encrypt configuration...${NC}"
    
    if [[ -z "$AUTO_CERT_TYPE" ]]; then
        add_info "SSL certificates disabled (AUTO_CERT_TYPE not set)"
        return 0
    fi
    
    case "$AUTO_CERT_TYPE" in
        "LE")
            add_success "Let's Encrypt certificate generation enabled"
            
            # Validate contact email
            if [[ -z "$AUTO_CERT_CONTACT" ]]; then
                add_error "AUTO_CERT_CONTACT email is required when AUTO_CERT_TYPE=LE"
            elif [[ "$AUTO_CERT_CONTACT" == "me@example.com" ]] || [[ "$AUTO_CERT_CONTACT" == *"@example.com"* ]] || [[ "$AUTO_CERT_CONTACT" == *"@yourdomain.com"* ]]; then
                add_error "AUTO_CERT_CONTACT contains example email - change to your real email address"
            elif [[ ! "$AUTO_CERT_CONTACT" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                add_error "AUTO_CERT_CONTACT has invalid email format: $AUTO_CERT_CONTACT"
            else
                add_success "Valid Let's Encrypt contact email: $AUTO_CERT_CONTACT"
            fi
            
            # Check FQDN requirement
            if [[ -z "$FQDN" ]]; then
                add_warning "FQDN not set - auto-detection will be attempted during deployment"
            else
                if [[ "$FQDN" == "localhost" ]] || [[ "$FQDN" == "127.0.0.1" ]] || [[ ! "$FQDN" =~ \. ]]; then
                    add_error "Invalid FQDN for Let's Encrypt: $FQDN (must be a valid domain name)"
                else
                    add_success "Valid FQDN for Let's Encrypt: $FQDN"
                fi
            fi
            
            # Check staging setting
            if [[ "$LETS_ENCRYPT_STAGING" == "yes" ]] || [[ -z "$LETS_ENCRYPT_STAGING" ]]; then
                add_warning "Let's Encrypt staging mode enabled - certificates won't be trusted by browsers"
                add_info "Set LETS_ENCRYPT_STAGING=\"no\" for production certificates"
            else
                add_info "Let's Encrypt production mode enabled"
            fi
            
            # Check challenge type
            if [[ "$LETS_ENCRYPT_CHALLENGE" == "dns" ]]; then
                add_info "DNS challenge configured - ensure DNS provider is supported"
                if [[ "$LETS_ENCRYPT_WILDCARD" == "yes" ]]; then
                    add_info "Wildcard certificates enabled with DNS challenge"
                fi
            else
                add_info "HTTP challenge configured (default)"
            fi
            ;;
        "ZeroSSL")
            add_warning "ZeroSSL support is draft/experimental - not fully implemented"
            ;;
        *)
            add_error "Invalid AUTO_CERT_TYPE: $AUTO_CERT_TYPE (valid options: LE, ZeroSSL)"
            ;;
    esac
}

# Function to validate admin configuration
validate_admin_config() {
    echo -e "${CYAN}Checking admin configuration...${NC}"
    
    if [[ -z "$ADMIN_USERNAME" ]]; then
        add_warning "ADMIN_USERNAME not set - will use default 'admin'"
    elif [[ ${#ADMIN_USERNAME} -lt 3 ]]; then
        add_warning "ADMIN_USERNAME is very short: $ADMIN_USERNAME (consider longer username for security)"
    elif [[ "$ADMIN_USERNAME" == "admin" ]]; then
        add_warning "Using default admin username 'admin' - consider changing for better security"
    else
        add_success "Custom admin username configured: $ADMIN_USERNAME"
    fi
}

# Function to validate network configuration
validate_network_config() {
    echo -e "${CYAN}Checking network configuration...${NC}"
    
    # Check network conflict detection
    if [[ "$AUTO_DETECT_NETWORK_CONFLICTS" == "no" ]]; then
        add_warning "Network conflict detection disabled - manual subnet configuration required"
    else
        add_success "Network conflict detection enabled"
    fi
    
    # Validate private networks format
    if [[ -n "$PRIVATE_NETWORKS_ALREADY_IN_USE" ]]; then
        local invalid_networks=()
        IFS=' ' read -ra networks <<< "$PRIVATE_NETWORKS_ALREADY_IN_USE"
        
        for network in "${networks[@]}"; do
            if [[ ! "$network" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
                invalid_networks+=("$network")
            fi
        done
        
        if [[ ${#invalid_networks[@]} -gt 0 ]]; then
            add_error "Invalid network format in PRIVATE_NETWORKS_ALREADY_IN_USE: ${invalid_networks[*]}"
        else
            add_success "Valid private networks specified: $PRIVATE_NETWORKS_ALREADY_IN_USE"
        fi
    else
        add_info "No private networks specified - auto-detection will scan system"
    fi
    
    # Check preferred subnet
    if [[ -n "$PREFERRED_DOCKER_SUBNET" ]]; then
        if [[ ! "$PREFERRED_DOCKER_SUBNET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            add_error "Invalid PREFERRED_DOCKER_SUBNET format: $PREFERRED_DOCKER_SUBNET"
        else
            add_success "Preferred Docker subnet specified: $PREFERRED_DOCKER_SUBNET"
        fi
    fi
}

# Function to validate greylist configuration
validate_greylist_config() {
    echo -e "${CYAN}Checking greylist configuration...${NC}"
    
    if [[ "$USE_GREYLIST" == "yes" ]]; then
        add_success "Greylist protection enabled for admin interface"
        
        if [[ -n "$GREYLIST_IP" ]]; then
            local invalid_ips=()
            IFS=' ' read -ra ips <<< "$GREYLIST_IP"
            
            for ip in "${ips[@]}"; do
                if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
                    invalid_ips+=("$ip")
                fi
            done
            
            if [[ ${#invalid_ips[@]} -gt 0 ]]; then
                add_error "Invalid IP format in GREYLIST_IP: ${invalid_ips[*]}"
            else
                add_success "Valid greylist IPs configured: $GREYLIST_IP"
            fi
        else
            add_info "GREYLIST_IP not set - will be auto-detected from SSH connections"
        fi
        
        if [[ -n "$GREYLIST_RDNS" ]]; then
            add_info "Greylist RDNS configured: $GREYLIST_RDNS"
        fi
    else
        add_warning "Greylist protection disabled - admin interface accessible from any IP"
        add_info "Consider enabling USE_GREYLIST=yes for better security"
    fi
}

# Function to validate service configuration
validate_service_config() {
    echo -e "${CYAN}Checking service configuration...${NC}"
    
    # Redis configuration
    if [[ "$REDIS_ENABLED" == "yes" ]] || [[ -z "$REDIS_ENABLED" ]]; then
        add_success "Redis support enabled (recommended for clustering)"
    else
        add_warning "Redis support disabled - limited clustering capabilities"
    fi
    
    # Syslog configuration
    if [[ "$SYSLOG_ENABLED" == "yes" ]] || [[ -z "$SYSLOG_ENABLED" ]]; then
        add_success "Syslog support enabled"
        
        if [[ -n "$SYSLOG_ADDRESS" && "$SYSLOG_ADDRESS" != "127.0.0.1" ]]; then
            add_info "External syslog server configured: $SYSLOG_ADDRESS"
        fi
    else
        add_info "Syslog support disabled"
    fi
    
    # Multisite configuration
    if [[ "$MULTISITE" == "yes" ]] || [[ -z "$MULTISITE" ]]; then
        add_success "Multisite mode enabled (supports multiple domains)"
    else
        add_info "Multisite mode disabled (single domain only)"
    fi
    
    # Security mode
    case "$SECURITY_MODE" in
        "block"|"")
            add_success "Security mode set to 'block' (recommended)"
            ;;
        "detect")
            add_warning "Security mode set to 'detect' only - threats will be logged but not blocked"
            ;;
        *)
            add_error "Invalid SECURITY_MODE: $SECURITY_MODE (valid: block, detect)"
            ;;
    esac
}

# Function to validate domain configuration
validate_domain_config() {
    echo -e "${CYAN}Checking domain configuration...${NC}"
    
    if [[ -n "$FQDN" ]]; then
        if [[ "$FQDN" == "localhost" ]] || [[ "$FQDN" == "127.0.0.1" ]]; then
            add_warning "FQDN set to localhost - SSL certificates will not work"
        elif [[ ! "$FQDN" =~ \. ]]; then
            add_warning "FQDN appears to be a hostname without domain: $FQDN"
        else
            add_success "FQDN configured: $FQDN"
        fi
    else
        add_info "FQDN not set - auto-detection will be attempted"
    fi
    
    if [[ -n "$SERVER_NAME" ]]; then
        if [[ "$SERVER_NAME" != "$FQDN" && -n "$FQDN" ]]; then
            add_info "SERVER_NAME differs from FQDN - ensure this is intentional"
        fi
        add_info "SERVER_NAME configured: $SERVER_NAME"
    fi
}

# Function to check for common configuration issues
check_common_issues() {
    echo -e "${CYAN}Checking for common configuration issues...${NC}"
    
    # Check for conflicting SSL settings
    if [[ -n "$AUTO_CERT_TYPE" && "$FQDN" == "localhost" ]]; then
        add_error "SSL certificates enabled but FQDN is localhost - this will fail"
    fi
    
    # Check for production readiness
    if [[ "$LETS_ENCRYPT_STAGING" == "yes" && "$AUTO_CERT_TYPE" == "LE" ]]; then
        add_warning "Let's Encrypt staging mode - not suitable for production"
    fi
    
    # Check for security best practices
    if [[ "$USE_GREYLIST" != "yes" && "$AUTO_CERT_TYPE" == "LE" ]]; then
        add_warning "Public SSL domain without greylist protection - consider enabling USE_GREYLIST"
    fi
    
    # Check for example values still in use
    local config_content=""
    local config_path
    if config_path=$(find_config_file); then
        config_content=$(cat "$config_path")
        
        if grep -q "yourdomain.com" <<< "$config_content"; then
            add_warning "Configuration contains 'yourdomain.com' - update with real domain"
        fi
        
        if grep -q "me@example.com" <<< "$config_content" && [[ "$AUTO_CERT_CONTACT" == "me@example.com" ]]; then
            add_error "AUTO_CERT_CONTACT still using example email"
        fi
    fi
}

# Function to provide configuration recommendations
provide_recommendations() {
    echo -e "${CYAN}Configuration recommendations:${NC}"
    
    local recommendations=()
    
    # Production recommendations
    if [[ ${#VALIDATION_ERRORS[@]} -eq 0 ]]; then
        if [[ "$RELEASE_CHANNEL" == "latest" && "$LETS_ENCRYPT_STAGING" != "yes" && "$USE_GREYLIST" == "yes" ]]; then
            recommendations+=("✓ Configuration appears production-ready")
        fi
    fi
    
    # Security recommendations
    if [[ "$USE_GREYLIST" != "yes" ]]; then
        recommendations+=("Enable greylist protection: USE_GREYLIST=\"yes\"")
    fi
    
    if [[ "$ADMIN_USERNAME" == "admin" ]]; then
        recommendations+=("Change default admin username for better security")
    fi
    
    # SSL recommendations
    if [[ -z "$AUTO_CERT_TYPE" ]]; then
        recommendations+=("Consider enabling SSL certificates for production: AUTO_CERT_TYPE=\"LE\"")
    fi
    
    if [[ "$LETS_ENCRYPT_STAGING" == "yes" && "$AUTO_CERT_TYPE" == "LE" ]]; then
        recommendations+=("Disable staging for production: LETS_ENCRYPT_STAGING=\"no\"")
    fi
    
    # Performance recommendations
    if [[ "$REDIS_ENABLED" != "yes" ]]; then
        recommendations+=("Enable Redis for better performance: REDIS_ENABLED=\"yes\"")
    fi
    
    if [[ ${#recommendations[@]} -gt 0 ]]; then
        for rec in "${recommendations[@]}"; do
            echo -e "${BLUE}  • $rec${NC}"
        done
    else
        echo -e "${GREEN}  • No additional recommendations${NC}"
    fi
}

# Function to display validation summary
show_validation_summary() {
    echo ""
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                    CONFIGURATION VALIDATION SUMMARY                    ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    # Count results
    local error_count=${#VALIDATION_ERRORS[@]}
    local warning_count=${#VALIDATION_WARNINGS[@]}
    local info_count=${#VALIDATION_INFO[@]}
    local success_count=${#VALIDATION_SUCCESS[@]}
    
    # Overall status
    if [[ $error_count -eq 0 ]]; then
        echo -e "${GREEN}✓ Configuration validation PASSED${NC}"
    else
        echo -e "${RED}✗ Configuration validation FAILED${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}Successful checks: $success_count${NC}"
    echo -e "${YELLOW}Warnings: $warning_count${NC}"
    echo -e "${CYAN}Information: $info_count${NC}"
    echo -e "${RED}Errors: $error_count${NC}"
    echo ""
    
    # Show errors
    if [[ $error_count -gt 0 ]]; then
        echo -e "${RED}ERRORS (must be fixed):${NC}"
        for error in "${VALIDATION_ERRORS[@]}"; do
            echo -e "${RED}  ✗ $error${NC}"
        done
        echo ""
    fi
    
    # Show warnings
    if [[ $warning_count -gt 0 ]]; then
        echo -e "${YELLOW}WARNINGS (should be reviewed):${NC}"
        for warning in "${VALIDATION_WARNINGS[@]}"; do
            echo -e "${YELLOW}  ⚠ $warning${NC}"
        done
        echo ""
    fi
    
    # Show successes (only if verbose or no errors)
    if [[ $error_count -eq 0 || "$VERBOSE" == "yes" ]]; then
        if [[ $success_count -gt 0 ]]; then
            echo -e "${GREEN}PASSED CHECKS:${NC}"
            for success in "${VALIDATION_SUCCESS[@]}"; do
                echo -e "${GREEN}  ✓ $success${NC}"
            done
            echo ""
        fi
    fi
    
    # Show info
    if [[ $info_count -gt 0 && "$VERBOSE" == "yes" ]]; then
        echo -e "${CYAN}INFORMATION:${NC}"
        for info in "${VALIDATION_INFO[@]}"; do
            echo -e "${CYAN}  ℹ $info${NC}"
        done
        echo ""
    fi
    
    # Recommendations
    provide_recommendations
    echo ""
    
    # Return appropriate exit code
    if [[ $error_count -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

# Function to show usage
show_usage() {
    echo -e "${BLUE}BunkerWeb Configuration Checker${NC}"
    echo ""
    echo -e "${YELLOW}Usage: $(basename "$0") [OPTIONS]${NC}"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  -v, --verbose          Show detailed information and passed checks"
    echo -e "  -q, --quiet            Only show errors and warnings"
    echo -e "  -c, --config FILE      Use specific configuration file"
    echo -e "  -h, --help             Show this help message"
    echo -e "  --errors-only          Only show errors (exit 1 if any errors found)"
    echo -e "  --warnings-only        Only show warnings"
    echo -e "  --summary-only         Only show the summary"
    echo ""
    echo -e "${YELLOW}Exit Codes:${NC}"
    echo -e "  0    Configuration validation passed (no errors)"
    echo -e "  1    Configuration validation failed (errors found)"
    echo -e "  2    Configuration file not found"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo -e "  $(basename "$0")                    # Run full validation"
    echo -e "  $(basename "$0") --verbose          # Show all details"
    echo -e "  $(basename "$0") --quiet            # Only show issues"
    echo -e "  $(basename "$0") --errors-only      # Only show errors"
    echo -e "  $(basename "$0") -c /path/to/config # Use specific config file"
    echo ""
}

# Function to run all validations
run_all_validations() {
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                    BUNKERWEB CONFIGURATION VALIDATION                    ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    # Load configuration
    if ! load_configuration; then
        echo -e "${RED}Cannot proceed without configuration file${NC}"
        return 2
    fi
    
    echo ""
    
    # Run all validation checks
    validate_release_channel
    validate_ssl_config
    validate_admin_config
    validate_domain_config
    validate_network_config
    validate_greylist_config
    validate_service_config
    check_common_issues
    
    echo ""
    
    # Show summary
    show_validation_summary
}

# Main function
main() {
    local verbose="no"
    local quiet="no"
    local errors_only="no"
    local warnings_only="no"
    local summary_only="no"
    local custom_config=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                verbose="yes"
                export VERBOSE="yes"
                shift
                ;;
            -q|--quiet)
                quiet="yes"
                shift
                ;;
            -c|--config)
                custom_config="$2"
                CONFIG_FILE="$custom_config"
                ROOT_CONFIG_FILE="$custom_config"
                shift 2
                ;;
            --errors-only)
                errors_only="yes"
                shift
                ;;
            --warnings-only)
                warnings_only="yes"
                shift
                ;;
            --summary-only)
                summary_only="yes"
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
    
    # Run validations
    if [[ "$summary_only" == "yes" ]]; then
        # Load config and run validations silently
        load_configuration >/dev/null 2>&1
        validate_release_channel >/dev/null 2>&1
        validate_ssl_config >/dev/null 2>&1
        validate_admin_config >/dev/null 2>&1
        validate_domain_config >/dev/null 2>&1
        validate_network_config >/dev/null 2>&1
        validate_greylist_config >/dev/null 2>&1
        validate_service_config >/dev/null 2>&1
        check_common_issues >/dev/null 2>&1
        
        show_validation_summary
    elif [[ "$quiet" == "yes" ]] || [[ "$errors_only" == "yes" ]] || [[ "$warnings_only" == "yes" ]]; then
        # Run validations silently
        load_configuration >/dev/null 2>&1
        validate_release_channel >/dev/null 2>&1
        validate_ssl_config >/dev/null 2>&1
        validate_admin_config >/dev/null 2>&1
        validate_domain_config >/dev/null 2>&1
        validate_network_config >/dev/null 2>&1
        validate_greylist_config >/dev/null 2>&1
        validate_service_config >/dev/null 2>&1
        check_common_issues >/dev/null 2>&1
        
        # Show only requested output
        if [[ "$errors_only" == "yes" ]]; then
            if [[ ${#VALIDATION_ERRORS[@]} -gt 0 ]]; then
                echo -e "${RED}Configuration Errors:${NC}"
                for error in "${VALIDATION_ERRORS[@]}"; do
                    echo -e "${RED}  ✗ $error${NC}"
                done
            fi
        elif [[ "$warnings_only" == "yes" ]]; then
            if [[ ${#VALIDATION_WARNINGS[@]} -gt 0 ]]; then
                echo -e "${YELLOW}Configuration Warnings:${NC}"
                for warning in "${VALIDATION_WARNINGS[@]}"; do
                    echo -e "${YELLOW}  ⚠ $warning${NC}"
                done
            fi
        else
            # Quiet mode - show errors and warnings
            if [[ ${#VALIDATION_ERRORS[@]} -gt 0 ]]; then
                echo -e "${RED}Errors:${NC}"
                for error in "${VALIDATION_ERRORS[@]}"; do
                    echo -e "${RED}  ✗ $error${NC}"
                done
            fi
            if [[ ${#VALIDATION_WARNINGS[@]} -gt 0 ]]; then
                echo -e "${YELLOW}Warnings:${NC}"
                for warning in "${VALIDATION_WARNINGS[@]}"; do
                    echo -e "${YELLOW}  ⚠ $warning${NC}"
                done
            fi
        fi
    else
        # Run full validation with output
        run_all_validations
    fi
    
    # Return appropriate exit code
    if [[ ${#VALIDATION_ERRORS[@]} -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi