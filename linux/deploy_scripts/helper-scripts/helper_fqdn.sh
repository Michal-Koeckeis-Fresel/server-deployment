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
# Auto-installing FQDN Detection and Validation Helper
# 
# Default behavior: Auto-detects system FQDN with automatic tool installation
# Usage: sudo ./script.sh (recommended) or ./script.sh (limited functionality)
# Debug logging enabled by default for comprehensive troubleshooting
#
# Features:
# - Automatic DNS tool installation (dig, nslookup, host, curl, jq, idn)
# - International Domain Name (IDN) support with Unicode and punycode
# - Strict RFC compliance (RFC 952, RFC 1123, RFC 1035) for ASCII domains
# - Comprehensive FQDN detection using multiple methods
# - Server IP detection (local and external) with NAT analysis
# - SSL certificate compatibility validation including CAA records
# - Reverse DNS consistency checking for all detected IPs
# - Cloud metadata detection (AWS, GCP, Azure)
# - JSON/XML output formats for automation
# - Machine-readable JSON logging with jq parsing support
# - Extensive testing framework

# ===============================================================================
# CONFIGURATION SECTION
# ===============================================================================

SCRIPT_NAME="FQDN Detection Helper"
SCRIPT_VERSION="2.2.0"
SCRIPT_PURPOSE="Auto-installing FQDN detection with IDN support and comprehensive debug logging for system administration"

DEFAULT_REQUIRE_SSL="yes"
DEFAULT_CHECK_DNS="yes"
DEFAULT_ALLOW_LOCALHOST="yes"
DEFAULT_ALLOW_IP_AS_FQDN="no"
DEFAULT_MIN_DOMAIN_PARTS="2"
DEFAULT_CONFIG_FILE=""
DEFAULT_LOG_LEVEL="DEBUG"
DEFAULT_OUTPUT_FORMAT="text"
DEFAULT_LOG_FILE="/tmp/fqdn_helper.log"
DEFAULT_LOG_MACHINE_FORMAT="yes"

USE_COLORS="yes"
DNS_TIMEOUT="5"
PING_TIMEOUT="3"

# ===============================================================================
# GLOBAL VARIABLES
# ===============================================================================

DETECTED_FQDN=""
DETECTION_METHOD=""
DETECTION_RESULTS=()
VALIDATION_RESULTS=()
CAA_RESULTS=()
REVERSE_DNS_RESULTS=()
IP_DETECTION_RESULTS=()

REQUIRE_SSL="$DEFAULT_REQUIRE_SSL"
CHECK_DNS="$DEFAULT_CHECK_DNS"
ALLOW_LOCALHOST="$DEFAULT_ALLOW_LOCALHOST"
ALLOW_IP_AS_FQDN="$DEFAULT_ALLOW_IP_AS_FQDN"
MIN_DOMAIN_PARTS="$DEFAULT_MIN_DOMAIN_PARTS"
LOG_LEVEL="$DEFAULT_LOG_LEVEL"
OUTPUT_FORMAT="$DEFAULT_OUTPUT_FORMAT"
LOG_FILE="$DEFAULT_LOG_FILE"
LOG_MACHINE_FORMAT="$DEFAULT_LOG_MACHINE_FORMAT"

# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

if [[ "$USE_COLORS" == "yes" ]] && [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    MAGENTA=''
    BOLD=''
    NC=''
fi

# Get timestamp in ISO format for machine readable logs
get_iso_timestamp() {
    date -u '+%Y-%m-%dT%H:%M:%S.%3NZ'
}

# Get timestamp for human readable logs
get_timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

# Machine-readable log function
log_machine() {
    local level="$1"
    local message="$2"
    local component="${3:-fqdn_helper}"
    local function_name="${4:-${FUNCNAME[2]}}"
    
    if [[ "$LOG_MACHINE_FORMAT" == "yes" && -n "$LOG_FILE" ]]; then
        # Create log directory if it doesn't exist
        local log_dir=$(dirname "$LOG_FILE")
        [[ ! -d "$log_dir" ]] && mkdir -p "$log_dir" 2>/dev/null
        
        # JSON format for machine readability
        local log_entry="{\"timestamp\":\"$(get_iso_timestamp)\",\"level\":\"$level\",\"component\":\"$component\",\"function\":\"$function_name\",\"message\":\"$message\",\"pid\":$,\"script\":\"$SCRIPT_NAME\",\"version\":\"$SCRIPT_VERSION\"}"
        
        # Append to log file (create if doesn't exist)
        echo "$log_entry" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# Enhanced logging functions with machine-readable output
log_debug() {
    local message="$1"
    [[ "$LOG_LEVEL" == "DEBUG" ]] && echo -e "${CYAN}[DEBUG]${NC} $message" >&2
    log_machine "DEBUG" "$message"
}

log_info() {
    local message="$1"
    [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && echo -e "${BLUE}[INFO]${NC} $message" >&2
    log_machine "INFO" "$message"
}

log_warning() {
    local message="$1"
    [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO|WARNING)$ ]] && echo -e "${YELLOW}[WARNING]${NC} $message" >&2
    log_machine "WARNING" "$message"
}

log_error() {
    local message="$1"
    echo -e "${RED}[ERROR]${NC} $message" >&2
    log_machine "ERROR" "$message"
}

log_success() {
    local message="$1"
    [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO|WARNING|SUCCESS)$ ]] && echo -e "${GREEN}[SUCCESS]${NC} $message" >&2
    log_machine "SUCCESS" "$message"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if running as root/sudo
is_root() {
    [[ $EUID -eq 0 ]]
}

# Install required DNS and network tools
install_required_tools() {
    local auto_mode="${1:-no}"
    
    if [[ "$auto_mode" == "yes" ]]; then
        log_info "Auto-installing required DNS and network tools..."
    else
        log_info "Checking and installing required DNS and network tools..."
    fi
    
    if ! is_root; then
        if [[ "$auto_mode" == "yes" ]]; then
            log_warning "Missing critical DNS tools but no root privileges available"
            log_info "Please run with sudo to auto-install missing tools, or install manually:"
            log_info "  sudo apt-get update && sudo apt-get install -y dnsutils bind9-host curl jq libidn2-tools"
            return 1
        else
            log_error "Root privileges required to install packages"
            log_info "Please run: sudo $0 install-tools"
            return 1
        fi
    fi
    
    # List of required tools and their packages
    local tools_packages=(
        "dig:dnsutils"
        "nslookup:dnsutils" 
        "host:bind9-host"
        "curl:curl"
        "timeout:coreutils"
        "ping:iputils-ping"
        "hostname:hostname"
        "jq:jq"
        "idn:libidn2-tools"
    )
    
    local missing_tools=()
    local packages_to_install=()
    local installed_packages=()
    
    if [[ "$auto_mode" != "yes" ]]; then
        log_info "Checking availability of required tools..."
    fi
    
    # Check which tools are missing
    for tool_package in "${tools_packages[@]}"; do
        local tool="${tool_package%%:*}"
        local package="${tool_package#*:}"
        
        if command_exists "$tool"; then
            if [[ "$auto_mode" != "yes" ]]; then
                log_success "✓ $tool is available"
            fi
        else
            if [[ "$auto_mode" == "yes" ]]; then
                log_debug "✗ $tool is missing (package: $package)"
            else
                log_warning "✗ $tool is missing (package: $package)"
            fi
            missing_tools+=("$tool")
            
            # Avoid duplicate packages
            if [[ ! " ${packages_to_install[*]} " =~ " ${package} " ]]; then
                packages_to_install+=("$package")
            fi
        fi
    done
    
    # Install missing packages if any
    if [[ ${#packages_to_install[@]} -gt 0 ]]; then
        if [[ "$auto_mode" == "yes" ]]; then
            log_info "Auto-installing missing packages: ${packages_to_install[*]}"
        else
            log_info "Installing missing packages: ${packages_to_install[*]}"
        fi
        
        # Update package list
        if [[ "$auto_mode" == "yes" ]]; then
            log_debug "Updating package list..."
        else
            log_info "Updating package list..."
        fi
        
        if apt-get update -qq 2>/dev/null; then
            if [[ "$auto_mode" != "yes" ]]; then
                log_success "Package list updated successfully"
            fi
        else
            log_error "Failed to update package list"
            return 1
        fi
        
        # Install packages
        for package in "${packages_to_install[@]}"; do
            if [[ "$auto_mode" == "yes" ]]; then
                log_debug "Installing package: $package"
            else
                log_info "Installing package: $package"
            fi
            
            if apt-get install -y -qq "$package" 2>/dev/null; then
                if [[ "$auto_mode" == "yes" ]]; then
                    log_debug "✓ Successfully installed: $package"
                else
                    log_success "✓ Successfully installed: $package"
                fi
                installed_packages+=("$package")
            else
                log_error "✗ Failed to install: $package"
                return 1
            fi
        done
        
        if [[ "$auto_mode" != "yes" ]]; then
            echo ""
        fi
        log_success "Installation completed successfully!"
        if [[ "$auto_mode" == "yes" ]]; then
            log_info "Auto-installed packages: ${installed_packages[*]}"
        else
            log_info "Installed packages: ${installed_packages[*]}"
        fi
        
        # Verify installation
        if [[ "$auto_mode" == "yes" ]]; then
            log_debug "Verifying tool availability after installation..."
        else
            log_info "Verifying tool availability after installation..."
        fi
        local verification_failed=false
        
        for tool in "${missing_tools[@]}"; do
            if command_exists "$tool"; then
                if [[ "$auto_mode" != "yes" ]]; then
                    log_success "✓ $tool is now available"
                fi
            else
                log_error "✗ $tool is still not available after installation"
                verification_failed=true
            fi
        done
        
        if [[ "$verification_failed" == "true" ]]; then
            log_error "Some tools are still missing after installation"
            return 1
        else
            if [[ "$auto_mode" == "yes" ]]; then
                log_success "All required DNS tools are now available!"
            else
                log_success "All required tools are now available!"
            fi
        fi
        
    else
        if [[ "$auto_mode" == "yes" ]]; then
            log_debug "All required tools are already installed"
        else
            log_success "All required tools are already installed!"
        fi
    fi
    
    # Additional system tools check (only in manual mode)
    if [[ "$auto_mode" != "yes" ]]; then
        log_info "Checking additional system tools..."
        
        local system_tools=("getent" "hostnamectl" "systemctl")
        local missing_system_tools=()
        
        for tool in "${system_tools[@]}"; do
            if command_exists "$tool"; then
                log_success "✓ $tool is available"
            else
                log_warning "⚠ $tool is not available (system-dependent)"
                missing_system_tools+=("$tool")
            fi
        done
        
        if [[ ${#missing_system_tools[@]} -gt 0 ]]; then
            log_info "Missing system tools: ${missing_system_tools[*]}"
            log_info "These tools are usually part of the base system but may affect some functionality"
        fi
        
        echo ""
        log_success "Tool installation and verification completed!"
    fi
    
    return 0
}

# Show tool availability status
show_tool_status() {
    echo -e "${BOLD}DNS and Network Tools Status:${NC}"
    echo ""
    
    local tools=(
        "dig:DNS queries (preferred)"
        "nslookup:DNS queries (fallback)"
        "host:DNS queries (fallback)"
        "curl:Cloud metadata and HTTP requests"
        "ping:Basic connectivity testing"
        "hostname:System hostname detection"
        "hostnamectl:Systemd hostname management"
        "getent:System resolver queries"
        "timeout:Command timeout handling"
        "jq:JSON log parsing and formatting"
        "idn:International domain name support"
    )
    
    local available_count=0
    local total_count=${#tools[@]}
    
    for tool_desc in "${tools[@]}"; do
        local tool="${tool_desc%%:*}"
        local description="${tool_desc#*:}"
        
        if command_exists "$tool"; then
            echo -e "${GREEN}  ✓ $tool${NC} - $description"
            ((available_count++))
        else
            echo -e "${RED}  ✗ $tool${NC} - $description"
        fi
    done
    
    echo ""
    echo -e "${CYAN}Summary: ${available_count}/${total_count} tools available${NC}"
    
    if [[ $available_count -eq $total_count ]]; then
        echo -e "${GREEN}All tools are available - full functionality enabled${NC}"
        return 0
    elif [[ $available_count -ge 8 ]]; then
        echo -e "${YELLOW}Most tools available - minor functionality may be limited${NC}"
        return 0
    else
        echo -e "${RED}Several tools missing - functionality will be significantly limited${NC}"
        echo -e "${BLUE}Run: sudo $0 install-tools${NC}"
        return 1
    fi
}

# Get script directory
get_script_dir() {
    cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
}

# Get timestamp
get_timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

# ===============================================================================
# CONFIGURATION FUNCTIONS
# ===============================================================================

# Load configuration from file
load_config() {
    local config_file="$1"
    
    if [[ -z "$config_file" ]]; then
        log_debug "No configuration file specified"
        return 0
    fi
    
    if [[ ! -f "$config_file" ]]; then
        log_warning "Configuration file not found: $config_file"
        return 1
    fi
    
    log_info "Loading configuration from: $config_file"
    
    while IFS='=' read -r key value; do
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${key// }" ]] && continue
        
        value="${value%\"}"
        value="${value#\"}"
        value="${value%\'}"
        value="${value#\'}"
        
        case "$key" in
            REQUIRE_SSL) REQUIRE_SSL="$value" ;;
            CHECK_DNS) CHECK_DNS="$value" ;;
            ALLOW_LOCALHOST) ALLOW_LOCALHOST="$value" ;;
            ALLOW_IP_AS_FQDN) ALLOW_IP_AS_FQDN="$value" ;;
            MIN_DOMAIN_PARTS) MIN_DOMAIN_PARTS="$value" ;;
            LOG_LEVEL) LOG_LEVEL="$value" ;;
            OUTPUT_FORMAT) OUTPUT_FORMAT="$value" ;;
            DNS_TIMEOUT) DNS_TIMEOUT="$value" ;;
            PING_TIMEOUT) PING_TIMEOUT="$value" ;;
            USE_COLORS) USE_COLORS="$value" ;;
            LOG_FILE) LOG_FILE="$value" ;;
            LOG_MACHINE_FORMAT) LOG_MACHINE_FORMAT="$value" ;;
        esac
    done < "$config_file"
    
    log_success "Configuration loaded successfully"
    return 0
}

# Save current configuration to file
save_config() {
    local config_file="$1"
    
    if [[ -z "$config_file" ]]; then
        log_error "No configuration file specified for saving"
        return 1
    fi
    
    log_info "Saving configuration to: $config_file"
    
    cat > "$config_file" << EOF
# FQDN Detection Helper Configuration
# Generated on: $(get_timestamp)

REQUIRE_SSL="$REQUIRE_SSL"
CHECK_DNS="$CHECK_DNS"
DNS_TIMEOUT="$DNS_TIMEOUT"
ALLOW_LOCALHOST="$ALLOW_LOCALHOST"
ALLOW_IP_AS_FQDN="$ALLOW_IP_AS_FQDN"
MIN_DOMAIN_PARTS="$MIN_DOMAIN_PARTS"
LOG_LEVEL="$LOG_LEVEL"
OUTPUT_FORMAT="$OUTPUT_FORMAT"
USE_COLORS="$USE_COLORS"
PING_TIMEOUT="$PING_TIMEOUT"

# Machine-readable logging
LOG_FILE="$LOG_FILE"
LOG_MACHINE_FORMAT="$LOG_MACHINE_FORMAT"
EOF
    
    if [[ -f "$config_file" ]]; then
        log_success "Configuration saved successfully"
        return 0
    else
        log_error "Failed to save configuration"
        return 1
    fi
}

# Display current configuration
show_config() {
    echo -e "${BOLD}Current Configuration:${NC}"
    echo -e "${CYAN}• Require SSL: ${NC}$REQUIRE_SSL"
    echo -e "${CYAN}• Check DNS: ${NC}$CHECK_DNS"
    echo -e "${CYAN}• Allow Localhost: ${NC}$ALLOW_LOCALHOST"
    echo -e "${CYAN}• Allow IP as FQDN: ${NC}$ALLOW_IP_AS_FQDN"
    echo -e "${CYAN}• Min Domain Parts: ${NC}$MIN_DOMAIN_PARTS"
    echo -e "${CYAN}• Log Level: ${NC}$LOG_LEVEL"
    echo -e "${CYAN}• Output Format: ${NC}$OUTPUT_FORMAT"
    echo -e "${CYAN}• DNS Timeout: ${NC}${DNS_TIMEOUT}s"
    echo -e "${CYAN}• Ping Timeout: ${NC}${PING_TIMEOUT}s"
    echo -e "${CYAN}• Log File: ${NC}$LOG_FILE"
    echo -e "${CYAN}• Machine Logs: ${NC}$LOG_MACHINE_FORMAT"
}

# ===============================================================================
# INTERNATIONAL DOMAIN NAME (IDN) FUNCTIONS
# ===============================================================================

# Check if a string contains non-ASCII characters
contains_unicode() {
    local string="$1"
    
    # Check if string contains any non-ASCII characters
    if [[ "$string" =~ [^[:ascii:]] ]]; then
        return 0  # Contains Unicode
    else
        return 1  # ASCII only
    fi
}

# Check if a domain is in punycode format
is_punycode() {
    local domain="$1"
    
    # Punycode domains contain xn-- labels
    if [[ "$domain" =~ xn-- ]]; then
        return 0  # Is punycode
    else
        return 1  # Not punycode
    fi
}

# Convert Unicode domain to punycode (ASCII-compatible encoding)
unicode_to_punycode() {
    local unicode_domain="$1"
    
    if command_exists idn; then
        # Use idn command for conversion
        local punycode_domain=$(echo "$unicode_domain" | idn --quiet 2>/dev/null || echo "")
        
        if [[ -n "$punycode_domain" ]]; then
            log_debug "Unicode to punycode: $unicode_domain → $punycode_domain"
            echo "$punycode_domain"
            return 0
        fi
    fi
    
    # Fallback: try with python if available
    if command_exists python3; then
        local punycode_domain=$(python3 -c "import sys; print(sys.argv[1].encode('idna').decode('ascii'))" "$unicode_domain" 2>/dev/null || echo "")
        
        if [[ -n "$punycode_domain" ]]; then
            log_debug "Unicode to punycode (python): $unicode_domain → $punycode_domain"
            echo "$punycode_domain"
            return 0
        fi
    fi
    
    log_warning "Cannot convert Unicode domain to punycode: $unicode_domain"
    return 1
}

# Convert punycode domain to Unicode (human-readable)
punycode_to_unicode() {
    local punycode_domain="$1"
    
    if command_exists idn; then
        # Use idn command for conversion
        local unicode_domain=$(echo "$punycode_domain" | idn --unicode --quiet 2>/dev/null || echo "")
        
        if [[ -n "$unicode_domain" ]]; then
            log_debug "Punycode to unicode: $punycode_domain → $unicode_domain"
            echo "$unicode_domain"
            return 0
        fi
    fi
    
    # Fallback: try with python if available
    if command_exists python3; then
        local unicode_domain=$(python3 -c "import sys; print(sys.argv[1].encode('ascii').decode('idna'))" "$punycode_domain" 2>/dev/null || echo "")
        
        if [[ -n "$unicode_domain" ]]; then
            log_debug "Punycode to unicode (python): $punycode_domain → $unicode_domain"
            echo "$unicode_domain"
            return 0
        fi
    fi
    
    # If conversion fails, return original domain
    echo "$punycode_domain"
    return 1
}

# Normalize domain for processing (convert to punycode if needed)
normalize_domain() {
    local domain="$1"
    
    # If domain contains Unicode characters, convert to punycode
    if contains_unicode "$domain"; then
        local punycode_domain=""
        if punycode_domain=$(unicode_to_punycode "$domain"); then
            echo "$punycode_domain"
            return 0
        else
            log_error "Failed to convert Unicode domain to punycode: $domain"
            return 1
        fi
    else
        # Already ASCII, return as-is
        echo "$domain"
        return 0
    fi
}

# Validate international domain name
is_valid_idn() {
    local domain="$1"
    local strict="${2:-no}"
    
    log_debug "Validating international domain: $domain"
    
    # Check if domain contains Unicode characters
    if contains_unicode "$domain"; then
        log_debug "Domain contains Unicode characters: $domain"
        
        # Try to convert to punycode to validate
        local punycode_domain=""
        if punycode_domain=$(unicode_to_punycode "$domain"); then
            log_debug "Unicode domain converted to punycode: $punycode_domain"
            # Validate the punycode version
            return $(is_valid_ascii_fqdn "$punycode_domain" "$strict")
        else
            log_debug "Failed to convert Unicode domain to punycode"
            return 1
        fi
    elif is_punycode "$domain"; then
        log_debug "Domain is in punycode format: $domain"
        # Validate punycode domain
        return $(is_valid_ascii_fqdn "$domain" "$strict")
    else
        log_debug "Domain is ASCII: $domain"
        # Regular ASCII domain
        return $(is_valid_ascii_fqdn "$domain" "$strict")
    fi
}

# ASCII-only FQDN validation with strict RFC compliance (RFC 952, RFC 1123, RFC 1035)
is_valid_ascii_fqdn() {
    local hostname="$1"
    local strict="${2:-no}"
    
    if [[ -z "$hostname" ]]; then
        log_debug "Empty hostname provided"
        return 1
    fi
    
    # Check if it's an IP address
    if is_ip_address "$hostname"; then
        if [[ "$ALLOW_IP_AS_FQDN" == "yes" ]]; then
            log_debug "IP address accepted as FQDN: $hostname"
            return 0
        else
            log_debug "IP address not allowed as FQDN: $hostname"
            return 1
        fi
    fi
    
    # Check localhost restrictions
    if [[ "$hostname" == "localhost" ]] || [[ "$hostname" == "localhost."* ]]; then
        if [[ "$ALLOW_LOCALHOST" == "yes" ]]; then
            log_debug "Localhost accepted: $hostname"
            return 0
        else
            log_debug "Localhost not allowed: $hostname"
            return 1
        fi
    fi
    
    # Remove trailing dot if present (for FQDN format)
    local domain="$hostname"
    if [[ "$domain" =~ \.$ ]]; then
        domain="${domain%\.}"
        log_debug "Removed trailing dot: $hostname → $domain"
    fi
    
    # RFC 1035: Total length must not exceed 253 characters
    if [[ ${#domain} -gt 253 ]]; then
        log_debug "RFC violation: Domain too long (>253 chars): $domain (${#domain} chars)"
        return 1
    fi
    
    # RFC 1035: Domain must not be empty after removing trailing dot
    if [[ -z "$domain" ]]; then
        log_debug "RFC violation: Empty domain after removing trailing dot"
        return 1
    fi
    
    # Check minimum domain parts requirement (configuration-dependent)
    if ! has_min_domain_parts "$domain" "$MIN_DOMAIN_PARTS"; then
        log_debug "Domain doesn't meet minimum domain parts requirement ($MIN_DOMAIN_PARTS): $domain"
        return 1
    fi
    
    # RFC 1035: Domain should not start or end with a dot (already handled above)
    # RFC 1035: Domain should not have consecutive dots
    if [[ "$domain" == *".."* ]]; then
        log_debug "RFC violation: Consecutive dots in domain: $domain"
        return 1
    fi
    
    # Split domain into labels and validate each label according to RFC
    local IFS='.'
    local labels=($domain)
    
    if [[ ${#labels[@]} -eq 0 ]]; then
        log_debug "RFC violation: No labels found in domain: $domain"
        return 1
    fi
    
    for label in "${labels[@]}"; do
        # RFC 1035: Each label must be 1-63 characters
        if [[ ${#label} -eq 0 ]]; then
            log_debug "RFC violation: Empty label in domain: $domain"
            return 1
        fi
        
        if [[ ${#label} -gt 63 ]]; then
            log_debug "RFC violation: Label too long (>63 chars): $label in $domain"
            return 1
        fi
        
        # RFC 952/1123: Labels can only contain letters, digits, and hyphens
        # Exception: Punycode labels starting with xn-- are allowed
        if [[ "$label" =~ ^xn-- ]]; then
            # Punycode label - allow additional characters as per IDN spec
            if [[ ! "$label" =~ ^[a-zA-Z0-9-]+$ ]]; then
                log_debug "RFC violation: Invalid characters in punycode label: $label"
                return 1
            fi
        else
            # Regular ASCII label
            if [[ ! "$label" =~ ^[a-zA-Z0-9-]+$ ]]; then
                log_debug "RFC violation: Invalid characters in label (only a-z, A-Z, 0-9, - allowed): $label"
                return 1
            fi
        fi
        
        # Labels should not start or end with hyphen (except punycode)
        # Exception: Punycode labels starting with xn-- are allowed to start with hyphen sequence
        if [[ ! "$label" =~ ^xn-- ]]; then
            if [[ "$label" =~ ^- ]]; then
                log_debug "RFC violation: Label starts with hyphen: $label"
                return 1
            fi
        fi
        
        if [[ "$label" =~ -$ ]]; then
            log_debug "RFC violation: Label ends with hyphen: $label"
            return 1
        fi
        
        # RFC 1123: Labels should start with a letter or digit (relaxed from RFC 952)
        # This is enforced by the character set check above
        
        # Additional RFC compliance checks in strict mode
        if [[ "$strict" == "yes" ]]; then
            # RFC 952: Hostnames should not be all numeric (but domain names can be)
            # Only apply this restriction to single-label hostnames
            if [[ ${#labels[@]} -eq 1 && "$label" =~ ^[0-9]+$ ]]; then
                log_debug "RFC strict: Single-label hostname cannot be all numeric: $label"
                return 1
            fi
            
            # RFC compliance: Labels should start with a letter (strict interpretation)
            if [[ ! "$label" =~ ^[a-zA-Z] && ! "$label" =~ ^xn-- ]]; then
                log_debug "RFC strict: Label should start with a letter: $label"
                return 1
            fi
        fi
    done
    
    # Additional validation: TLD should not be all numeric (RFC compliance)
    if [[ ${#labels[@]} -gt 1 ]]; then
        local tld="${labels[-1]}"
        if [[ "$tld" =~ ^[0-9]+$ ]]; then
            log_debug "RFC violation: TLD cannot be all numeric: $tld"
            return 1
        fi
        
        # TLD should be at least 2 characters (practical rule)
        if [[ ${#tld} -lt 2 ]]; then
            log_debug "RFC violation: TLD too short (<2 chars): $tld"
            return 1
        fi
    fi
    
    log_debug "RFC compliant ASCII FQDN validation passed: $domain"
    return 0
}

# ===============================================================================
# VALIDATION FUNCTIONS
# ===============================================================================

# Check if hostname is a valid IP address
is_ip_address() {
    local hostname="$1"
    
    if [[ "$hostname" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        local IFS='.'
        local ip=($hostname)
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        return $?
    fi
    
    if [[ "$hostname" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$hostname" == *":"* ]]; then
        return 0
    fi
    
    return 1
}

# Check if hostname has minimum required domain parts
has_min_domain_parts() {
    local hostname="$1"
    local min_parts="$2"
    
    local parts_count=$(echo "$hostname" | tr '.' '\n' | wc -l)
    [[ $parts_count -ge $min_parts ]]
}

# Advanced FQDN validation with international domain name support
is_valid_fqdn() {
    local hostname="$1"
    local strict="${2:-no}"
    
    if [[ -z "$hostname" ]]; then
        log_debug "Empty hostname provided"
        return 1
    fi
    
    # Use IDN-aware validation
    if is_valid_idn "$hostname" "$strict"; then
        log_debug "FQDN validation passed (IDN-aware): $hostname"
        return 0
    else
        log_debug "FQDN validation failed (IDN-aware): $hostname"
        return 1
    fi
}

# ===============================================================================
# DETECTION FUNCTIONS
# ===============================================================================

# Method 1: hostname -f command
detect_fqdn_hostname() {
    local detected=""
    
    if command_exists hostname; then
        detected=$(hostname -f 2>/dev/null || echo "")
        if is_valid_fqdn "$detected"; then
            log_debug "FQDN detected via hostname -f: $detected"
            echo "$detected"
            return 0
        fi
    fi
    
    log_debug "hostname -f method failed"
    return 1
}

# Method 2: systemd hostnamectl
detect_fqdn_hostnamectl() {
    local detected=""
    
    if command_exists hostnamectl; then
        detected=$(hostnamectl --static 2>/dev/null || echo "")
        if is_valid_fqdn "$detected"; then
            log_debug "FQDN detected via hostnamectl --static: $detected"
            echo "$detected"
            return 0
        fi
        
        detected=$(hostnamectl --pretty 2>/dev/null || echo "")
        if is_valid_fqdn "$detected"; then
            log_debug "FQDN detected via hostnamectl --pretty: $detected"
            echo "$detected"
            return 0
        fi
        
        detected=$(hostnamectl --transient 2>/dev/null || echo "")
        if is_valid_fqdn "$detected"; then
            log_debug "FQDN detected via hostnamectl --transient: $detected"
            echo "$detected"
            return 0
        fi
    fi
    
    log_debug "hostnamectl method failed"
    return 1
}

# Method 3: dnsdomainname + hostname combination
detect_fqdn_dns_domain() {
    local detected=""
    
    if command_exists dnsdomainname && command_exists hostname; then
        local domain=$(dnsdomainname 2>/dev/null || echo "")
        local hostname=$(hostname 2>/dev/null || echo "")
        
        if [[ -n "$domain" && -n "$hostname" ]]; then
            detected="$hostname.$domain"
            if is_valid_fqdn "$detected"; then
                log_debug "FQDN detected via dnsdomainname + hostname: $detected"
                echo "$detected"
                return 0
            fi
        fi
    fi
    
    log_debug "dnsdomainname + hostname method failed"
    return 1
}

# Method 4: /etc/hostname file
detect_fqdn_etc_hostname() {
    local detected=""
    
    if [[ -f "/etc/hostname" ]]; then
        detected=$(cat /etc/hostname 2>/dev/null | head -1 | tr -d '\n\r')
        if is_valid_fqdn "$detected"; then
            log_debug "FQDN detected via /etc/hostname: $detected"
            echo "$detected"
            return 0
        fi
    fi
    
    log_debug "/etc/hostname method failed"
    return 1
}

# Method 5: /etc/hosts file analysis
detect_fqdn_etc_hosts() {
    local detected=""
    
    if [[ -f "/etc/hosts" ]]; then
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue
            
            local ip=$(echo "$line" | awk '{print $1}')
            local hostnames=$(echo "$line" | awk '{for(i=2;i<=NF;i++) print $i}')
            
            if [[ "$ip" == "127.0.0.1" || "$ip" == "::1" ]]; then
                [[ "$ALLOW_LOCALHOST" != "yes" ]] && continue
            fi
            
            for hostname in $hostnames; do
                if is_valid_fqdn "$hostname"; then
                    log_debug "FQDN detected via /etc/hosts: $hostname"
                    echo "$hostname"
                    return 0
                fi
            done
        done < /etc/hosts
    fi
    
    log_debug "/etc/hosts method failed"
    return 1
}

# Method 6: Reverse DNS lookup
detect_fqdn_reverse_dns() {
    local detected=""
    local primary_ip=""
    
    if command_exists hostname; then
        primary_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "")
    fi
    
    if [[ -z "$primary_ip" ]] && command_exists ip; then
        primary_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[^ ]+' || echo "")
    fi
    
    if [[ -n "$primary_ip" && "$primary_ip" != "127.0.0.1" ]]; then
        if command_exists nslookup; then
            detected=$(timeout "$DNS_TIMEOUT" nslookup "$primary_ip" 2>/dev/null | grep "name =" | awk '{print $4}' | sed 's/\.$//' || echo "")
        elif command_exists dig; then
            detected=$(timeout "$DNS_TIMEOUT" dig +short -x "$primary_ip" 2>/dev/null | sed 's/\.$//' || echo "")
        elif command_exists host; then
            detected=$(timeout "$DNS_TIMEOUT" host "$primary_ip" 2>/dev/null | awk '{print $NF}' | sed 's/\.$//' || echo "")
        fi
        
        if is_valid_fqdn "$detected"; then
            log_debug "FQDN detected via reverse DNS: $detected"
            echo "$detected"
            return 0
        fi
    fi
    
    log_debug "Reverse DNS method failed"
    return 1
}

# Method 7: Cloud metadata services
detect_fqdn_cloud_metadata() {
    local detected=""
    
    if command_exists curl; then
        detected=$(timeout 3 curl -s -f "http://169.254.169.254/latest/meta-data/public-hostname" 2>/dev/null || echo "")
        if is_valid_fqdn "$detected"; then
            log_debug "FQDN detected via AWS metadata: $detected"
            echo "$detected"
            return 0
        fi
    fi
    
    if command_exists curl; then
        detected=$(timeout 3 curl -s -f -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/hostname" 2>/dev/null || echo "")
        if is_valid_fqdn "$detected"; then
            log_debug "FQDN detected via GCP metadata: $detected"
            echo "$detected"
            return 0
        fi
    fi
    
    if command_exists curl; then
        detected=$(timeout 3 curl -s -f -H "Metadata: true" "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text" 2>/dev/null || echo "")
        if is_valid_fqdn "$detected"; then
            log_debug "FQDN detected via Azure metadata: $detected"
            echo "$detected"
            return 0
        fi
    fi
    
    log_debug "Cloud metadata method failed"
    return 1
}

# ===============================================================================
# DNS VALIDATION FUNCTIONS
# ===============================================================================

# Check DNS resolution with multiple tools (IDN-aware)
check_dns_resolution() {
    local fqdn="$1"
    local timeout="${2:-$DNS_TIMEOUT}"
    
    log_debug "Checking DNS resolution for: $fqdn"
    
    # Normalize domain to punycode for DNS queries
    local normalized_fqdn=""
    if normalized_fqdn=$(normalize_domain "$fqdn"); then
        log_debug "Domain normalized for DNS: $fqdn → $normalized_fqdn"
    else
        log_error "Failed to normalize domain for DNS resolution: $fqdn"
        return 1
    fi
    
    local resolved=false
    local resolution_method=""
    
    if command_exists nslookup && [[ "$resolved" == "false" ]]; then
        if timeout "$timeout" nslookup "$normalized_fqdn" &>/dev/null; then
            resolved=true
            resolution_method="nslookup"
            log_dns_query "A_record" "$normalized_fqdn" "success" "nslookup"
        else
            log_dns_query "A_record" "$normalized_fqdn" "failed" "nslookup"
        fi
    fi
    
    if command_exists dig && [[ "$resolved" == "false" ]]; then
        if timeout "$timeout" dig +short "$normalized_fqdn" &>/dev/null; then
            resolved=true
            resolution_method="dig"
            log_dns_query "A_record" "$normalized_fqdn" "success" "dig"
        else
            log_dns_query "A_record" "$normalized_fqdn" "failed" "dig"
        fi
    fi
    
    if command_exists host && [[ "$resolved" == "false" ]]; then
        if timeout "$timeout" host "$normalized_fqdn" &>/dev/null; then
            resolved=true
            resolution_method="host"
            log_dns_query "A_record" "$normalized_fqdn" "success" "host"
        else
            log_dns_query "A_record" "$normalized_fqdn" "failed" "host"
        fi
    fi
    
    if command_exists getent && [[ "$resolved" == "false" ]]; then
        if timeout "$timeout" getent hosts "$normalized_fqdn" &>/dev/null; then
            resolved=true
            resolution_method="getent"
            log_dns_query "hosts_lookup" "$normalized_fqdn" "success" "getent"
        else
            log_dns_query "hosts_lookup" "$normalized_fqdn" "failed" "getent"
        fi
    fi
    
    if command_exists ping && [[ "$resolved" == "false" ]]; then
        if timeout "$PING_TIMEOUT" ping -c 1 -W "$PING_TIMEOUT" "$normalized_fqdn" &>/dev/null; then
            resolved=true
            resolution_method="ping"
            log_dns_query "ping_test" "$normalized_fqdn" "success" "ping"
        else
            log_dns_query "ping_test" "$normalized_fqdn" "failed" "ping"
        fi
    fi
    
    if [[ "$resolved" == "true" ]]; then
        log_debug "DNS resolution successful via $resolution_method"
        return 0
    else
        log_debug "DNS resolution failed for $fqdn (normalized: $normalized_fqdn)"
        return 1
    fi
}

# Get IP addresses for a given FQDN
get_ip_addresses() {
    local fqdn="$1"
    local timeout="${2:-$DNS_TIMEOUT}"
    local ip_addresses=()
    
    log_debug "Getting IP addresses for: $fqdn"
    
    # Try different methods to get IP addresses
    if command_exists dig; then
        # Get IPv4 addresses (A records)
        local ipv4_addresses=$(timeout "$timeout" dig +short A "$fqdn" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+

# ===============================================================================
# CAA RECORD VALIDATION FUNCTIONS
# ===============================================================================

# Extract domain hierarchy from FQDN
get_domain_hierarchy() {
    local fqdn="$1"
    local domains=()
    
    # Remove trailing dot if present
    fqdn="${fqdn%.}"
    
    # Split domain into parts
    local IFS='.'
    local parts=($fqdn)
    
    # Build domain hierarchy from specific to general
    for ((i=0; i<${#parts[@]}; i++)); do
        local domain=""
        for ((j=i; j<${#parts[@]}; j++)); do
            if [[ -n "$domain" ]]; then
                domain="$domain.${parts[j]}"
            else
                domain="${parts[j]}"
            fi
        done
        domains+=("$domain")
    done
    
    printf '%s\n' "${domains[@]}"
}

# Check CAA record for a specific domain (IDN-aware)
check_caa_record() {
    local domain="$1"
    local timeout="${2:-$DNS_TIMEOUT}"
    
    log_debug "Checking CAA record for domain: $domain"
    
    # Normalize domain to punycode for DNS queries
    local normalized_domain=""
    if normalized_domain=$(normalize_domain "$domain"); then
        log_debug "Domain normalized for CAA lookup: $domain → $normalized_domain"
    else
        log_error "Failed to normalize domain for CAA lookup: $domain"
        return 1
    fi
    
    local caa_records=""
    local query_method=""
    
    # Try different DNS tools to query CAA records
    if command_exists dig; then
        caa_records=$(timeout "$timeout" dig +short CAA "$normalized_domain" 2>/dev/null || echo "")
        query_method="dig"
    elif command_exists nslookup; then
        # nslookup doesn't support CAA records directly, but we can try
        caa_records=$(timeout "$timeout" nslookup -type=CAA "$normalized_domain" 2>/dev/null | grep -E "issue|issuewild|iodef" || echo "")
        query_method="nslookup"
    elif command_exists host; then
        caa_records=$(timeout "$timeout" host -t CAA "$normalized_domain" 2>/dev/null || echo "")
        query_method="host"
    fi
    
    if [[ -n "$caa_records" ]]; then
        log_debug "CAA records found for $domain (normalized: $normalized_domain) via $query_method"
        echo "$caa_records"
        return 0
    else
        log_debug "No CAA records found for $domain (normalized: $normalized_domain)"
        return 1
    fi
}

# Parse CAA record and check if CA is allowed
is_ca_allowed_by_caa() {
    local caa_record="$1"
    local ca_identifier="$2"
    
    # Common CA identifiers
    local common_cas=(
        "letsencrypt.org"
        "amazon.com"
        "digicert.com"
        "globalsign.com"
        "sectigo.com"
        "godaddy.com"
        "comodo.com"
    )
    
    # If no specific CA provided, check against common ones
    if [[ -z "$ca_identifier" ]]; then
        for ca in "${common_cas[@]}"; do
            if echo "$caa_record" | grep -q "issue.*$ca"; then
                return 0
            fi
        done
        return 1
    fi
    
    # Check if specific CA is allowed
    if echo "$caa_record" | grep -q "issue.*$ca_identifier"; then
        return 0
    fi
    
    return 1
}

# Comprehensive CAA record checking for SSL certificate rollout
check_caa_ssl_compatibility() {
    local fqdn="$1"
    local ca_identifier="${2:-letsencrypt.org}"
    
    log_info "Checking CAA records for SSL certificate compatibility: $fqdn"
    
    # Clear previous CAA results
    CAA_RESULTS=()
    
    local domains=($(get_domain_hierarchy "$fqdn"))
    local caa_blocking=false
    local caa_found=false
    local blocking_domain=""
    local allowed_cas=()
    
    log_debug "Domain hierarchy: ${domains[*]}"
    
    # Check each domain in the hierarchy
    for domain in "${domains[@]}"; do
        log_debug "Checking CAA for domain level: $domain"
        
        local caa_records=""
        if caa_records=$(check_caa_record "$domain"); then
            caa_found=true
            log_info "CAA records found for $domain"
            
            # Parse CAA records
            local has_issue_restriction=false
            local ca_allowed=false
            local wildcard_allowed=false
            
            while IFS= read -r record; do
                if [[ -n "$record" ]]; then
                    log_debug "CAA record: $record"
                    
                    # Check for issue restriction
                    if echo "$record" | grep -q "issue"; then
                        has_issue_restriction=true
                        
                        # Check if our CA is allowed
                        if is_ca_allowed_by_caa "$record" "$ca_identifier"; then
                            ca_allowed=true
                            log_success "CA $ca_identifier is allowed by CAA record"
                        fi
                        
                        # Extract allowed CAs
                        local allowed_ca=$(echo "$record" | grep -oE 'issue[[:space:]]+"[^"]+"' | cut -d'"' -f2)
                        if [[ -n "$allowed_ca" ]]; then
                            allowed_cas+=("$allowed_ca")
                        fi
                    fi
                    
                    # Check for wildcard restrictions
                    if echo "$record" | grep -q "issuewild"; then
                        if is_ca_allowed_by_caa "$record" "$ca_identifier"; then
                            wildcard_allowed=true
                            log_success "Wildcard certificates allowed for $ca_identifier"
                        fi
                    fi
                    
                    # Check for iodef (incident reporting)
                    if echo "$record" | grep -q "iodef"; then
                        local iodef_contact=$(echo "$record" | grep -oE 'iodef[[:space:]]+"[^"]+"' | cut -d'"' -f2)
                        log_info "CAA incident reporting configured: $iodef_contact"
                        CAA_RESULTS+=("iodef:$domain:$iodef_contact")
                    fi
                fi
            done <<< "$caa_records"
            
            # If issue restriction exists but CA not allowed, it's blocking
            if [[ "$has_issue_restriction" == "true" && "$ca_allowed" == "false" ]]; then
                caa_blocking=true
                blocking_domain="$domain"
                log_warning "CAA records at $domain would block $ca_identifier"
                CAA_RESULTS+=("blocking:$domain:$ca_identifier")
                break
            elif [[ "$has_issue_restriction" == "true" && "$ca_allowed" == "true" ]]; then
                log_success "CAA records at $domain allow $ca_identifier"
                CAA_RESULTS+=("allowed:$domain:$ca_identifier")
            fi
        else
            log_debug "No CAA records found for $domain"
            CAA_RESULTS+=("no_caa:$domain")
        fi
    done
    
    # Generate summary
    if [[ "$caa_blocking" == "true" ]]; then
        log_error "CAA records would block SSL certificate issuance"
        log_error "Blocking domain: $blocking_domain"
        if [[ ${#allowed_cas[@]} -gt 0 ]]; then
            log_info "Allowed CAs: ${allowed_cas[*]}"
        fi
        return 1
    elif [[ "$caa_found" == "true" ]]; then
        log_success "CAA records found but do not block $ca_identifier"
        return 0
    else
        log_info "No CAA records found - certificate issuance should proceed normally"
        return 0
    fi
}

# Get CAA checking results
get_caa_results() {
    printf '%s\n' "${CAA_RESULTS[@]}"
}

# ===============================================================================
# MAIN DETECTION FUNCTION
# ===============================================================================

# Main FQDN detection function with comprehensive reporting
auto_detect_fqdn() {
    local provided_fqdn="$1"
    local require_ssl="${2:-$REQUIRE_SSL}"
    local check_dns="${3:-$CHECK_DNS}"
    
    DETECTED_FQDN=""
    DETECTION_METHOD=""
    DETECTION_RESULTS=()
    VALIDATION_RESULTS=()
    
    log_info "Starting FQDN detection process..."
    log_debug "Parameters: provided_fqdn='$provided_fqdn', require_ssl='$require_ssl', check_dns='$check_dns'"
    
    # Perform comprehensive IP detection first
    log_info "Detecting server IP configuration..."
    detect_ip_configuration >/dev/null
    
    if [[ -n "$provided_fqdn" ]]; then
        log_info "Validating provided FQDN: $provided_fqdn"
        
        if is_valid_fqdn "$provided_fqdn"; then
            log_success "Provided FQDN is valid: $provided_fqdn"
            DETECTED_FQDN="$provided_fqdn"
            DETECTION_METHOD="user-provided"
            
            if [[ "$check_dns" == "yes" ]]; then
                if check_dns_resolution "$provided_fqdn"; then
                    log_success "Provided FQDN resolves correctly"
                    VALIDATION_RESULTS+=("dns:success")
                    
                    # Check reverse DNS consistency
                    if validate_reverse_dns_comprehensive "$provided_fqdn"; then
                        log_success "Comprehensive reverse DNS validation passed"
                        VALIDATION_RESULTS+=("reverse_dns:consistent")
                    else
                        log_warning "Comprehensive reverse DNS validation failed or inconsistent"
                        VALIDATION_RESULTS+=("reverse_dns:inconsistent")
                    fi
                else
                    log_warning "Provided FQDN does not resolve (may be expected for new domains)"
                    VALIDATION_RESULTS+=("dns:failed")
                fi
            fi
            
            # Check CAA records if SSL is required
            if [[ "$require_ssl" == "yes" ]]; then
                if check_caa_ssl_compatibility "$provided_fqdn"; then
                    log_success "CAA records do not block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:compatible")
                else
                    log_warning "CAA records may block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:blocking")
                fi
            fi
            
            echo "$provided_fqdn"
            return 0
        else
            log_error "Provided FQDN is invalid: $provided_fqdn"
            if [[ "$require_ssl" == "yes" ]]; then
                log_error "Valid FQDN is required for SSL certificate enrollment"
                return 1
            fi
        fi
    fi
    
    log_info "Auto-detecting FQDN using multiple methods..."
    
    local methods=(
        "detect_fqdn_hostname:hostname -f command:system"
        "detect_fqdn_hostnamectl:systemd hostnamectl:system"
        "detect_fqdn_dns_domain:dnsdomainname + hostname:dns"
        "detect_fqdn_etc_hostname:/etc/hostname file:file"
        "detect_fqdn_etc_hosts:/etc/hosts file:file"
        "detect_fqdn_reverse_dns:reverse DNS lookup:dns"
        "detect_fqdn_cloud_metadata:cloud metadata services:cloud"
    )
    
    for method_info in "${methods[@]}"; do
        local method_func="${method_info%%:*}"
        local method_desc="${method_info#*:}"
        method_desc="${method_desc%:*}"
        local method_type="${method_info##*:}"
        
        log_info "Trying: $method_desc"
        
        if detected_fqdn=$($method_func); then
            log_success "FQDN detected via $method_desc: $detected_fqdn"
            DETECTED_FQDN="$detected_fqdn"
            DETECTION_METHOD="$method_func"
            DETECTION_RESULTS+=("$method_func:success:$detected_fqdn")
            
            # Log structured detection result
            log_fqdn_detection "$detected_fqdn" "$method_func" "success"
            
            if [[ "$check_dns" == "yes" ]]; then
                if check_dns_resolution "$detected_fqdn"; then
                    log_success "Detected FQDN resolves correctly"
                    VALIDATION_RESULTS+=("dns:success")
                    log_validation_result "$detected_fqdn" "dns_resolution" "success"
                    
                    # Check reverse DNS consistency
                    if validate_reverse_dns_comprehensive "$detected_fqdn"; then
                        log_success "Comprehensive reverse DNS validation passed"
                        VALIDATION_RESULTS+=("reverse_dns:consistent")
                        log_validation_result "$detected_fqdn" "reverse_dns" "consistent"
                    else
                        log_warning "Comprehensive reverse DNS validation failed or inconsistent"
                        VALIDATION_RESULTS+=("reverse_dns:inconsistent")
                        log_validation_result "$detected_fqdn" "reverse_dns" "inconsistent"
                    fi
                else
                    log_warning "Detected FQDN does not resolve"
                    VALIDATION_RESULTS+=("dns:failed")
                    log_validation_result "$detected_fqdn" "dns_resolution" "failed"
                fi
            fi
            
            # Check CAA records if SSL is required
            if [[ "$require_ssl" == "yes" ]]; then
                if check_caa_ssl_compatibility "$detected_fqdn"; then
                    log_success "CAA records do not block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:compatible")
                    log_validation_result "$detected_fqdn" "caa_records" "compatible"
                else
                    log_warning "CAA records may block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:blocking")
                    log_validation_result "$detected_fqdn" "caa_records" "blocking"
                fi
            fi
            
            echo "$detected_fqdn"
            return 0
        else
            log_warning "No valid FQDN found via $method_desc"
            DETECTION_RESULTS+=("$method_func:failed")
        fi
    done
    
    log_warning "Could not auto-detect valid FQDN using any method"
    
    if [[ "$require_ssl" == "yes" ]]; then
        log_error "FQDN is required for SSL certificate enrollment"
        log_info "Please provide a valid FQDN using appropriate parameters"
        return 1
    elif [[ "$ALLOW_LOCALHOST" == "yes" ]]; then
        log_info "Using localhost as fallback"
        DETECTED_FQDN="localhost"
        DETECTION_METHOD="fallback"
        echo "localhost"
        return 0
    else
        log_error "No valid FQDN found and localhost not allowed"
        return 1
    fi
}

# ===============================================================================
# OUTPUT AND REPORTING FUNCTIONS
# ===============================================================================

# Generate JSON output
generate_json_output() {
    local fqdn="$1"
    local status="$2"
    
    cat << EOF
{
  "timestamp": "$(get_timestamp)",
  "script": {
    "name": "$SCRIPT_NAME",
    "version": "$SCRIPT_VERSION"
  },
  "detection": {
    "fqdn": "$fqdn",
    "method": "$DETECTION_METHOD",
    "status": "$status"
  },
  "validation": {
    "dns_check": "$CHECK_DNS",
    "results": [$(printf '"%s",' "${VALIDATION_RESULTS[@]}" | sed 's/,$//')"]
  },
  "caa_check": {
    "results": [$(printf '"%s",' "${CAA_RESULTS[@]}" | sed 's/,$//')"]
  },
  "reverse_dns_check": {
    "results": [$(printf '"%s",' "${REVERSE_DNS_RESULTS[@]}" | sed 's/,$//')"]
  },
  "ip_detection": {
    "results": [$(printf '"%s",' "${IP_DETECTION_RESULTS[@]}" | sed 's/,$//')"]
  },
  "config": {
    "require_ssl": "$REQUIRE_SSL",
    "allow_localhost": "$ALLOW_LOCALHOST",
    "allow_ip_as_fqdn": "$ALLOW_IP_AS_FQDN",
    "min_domain_parts": "$MIN_DOMAIN_PARTS"
  },
  "detection_attempts": [$(printf '"%s",' "${DETECTION_RESULTS[@]}" | sed 's/,$//')")]
}
EOF
}

# Generate XML output
generate_xml_output() {
    local fqdn="$1"
    local status="$2"
    
    cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<fqdn_detection>
  <timestamp>$(get_timestamp)</timestamp>
  <script>
    <name>$SCRIPT_NAME</name>
    <version>$SCRIPT_VERSION</version>
  </script>
  <detection>
    <fqdn>$fqdn</fqdn>
    <method>$DETECTION_METHOD</method>
    <status>$status</status>
  </detection>
  <validation>
    <dns_check>$CHECK_DNS</dns_check>
    <results>
$(for result in "${VALIDATION_RESULTS[@]}"; do echo "      <result>$result</result>"; done)
    </results>
  </validation>
  <caa_check>
    <results>
$(for result in "${CAA_RESULTS[@]}"; do echo "      <result>$result</result>"; done)
    </results>
  </caa_check>
  <config>
    <require_ssl>$REQUIRE_SSL</require_ssl>
    <allow_localhost>$ALLOW_LOCALHOST</allow_localhost>
    <allow_ip_as_fqdn>$ALLOW_IP_AS_FQDN</allow_ip_as_fqdn>
    <min_domain_parts>$MIN_DOMAIN_PARTS</min_domain_parts>
  </config>
  <detection_attempts>
$(for result in "${DETECTION_RESULTS[@]}"; do echo "    <attempt>$result</attempt>"; done)
  </detection_attempts>
</fqdn_detection>
EOF
}

# ===============================================================================
# GETTER FUNCTIONS
# ===============================================================================

# Get the detected FQDN
get_detected_fqdn() {
    echo "$DETECTED_FQDN"
}

# Get the detection method used
get_detection_method() {
    echo "$DETECTION_METHOD"
}

# Get all detection results
get_detection_results() {
    printf '%s\n' "${DETECTION_RESULTS[@]}"
}

# Get validation results
get_validation_results() {
    printf '%s\n' "${VALIDATION_RESULTS[@]}"
}

# ===============================================================================
# VALIDATION AND REPORTING FUNCTIONS
# ===============================================================================

# Comprehensive FQDN validation with detailed reporting
validate_fqdn_comprehensive() {
    local fqdn="$1"
    local check_dns="${2:-$CHECK_DNS}"
    local strict="${3:-no}"
    
    log_info "Performing comprehensive FQDN validation for: $fqdn"
    
    local validation_passed=true
    local validation_details=()
    
    if is_valid_fqdn "$fqdn" "$strict"; then
        log_success "FQDN format validation passed"
        validation_details+=("format:passed")
    else
        log_error "FQDN format validation failed"
        validation_details+=("format:failed")
        validation_passed=false
    fi
    
    if [[ "$check_dns" == "yes" ]]; then
        if check_dns_resolution "$fqdn"; then
            log_success "DNS resolution validation passed"
            validation_details+=("dns:passed")
            
            # Check reverse DNS consistency
            if validate_reverse_dns_comprehensive "$fqdn"; then
                log_success "Comprehensive reverse DNS validation passed"
                validation_details+=("reverse_dns:consistent")
            else
                log_warning "Comprehensive reverse DNS validation failed or inconsistent"
                validation_details+=("reverse_dns:inconsistent")
                # Don't fail validation for reverse DNS issues unless strict mode
                [[ "$strict" == "yes" ]] && validation_passed=false
            fi
        else
            log_warning "DNS resolution validation failed"
            validation_details+=("dns:failed")
            [[ "$strict" == "yes" ]] && validation_passed=false
        fi
    fi
    
    if [[ "$REQUIRE_SSL" == "yes" ]]; then
        if [[ "$fqdn" != "localhost" ]] && [[ "$fqdn" != "127.0.0.1" ]] && ! is_ip_address "$fqdn"; then
            log_success "SSL readiness validation passed"
            validation_details+=("ssl:ready")
            
            # Check CAA records for SSL compatibility
            if check_caa_ssl_compatibility "$fqdn"; then
                log_success "CAA validation passed"
                validation_details+=("caa:compatible")
            else
                log_warning "CAA validation failed"
                validation_details+=("caa:blocking")
                [[ "$strict" == "yes" ]] && validation_passed=false
            fi
        else
            log_error "SSL readiness validation failed (localhost/IP not suitable for SSL)"
            validation_details+=("ssl:not_ready")
            validation_passed=false
        fi
    fi
    
    VALIDATION_RESULTS=("${validation_details[@]}")
    
    if [[ "$validation_passed" == "true" ]]; then
        log_success "Comprehensive FQDN validation passed"
        return 0
    else
        log_error "Comprehensive FQDN validation failed"
        return 1
    fi
}

# Show detailed FQDN detection and validation summary
show_fqdn_summary() {
    local fqdn="$1"
    
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}                           FQDN DETECTION SUMMARY                              ${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${CYAN}Detection Results:${NC}"
    echo -e "${GREEN}• Detected FQDN: ${NC}${fqdn:-"Not detected"}"
    echo -e "${GREEN}• Detection Method: ${NC}${DETECTION_METHOD:-"None"}"
    echo -e "${GREEN}• Timestamp: ${NC}$(get_timestamp)"
    echo ""
    
    echo -e "${CYAN}Validation Status:${NC}"
    if [[ -n "$fqdn" && "$fqdn" != "localhost" ]]; then
        echo -e "${GREEN}• SSL Ready: ${NC}Yes"
        echo -e "${GREEN}• Domain Configuration: ${NC}Ready"
        echo -e "${GREEN}• External Access: ${NC}Possible"
    else
        echo -e "${YELLOW}• SSL Ready: ${NC}No (localhost or invalid FQDN)"
        echo -e "${YELLOW}• Domain Configuration: ${NC}Manual setup required"
        echo -e "${YELLOW}• External Access: ${NC}Limited"
    fi
    echo ""
    
    if [[ ${#VALIDATION_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}Validation Details:${NC}"
        for result in "${VALIDATION_RESULTS[@]}"; do
            local check="${result%%:*}"
            local status="${result#*:}"
            local icon="✓"
            local color="$GREEN"
            
            if [[ "$status" == "failed" ]] || [[ "$status" == "not_ready" ]] || [[ "$status" == "blocking" ]]; then
                icon="✗"
                color="$RED"
            elif [[ "$status" == "warning" ]]; then
                icon="⚠"
                color="$YELLOW"
            fi
            
            echo -e "${color}  $icon $check: $status${NC}"
        done
        echo ""
    fi
    
    if [[ ${#IP_DETECTION_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}IP Address Analysis:${NC}"
        local local_ips=()
        local external_ip=""
        local behind_nat="unknown"
        local nat_type=""
        
        for result in "${IP_DETECTION_RESULTS[@]}"; do
            local type="${result%%:*}"
            local value="${result#*:}"
            
            case "$type" in
                "local")
                    local ip="${value%%:*}"
                    local ip_type="${value#*:}"
                    local_ips+=("$ip")
                    if [[ "$ip_type" == "private" ]]; then
                        echo -e "${BLUE}  • Local IP: ${NC}$ip ${YELLOW}(private)${NC}"
                    else
                        echo -e "${BLUE}  • Local IP: ${NC}$ip ${GREEN}(public)${NC}"
                    fi
                    ;;
                "external")
                    external_ip="${value%%:*}"
                    echo -e "${GREEN}  • External IP: ${NC}$external_ip ${GREEN}(public)${NC}"
                    ;;
                "behind_nat")
                    behind_nat="$value"
                    ;;
                "nat_type")
                    nat_type="$value"
                    ;;
            esac
        done
        
        echo ""
        echo -e "${CYAN}Network Configuration:${NC}"
        if [[ "$behind_nat" == "true" ]]; then
            echo -e "${YELLOW}  • Behind NAT: Yes ($nat_type)${NC}"
            echo -e "${YELLOW}  • Impact: External services see $external_ip, internal services see ${local_ips[0]:-unknown}${NC}"
        elif [[ "$behind_nat" == "false" ]]; then
            echo -e "${GREEN}  • Behind NAT: No (direct public IP access)${NC}"
        else
            echo -e "${BLUE}  • Behind NAT: Unknown${NC}"
        fi
        
        if [[ -n "$external_ip" && ${#local_ips[@]} -gt 0 ]]; then
            echo -e "${BLUE}  • Total IPs detected: $((${#local_ips[@]} + 1))${NC}"
        elif [[ ${#local_ips[@]} -gt 0 ]]; then
            echo -e "${BLUE}  • Total IPs detected: ${#local_ips[@]} (local only)${NC}"
        fi
        echo ""
    fi

    if [[ ${#REVERSE_DNS_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}Reverse DNS Analysis:${NC}"
        local matches=0
        local mismatches=0
        local failures=0
        
        for result in "${REVERSE_DNS_RESULTS[@]}"; do
            local ip="${result%%:*}"
            local reverse_hostname="${result#*:}"
            
            if [[ "$reverse_hostname" == "no_reverse_dns" ]]; then
                echo -e "${RED}  ✗ $ip: No reverse DNS record${NC}"
                ((failures++))
            elif [[ "$reverse_hostname" == "$fqdn" ]]; then
                echo -e "${GREEN}  ✓ $ip: $reverse_hostname (matches)${NC}"
                ((matches++))
            else
                echo -e "${YELLOW}  ⚠ $ip: $reverse_hostname (differs from $fqdn)${NC}"
                ((mismatches++))
            fi
        done
        
        echo ""
        echo -e "${CYAN}Reverse DNS Summary:${NC}"
        echo -e "${BLUE}• Total IPs: $((matches + mismatches + failures))${NC}"
        echo -e "${GREEN}• Matching: $matches${NC}"
        echo -e "${YELLOW}• Different: $mismatches${NC}"
        echo -e "${RED}• No reverse DNS: $failures${NC}"
        
        if [[ $mismatches -gt 0 ]]; then
            echo -e "${YELLOW}• Impact: Reverse DNS mismatches may affect email delivery and some services${NC}"
        fi
        echo ""
    fi

    if [[ ${#CAA_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}CAA Record Analysis:${NC}"
        for result in "${CAA_RESULTS[@]}"; do
            local type="${result%%:*}"
            local domain="${result#*:}"
            domain="${domain%%:*}"
            local details="${result##*:}"
            
            local icon="ℹ"
            local color="$BLUE"
            
            case "$type" in
                "blocking")
                    icon="✗"
                    color="$RED"
                    echo -e "${color}  $icon Domain $domain blocks CA: $details${NC}"
                    ;;
                "allowed")
                    icon="✓"
                    color="$GREEN"
                    echo -e "${color}  $icon Domain $domain allows CA: $details${NC}"
                    ;;
                "no_caa")
                    icon="○"
                    color="$BLUE"
                    echo -e "${color}  $icon No CAA records for: $domain${NC}"
                    ;;
                "iodef")
                    icon="📧"
                    color="$CYAN"
                    echo -e "${color}  $icon Incident reporting configured for $domain: $details${NC}"
                    ;;
            esac
        done
        echo ""
    fi
    
    if [[ ${#DETECTION_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}Detection Attempts:${NC}"
        for result in "${DETECTION_RESULTS[@]}"; do
            local method="${result%%:*}"
            local status="${result#*:}"
            status="${status%%:*}"
            local detected="${result##*:}"
            
            local icon="✓"
            local color="$GREEN"
            
            if [[ "$status" == "failed" ]]; then
                icon="✗"
                color="$RED"
                detected="N/A"
            fi
            
            echo -e "${color}  $icon $method: $status${NC}"
            [[ "$detected" != "N/A" && "$detected" != "$method" ]] && echo -e "    ${CYAN}→ $detected${NC}"
        done
        echo ""
    fi
    
    echo -e "${CYAN}Current Configuration:${NC}"
    echo -e "${BLUE}• Require SSL: ${NC}$REQUIRE_SSL"
    echo -e "${BLUE}• Check DNS: ${NC}$CHECK_DNS"
    echo -e "${BLUE}• Allow Localhost: ${NC}$ALLOW_LOCALHOST"
    echo -e "${BLUE}• Allow IP as FQDN: ${NC}$ALLOW_IP_AS_FQDN"
    
    if [[ "$LOG_MACHINE_FORMAT" == "yes" && -n "$LOG_FILE" ]]; then
        echo ""
        echo -e "${CYAN}Machine-Readable Logs:${NC}"
        echo -e "${BLUE}• Log File: ${NC}$LOG_FILE"
        if [[ -f "$LOG_FILE" ]]; then
            local log_lines=$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)
            echo -e "${BLUE}• Entries: ${NC}$log_lines JSON records"
            echo -e "${BLUE}• View: ${NC}tail -f $LOG_FILE | jq ."
        fi
    fi
    echo ""
}

# ===============================================================================
# TESTING FRAMEWORK
# ===============================================================================

# Test IDN functionality
test_idn_support() {
    echo "Testing International Domain Name (IDN) support..."
    echo ""
    
    # Test IDN conversion tools availability
    echo "  Checking IDN tools availability:"
    if command_exists idn; then
        echo -e "    ${GREEN}✓ idn command available${NC}"
    else
        echo -e "    ${YELLOW}⚠ idn command not available (install libidn2-tools)${NC}"
    fi
    
    if command_exists python3; then
        if python3 -c "import sys; 'test'.encode('idna')" &>/dev/null; then
            echo -e "    ${GREEN}✓ Python3 IDNA support available${NC}"
        else
            echo -e "    ${YELLOW}⚠ Python3 IDNA support not available${NC}"
        fi
    else
        echo -e "    ${YELLOW}⚠ Python3 not available${NC}"
    fi
    
    echo ""
    
    # Test domain validation with various formats
    local test_domains=(
        "example.com:ascii"
        "xn--mller-kva.de:punycode"
        "müller.de:unicode"
        "测试.中国:unicode"
        "тест.рф:unicode"
        "xn--0zwm56d.xn--fiqs8s:punycode"
        "العربية.السعودية:unicode"
    )
    
    echo "  Testing domain validation:"
    for test_case in "${test_domains[@]}"; do
        local domain="${test_case%%:*}"
        local type="${test_case#*:}"
        
        echo -n "    Testing $type domain ($domain): "
        
        if is_valid_fqdn "$domain"; then
            echo -e "${GREEN}✓ Valid${NC}"
        else
            echo -e "${RED}✗ Invalid${NC}"
        fi
    done
    
    echo ""
    
    # Test domain normalization if tools are available
    if command_exists idn || command_exists python3; then
        echo "  Testing domain normalization:"
        
        local unicode_domains=("müller.de" "测试.中国" "тест.рф")
        
        for domain in "${unicode_domains[@]}"; do
            echo -n "    Normalizing $domain: "
            
            local normalized=""
            if normalized=$(normalize_domain "$domain" 2>/dev/null); then
                echo -e "${GREEN}✓ $normalized${NC}"
            else
                echo -e "${RED}✗ Failed${NC}"
            fi
        done
    else
        echo -e "    ${YELLOW}⚠ Domain normalization not available (no IDN tools)${NC}"
    fi
    
    echo ""
}

# Test individual validation functions
test_validation_functions() {
    echo "Testing FQDN validation functions (RFC compliant)..."
    echo ""
    
    local test_cases=(
        "example.com:valid:RFC compliant domain"
        "sub.example.com:valid:RFC compliant subdomain"
        "very.long.domain.example.com:valid:RFC compliant long domain"
        "test-site.example.com:valid:RFC compliant with hyphens"
        "xn--mller-kva.de:valid:RFC compliant punycode"
        "müller.de:valid:IDN domain (converted to punycode)"
        "测试.中国:valid:IDN domain (converted to punycode)"
        "localhost:depends_on_config:Special case"
        "192.168.1.1:depends_on_config:IP address"
        "-example.com:invalid:RFC violation - starts with hyphen"
        "example-.com:invalid:RFC violation - label ends with hyphen"
        "example..com:invalid:RFC violation - consecutive dots"
        "example.:invalid:RFC violation - ends with dot after normalization"
        ".example.com:invalid:RFC violation - starts with dot"
        "ex ample.com:invalid:RFC violation - contains space"
        "example.123:invalid:RFC violation - numeric TLD"
        "123:invalid:RFC violation - all numeric single label"
        "a.b:valid:Short but valid domain"
        "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z:valid:Long but valid domain"
    )
    
    echo "  Testing ASCII/RFC compliance:"
    for test_case in "${test_cases[@]}"; do
        local fqdn="${test_case%%:*}"
        local temp="${test_case#*:}"
        local expected="${temp%%:*}"
        local description="${temp#*:}"
        
        echo -n "    $fqdn ($description): "
        
        if is_valid_fqdn "$fqdn"; then
            if [[ "$expected" == "valid" ]]; then
                echo -e "${GREEN}✓ Valid (as expected)${NC}"
            elif [[ "$expected" == "depends_on_config" ]]; then
                echo -e "${YELLOW}✓ Valid (config dependent)${NC}"
            else
                echo -e "${RED}✗ Valid (expected invalid)${NC}"
            fi
        else
            if [[ "$expected" == "invalid" ]]; then
                echo -e "${GREEN}✓ Invalid (as expected)${NC}"
            elif [[ "$expected" == "depends_on_config" ]]; then
                echo -e "${YELLOW}✓ Invalid (config dependent)${NC}"
            else
                echo -e "${RED}✗ Invalid (expected valid)${NC}"
            fi
        fi
    done
    
    echo ""
    echo "  Testing RFC strict mode:"
    local strict_test_cases=(
        "123.example.com:valid:Numeric subdomain allowed"
        "test123.example.com:valid:Alphanumeric label"
        "test-123.example.com:valid:Mixed alphanumeric with hyphen"
        "123:invalid:All numeric single label (strict)"
        "1example.com:invalid:Label starts with digit (strict)"
    )
    
    for test_case in "${strict_test_cases[@]}"; do
        local fqdn="${test_case%%:*}"
        local temp="${test_case#*:}"
        local expected="${temp%%:*}"
        local description="${temp#*:}"
        
        echo -n "    $fqdn ($description): "
        
        if is_valid_ascii_fqdn "$fqdn" "yes"; then
            if [[ "$expected" == "valid" ]]; then
                echo -e "${GREEN}✓ Valid (strict)${NC}"
            else
                echo -e "${RED}✗ Valid (expected invalid in strict mode)${NC}"
            fi
        else
            if [[ "$expected" == "invalid" ]]; then
                echo -e "${GREEN}✓ Invalid (strict)${NC}"
            else
                echo -e "${RED}✗ Invalid (expected valid in strict mode)${NC}"
            fi
        fi
    done
    
    echo ""
}

# Test all detection methods
test_detection_methods() {
    echo "Testing FQDN detection methods..."
    echo ""
    
    local methods=(
        "detect_fqdn_hostname:hostname -f"
        "detect_fqdn_hostnamectl:hostnamectl"
        "detect_fqdn_dns_domain:dnsdomainname"
        "detect_fqdn_etc_hostname:/etc/hostname"
        "detect_fqdn_etc_hosts:/etc/hosts"
        "detect_fqdn_reverse_dns:reverse DNS"
        "detect_fqdn_cloud_metadata:cloud metadata"
    )
    
    for method_info in "${methods[@]}"; do
        local method_func="${method_info%%:*}"
        local method_desc="${method_info#*:}"
        
        echo -n "  Testing $method_desc... "
        
        if detected=$($method_func 2>/dev/null); then
            echo -e "${GREEN}✓ $detected${NC}"
        else
            echo -e "${YELLOW}- No result${NC}"
        fi
    done
    echo ""
}

# Test DNS resolution
test_dns_resolution() {
    local test_domains=("google.com" "github.com" "nonexistent.example.invalid")
    
    echo "Testing DNS resolution capabilities..."
    echo ""
    
    for domain in "${test_domains[@]}"; do
        echo -n "  Testing $domain... "
        
        if check_dns_resolution "$domain" 3; then
            echo -e "${GREEN}✓ Resolves${NC}"
        else
            echo -e "${RED}✗ Does not resolve${NC}"
        fi
    done
    echo ""
}

# Test IP detection functionality
test_ip_detection() {
    echo "Testing IP address detection..."
    echo ""
    
    echo "  Testing local IP detection:"
    local local_ips=($(get_local_ip_addresses))
    
    if [[ ${#local_ips[@]} -gt 0 ]]; then
        echo -e "    ${GREEN}✓ Found ${#local_ips[@]} local IP(s)${NC}"
        for ip in "${local_ips[@]}"; do
            if is_private_ip "$ip"; then
                echo -e "      ${YELLOW}$ip (private)${NC}"
            else
                echo -e "      ${GREEN}$ip (public)${NC}"
            fi
        done
    else
        echo -e "    ${RED}✗ No local IPs found${NC}"
    fi
    
    echo ""
    echo "  Testing external IP detection:"
    local external_ip=""
    if external_ip=$(get_external_ip_address 5); then
        echo -e "    ${GREEN}✓ External IP: $external_ip${NC}"
    else
        echo -e "    ${RED}✗ Could not detect external IP${NC}"
    fi
    
    echo ""
    echo "  Testing comprehensive IP analysis:"
    local ip_config_output=$(detect_ip_configuration)
    
    if [[ -n "$ip_config_output" ]]; then
        echo -e "    ${GREEN}✓ IP configuration analysis completed${NC}"
        
        local behind_nat=$(echo "$ip_config_output" | grep "behind_nat:" | cut -d: -f2)
        local nat_type=$(echo "$ip_config_output" | grep "nat_type:" | cut -d: -f2)
        
        if [[ "$behind_nat" == "true" ]]; then
            echo -e "    ${YELLOW}⚠ Server is behind NAT ($nat_type)${NC}"
        elif [[ "$behind_nat" == "false" ]]; then
            echo -e "    ${GREEN}ℹ Server has direct public IP access${NC}"
        else
            echo -e "    ${BLUE}ℹ NAT status unknown${NC}"
        fi
    else
        echo -e "    ${RED}✗ IP configuration analysis failed${NC}"
    fi
    
    # Clear results for next test
    IP_DETECTION_RESULTS=()
    echo ""
}
    local test_domains=("google.com" "github.com" "cloudflare.com")
    
    echo "Testing reverse DNS functionality..."
    echo ""
    
    for domain in "${test_domains[@]}"; do
        echo "  Testing reverse DNS for $domain:"
        
        # Get IP addresses
        local ip_addresses=($(get_ip_addresses "$domain" 3))
        
        if [[ ${#ip_addresses[@]} -gt 0 ]]; then
            echo -e "    ${BLUE}Found ${#ip_addresses[@]} IP address(es)${NC}"
            
            for ip in "${ip_addresses[@]}"; do
                echo -n "    $ip: "
                
                if reverse_hostname=$(reverse_dns_lookup "$ip" 3); then
                    if [[ "$reverse_hostname" == "$domain" ]]; then
                        echo -e "${GREEN}✓ $reverse_hostname (matches)${NC}"
                    else
                        echo -e "${YELLOW}⚠ $reverse_hostname (differs)${NC}"
                    fi
                else
                    echo -e "${RED}✗ No reverse DNS${NC}"
                fi
            done
        else
            echo -e "    ${RED}✗ No IP addresses found${NC}"
        fi
        
        # Test comprehensive validation
        echo -n "    Comprehensive validation: "
        if validate_reverse_dns "$domain" 3; then
            echo -e "${GREEN}✓ Passed${NC}"
        else
            echo -e "${RED}✗ Failed${NC}"
        fi
        
        # Clear results for next test
        REVERSE_DNS_RESULTS=()
        echo ""
    done
}
    local test_domains=("github.com" "google.com" "example.com")
    
    echo "Testing CAA record checking..."
    echo ""
    
    for domain in "${test_domains[@]}"; do
        echo "  Testing CAA for $domain:"
        
        if check_caa_ssl_compatibility "$domain" "letsencrypt.org"; then
            echo -e "    ${GREEN}✓ SSL certificate issuance would be allowed${NC}"
        else
            echo -e "    ${RED}✗ SSL certificate issuance might be blocked${NC}"
        fi
        
        local caa_results=($(get_caa_results))
        for result in "${caa_results[@]}"; do
            echo -e "    ${BLUE}→ $result${NC}"
        done
        
        CAA_RESULTS=()
        echo ""
    done
}

# Comprehensive test suite
run_comprehensive_tests() {
    echo -e "${BOLD}Running Comprehensive Test Suite${NC}"
    echo -e "${BOLD}=================================${NC}"
    echo ""
    
    # Check tool availability first
    log_info "Checking tool availability before running tests..."
    if ! show_tool_status >/dev/null; then
        echo -e "${YELLOW}Warning: Some tools are missing. Test results may be limited.${NC}"
        echo -e "${BLUE}Consider running: sudo $0 install-tools${NC}"
        echo ""
    fi
    
    test_validation_functions
    test_idn_support
    test_detection_methods
    test_dns_resolution
    test_ip_detection
    test_reverse_dns
    test_caa_checking
    
    echo "Testing complete FQDN detection process..."
    detected=$(auto_detect_fqdn "" "no" "yes")
    echo "  Auto-detected FQDN: ${detected:-"None"}"
    echo ""
    
    show_fqdn_summary "$detected"
    
    # Show machine-readable log info
    if [[ "$LOG_MACHINE_FORMAT" == "yes" ]]; then
        echo -e "${BOLD}Machine-Readable Logging Results:${NC}"
        show_log_info
    fi
}

# ===============================================================================
# CLI INTERFACE
# ===============================================================================

# Show usage information
show_usage() {
    cat << EOF
${BOLD}$SCRIPT_NAME v$SCRIPT_VERSION${NC}
$SCRIPT_PURPOSE

${BOLD}AUTO-INSTALLATION:${NC}
When run with sudo, missing DNS tools are automatically installed.
Without sudo, the script warns about missing tools but continues with limited functionality.
Running without arguments automatically detects and validates your system's FQDN.

${BOLD}USAGE:${NC}
  $0 [OPTIONS]              Auto-detect FQDN (default behavior)
  $0 [OPTIONS] [COMMAND]    Run specific command

${BOLD}COMMANDS:${NC}
  (no command)              Auto-detect FQDN (default behavior)
  detect [FQDN]             Auto-detect or validate FQDN (explicit)
  validate FQDN             Validate specific FQDN  
  test                      Run comprehensive tests
  check-caa FQDN [CA]       Check CAA records for SSL compatibility
  check-rdns FQDN           Check reverse DNS consistency
  check-ip                  Analyze server IP configuration and NAT status
  install-tools             Install required DNS and network tools (requires sudo)
  check-tools               Show availability status of required tools
  log-info                  Show machine-readable log file information
  config                    Show current configuration
  save-config FILE          Save configuration to file
  load-config FILE          Load configuration from file

${BOLD}OPTIONS:${NC}
  --require-ssl         Require SSL-compatible FQDN
  --no-dns-check        Skip DNS resolution check
  --allow-localhost     Allow localhost as valid FQDN
  --allow-ip            Allow IP addresses as FQDN
  --min-parts N         Minimum domain parts required (default: $DEFAULT_MIN_DOMAIN_PARTS)
  --log-level LEVEL     Set log level (DEBUG|INFO|WARNING|ERROR) - default: DEBUG
  --output FORMAT       Output format (text|json|xml)
  --config FILE         Load configuration from file
  --no-colors           Disable colored output
  --strict              Enable strict RFC validation mode (stricter hostname rules)
  --rfc-compliant       Alias for --strict (RFC 952/1123/1035 compliance)
  --timeout N           Set DNS timeout in seconds
  --log-file FILE       Set log file path (default: $DEFAULT_LOG_FILE)
  --no-machine-logs     Disable machine-readable logging

${BOLD}EXAMPLES:${NC}
  sudo $0                             # Auto-install tools and detect FQDN (recommended)
  $0                                  # Detect FQDN (install tools manually if missing)
  $0 example.com                      # Validate specific FQDN (auto-detects this is an FQDN)
  $0 müller.de                        # Validate Unicode IDN domain
  $0 xn--mller-kva.de                 # Validate punycode IDN domain
  $0 测试.中国                          # Validate Chinese IDN domain
  $0 --require-ssl                    # Detect FQDN with SSL validation
  $0 --output json                    # Output FQDN detection in JSON format
  $0 --strict                         # Use strict RFC compliance (RFC 952/1123/1035)
  $0 --rfc-compliant                  # Alias for strict RFC validation
  $0 --log-level INFO                 # Reduce verbosity (default is DEBUG)
  $0 --log-level ERROR                # Only log errors to file
  $0 --log-file /var/log/fqdn.log     # Custom log file location
  $0 --no-machine-logs                # Disable machine-readable logging
  $0 validate example.com             # Explicitly validate specific FQDN
  $0 check-caa example.com            # Check CAA records for Let's Encrypt
  $0 check-rdns example.com           # Check reverse DNS consistency
  $0 check-ip                         # Analyze server IP configuration and NAT status
  $0 log-info                         # Show machine-readable log file info
  $0 test                             # Run comprehensive test suite
  $0 install-tools                    # Manually install all DNS tools
  $0 check-tools                      # Check tool availability

${BOLD}RETURN CODES:${NC}
  0  Success
  1  FQDN validation/detection failed
  2  Configuration error
  3  Invalid arguments

${BOLD}MACHINE-READABLE LOGGING:${NC}
All operations are automatically logged to $DEFAULT_LOG_FILE in JSON format at DEBUG level.
Each log entry contains timestamp, level, component, function, message, and metadata.
Perfect for automation, monitoring, troubleshooting, and integration with log analysis tools.
Full support for International Domain Names (IDN) with Unicode and punycode conversion.
Strict RFC compliance (RFC 952/1123/1035) for ASCII domains with detailed validation logging.

View logs: tail -f $DEFAULT_LOG_FILE | jq . (jq auto-installed)
Parse logs: cat $DEFAULT_LOG_FILE | jq -r '.timestamp + " " + .level + " " + .message'
  dig, nslookup, host   DNS query tools (install with: sudo $0 install-tools)
  curl                  HTTP requests and cloud metadata
  ping, hostname        Basic network and system tools

${BOLD}FIRST TIME SETUP:${NC}
  sudo $0 install-tools # Install all required DNS and network tools
  $0 check-tools        # Verify tool availability
  $0 test              # Run comprehensive test suite
EOF
}

# Parse command line arguments
parse_cli_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --require-ssl)
                REQUIRE_SSL="yes"
                shift
                ;;
            --no-dns-check)
                CHECK_DNS="no"
                shift
                ;;
            --allow-localhost)
                ALLOW_LOCALHOST="yes"
                shift
                ;;
            --allow-ip)
                ALLOW_IP_AS_FQDN="yes"
                shift
                ;;
            --min-parts)
                MIN_DOMAIN_PARTS="$2"
                shift 2
                ;;
            --log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            --output)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            --config)
                load_config "$2" || exit 2
                shift 2
                ;;
            --no-colors)
                USE_COLORS="no"
                shift
                ;;
            --strict)
                STRICT_MODE="yes"
                shift
                ;;
            --rfc-compliant)
                STRICT_MODE="yes"
                shift
                ;;
            --timeout)
                DNS_TIMEOUT="$2"
                PING_TIMEOUT="$2"
                shift 2
                ;;
            --log-file)
                LOG_FILE="$2"
                shift 2
                ;;
            --no-machine-logs)
                LOG_MACHINE_FORMAT="no"
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            --)
                shift
                break
                ;;
            -*)
                log_error "Unknown option: $1"
                show_usage
                exit 3
                ;;
            *)
                break
                ;;
        esac
    done
    
    # If no arguments remain, default to detect command
    if [[ $# -eq 0 ]]; then
        CLI_ARGS=("detect")
    else
        CLI_ARGS=("$@")
    fi
}

# Main CLI function
main_cli() {
    local command="${1:-detect}"
    shift || true
    
    # If the "command" looks like an FQDN (including IDN), treat it as detect with FQDN parameter
    if [[ "$command" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || [[ "$command" == "localhost" ]] || [[ "$command" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$command" =~ xn-- ]] || contains_unicode "$command"; then
        local fqdn="$command"
        command="detect"
        set -- "$fqdn" "$@"
    fi
    
    case "$command" in
        detect)
            local fqdn="$1"
            local detected_fqdn=""
            
            if detected_fqdn=$(auto_detect_fqdn "$fqdn" "$REQUIRE_SSL" "$CHECK_DNS"); then
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "$detected_fqdn" "success"
                        ;;
                    xml)
                        generate_xml_output "$detected_fqdn" "success"
                        ;;
                    *)
                        echo "$detected_fqdn"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary "$detected_fqdn"
                        ;;
                esac
                return 0
            else
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "" "failed"
                        ;;
                    xml)
                        generate_xml_output "" "failed"
                        ;;
                    *)
                        log_error "FQDN detection failed"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary ""
                        ;;
                esac
                return 1
            fi
            ;;
        validate)
            local fqdn="$1"
            if [[ -z "$fqdn" ]]; then
                log_error "FQDN required for validation"
                return 3
            fi
            
            if validate_fqdn_comprehensive "$fqdn" "$CHECK_DNS" "${STRICT_MODE:-no}"; then
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "$fqdn" "valid"
                        ;;
                    xml)
                        generate_xml_output "$fqdn" "valid"
                        ;;
                    *)
                        echo "valid"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary "$fqdn"
                        ;;
                esac
                return 0
            else
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "$fqdn" "invalid"
                        ;;
                    xml)
                        generate_xml_output "$fqdn" "invalid"
                        ;;
                    *)
                        echo "invalid"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary "$fqdn"
                        ;;
                esac
                return 1
            fi
            ;;
        check-caa)
            local fqdn="$1"
            local ca_identifier="${2:-letsencrypt.org}"
            
            if [[ -z "$fqdn" ]]; then
                log_error "FQDN required for CAA checking"
                return 3
            fi
            
            if check_caa_ssl_compatibility "$fqdn" "$ca_identifier"; then
                echo "CAA records allow SSL certificate issuance for $ca_identifier"
                return 0
            else
                echo "CAA records may block SSL certificate issuance for $ca_identifier"
                return 1
            fi
            ;;
        check-rdns)
            local fqdn="$1"
            
            if [[ -z "$fqdn" ]]; then
                log_error "FQDN required for reverse DNS checking"
                return 3
            fi
            
            if validate_reverse_dns_comprehensive "$fqdn"; then
                echo "Comprehensive reverse DNS is consistent for $fqdn"
                
                # Show detailed results
                local reverse_results=($(get_reverse_dns_results))
                if [[ ${#reverse_results[@]} -gt 0 ]]; then
                    echo ""
                    echo "Detailed Results:"
                    for result in "${reverse_results[@]}"; do
                        local ip="${result%%:*}"
                        local reverse_hostname="${result#*:}"
                        
                        if [[ "$reverse_hostname" == "no_reverse_dns" ]]; then
                            echo "  $ip: No reverse DNS record"
                        elif [[ "$reverse_hostname" == "$fqdn" ]]; then
                            echo "  $ip: $reverse_hostname (✓ matches)"
                        else
                            echo "  $ip: $reverse_hostname (⚠ differs from $fqdn)"
                        fi
                    done
                fi
                return 0
            else
                echo "Comprehensive reverse DNS validation failed for $fqdn"
                
                # Show detailed results even on failure
                local reverse_results=($(get_reverse_dns_results))
                if [[ ${#reverse_results[@]} -gt 0 ]]; then
                    echo ""
                    echo "Detailed Results:"
                    for result in "${reverse_results[@]}"; do
                        local ip="${result%%:*}"
                        local reverse_hostname="${result#*:}"
                        
                        if [[ "$reverse_hostname" == "no_reverse_dns" ]]; then
                            echo "  $ip: No reverse DNS record"
                        elif [[ "$reverse_hostname" == "$fqdn" ]]; then
                            echo "  $ip: $reverse_hostname (✓ matches)"
                        else
                            echo "  $ip: $reverse_hostname (⚠ differs from $fqdn)"
                        fi
                    done
                fi
                return 1
            fi
            ;;
        check-ip)
            echo "Analyzing server IP configuration..."
            echo ""
            
            local ip_config_output=$(detect_ip_configuration)
            
            if [[ -n "$ip_config_output" ]]; then
                # Parse results
                local local_ips_line=$(echo "$ip_config_output" | grep "local_ips:")
                local external_ip_line=$(echo "$ip_config_output" | grep "external_ip:")
                local behind_nat_line=$(echo "$ip_config_output" | grep "behind_nat:")
                local nat_type_line=$(echo "$ip_config_output" | grep "nat_type:")
                
                local local_ips="${local_ips_line#local_ips:}"
                local external_ip="${external_ip_line#external_ip:}"
                local behind_nat="${behind_nat_line#behind_nat:}"
                local nat_type="${nat_type_line#nat_type:}"
                
                echo "IP Configuration Analysis Results:"
                echo ""
                
                if [[ -n "$local_ips" ]]; then
                    echo "Local IP Addresses:"
                    for ip in $local_ips; do
                        if is_private_ip "$ip"; then
                            echo "  $ip (private)"
                        else
                            echo "  $ip (public)"
                        fi
                    done
                    echo ""
                fi
                
                if [[ -n "$external_ip" ]]; then
                    echo "External IP Address: $external_ip"
                    echo ""
                fi
                
                echo "Network Configuration:"
                if [[ "$behind_nat" == "true" ]]; then
                    echo "  Behind NAT: Yes ($nat_type)"
                    echo "  Impact: External services see $external_ip, internal services see local IPs"
                elif [[ "$behind_nat" == "false" ]]; then
                    echo "  Behind NAT: No (direct public IP access)"
                else
                    echo "  Behind NAT: Unknown"
                fi
                
                return 0
            else
                echo "IP configuration analysis failed"
                return 1
            fi
            ;;
        install-tools)
            install_required_tools "no"
            ;;
        check-tools)
            show_tool_status
            ;;
        log-info)
            show_log_info
            ;;
        test)
            run_comprehensive_tests
            ;;
        config)
            show_config
            ;;
        save-config)
            local config_file="$1"
            if [[ -z "$config_file" ]]; then
                log_error "Configuration file path required"
                return 3
            fi
            save_config "$config_file"
            ;;
        load-config)
            local config_file="$1"
            if [[ -z "$config_file" ]]; then
                log_error "Configuration file path required"
                return 3
            fi
            load_config "$config_file"
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            return 3
            ;;
    esac
}

# ===============================================================================
# MAIN EXECUTION
# ===============================================================================

# Main execution logic
main() {
    if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
        log_debug "Script sourced, functions available"
        return 0
    fi
    
    parse_cli_arguments "$@"
    main_cli "${CLI_ARGS[@]}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi || echo "")
        if [[ -n "$ipv4_addresses" ]]; then
            while IFS= read -r ip; do
                [[ -n "$ip" ]] && ip_addresses+=("$ip")
            done <<< "$ipv4_addresses"
        fi
        
        # Get IPv6 addresses (AAAA records)
        local ipv6_addresses=$(timeout "$timeout" dig +short AAAA "$fqdn" 2>/dev/null | grep -E '^[0-9a-fA-F:]+

# ===============================================================================
# CAA RECORD VALIDATION FUNCTIONS
# ===============================================================================

# Extract domain hierarchy from FQDN
get_domain_hierarchy() {
    local fqdn="$1"
    local domains=()
    
    # Remove trailing dot if present
    fqdn="${fqdn%.}"
    
    # Split domain into parts
    local IFS='.'
    local parts=($fqdn)
    
    # Build domain hierarchy from specific to general
    for ((i=0; i<${#parts[@]}; i++)); do
        local domain=""
        for ((j=i; j<${#parts[@]}; j++)); do
            if [[ -n "$domain" ]]; then
                domain="$domain.${parts[j]}"
            else
                domain="${parts[j]}"
            fi
        done
        domains+=("$domain")
    done
    
    printf '%s\n' "${domains[@]}"
}

# Check CAA record for a specific domain
check_caa_record() {
    local domain="$1"
    local timeout="${2:-$DNS_TIMEOUT}"
    
    log_debug "Checking CAA record for domain: $domain"
    
    local caa_records=""
    local query_method=""
    
    # Try different DNS tools to query CAA records
    if command_exists dig; then
        caa_records=$(timeout "$timeout" dig +short CAA "$domain" 2>/dev/null || echo "")
        query_method="dig"
    elif command_exists nslookup; then
        # nslookup doesn't support CAA records directly, but we can try
        caa_records=$(timeout "$timeout" nslookup -type=CAA "$domain" 2>/dev/null | grep -E "issue|issuewild|iodef" || echo "")
        query_method="nslookup"
    elif command_exists host; then
        caa_records=$(timeout "$timeout" host -t CAA "$domain" 2>/dev/null || echo "")
        query_method="host"
    fi
    
    if [[ -n "$caa_records" ]]; then
        log_debug "CAA records found for $domain via $query_method"
        echo "$caa_records"
        return 0
    else
        log_debug "No CAA records found for $domain"
        return 1
    fi
}

# Parse CAA record and check if CA is allowed
is_ca_allowed_by_caa() {
    local caa_record="$1"
    local ca_identifier="$2"
    
    # Common CA identifiers
    local common_cas=(
        "letsencrypt.org"
        "amazon.com"
        "digicert.com"
        "globalsign.com"
        "sectigo.com"
        "godaddy.com"
        "comodo.com"
    )
    
    # If no specific CA provided, check against common ones
    if [[ -z "$ca_identifier" ]]; then
        for ca in "${common_cas[@]}"; do
            if echo "$caa_record" | grep -q "issue.*$ca"; then
                return 0
            fi
        done
        return 1
    fi
    
    # Check if specific CA is allowed
    if echo "$caa_record" | grep -q "issue.*$ca_identifier"; then
        return 0
    fi
    
    return 1
}

# Comprehensive CAA record checking for SSL certificate rollout
check_caa_ssl_compatibility() {
    local fqdn="$1"
    local ca_identifier="${2:-letsencrypt.org}"
    
    log_info "Checking CAA records for SSL certificate compatibility: $fqdn"
    
    # Clear previous CAA results
    CAA_RESULTS=()
    
    local domains=($(get_domain_hierarchy "$fqdn"))
    local caa_blocking=false
    local caa_found=false
    local blocking_domain=""
    local allowed_cas=()
    
    log_debug "Domain hierarchy: ${domains[*]}"
    
    # Check each domain in the hierarchy
    for domain in "${domains[@]}"; do
        log_debug "Checking CAA for domain level: $domain"
        
        local caa_records=""
        if caa_records=$(check_caa_record "$domain"); then
            caa_found=true
            log_info "CAA records found for $domain"
            
            # Parse CAA records
            local has_issue_restriction=false
            local ca_allowed=false
            local wildcard_allowed=false
            
            while IFS= read -r record; do
                if [[ -n "$record" ]]; then
                    log_debug "CAA record: $record"
                    
                    # Check for issue restriction
                    if echo "$record" | grep -q "issue"; then
                        has_issue_restriction=true
                        
                        # Check if our CA is allowed
                        if is_ca_allowed_by_caa "$record" "$ca_identifier"; then
                            ca_allowed=true
                            log_success "CA $ca_identifier is allowed by CAA record"
                        fi
                        
                        # Extract allowed CAs
                        local allowed_ca=$(echo "$record" | grep -oE 'issue[[:space:]]+"[^"]+"' | cut -d'"' -f2)
                        if [[ -n "$allowed_ca" ]]; then
                            allowed_cas+=("$allowed_ca")
                        fi
                    fi
                    
                    # Check for wildcard restrictions
                    if echo "$record" | grep -q "issuewild"; then
                        if is_ca_allowed_by_caa "$record" "$ca_identifier"; then
                            wildcard_allowed=true
                            log_success "Wildcard certificates allowed for $ca_identifier"
                        fi
                    fi
                    
                    # Check for iodef (incident reporting)
                    if echo "$record" | grep -q "iodef"; then
                        local iodef_contact=$(echo "$record" | grep -oE 'iodef[[:space:]]+"[^"]+"' | cut -d'"' -f2)
                        log_info "CAA incident reporting configured: $iodef_contact"
                        CAA_RESULTS+=("iodef:$domain:$iodef_contact")
                    fi
                fi
            done <<< "$caa_records"
            
            # If issue restriction exists but CA not allowed, it's blocking
            if [[ "$has_issue_restriction" == "true" && "$ca_allowed" == "false" ]]; then
                caa_blocking=true
                blocking_domain="$domain"
                log_warning "CAA records at $domain would block $ca_identifier"
                CAA_RESULTS+=("blocking:$domain:$ca_identifier")
                break
            elif [[ "$has_issue_restriction" == "true" && "$ca_allowed" == "true" ]]; then
                log_success "CAA records at $domain allow $ca_identifier"
                CAA_RESULTS+=("allowed:$domain:$ca_identifier")
            fi
        else
            log_debug "No CAA records found for $domain"
            CAA_RESULTS+=("no_caa:$domain")
        fi
    done
    
    # Generate summary
    if [[ "$caa_blocking" == "true" ]]; then
        log_error "CAA records would block SSL certificate issuance"
        log_error "Blocking domain: $blocking_domain"
        if [[ ${#allowed_cas[@]} -gt 0 ]]; then
            log_info "Allowed CAs: ${allowed_cas[*]}"
        fi
        return 1
    elif [[ "$caa_found" == "true" ]]; then
        log_success "CAA records found but do not block $ca_identifier"
        return 0
    else
        log_info "No CAA records found - certificate issuance should proceed normally"
        return 0
    fi
}

# Get CAA checking results
get_caa_results() {
    printf '%s\n' "${CAA_RESULTS[@]}"
}

# ===============================================================================
# MAIN DETECTION FUNCTION
# ===============================================================================

# Main FQDN detection function with comprehensive reporting
auto_detect_fqdn() {
    local provided_fqdn="$1"
    local require_ssl="${2:-$REQUIRE_SSL}"
    local check_dns="${3:-$CHECK_DNS}"
    
    DETECTED_FQDN=""
    DETECTION_METHOD=""
    DETECTION_RESULTS=()
    VALIDATION_RESULTS=()
    
    log_info "Starting FQDN detection process..."
    log_debug "Parameters: provided_fqdn='$provided_fqdn', require_ssl='$require_ssl', check_dns='$check_dns'"
    
    if [[ -n "$provided_fqdn" ]]; then
        log_info "Validating provided FQDN: $provided_fqdn"
        
        if is_valid_fqdn "$provided_fqdn"; then
            log_success "Provided FQDN is valid: $provided_fqdn"
            DETECTED_FQDN="$provided_fqdn"
            DETECTION_METHOD="user-provided"
            
            if [[ "$check_dns" == "yes" ]]; then
                if check_dns_resolution "$provided_fqdn"; then
                    log_success "Provided FQDN resolves correctly"
                    VALIDATION_RESULTS+=("dns:success")
                else
                    log_warning "Provided FQDN does not resolve (may be expected for new domains)"
                    VALIDATION_RESULTS+=("dns:failed")
                fi
            fi
            
            # Check CAA records if SSL is required
            if [[ "$require_ssl" == "yes" ]]; then
                if check_caa_ssl_compatibility "$provided_fqdn"; then
                    log_success "CAA records do not block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:compatible")
                else
                    log_warning "CAA records may block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:blocking")
                fi
            fi
            
            echo "$provided_fqdn"
            return 0
        else
            log_error "Provided FQDN is invalid: $provided_fqdn"
            if [[ "$require_ssl" == "yes" ]]; then
                log_error "Valid FQDN is required for SSL certificate enrollment"
                return 1
            fi
        fi
    fi
    
    log_info "Auto-detecting FQDN using multiple methods..."
    
    local methods=(
        "detect_fqdn_hostname:hostname -f command:system"
        "detect_fqdn_hostnamectl:systemd hostnamectl:system"
        "detect_fqdn_dns_domain:dnsdomainname + hostname:dns"
        "detect_fqdn_etc_hostname:/etc/hostname file:file"
        "detect_fqdn_etc_hosts:/etc/hosts file:file"
        "detect_fqdn_reverse_dns:reverse DNS lookup:dns"
        "detect_fqdn_cloud_metadata:cloud metadata services:cloud"
    )
    
    for method_info in "${methods[@]}"; do
        local method_func="${method_info%%:*}"
        local method_desc="${method_info#*:}"
        method_desc="${method_desc%:*}"
        local method_type="${method_info##*:}"
        
        log_info "Trying: $method_desc"
        
        if detected_fqdn=$($method_func); then
            log_success "FQDN detected via $method_desc: $detected_fqdn"
            DETECTED_FQDN="$detected_fqdn"
            DETECTION_METHOD="$method_func"
            DETECTION_RESULTS+=("$method_func:success:$detected_fqdn")
            
            if [[ "$check_dns" == "yes" ]]; then
                if check_dns_resolution "$detected_fqdn"; then
                    log_success "Detected FQDN resolves correctly"
                    VALIDATION_RESULTS+=("dns:success")
                else
                    log_warning "Detected FQDN does not resolve"
                    VALIDATION_RESULTS+=("dns:failed")
                fi
            fi
            
            # Check CAA records if SSL is required
            if [[ "$require_ssl" == "yes" ]]; then
                if check_caa_ssl_compatibility "$detected_fqdn"; then
                    log_success "CAA records do not block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:compatible")
                else
                    log_warning "CAA records may block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:blocking")
                fi
            fi
            
            echo "$detected_fqdn"
            return 0
        else
            log_warning "No valid FQDN found via $method_desc"
            DETECTION_RESULTS+=("$method_func:failed")
        fi
    done
    
    log_warning "Could not auto-detect valid FQDN using any method"
    
    if [[ "$require_ssl" == "yes" ]]; then
        log_error "FQDN is required for SSL certificate enrollment"
        log_info "Please provide a valid FQDN using appropriate parameters"
        return 1
    elif [[ "$ALLOW_LOCALHOST" == "yes" ]]; then
        log_info "Using localhost as fallback"
        DETECTED_FQDN="localhost"
        DETECTION_METHOD="fallback"
        echo "localhost"
        return 0
    else
        log_error "No valid FQDN found and localhost not allowed"
        return 1
    fi
}

# ===============================================================================
# OUTPUT AND REPORTING FUNCTIONS
# ===============================================================================

# Generate JSON output
generate_json_output() {
    local fqdn="$1"
    local status="$2"
    
    cat << EOF
{
  "timestamp": "$(get_timestamp)",
  "script": {
    "name": "$SCRIPT_NAME",
    "version": "$SCRIPT_VERSION"
  },
  "detection": {
    "fqdn": "$fqdn",
    "method": "$DETECTION_METHOD",
    "status": "$status"
  },
  "validation": {
    "dns_check": "$CHECK_DNS",
    "results": [$(printf '"%s",' "${VALIDATION_RESULTS[@]}" | sed 's/,$//')"]
  },
  "caa_check": {
    "results": [$(printf '"%s",' "${CAA_RESULTS[@]}" | sed 's/,$//')"]
  },
  "config": {
    "require_ssl": "$REQUIRE_SSL",
    "allow_localhost": "$ALLOW_LOCALHOST",
    "allow_ip_as_fqdn": "$ALLOW_IP_AS_FQDN",
    "min_domain_parts": "$MIN_DOMAIN_PARTS"
  },
  "detection_attempts": [$(printf '"%s",' "${DETECTION_RESULTS[@]}" | sed 's/,$//')")]
}
EOF
}

# Generate XML output
generate_xml_output() {
    local fqdn="$1"
    local status="$2"
    
    cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<fqdn_detection>
  <timestamp>$(get_timestamp)</timestamp>
  <script>
    <name>$SCRIPT_NAME</name>
    <version>$SCRIPT_VERSION</version>
  </script>
  <detection>
    <fqdn>$fqdn</fqdn>
    <method>$DETECTION_METHOD</method>
    <status>$status</status>
  </detection>
  <validation>
    <dns_check>$CHECK_DNS</dns_check>
    <results>
$(for result in "${VALIDATION_RESULTS[@]}"; do echo "      <result>$result</result>"; done)
    </results>
  </validation>
  <caa_check>
    <results>
$(for result in "${CAA_RESULTS[@]}"; do echo "      <result>$result</result>"; done)
    </results>
  </caa_check>
  <config>
    <require_ssl>$REQUIRE_SSL</require_ssl>
    <allow_localhost>$ALLOW_LOCALHOST</allow_localhost>
    <allow_ip_as_fqdn>$ALLOW_IP_AS_FQDN</allow_ip_as_fqdn>
    <min_domain_parts>$MIN_DOMAIN_PARTS</min_domain_parts>
  </config>
  <detection_attempts>
$(for result in "${DETECTION_RESULTS[@]}"; do echo "    <attempt>$result</attempt>"; done)
  </detection_attempts>
</fqdn_detection>
EOF
}

# ===============================================================================
# GETTER FUNCTIONS
# ===============================================================================

# Get the detected FQDN
get_detected_fqdn() {
    echo "$DETECTED_FQDN"
}

# Get the detection method used
get_detection_method() {
    echo "$DETECTION_METHOD"
}

# Get all detection results
get_detection_results() {
    printf '%s\n' "${DETECTION_RESULTS[@]}"
}

# Get validation results
get_validation_results() {
    printf '%s\n' "${VALIDATION_RESULTS[@]}"
}

# ===============================================================================
# VALIDATION AND REPORTING FUNCTIONS
# ===============================================================================

# Comprehensive FQDN validation with detailed reporting
validate_fqdn_comprehensive() {
    local fqdn="$1"
    local check_dns="${2:-$CHECK_DNS}"
    local strict="${3:-no}"
    
    log_info "Performing comprehensive FQDN validation for: $fqdn"
    
    local validation_passed=true
    local validation_details=()
    
    if is_valid_fqdn "$fqdn" "$strict"; then
        log_success "FQDN format validation passed"
        validation_details+=("format:passed")
    else
        log_error "FQDN format validation failed"
        validation_details+=("format:failed")
        validation_passed=false
    fi
    
    if [[ "$check_dns" == "yes" ]]; then
        if check_dns_resolution "$fqdn"; then
            log_success "DNS resolution validation passed"
            validation_details+=("dns:passed")
        else
            log_warning "DNS resolution validation failed"
            validation_details+=("dns:failed")
            [[ "$strict" == "yes" ]] && validation_passed=false
        fi
    fi
    
    if [[ "$REQUIRE_SSL" == "yes" ]]; then
        if [[ "$fqdn" != "localhost" ]] && [[ "$fqdn" != "127.0.0.1" ]] && ! is_ip_address "$fqdn"; then
            log_success "SSL readiness validation passed"
            validation_details+=("ssl:ready")
            
            # Check CAA records for SSL compatibility
            if check_caa_ssl_compatibility "$fqdn"; then
                log_success "CAA validation passed"
                validation_details+=("caa:compatible")
            else
                log_warning "CAA validation failed"
                validation_details+=("caa:blocking")
                [[ "$strict" == "yes" ]] && validation_passed=false
            fi
        else
            log_error "SSL readiness validation failed (localhost/IP not suitable for SSL)"
            validation_details+=("ssl:not_ready")
            validation_passed=false
        fi
    fi
    
    VALIDATION_RESULTS=("${validation_details[@]}")
    
    if [[ "$validation_passed" == "true" ]]; then
        log_success "Comprehensive FQDN validation passed"
        return 0
    else
        log_error "Comprehensive FQDN validation failed"
        return 1
    fi
}

# Show detailed FQDN detection and validation summary
show_fqdn_summary() {
    local fqdn="$1"
    
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}                           FQDN DETECTION SUMMARY                              ${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${CYAN}Detection Results:${NC}"
    echo -e "${GREEN}• Detected FQDN: ${NC}${fqdn:-"Not detected"}"
    echo -e "${GREEN}• Detection Method: ${NC}${DETECTION_METHOD:-"None"}"
    echo -e "${GREEN}• Timestamp: ${NC}$(get_timestamp)"
    echo ""
    
    echo -e "${CYAN}Validation Status:${NC}"
    if [[ -n "$fqdn" && "$fqdn" != "localhost" ]]; then
        echo -e "${GREEN}• SSL Ready: ${NC}Yes"
        echo -e "${GREEN}• Domain Configuration: ${NC}Ready"
        echo -e "${GREEN}• External Access: ${NC}Possible"
    else
        echo -e "${YELLOW}• SSL Ready: ${NC}No (localhost or invalid FQDN)"
        echo -e "${YELLOW}• Domain Configuration: ${NC}Manual setup required"
        echo -e "${YELLOW}• External Access: ${NC}Limited"
    fi
    echo ""
    
    if [[ ${#VALIDATION_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}Validation Details:${NC}"
        for result in "${VALIDATION_RESULTS[@]}"; do
            local check="${result%%:*}"
            local status="${result#*:}"
            local icon="✓"
            local color="$GREEN"
            
            if [[ "$status" == "failed" ]] || [[ "$status" == "not_ready" ]] || [[ "$status" == "blocking" ]]; then
                icon="✗"
                color="$RED"
            elif [[ "$status" == "warning" ]]; then
                icon="⚠"
                color="$YELLOW"
            fi
            
            echo -e "${color}  $icon $check: $status${NC}"
        done
        echo ""
    fi
    
    if [[ ${#CAA_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}CAA Record Analysis:${NC}"
        for result in "${CAA_RESULTS[@]}"; do
            local type="${result%%:*}"
            local domain="${result#*:}"
            domain="${domain%%:*}"
            local details="${result##*:}"
            
            local icon="ℹ"
            local color="$BLUE"
            
            case "$type" in
                "blocking")
                    icon="✗"
                    color="$RED"
                    echo -e "${color}  $icon Domain $domain blocks CA: $details${NC}"
                    ;;
                "allowed")
                    icon="✓"
                    color="$GREEN"
                    echo -e "${color}  $icon Domain $domain allows CA: $details${NC}"
                    ;;
                "no_caa")
                    icon="○"
                    color="$BLUE"
                    echo -e "${color}  $icon No CAA records for: $domain${NC}"
                    ;;
                "iodef")
                    icon="📧"
                    color="$CYAN"
                    echo -e "${color}  $icon Incident reporting configured for $domain: $details${NC}"
                    ;;
            esac
        done
        echo ""
    fi
    
    if [[ ${#DETECTION_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}Detection Attempts:${NC}"
        for result in "${DETECTION_RESULTS[@]}"; do
            local method="${result%%:*}"
            local status="${result#*:}"
            status="${status%%:*}"
            local detected="${result##*:}"
            
            local icon="✓"
            local color="$GREEN"
            
            if [[ "$status" == "failed" ]]; then
                icon="✗"
                color="$RED"
                detected="N/A"
            fi
            
            echo -e "${color}  $icon $method: $status${NC}"
            [[ "$detected" != "N/A" && "$detected" != "$method" ]] && echo -e "    ${CYAN}→ $detected${NC}"
        done
        echo ""
    fi
    
    echo -e "${CYAN}Current Configuration:${NC}"
    echo -e "${BLUE}• Require SSL: ${NC}$REQUIRE_SSL"
    echo -e "${BLUE}• Check DNS: ${NC}$CHECK_DNS"
    echo -e "${BLUE}• Allow Localhost: ${NC}$ALLOW_LOCALHOST"
    echo -e "${BLUE}• Allow IP as FQDN: ${NC}$ALLOW_IP_AS_FQDN"
    echo ""
}

# ===============================================================================
# TESTING FRAMEWORK
# ===============================================================================

# Test individual validation functions
test_validation_functions() {
    echo "Testing FQDN validation functions..."
    echo ""
    
    local test_cases=(
        "example.com:valid"
        "sub.example.com:valid"
        "very.long.domain.example.com:valid"
        "localhost:depends_on_config"
        "192.168.1.1:depends_on_config"
        "invalid:invalid"
        "test.:invalid"
        ".example.com:invalid"
        "example..com:invalid"
        "ex ample.com:invalid"
        "example-.com:invalid"
        "-example.com:invalid"
    )
    
    for test_case in "${test_cases[@]}"; do
        local fqdn="${test_case%%:*}"
        local expected="${test_case#*:}"
        
        if is_valid_fqdn "$fqdn"; then
            echo -e "  ${GREEN}✓${NC} $fqdn - Valid"
        else
            echo -e "  ${RED}✗${NC} $fqdn - Invalid"
        fi
    done
    echo ""
}

# Test all detection methods
test_detection_methods() {
    echo "Testing FQDN detection methods..."
    echo ""
    
    local methods=(
        "detect_fqdn_hostname:hostname -f"
        "detect_fqdn_hostnamectl:hostnamectl"
        "detect_fqdn_dns_domain:dnsdomainname"
        "detect_fqdn_etc_hostname:/etc/hostname"
        "detect_fqdn_etc_hosts:/etc/hosts"
        "detect_fqdn_reverse_dns:reverse DNS"
        "detect_fqdn_cloud_metadata:cloud metadata"
    )
    
    for method_info in "${methods[@]}"; do
        local method_func="${method_info%%:*}"
        local method_desc="${method_info#*:}"
        
        echo -n "  Testing $method_desc... "
        
        if detected=$($method_func 2>/dev/null); then
            echo -e "${GREEN}✓ $detected${NC}"
        else
            echo -e "${YELLOW}- No result${NC}"
        fi
    done
    echo ""
}

# Test DNS resolution
test_dns_resolution() {
    local test_domains=("google.com" "github.com" "nonexistent.example.invalid")
    
    echo "Testing DNS resolution capabilities..."
    echo ""
    
    for domain in "${test_domains[@]}"; do
        echo -n "  Testing $domain... "
        
        if check_dns_resolution "$domain" 3; then
            echo -e "${GREEN}✓ Resolves${NC}"
        else
            echo -e "${RED}✗ Does not resolve${NC}"
        fi
    done
    echo ""
}

# Test CAA record checking
test_caa_checking() {
    local test_domains=("github.com" "google.com" "example.com")
    
    echo "Testing CAA record checking..."
    echo ""
    
    for domain in "${test_domains[@]}"; do
        echo "  Testing CAA for $domain:"
        
        if check_caa_ssl_compatibility "$domain" "letsencrypt.org"; then
            echo -e "    ${GREEN}✓ SSL certificate issuance would be allowed${NC}"
        else
            echo -e "    ${RED}✗ SSL certificate issuance might be blocked${NC}"
        fi
        
        local caa_results=($(get_caa_results))
        for result in "${caa_results[@]}"; do
            echo -e "    ${BLUE}→ $result${NC}"
        done
        
        CAA_RESULTS=()
        echo ""
    done
}

# Comprehensive test suite
run_comprehensive_tests() {
    echo -e "${BOLD}Running Comprehensive Test Suite${NC}"
    echo -e "${BOLD}=================================${NC}"
    echo ""
    
    test_validation_functions
    test_detection_methods
    test_dns_resolution
    test_caa_checking
    
    echo "Testing complete FQDN detection process..."
    detected=$(auto_detect_fqdn "" "no" "yes")
    echo "  Auto-detected FQDN: ${detected:-"None"}"
    echo ""
    
    show_fqdn_summary "$detected"
}

# ===============================================================================
# CLI INTERFACE
# ===============================================================================

# Show usage information
show_usage() {
    cat << EOF
${BOLD}$SCRIPT_NAME v$SCRIPT_VERSION${NC}
$SCRIPT_PURPOSE

${BOLD}USAGE:${NC}
  $0 [OPTIONS] [COMMAND]

${BOLD}COMMANDS:${NC}
  detect [FQDN]         Auto-detect or validate FQDN
  validate FQDN         Validate specific FQDN  
  test                  Run comprehensive tests
  check-caa FQDN [CA]   Check CAA records for SSL compatibility
  config                Show current configuration
  save-config FILE      Save configuration to file
  load-config FILE      Load configuration from file

${BOLD}OPTIONS:${NC}
  --require-ssl         Require SSL-compatible FQDN
  --no-dns-check        Skip DNS resolution check
  --allow-localhost     Allow localhost as valid FQDN
  --allow-ip            Allow IP addresses as FQDN
  --min-parts N         Minimum domain parts required (default: $DEFAULT_MIN_DOMAIN_PARTS)
  --log-level LEVEL     Set log level (DEBUG|INFO|WARNING|ERROR)
  --output FORMAT       Output format (text|json|xml)
  --config FILE         Load configuration from file
  --no-colors           Disable colored output
  --strict              Enable strict validation mode
  --timeout N           Set DNS timeout in seconds

${BOLD}EXAMPLES:${NC}
  $0 detect                           # Auto-detect FQDN
  $0 detect example.com               # Validate provided FQDN
  $0 validate example.com             # Validate specific FQDN
  $0 check-caa example.com            # Check CAA records for Let's Encrypt
  $0 check-caa example.com digicert.com # Check CAA for specific CA
  $0 --require-ssl detect             # Require SSL-compatible FQDN
  $0 --output json detect             # Output in JSON format
  $0 test                             # Run test suite

${BOLD}RETURN CODES:${NC}
  0  Success
  1  FQDN validation/detection failed
  2  Configuration error
  3  Invalid arguments
EOF
}

# Parse command line arguments
parse_cli_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --require-ssl)
                REQUIRE_SSL="yes"
                shift
                ;;
            --no-dns-check)
                CHECK_DNS="no"
                shift
                ;;
            --allow-localhost)
                ALLOW_LOCALHOST="yes"
                shift
                ;;
            --allow-ip)
                ALLOW_IP_AS_FQDN="yes"
                shift
                ;;
            --min-parts)
                MIN_DOMAIN_PARTS="$2"
                shift 2
                ;;
            --log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            --output)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            --config)
                load_config "$2" || exit 2
                shift 2
                ;;
            --no-colors)
                USE_COLORS="no"
                shift
                ;;
            --strict)
                STRICT_MODE="yes"
                shift
                ;;
            --timeout)
                DNS_TIMEOUT="$2"
                PING_TIMEOUT="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            --)
                shift
                break
                ;;
            -*)
                log_error "Unknown option: $1"
                show_usage
                exit 3
                ;;
            *)
                break
                ;;
        esac
    done
    
    CLI_ARGS=("$@")
}

# Main CLI function
main_cli() {
    local command="${1:-detect}"
    shift || true
    
    case "$command" in
        detect)
            local fqdn="$1"
            local detected_fqdn=""
            
            if detected_fqdn=$(auto_detect_fqdn "$fqdn" "$REQUIRE_SSL" "$CHECK_DNS"); then
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "$detected_fqdn" "success"
                        ;;
                    xml)
                        generate_xml_output "$detected_fqdn" "success"
                        ;;
                    *)
                        echo "$detected_fqdn"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary "$detected_fqdn"
                        ;;
                esac
                return 0
            else
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "" "failed"
                        ;;
                    xml)
                        generate_xml_output "" "failed"
                        ;;
                    *)
                        log_error "FQDN detection failed"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary ""
                        ;;
                esac
                return 1
            fi
            ;;
        validate)
            local fqdn="$1"
            if [[ -z "$fqdn" ]]; then
                log_error "FQDN required for validation"
                return 3
            fi
            
            if validate_fqdn_comprehensive "$fqdn" "$CHECK_DNS" "${STRICT_MODE:-no}"; then
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "$fqdn" "valid"
                        ;;
                    xml)
                        generate_xml_output "$fqdn" "valid"
                        ;;
                    *)
                        echo "valid"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary "$fqdn"
                        ;;
                esac
                return 0
            else
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "$fqdn" "invalid"
                        ;;
                    xml)
                        generate_xml_output "$fqdn" "invalid"
                        ;;
                    *)
                        echo "invalid"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary "$fqdn"
                        ;;
                esac
                return 1
            fi
            ;;
        check-caa)
            local fqdn="$1"
            local ca_identifier="${2:-letsencrypt.org}"
            
            if [[ -z "$fqdn" ]]; then
                log_error "FQDN required for CAA checking"
                return 3
            fi
            
            if check_caa_ssl_compatibility "$fqdn" "$ca_identifier"; then
                echo "CAA records allow SSL certificate issuance for $ca_identifier"
                return 0
            else
                echo "CAA records may block SSL certificate issuance for $ca_identifier"
                return 1
            fi
            ;;
        test)
            run_comprehensive_tests
            ;;
        config)
            show_config
            ;;
        save-config)
            local config_file="$1"
            if [[ -z "$config_file" ]]; then
                log_error "Configuration file path required"
                return 3
            fi
            save_config "$config_file"
            ;;
        load-config)
            local config_file="$1"
            if [[ -z "$config_file" ]]; then
                log_error "Configuration file path required"
                return 3
            fi
            load_config "$config_file"
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            return 3
            ;;
    esac
}

# ===============================================================================
# MAIN EXECUTION
# ===============================================================================

# Main execution logic
main() {
    if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
        log_debug "Script sourced, functions available"
        return 0
    fi
    
    parse_cli_arguments "$@"
    main_cli "${CLI_ARGS[@]}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi || echo "")
        if [[ -n "$ipv6_addresses" ]]; then
            while IFS= read -r ip; do
                [[ -n "$ip" ]] && ip_addresses+=("$ip")
            done <<< "$ipv6_addresses"
        fi
    elif command_exists nslookup; then
        # Fallback to nslookup
        local nslookup_output=$(timeout "$timeout" nslookup "$fqdn" 2>/dev/null || echo "")
        local addresses=$(echo "$nslookup_output" | grep -E '^Address: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$|^Address: [0-9a-fA-F:]+

# ===============================================================================
# CAA RECORD VALIDATION FUNCTIONS
# ===============================================================================

# Extract domain hierarchy from FQDN
get_domain_hierarchy() {
    local fqdn="$1"
    local domains=()
    
    # Remove trailing dot if present
    fqdn="${fqdn%.}"
    
    # Split domain into parts
    local IFS='.'
    local parts=($fqdn)
    
    # Build domain hierarchy from specific to general
    for ((i=0; i<${#parts[@]}; i++)); do
        local domain=""
        for ((j=i; j<${#parts[@]}; j++)); do
            if [[ -n "$domain" ]]; then
                domain="$domain.${parts[j]}"
            else
                domain="${parts[j]}"
            fi
        done
        domains+=("$domain")
    done
    
    printf '%s\n' "${domains[@]}"
}

# Check CAA record for a specific domain
check_caa_record() {
    local domain="$1"
    local timeout="${2:-$DNS_TIMEOUT}"
    
    log_debug "Checking CAA record for domain: $domain"
    
    local caa_records=""
    local query_method=""
    
    # Try different DNS tools to query CAA records
    if command_exists dig; then
        caa_records=$(timeout "$timeout" dig +short CAA "$domain" 2>/dev/null || echo "")
        query_method="dig"
    elif command_exists nslookup; then
        # nslookup doesn't support CAA records directly, but we can try
        caa_records=$(timeout "$timeout" nslookup -type=CAA "$domain" 2>/dev/null | grep -E "issue|issuewild|iodef" || echo "")
        query_method="nslookup"
    elif command_exists host; then
        caa_records=$(timeout "$timeout" host -t CAA "$domain" 2>/dev/null || echo "")
        query_method="host"
    fi
    
    if [[ -n "$caa_records" ]]; then
        log_debug "CAA records found for $domain via $query_method"
        echo "$caa_records"
        return 0
    else
        log_debug "No CAA records found for $domain"
        return 1
    fi
}

# Parse CAA record and check if CA is allowed
is_ca_allowed_by_caa() {
    local caa_record="$1"
    local ca_identifier="$2"
    
    # Common CA identifiers
    local common_cas=(
        "letsencrypt.org"
        "amazon.com"
        "digicert.com"
        "globalsign.com"
        "sectigo.com"
        "godaddy.com"
        "comodo.com"
    )
    
    # If no specific CA provided, check against common ones
    if [[ -z "$ca_identifier" ]]; then
        for ca in "${common_cas[@]}"; do
            if echo "$caa_record" | grep -q "issue.*$ca"; then
                return 0
            fi
        done
        return 1
    fi
    
    # Check if specific CA is allowed
    if echo "$caa_record" | grep -q "issue.*$ca_identifier"; then
        return 0
    fi
    
    return 1
}

# Comprehensive CAA record checking for SSL certificate rollout
check_caa_ssl_compatibility() {
    local fqdn="$1"
    local ca_identifier="${2:-letsencrypt.org}"
    
    log_info "Checking CAA records for SSL certificate compatibility: $fqdn"
    
    # Clear previous CAA results
    CAA_RESULTS=()
    
    local domains=($(get_domain_hierarchy "$fqdn"))
    local caa_blocking=false
    local caa_found=false
    local blocking_domain=""
    local allowed_cas=()
    
    log_debug "Domain hierarchy: ${domains[*]}"
    
    # Check each domain in the hierarchy
    for domain in "${domains[@]}"; do
        log_debug "Checking CAA for domain level: $domain"
        
        local caa_records=""
        if caa_records=$(check_caa_record "$domain"); then
            caa_found=true
            log_info "CAA records found for $domain"
            
            # Parse CAA records
            local has_issue_restriction=false
            local ca_allowed=false
            local wildcard_allowed=false
            
            while IFS= read -r record; do
                if [[ -n "$record" ]]; then
                    log_debug "CAA record: $record"
                    
                    # Check for issue restriction
                    if echo "$record" | grep -q "issue"; then
                        has_issue_restriction=true
                        
                        # Check if our CA is allowed
                        if is_ca_allowed_by_caa "$record" "$ca_identifier"; then
                            ca_allowed=true
                            log_success "CA $ca_identifier is allowed by CAA record"
                        fi
                        
                        # Extract allowed CAs
                        local allowed_ca=$(echo "$record" | grep -oE 'issue[[:space:]]+"[^"]+"' | cut -d'"' -f2)
                        if [[ -n "$allowed_ca" ]]; then
                            allowed_cas+=("$allowed_ca")
                        fi
                    fi
                    
                    # Check for wildcard restrictions
                    if echo "$record" | grep -q "issuewild"; then
                        if is_ca_allowed_by_caa "$record" "$ca_identifier"; then
                            wildcard_allowed=true
                            log_success "Wildcard certificates allowed for $ca_identifier"
                        fi
                    fi
                    
                    # Check for iodef (incident reporting)
                    if echo "$record" | grep -q "iodef"; then
                        local iodef_contact=$(echo "$record" | grep -oE 'iodef[[:space:]]+"[^"]+"' | cut -d'"' -f2)
                        log_info "CAA incident reporting configured: $iodef_contact"
                        CAA_RESULTS+=("iodef:$domain:$iodef_contact")
                    fi
                fi
            done <<< "$caa_records"
            
            # If issue restriction exists but CA not allowed, it's blocking
            if [[ "$has_issue_restriction" == "true" && "$ca_allowed" == "false" ]]; then
                caa_blocking=true
                blocking_domain="$domain"
                log_warning "CAA records at $domain would block $ca_identifier"
                CAA_RESULTS+=("blocking:$domain:$ca_identifier")
                break
            elif [[ "$has_issue_restriction" == "true" && "$ca_allowed" == "true" ]]; then
                log_success "CAA records at $domain allow $ca_identifier"
                CAA_RESULTS+=("allowed:$domain:$ca_identifier")
            fi
        else
            log_debug "No CAA records found for $domain"
            CAA_RESULTS+=("no_caa:$domain")
        fi
    done
    
    # Generate summary
    if [[ "$caa_blocking" == "true" ]]; then
        log_error "CAA records would block SSL certificate issuance"
        log_error "Blocking domain: $blocking_domain"
        if [[ ${#allowed_cas[@]} -gt 0 ]]; then
            log_info "Allowed CAs: ${allowed_cas[*]}"
        fi
        return 1
    elif [[ "$caa_found" == "true" ]]; then
        log_success "CAA records found but do not block $ca_identifier"
        return 0
    else
        log_info "No CAA records found - certificate issuance should proceed normally"
        return 0
    fi
}

# Get CAA checking results
get_caa_results() {
    printf '%s\n' "${CAA_RESULTS[@]}"
}

# ===============================================================================
# MAIN DETECTION FUNCTION
# ===============================================================================

# Main FQDN detection function with comprehensive reporting
auto_detect_fqdn() {
    local provided_fqdn="$1"
    local require_ssl="${2:-$REQUIRE_SSL}"
    local check_dns="${3:-$CHECK_DNS}"
    
    DETECTED_FQDN=""
    DETECTION_METHOD=""
    DETECTION_RESULTS=()
    VALIDATION_RESULTS=()
    
    log_info "Starting FQDN detection process..."
    log_debug "Parameters: provided_fqdn='$provided_fqdn', require_ssl='$require_ssl', check_dns='$check_dns'"
    
    if [[ -n "$provided_fqdn" ]]; then
        log_info "Validating provided FQDN: $provided_fqdn"
        
        if is_valid_fqdn "$provided_fqdn"; then
            log_success "Provided FQDN is valid: $provided_fqdn"
            DETECTED_FQDN="$provided_fqdn"
            DETECTION_METHOD="user-provided"
            
            if [[ "$check_dns" == "yes" ]]; then
                if check_dns_resolution "$provided_fqdn"; then
                    log_success "Provided FQDN resolves correctly"
                    VALIDATION_RESULTS+=("dns:success")
                else
                    log_warning "Provided FQDN does not resolve (may be expected for new domains)"
                    VALIDATION_RESULTS+=("dns:failed")
                fi
            fi
            
            # Check CAA records if SSL is required
            if [[ "$require_ssl" == "yes" ]]; then
                if check_caa_ssl_compatibility "$provided_fqdn"; then
                    log_success "CAA records do not block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:compatible")
                else
                    log_warning "CAA records may block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:blocking")
                fi
            fi
            
            echo "$provided_fqdn"
            return 0
        else
            log_error "Provided FQDN is invalid: $provided_fqdn"
            if [[ "$require_ssl" == "yes" ]]; then
                log_error "Valid FQDN is required for SSL certificate enrollment"
                return 1
            fi
        fi
    fi
    
    log_info "Auto-detecting FQDN using multiple methods..."
    
    local methods=(
        "detect_fqdn_hostname:hostname -f command:system"
        "detect_fqdn_hostnamectl:systemd hostnamectl:system"
        "detect_fqdn_dns_domain:dnsdomainname + hostname:dns"
        "detect_fqdn_etc_hostname:/etc/hostname file:file"
        "detect_fqdn_etc_hosts:/etc/hosts file:file"
        "detect_fqdn_reverse_dns:reverse DNS lookup:dns"
        "detect_fqdn_cloud_metadata:cloud metadata services:cloud"
    )
    
    for method_info in "${methods[@]}"; do
        local method_func="${method_info%%:*}"
        local method_desc="${method_info#*:}"
        method_desc="${method_desc%:*}"
        local method_type="${method_info##*:}"
        
        log_info "Trying: $method_desc"
        
        if detected_fqdn=$($method_func); then
            log_success "FQDN detected via $method_desc: $detected_fqdn"
            DETECTED_FQDN="$detected_fqdn"
            DETECTION_METHOD="$method_func"
            DETECTION_RESULTS+=("$method_func:success:$detected_fqdn")
            
            if [[ "$check_dns" == "yes" ]]; then
                if check_dns_resolution "$detected_fqdn"; then
                    log_success "Detected FQDN resolves correctly"
                    VALIDATION_RESULTS+=("dns:success")
                else
                    log_warning "Detected FQDN does not resolve"
                    VALIDATION_RESULTS+=("dns:failed")
                fi
            fi
            
            # Check CAA records if SSL is required
            if [[ "$require_ssl" == "yes" ]]; then
                if check_caa_ssl_compatibility "$detected_fqdn"; then
                    log_success "CAA records do not block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:compatible")
                else
                    log_warning "CAA records may block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:blocking")
                fi
            fi
            
            echo "$detected_fqdn"
            return 0
        else
            log_warning "No valid FQDN found via $method_desc"
            DETECTION_RESULTS+=("$method_func:failed")
        fi
    done
    
    log_warning "Could not auto-detect valid FQDN using any method"
    
    if [[ "$require_ssl" == "yes" ]]; then
        log_error "FQDN is required for SSL certificate enrollment"
        log_info "Please provide a valid FQDN using appropriate parameters"
        return 1
    elif [[ "$ALLOW_LOCALHOST" == "yes" ]]; then
        log_info "Using localhost as fallback"
        DETECTED_FQDN="localhost"
        DETECTION_METHOD="fallback"
        echo "localhost"
        return 0
    else
        log_error "No valid FQDN found and localhost not allowed"
        return 1
    fi
}

# ===============================================================================
# OUTPUT AND REPORTING FUNCTIONS
# ===============================================================================

# Generate JSON output
generate_json_output() {
    local fqdn="$1"
    local status="$2"
    
    cat << EOF
{
  "timestamp": "$(get_timestamp)",
  "script": {
    "name": "$SCRIPT_NAME",
    "version": "$SCRIPT_VERSION"
  },
  "detection": {
    "fqdn": "$fqdn",
    "method": "$DETECTION_METHOD",
    "status": "$status"
  },
  "validation": {
    "dns_check": "$CHECK_DNS",
    "results": [$(printf '"%s",' "${VALIDATION_RESULTS[@]}" | sed 's/,$//')"]
  },
  "caa_check": {
    "results": [$(printf '"%s",' "${CAA_RESULTS[@]}" | sed 's/,$//')"]
  },
  "config": {
    "require_ssl": "$REQUIRE_SSL",
    "allow_localhost": "$ALLOW_LOCALHOST",
    "allow_ip_as_fqdn": "$ALLOW_IP_AS_FQDN",
    "min_domain_parts": "$MIN_DOMAIN_PARTS"
  },
  "detection_attempts": [$(printf '"%s",' "${DETECTION_RESULTS[@]}" | sed 's/,$//')")]
}
EOF
}

# Generate XML output
generate_xml_output() {
    local fqdn="$1"
    local status="$2"
    
    cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<fqdn_detection>
  <timestamp>$(get_timestamp)</timestamp>
  <script>
    <name>$SCRIPT_NAME</name>
    <version>$SCRIPT_VERSION</version>
  </script>
  <detection>
    <fqdn>$fqdn</fqdn>
    <method>$DETECTION_METHOD</method>
    <status>$status</status>
  </detection>
  <validation>
    <dns_check>$CHECK_DNS</dns_check>
    <results>
$(for result in "${VALIDATION_RESULTS[@]}"; do echo "      <result>$result</result>"; done)
    </results>
  </validation>
  <caa_check>
    <results>
$(for result in "${CAA_RESULTS[@]}"; do echo "      <result>$result</result>"; done)
    </results>
  </caa_check>
  <config>
    <require_ssl>$REQUIRE_SSL</require_ssl>
    <allow_localhost>$ALLOW_LOCALHOST</allow_localhost>
    <allow_ip_as_fqdn>$ALLOW_IP_AS_FQDN</allow_ip_as_fqdn>
    <min_domain_parts>$MIN_DOMAIN_PARTS</min_domain_parts>
  </config>
  <detection_attempts>
$(for result in "${DETECTION_RESULTS[@]}"; do echo "    <attempt>$result</attempt>"; done)
  </detection_attempts>
</fqdn_detection>
EOF
}

# ===============================================================================
# GETTER FUNCTIONS
# ===============================================================================

# Get the detected FQDN
get_detected_fqdn() {
    echo "$DETECTED_FQDN"
}

# Get the detection method used
get_detection_method() {
    echo "$DETECTION_METHOD"
}

# Get all detection results
get_detection_results() {
    printf '%s\n' "${DETECTION_RESULTS[@]}"
}

# Get validation results
get_validation_results() {
    printf '%s\n' "${VALIDATION_RESULTS[@]}"
}

# ===============================================================================
# VALIDATION AND REPORTING FUNCTIONS
# ===============================================================================

# Comprehensive FQDN validation with detailed reporting
validate_fqdn_comprehensive() {
    local fqdn="$1"
    local check_dns="${2:-$CHECK_DNS}"
    local strict="${3:-no}"
    
    log_info "Performing comprehensive FQDN validation for: $fqdn"
    
    local validation_passed=true
    local validation_details=()
    
    if is_valid_fqdn "$fqdn" "$strict"; then
        log_success "FQDN format validation passed"
        validation_details+=("format:passed")
    else
        log_error "FQDN format validation failed"
        validation_details+=("format:failed")
        validation_passed=false
    fi
    
    if [[ "$check_dns" == "yes" ]]; then
        if check_dns_resolution "$fqdn"; then
            log_success "DNS resolution validation passed"
            validation_details+=("dns:passed")
        else
            log_warning "DNS resolution validation failed"
            validation_details+=("dns:failed")
            [[ "$strict" == "yes" ]] && validation_passed=false
        fi
    fi
    
    if [[ "$REQUIRE_SSL" == "yes" ]]; then
        if [[ "$fqdn" != "localhost" ]] && [[ "$fqdn" != "127.0.0.1" ]] && ! is_ip_address "$fqdn"; then
            log_success "SSL readiness validation passed"
            validation_details+=("ssl:ready")
            
            # Check CAA records for SSL compatibility
            if check_caa_ssl_compatibility "$fqdn"; then
                log_success "CAA validation passed"
                validation_details+=("caa:compatible")
            else
                log_warning "CAA validation failed"
                validation_details+=("caa:blocking")
                [[ "$strict" == "yes" ]] && validation_passed=false
            fi
        else
            log_error "SSL readiness validation failed (localhost/IP not suitable for SSL)"
            validation_details+=("ssl:not_ready")
            validation_passed=false
        fi
    fi
    
    VALIDATION_RESULTS=("${validation_details[@]}")
    
    if [[ "$validation_passed" == "true" ]]; then
        log_success "Comprehensive FQDN validation passed"
        return 0
    else
        log_error "Comprehensive FQDN validation failed"
        return 1
    fi
}

# Show detailed FQDN detection and validation summary
show_fqdn_summary() {
    local fqdn="$1"
    
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}                           FQDN DETECTION SUMMARY                              ${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${CYAN}Detection Results:${NC}"
    echo -e "${GREEN}• Detected FQDN: ${NC}${fqdn:-"Not detected"}"
    echo -e "${GREEN}• Detection Method: ${NC}${DETECTION_METHOD:-"None"}"
    echo -e "${GREEN}• Timestamp: ${NC}$(get_timestamp)"
    echo ""
    
    echo -e "${CYAN}Validation Status:${NC}"
    if [[ -n "$fqdn" && "$fqdn" != "localhost" ]]; then
        echo -e "${GREEN}• SSL Ready: ${NC}Yes"
        echo -e "${GREEN}• Domain Configuration: ${NC}Ready"
        echo -e "${GREEN}• External Access: ${NC}Possible"
    else
        echo -e "${YELLOW}• SSL Ready: ${NC}No (localhost or invalid FQDN)"
        echo -e "${YELLOW}• Domain Configuration: ${NC}Manual setup required"
        echo -e "${YELLOW}• External Access: ${NC}Limited"
    fi
    echo ""
    
    if [[ ${#VALIDATION_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}Validation Details:${NC}"
        for result in "${VALIDATION_RESULTS[@]}"; do
            local check="${result%%:*}"
            local status="${result#*:}"
            local icon="✓"
            local color="$GREEN"
            
            if [[ "$status" == "failed" ]] || [[ "$status" == "not_ready" ]] || [[ "$status" == "blocking" ]]; then
                icon="✗"
                color="$RED"
            elif [[ "$status" == "warning" ]]; then
                icon="⚠"
                color="$YELLOW"
            fi
            
            echo -e "${color}  $icon $check: $status${NC}"
        done
        echo ""
    fi
    
    if [[ ${#CAA_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}CAA Record Analysis:${NC}"
        for result in "${CAA_RESULTS[@]}"; do
            local type="${result%%:*}"
            local domain="${result#*:}"
            domain="${domain%%:*}"
            local details="${result##*:}"
            
            local icon="ℹ"
            local color="$BLUE"
            
            case "$type" in
                "blocking")
                    icon="✗"
                    color="$RED"
                    echo -e "${color}  $icon Domain $domain blocks CA: $details${NC}"
                    ;;
                "allowed")
                    icon="✓"
                    color="$GREEN"
                    echo -e "${color}  $icon Domain $domain allows CA: $details${NC}"
                    ;;
                "no_caa")
                    icon="○"
                    color="$BLUE"
                    echo -e "${color}  $icon No CAA records for: $domain${NC}"
                    ;;
                "iodef")
                    icon="📧"
                    color="$CYAN"
                    echo -e "${color}  $icon Incident reporting configured for $domain: $details${NC}"
                    ;;
            esac
        done
        echo ""
    fi
    
    if [[ ${#DETECTION_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}Detection Attempts:${NC}"
        for result in "${DETECTION_RESULTS[@]}"; do
            local method="${result%%:*}"
            local status="${result#*:}"
            status="${status%%:*}"
            local detected="${result##*:}"
            
            local icon="✓"
            local color="$GREEN"
            
            if [[ "$status" == "failed" ]]; then
                icon="✗"
                color="$RED"
                detected="N/A"
            fi
            
            echo -e "${color}  $icon $method: $status${NC}"
            [[ "$detected" != "N/A" && "$detected" != "$method" ]] && echo -e "    ${CYAN}→ $detected${NC}"
        done
        echo ""
    fi
    
    echo -e "${CYAN}Current Configuration:${NC}"
    echo -e "${BLUE}• Require SSL: ${NC}$REQUIRE_SSL"
    echo -e "${BLUE}• Check DNS: ${NC}$CHECK_DNS"
    echo -e "${BLUE}• Allow Localhost: ${NC}$ALLOW_LOCALHOST"
    echo -e "${BLUE}• Allow IP as FQDN: ${NC}$ALLOW_IP_AS_FQDN"
    echo ""
}

# ===============================================================================
# TESTING FRAMEWORK
# ===============================================================================

# Test individual validation functions
test_validation_functions() {
    echo "Testing FQDN validation functions..."
    echo ""
    
    local test_cases=(
        "example.com:valid"
        "sub.example.com:valid"
        "very.long.domain.example.com:valid"
        "localhost:depends_on_config"
        "192.168.1.1:depends_on_config"
        "invalid:invalid"
        "test.:invalid"
        ".example.com:invalid"
        "example..com:invalid"
        "ex ample.com:invalid"
        "example-.com:invalid"
        "-example.com:invalid"
    )
    
    for test_case in "${test_cases[@]}"; do
        local fqdn="${test_case%%:*}"
        local expected="${test_case#*:}"
        
        if is_valid_fqdn "$fqdn"; then
            echo -e "  ${GREEN}✓${NC} $fqdn - Valid"
        else
            echo -e "  ${RED}✗${NC} $fqdn - Invalid"
        fi
    done
    echo ""
}

# Test all detection methods
test_detection_methods() {
    echo "Testing FQDN detection methods..."
    echo ""
    
    local methods=(
        "detect_fqdn_hostname:hostname -f"
        "detect_fqdn_hostnamectl:hostnamectl"
        "detect_fqdn_dns_domain:dnsdomainname"
        "detect_fqdn_etc_hostname:/etc/hostname"
        "detect_fqdn_etc_hosts:/etc/hosts"
        "detect_fqdn_reverse_dns:reverse DNS"
        "detect_fqdn_cloud_metadata:cloud metadata"
    )
    
    for method_info in "${methods[@]}"; do
        local method_func="${method_info%%:*}"
        local method_desc="${method_info#*:}"
        
        echo -n "  Testing $method_desc... "
        
        if detected=$($method_func 2>/dev/null); then
            echo -e "${GREEN}✓ $detected${NC}"
        else
            echo -e "${YELLOW}- No result${NC}"
        fi
    done
    echo ""
}

# Test DNS resolution
test_dns_resolution() {
    local test_domains=("google.com" "github.com" "nonexistent.example.invalid")
    
    echo "Testing DNS resolution capabilities..."
    echo ""
    
    for domain in "${test_domains[@]}"; do
        echo -n "  Testing $domain... "
        
        if check_dns_resolution "$domain" 3; then
            echo -e "${GREEN}✓ Resolves${NC}"
        else
            echo -e "${RED}✗ Does not resolve${NC}"
        fi
    done
    echo ""
}

# Test CAA record checking
test_caa_checking() {
    local test_domains=("github.com" "google.com" "example.com")
    
    echo "Testing CAA record checking..."
    echo ""
    
    for domain in "${test_domains[@]}"; do
        echo "  Testing CAA for $domain:"
        
        if check_caa_ssl_compatibility "$domain" "letsencrypt.org"; then
            echo -e "    ${GREEN}✓ SSL certificate issuance would be allowed${NC}"
        else
            echo -e "    ${RED}✗ SSL certificate issuance might be blocked${NC}"
        fi
        
        local caa_results=($(get_caa_results))
        for result in "${caa_results[@]}"; do
            echo -e "    ${BLUE}→ $result${NC}"
        done
        
        CAA_RESULTS=()
        echo ""
    done
}

# Comprehensive test suite
run_comprehensive_tests() {
    echo -e "${BOLD}Running Comprehensive Test Suite${NC}"
    echo -e "${BOLD}=================================${NC}"
    echo ""
    
    test_validation_functions
    test_detection_methods
    test_dns_resolution
    test_caa_checking
    
    echo "Testing complete FQDN detection process..."
    detected=$(auto_detect_fqdn "" "no" "yes")
    echo "  Auto-detected FQDN: ${detected:-"None"}"
    echo ""
    
    show_fqdn_summary "$detected"
}

# ===============================================================================
# CLI INTERFACE
# ===============================================================================

# Show usage information
show_usage() {
    cat << EOF
${BOLD}$SCRIPT_NAME v$SCRIPT_VERSION${NC}
$SCRIPT_PURPOSE

${BOLD}USAGE:${NC}
  $0 [OPTIONS] [COMMAND]

${BOLD}COMMANDS:${NC}
  detect [FQDN]         Auto-detect or validate FQDN
  validate FQDN         Validate specific FQDN  
  test                  Run comprehensive tests
  check-caa FQDN [CA]   Check CAA records for SSL compatibility
  config                Show current configuration
  save-config FILE      Save configuration to file
  load-config FILE      Load configuration from file

${BOLD}OPTIONS:${NC}
  --require-ssl         Require SSL-compatible FQDN
  --no-dns-check        Skip DNS resolution check
  --allow-localhost     Allow localhost as valid FQDN
  --allow-ip            Allow IP addresses as FQDN
  --min-parts N         Minimum domain parts required (default: $DEFAULT_MIN_DOMAIN_PARTS)
  --log-level LEVEL     Set log level (DEBUG|INFO|WARNING|ERROR)
  --output FORMAT       Output format (text|json|xml)
  --config FILE         Load configuration from file
  --no-colors           Disable colored output
  --strict              Enable strict validation mode
  --timeout N           Set DNS timeout in seconds

${BOLD}EXAMPLES:${NC}
  $0 detect                           # Auto-detect FQDN
  $0 detect example.com               # Validate provided FQDN
  $0 validate example.com             # Validate specific FQDN
  $0 check-caa example.com            # Check CAA records for Let's Encrypt
  $0 check-caa example.com digicert.com # Check CAA for specific CA
  $0 --require-ssl detect             # Require SSL-compatible FQDN
  $0 --output json detect             # Output in JSON format
  $0 test                             # Run test suite

${BOLD}RETURN CODES:${NC}
  0  Success
  1  FQDN validation/detection failed
  2  Configuration error
  3  Invalid arguments
EOF
}

# Parse command line arguments
parse_cli_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --require-ssl)
                REQUIRE_SSL="yes"
                shift
                ;;
            --no-dns-check)
                CHECK_DNS="no"
                shift
                ;;
            --allow-localhost)
                ALLOW_LOCALHOST="yes"
                shift
                ;;
            --allow-ip)
                ALLOW_IP_AS_FQDN="yes"
                shift
                ;;
            --min-parts)
                MIN_DOMAIN_PARTS="$2"
                shift 2
                ;;
            --log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            --output)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            --config)
                load_config "$2" || exit 2
                shift 2
                ;;
            --no-colors)
                USE_COLORS="no"
                shift
                ;;
            --strict)
                STRICT_MODE="yes"
                shift
                ;;
            --timeout)
                DNS_TIMEOUT="$2"
                PING_TIMEOUT="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            --)
                shift
                break
                ;;
            -*)
                log_error "Unknown option: $1"
                show_usage
                exit 3
                ;;
            *)
                break
                ;;
        esac
    done
    
    CLI_ARGS=("$@")
}

# Main CLI function
main_cli() {
    local command="${1:-detect}"
    shift || true
    
    case "$command" in
        detect)
            local fqdn="$1"
            local detected_fqdn=""
            
            if detected_fqdn=$(auto_detect_fqdn "$fqdn" "$REQUIRE_SSL" "$CHECK_DNS"); then
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "$detected_fqdn" "success"
                        ;;
                    xml)
                        generate_xml_output "$detected_fqdn" "success"
                        ;;
                    *)
                        echo "$detected_fqdn"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary "$detected_fqdn"
                        ;;
                esac
                return 0
            else
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "" "failed"
                        ;;
                    xml)
                        generate_xml_output "" "failed"
                        ;;
                    *)
                        log_error "FQDN detection failed"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary ""
                        ;;
                esac
                return 1
            fi
            ;;
        validate)
            local fqdn="$1"
            if [[ -z "$fqdn" ]]; then
                log_error "FQDN required for validation"
                return 3
            fi
            
            if validate_fqdn_comprehensive "$fqdn" "$CHECK_DNS" "${STRICT_MODE:-no}"; then
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "$fqdn" "valid"
                        ;;
                    xml)
                        generate_xml_output "$fqdn" "valid"
                        ;;
                    *)
                        echo "valid"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary "$fqdn"
                        ;;
                esac
                return 0
            else
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "$fqdn" "invalid"
                        ;;
                    xml)
                        generate_xml_output "$fqdn" "invalid"
                        ;;
                    *)
                        echo "invalid"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary "$fqdn"
                        ;;
                esac
                return 1
            fi
            ;;
        check-caa)
            local fqdn="$1"
            local ca_identifier="${2:-letsencrypt.org}"
            
            if [[ -z "$fqdn" ]]; then
                log_error "FQDN required for CAA checking"
                return 3
            fi
            
            if check_caa_ssl_compatibility "$fqdn" "$ca_identifier"; then
                echo "CAA records allow SSL certificate issuance for $ca_identifier"
                return 0
            else
                echo "CAA records may block SSL certificate issuance for $ca_identifier"
                return 1
            fi
            ;;
        test)
            run_comprehensive_tests
            ;;
        config)
            show_config
            ;;
        save-config)
            local config_file="$1"
            if [[ -z "$config_file" ]]; then
                log_error "Configuration file path required"
                return 3
            fi
            save_config "$config_file"
            ;;
        load-config)
            local config_file="$1"
            if [[ -z "$config_file" ]]; then
                log_error "Configuration file path required"
                return 3
            fi
            load_config "$config_file"
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            return 3
            ;;
    esac
}

# ===============================================================================
# MAIN EXECUTION
# ===============================================================================

# Main execution logic
main() {
    if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
        log_debug "Script sourced, functions available"
        return 0
    fi
    
    parse_cli_arguments "$@"
    main_cli "${CLI_ARGS[@]}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi | awk '{print $2}' || echo "")
        if [[ -n "$addresses" ]]; then
            while IFS= read -r ip; do
                [[ -n "$ip" ]] && ip_addresses+=("$ip")
            done <<< "$addresses"
        fi
    elif command_exists host; then
        # Fallback to host command
        local host_output=$(timeout "$timeout" host "$fqdn" 2>/dev/null || echo "")
        local addresses=$(echo "$host_output" | grep -E 'has address|has IPv6 address' | awk '{print $NF}' || echo "")
        if [[ -n "$addresses" ]]; then
            while IFS= read -r ip; do
                [[ -n "$ip" ]] && ip_addresses+=("$ip")
            done <<< "$addresses"
        fi
    elif command_exists getent; then
        # Fallback to getent
        local getent_output=$(timeout "$timeout" getent hosts "$fqdn" 2>/dev/null || echo "")
        local addresses=$(echo "$getent_output" | awk '{print $1}' || echo "")
        if [[ -n "$addresses" ]]; then
            while IFS= read -r ip; do
                [[ -n "$ip" ]] && ip_addresses+=("$ip")
            done <<< "$addresses"
        fi
    fi
    
    if [[ ${#ip_addresses[@]} -gt 0 ]]; then
        printf '%s\n' "${ip_addresses[@]}"
        return 0
    else
        log_debug "No IP addresses found for $fqdn"
        return 1
    fi
}

# Perform reverse DNS lookup on IP address
reverse_dns_lookup() {
    local ip_address="$1"
    local timeout="${2:-$DNS_TIMEOUT}"
    local reverse_hostname=""
    
    log_debug "Performing reverse DNS lookup for: $ip_address"
    
    # Try different tools for reverse DNS lookup
    if command_exists dig; then
        reverse_hostname=$(timeout "$timeout" dig +short -x "$ip_address" 2>/dev/null | sed 's/\.$//' || echo "")
    elif command_exists nslookup; then
        reverse_hostname=$(timeout "$timeout" nslookup "$ip_address" 2>/dev/null | grep "name =" | awk '{print $4}' | sed 's/\.$//' || echo "")
    elif command_exists host; then
        reverse_hostname=$(timeout "$timeout" host "$ip_address" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | sed 's/\.$//' || echo "")
    fi
    
    if [[ -n "$reverse_hostname" ]]; then
        log_debug "Reverse DNS lookup successful: $ip_address -> $reverse_hostname"
        echo "$reverse_hostname"
        return 0
    else
        log_debug "Reverse DNS lookup failed for: $ip_address"
        return 1
    fi
}

# Validate reverse DNS consistency
validate_reverse_dns() {
    local fqdn="$1"
    local timeout="${2:-$DNS_TIMEOUT}"
    
    log_info "Validating reverse DNS consistency for: $fqdn"
    
    # Get IP addresses for the FQDN
    local ip_addresses=($(get_ip_addresses "$fqdn" "$timeout"))
    
    if [[ ${#ip_addresses[@]} -eq 0 ]]; then
        log_warning "Cannot validate reverse DNS - no IP addresses found for $fqdn"
        return 1
    fi
    
    local reverse_dns_results=()
    local reverse_dns_matches=0
    local reverse_dns_mismatches=0
    local reverse_dns_failures=0
    
    # Check reverse DNS for each IP address
    for ip in "${ip_addresses[@]}"; do
        log_debug "Checking reverse DNS for IP: $ip"
        
        local reverse_hostname=""
        if reverse_hostname=$(reverse_dns_lookup "$ip" "$timeout"); then
            reverse_dns_results+=("$ip:$reverse_hostname")
            
            # Check if reverse DNS matches the original FQDN
            if [[ "$reverse_hostname" == "$fqdn" ]]; then
                log_success "Reverse DNS matches for $ip: $reverse_hostname"
                ((reverse_dns_matches++))
            else
                log_warning "Reverse DNS mismatch for $ip: expected '$fqdn', got '$reverse_hostname'"
                ((reverse_dns_mismatches++))
            fi
        else
            log_warning "Reverse DNS lookup failed for IP: $ip"
            reverse_dns_results+=("$ip:no_reverse_dns")
            ((reverse_dns_failures++))
        fi
    done
    
    # Store results in global variable for reporting
    REVERSE_DNS_RESULTS=("${reverse_dns_results[@]}")
    
    # Generate summary
    local total_ips=${#ip_addresses[@]}
    log_info "Reverse DNS validation summary:"
    log_info "  Total IPs checked: $total_ips"
    log_info "  Matches: $reverse_dns_matches"
    log_info "  Mismatches: $reverse_dns_mismatches"
    log_info "  Failures: $reverse_dns_failures"
    
    # Return success if at least one IP has matching reverse DNS
    if [[ $reverse_dns_matches -gt 0 ]]; then
        return 0
    else
        return 1
    fi
}

# Get reverse DNS validation results
get_reverse_dns_results() {
    printf '%s\n' "${REVERSE_DNS_RESULTS[@]}"
}

# ===============================================================================
# IP ADDRESS DETECTION FUNCTIONS
# ===============================================================================

# Check if IP address is private/local
is_private_ip() {
    local ip="$1"
    
    # IPv4 private ranges
    if [[ "$ip" =~ ^10\. ]]; then
        return 0  # 10.0.0.0/8
    elif [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
        return 0  # 172.16.0.0/12
    elif [[ "$ip" =~ ^192\.168\. ]]; then
        return 0  # 192.168.0.0/16
    elif [[ "$ip" =~ ^127\. ]]; then
        return 0  # 127.0.0.0/8 (loopback)
    elif [[ "$ip" =~ ^169\.254\. ]]; then
        return 0  # 169.254.0.0/16 (link-local)
    fi
    
    # IPv6 private ranges (basic check)
    if [[ "$ip" =~ ^::1$ ]]; then
        return 0  # IPv6 loopback
    elif [[ "$ip" =~ ^fc[0-9a-f][0-9a-f]: ]]; then
        return 0  # IPv6 unique local
    elif [[ "$ip" =~ ^fe80: ]]; then
        return 0  # IPv6 link-local
    fi
    
    return 1  # Public IP
}

# Get local/internal IP addresses
get_local_ip_addresses() {
    local local_ips=()
    
    log_debug "Detecting local IP addresses..."
    
    # Method 1: hostname -I (most reliable for primary IPs)
    if command_exists hostname; then
        local hostname_ips=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+

# ===============================================================================
# CAA RECORD VALIDATION FUNCTIONS
# ===============================================================================

# Extract domain hierarchy from FQDN
get_domain_hierarchy() {
    local fqdn="$1"
    local domains=()
    
    # Remove trailing dot if present
    fqdn="${fqdn%.}"
    
    # Split domain into parts
    local IFS='.'
    local parts=($fqdn)
    
    # Build domain hierarchy from specific to general
    for ((i=0; i<${#parts[@]}; i++)); do
        local domain=""
        for ((j=i; j<${#parts[@]}; j++)); do
            if [[ -n "$domain" ]]; then
                domain="$domain.${parts[j]}"
            else
                domain="${parts[j]}"
            fi
        done
        domains+=("$domain")
    done
    
    printf '%s\n' "${domains[@]}"
}

# Check CAA record for a specific domain
check_caa_record() {
    local domain="$1"
    local timeout="${2:-$DNS_TIMEOUT}"
    
    log_debug "Checking CAA record for domain: $domain"
    
    local caa_records=""
    local query_method=""
    
    # Try different DNS tools to query CAA records
    if command_exists dig; then
        caa_records=$(timeout "$timeout" dig +short CAA "$domain" 2>/dev/null || echo "")
        query_method="dig"
    elif command_exists nslookup; then
        # nslookup doesn't support CAA records directly, but we can try
        caa_records=$(timeout "$timeout" nslookup -type=CAA "$domain" 2>/dev/null | grep -E "issue|issuewild|iodef" || echo "")
        query_method="nslookup"
    elif command_exists host; then
        caa_records=$(timeout "$timeout" host -t CAA "$domain" 2>/dev/null || echo "")
        query_method="host"
    fi
    
    if [[ -n "$caa_records" ]]; then
        log_debug "CAA records found for $domain via $query_method"
        echo "$caa_records"
        return 0
    else
        log_debug "No CAA records found for $domain"
        return 1
    fi
}

# Parse CAA record and check if CA is allowed
is_ca_allowed_by_caa() {
    local caa_record="$1"
    local ca_identifier="$2"
    
    # Common CA identifiers
    local common_cas=(
        "letsencrypt.org"
        "amazon.com"
        "digicert.com"
        "globalsign.com"
        "sectigo.com"
        "godaddy.com"
        "comodo.com"
    )
    
    # If no specific CA provided, check against common ones
    if [[ -z "$ca_identifier" ]]; then
        for ca in "${common_cas[@]}"; do
            if echo "$caa_record" | grep -q "issue.*$ca"; then
                return 0
            fi
        done
        return 1
    fi
    
    # Check if specific CA is allowed
    if echo "$caa_record" | grep -q "issue.*$ca_identifier"; then
        return 0
    fi
    
    return 1
}

# Comprehensive CAA record checking for SSL certificate rollout
check_caa_ssl_compatibility() {
    local fqdn="$1"
    local ca_identifier="${2:-letsencrypt.org}"
    
    log_info "Checking CAA records for SSL certificate compatibility: $fqdn"
    
    # Clear previous CAA results
    CAA_RESULTS=()
    
    local domains=($(get_domain_hierarchy "$fqdn"))
    local caa_blocking=false
    local caa_found=false
    local blocking_domain=""
    local allowed_cas=()
    
    log_debug "Domain hierarchy: ${domains[*]}"
    
    # Check each domain in the hierarchy
    for domain in "${domains[@]}"; do
        log_debug "Checking CAA for domain level: $domain"
        
        local caa_records=""
        if caa_records=$(check_caa_record "$domain"); then
            caa_found=true
            log_info "CAA records found for $domain"
            
            # Parse CAA records
            local has_issue_restriction=false
            local ca_allowed=false
            local wildcard_allowed=false
            
            while IFS= read -r record; do
                if [[ -n "$record" ]]; then
                    log_debug "CAA record: $record"
                    
                    # Check for issue restriction
                    if echo "$record" | grep -q "issue"; then
                        has_issue_restriction=true
                        
                        # Check if our CA is allowed
                        if is_ca_allowed_by_caa "$record" "$ca_identifier"; then
                            ca_allowed=true
                            log_success "CA $ca_identifier is allowed by CAA record"
                        fi
                        
                        # Extract allowed CAs
                        local allowed_ca=$(echo "$record" | grep -oE 'issue[[:space:]]+"[^"]+"' | cut -d'"' -f2)
                        if [[ -n "$allowed_ca" ]]; then
                            allowed_cas+=("$allowed_ca")
                        fi
                    fi
                    
                    # Check for wildcard restrictions
                    if echo "$record" | grep -q "issuewild"; then
                        if is_ca_allowed_by_caa "$record" "$ca_identifier"; then
                            wildcard_allowed=true
                            log_success "Wildcard certificates allowed for $ca_identifier"
                        fi
                    fi
                    
                    # Check for iodef (incident reporting)
                    if echo "$record" | grep -q "iodef"; then
                        local iodef_contact=$(echo "$record" | grep -oE 'iodef[[:space:]]+"[^"]+"' | cut -d'"' -f2)
                        log_info "CAA incident reporting configured: $iodef_contact"
                        CAA_RESULTS+=("iodef:$domain:$iodef_contact")
                    fi
                fi
            done <<< "$caa_records"
            
            # If issue restriction exists but CA not allowed, it's blocking
            if [[ "$has_issue_restriction" == "true" && "$ca_allowed" == "false" ]]; then
                caa_blocking=true
                blocking_domain="$domain"
                log_warning "CAA records at $domain would block $ca_identifier"
                CAA_RESULTS+=("blocking:$domain:$ca_identifier")
                break
            elif [[ "$has_issue_restriction" == "true" && "$ca_allowed" == "true" ]]; then
                log_success "CAA records at $domain allow $ca_identifier"
                CAA_RESULTS+=("allowed:$domain:$ca_identifier")
            fi
        else
            log_debug "No CAA records found for $domain"
            CAA_RESULTS+=("no_caa:$domain")
        fi
    done
    
    # Generate summary
    if [[ "$caa_blocking" == "true" ]]; then
        log_error "CAA records would block SSL certificate issuance"
        log_error "Blocking domain: $blocking_domain"
        if [[ ${#allowed_cas[@]} -gt 0 ]]; then
            log_info "Allowed CAs: ${allowed_cas[*]}"
        fi
        return 1
    elif [[ "$caa_found" == "true" ]]; then
        log_success "CAA records found but do not block $ca_identifier"
        return 0
    else
        log_info "No CAA records found - certificate issuance should proceed normally"
        return 0
    fi
}

# Get CAA checking results
get_caa_results() {
    printf '%s\n' "${CAA_RESULTS[@]}"
}

# ===============================================================================
# MAIN DETECTION FUNCTION
# ===============================================================================

# Main FQDN detection function with comprehensive reporting
auto_detect_fqdn() {
    local provided_fqdn="$1"
    local require_ssl="${2:-$REQUIRE_SSL}"
    local check_dns="${3:-$CHECK_DNS}"
    
    DETECTED_FQDN=""
    DETECTION_METHOD=""
    DETECTION_RESULTS=()
    VALIDATION_RESULTS=()
    
    log_info "Starting FQDN detection process..."
    log_debug "Parameters: provided_fqdn='$provided_fqdn', require_ssl='$require_ssl', check_dns='$check_dns'"
    
    if [[ -n "$provided_fqdn" ]]; then
        log_info "Validating provided FQDN: $provided_fqdn"
        
        if is_valid_fqdn "$provided_fqdn"; then
            log_success "Provided FQDN is valid: $provided_fqdn"
            DETECTED_FQDN="$provided_fqdn"
            DETECTION_METHOD="user-provided"
            
            if [[ "$check_dns" == "yes" ]]; then
                if check_dns_resolution "$provided_fqdn"; then
                    log_success "Provided FQDN resolves correctly"
                    VALIDATION_RESULTS+=("dns:success")
                else
                    log_warning "Provided FQDN does not resolve (may be expected for new domains)"
                    VALIDATION_RESULTS+=("dns:failed")
                fi
            fi
            
            # Check CAA records if SSL is required
            if [[ "$require_ssl" == "yes" ]]; then
                if check_caa_ssl_compatibility "$provided_fqdn"; then
                    log_success "CAA records do not block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:compatible")
                else
                    log_warning "CAA records may block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:blocking")
                fi
            fi
            
            echo "$provided_fqdn"
            return 0
        else
            log_error "Provided FQDN is invalid: $provided_fqdn"
            if [[ "$require_ssl" == "yes" ]]; then
                log_error "Valid FQDN is required for SSL certificate enrollment"
                return 1
            fi
        fi
    fi
    
    log_info "Auto-detecting FQDN using multiple methods..."
    
    local methods=(
        "detect_fqdn_hostname:hostname -f command:system"
        "detect_fqdn_hostnamectl:systemd hostnamectl:system"
        "detect_fqdn_dns_domain:dnsdomainname + hostname:dns"
        "detect_fqdn_etc_hostname:/etc/hostname file:file"
        "detect_fqdn_etc_hosts:/etc/hosts file:file"
        "detect_fqdn_reverse_dns:reverse DNS lookup:dns"
        "detect_fqdn_cloud_metadata:cloud metadata services:cloud"
    )
    
    for method_info in "${methods[@]}"; do
        local method_func="${method_info%%:*}"
        local method_desc="${method_info#*:}"
        method_desc="${method_desc%:*}"
        local method_type="${method_info##*:}"
        
        log_info "Trying: $method_desc"
        
        if detected_fqdn=$($method_func); then
            log_success "FQDN detected via $method_desc: $detected_fqdn"
            DETECTED_FQDN="$detected_fqdn"
            DETECTION_METHOD="$method_func"
            DETECTION_RESULTS+=("$method_func:success:$detected_fqdn")
            
            if [[ "$check_dns" == "yes" ]]; then
                if check_dns_resolution "$detected_fqdn"; then
                    log_success "Detected FQDN resolves correctly"
                    VALIDATION_RESULTS+=("dns:success")
                else
                    log_warning "Detected FQDN does not resolve"
                    VALIDATION_RESULTS+=("dns:failed")
                fi
            fi
            
            # Check CAA records if SSL is required
            if [[ "$require_ssl" == "yes" ]]; then
                if check_caa_ssl_compatibility "$detected_fqdn"; then
                    log_success "CAA records do not block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:compatible")
                else
                    log_warning "CAA records may block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:blocking")
                fi
            fi
            
            echo "$detected_fqdn"
            return 0
        else
            log_warning "No valid FQDN found via $method_desc"
            DETECTION_RESULTS+=("$method_func:failed")
        fi
    done
    
    log_warning "Could not auto-detect valid FQDN using any method"
    
    if [[ "$require_ssl" == "yes" ]]; then
        log_error "FQDN is required for SSL certificate enrollment"
        log_info "Please provide a valid FQDN using appropriate parameters"
        return 1
    elif [[ "$ALLOW_LOCALHOST" == "yes" ]]; then
        log_info "Using localhost as fallback"
        DETECTED_FQDN="localhost"
        DETECTION_METHOD="fallback"
        echo "localhost"
        return 0
    else
        log_error "No valid FQDN found and localhost not allowed"
        return 1
    fi
}

# ===============================================================================
# OUTPUT AND REPORTING FUNCTIONS
# ===============================================================================

# Generate JSON output
generate_json_output() {
    local fqdn="$1"
    local status="$2"
    
    cat << EOF
{
  "timestamp": "$(get_timestamp)",
  "script": {
    "name": "$SCRIPT_NAME",
    "version": "$SCRIPT_VERSION"
  },
  "detection": {
    "fqdn": "$fqdn",
    "method": "$DETECTION_METHOD",
    "status": "$status"
  },
  "validation": {
    "dns_check": "$CHECK_DNS",
    "results": [$(printf '"%s",' "${VALIDATION_RESULTS[@]}" | sed 's/,$//')"]
  },
  "caa_check": {
    "results": [$(printf '"%s",' "${CAA_RESULTS[@]}" | sed 's/,$//')"]
  },
  "config": {
    "require_ssl": "$REQUIRE_SSL",
    "allow_localhost": "$ALLOW_LOCALHOST",
    "allow_ip_as_fqdn": "$ALLOW_IP_AS_FQDN",
    "min_domain_parts": "$MIN_DOMAIN_PARTS"
  },
  "detection_attempts": [$(printf '"%s",' "${DETECTION_RESULTS[@]}" | sed 's/,$//')")]
}
EOF
}

# Generate XML output
generate_xml_output() {
    local fqdn="$1"
    local status="$2"
    
    cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<fqdn_detection>
  <timestamp>$(get_timestamp)</timestamp>
  <script>
    <name>$SCRIPT_NAME</name>
    <version>$SCRIPT_VERSION</version>
  </script>
  <detection>
    <fqdn>$fqdn</fqdn>
    <method>$DETECTION_METHOD</method>
    <status>$status</status>
  </detection>
  <validation>
    <dns_check>$CHECK_DNS</dns_check>
    <results>
$(for result in "${VALIDATION_RESULTS[@]}"; do echo "      <result>$result</result>"; done)
    </results>
  </validation>
  <caa_check>
    <results>
$(for result in "${CAA_RESULTS[@]}"; do echo "      <result>$result</result>"; done)
    </results>
  </caa_check>
  <config>
    <require_ssl>$REQUIRE_SSL</require_ssl>
    <allow_localhost>$ALLOW_LOCALHOST</allow_localhost>
    <allow_ip_as_fqdn>$ALLOW_IP_AS_FQDN</allow_ip_as_fqdn>
    <min_domain_parts>$MIN_DOMAIN_PARTS</min_domain_parts>
  </config>
  <detection_attempts>
$(for result in "${DETECTION_RESULTS[@]}"; do echo "    <attempt>$result</attempt>"; done)
  </detection_attempts>
</fqdn_detection>
EOF
}

# ===============================================================================
# GETTER FUNCTIONS
# ===============================================================================

# Get the detected FQDN
get_detected_fqdn() {
    echo "$DETECTED_FQDN"
}

# Get the detection method used
get_detection_method() {
    echo "$DETECTION_METHOD"
}

# Get all detection results
get_detection_results() {
    printf '%s\n' "${DETECTION_RESULTS[@]}"
}

# Get validation results
get_validation_results() {
    printf '%s\n' "${VALIDATION_RESULTS[@]}"
}

# ===============================================================================
# VALIDATION AND REPORTING FUNCTIONS
# ===============================================================================

# Comprehensive FQDN validation with detailed reporting
validate_fqdn_comprehensive() {
    local fqdn="$1"
    local check_dns="${2:-$CHECK_DNS}"
    local strict="${3:-no}"
    
    log_info "Performing comprehensive FQDN validation for: $fqdn"
    
    local validation_passed=true
    local validation_details=()
    
    if is_valid_fqdn "$fqdn" "$strict"; then
        log_success "FQDN format validation passed"
        validation_details+=("format:passed")
    else
        log_error "FQDN format validation failed"
        validation_details+=("format:failed")
        validation_passed=false
    fi
    
    if [[ "$check_dns" == "yes" ]]; then
        if check_dns_resolution "$fqdn"; then
            log_success "DNS resolution validation passed"
            validation_details+=("dns:passed")
        else
            log_warning "DNS resolution validation failed"
            validation_details+=("dns:failed")
            [[ "$strict" == "yes" ]] && validation_passed=false
        fi
    fi
    
    if [[ "$REQUIRE_SSL" == "yes" ]]; then
        if [[ "$fqdn" != "localhost" ]] && [[ "$fqdn" != "127.0.0.1" ]] && ! is_ip_address "$fqdn"; then
            log_success "SSL readiness validation passed"
            validation_details+=("ssl:ready")
            
            # Check CAA records for SSL compatibility
            if check_caa_ssl_compatibility "$fqdn"; then
                log_success "CAA validation passed"
                validation_details+=("caa:compatible")
            else
                log_warning "CAA validation failed"
                validation_details+=("caa:blocking")
                [[ "$strict" == "yes" ]] && validation_passed=false
            fi
        else
            log_error "SSL readiness validation failed (localhost/IP not suitable for SSL)"
            validation_details+=("ssl:not_ready")
            validation_passed=false
        fi
    fi
    
    VALIDATION_RESULTS=("${validation_details[@]}")
    
    if [[ "$validation_passed" == "true" ]]; then
        log_success "Comprehensive FQDN validation passed"
        return 0
    else
        log_error "Comprehensive FQDN validation failed"
        return 1
    fi
}

# Show detailed FQDN detection and validation summary
show_fqdn_summary() {
    local fqdn="$1"
    
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}                           FQDN DETECTION SUMMARY                              ${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${CYAN}Detection Results:${NC}"
    echo -e "${GREEN}• Detected FQDN: ${NC}${fqdn:-"Not detected"}"
    echo -e "${GREEN}• Detection Method: ${NC}${DETECTION_METHOD:-"None"}"
    echo -e "${GREEN}• Timestamp: ${NC}$(get_timestamp)"
    echo ""
    
    echo -e "${CYAN}Validation Status:${NC}"
    if [[ -n "$fqdn" && "$fqdn" != "localhost" ]]; then
        echo -e "${GREEN}• SSL Ready: ${NC}Yes"
        echo -e "${GREEN}• Domain Configuration: ${NC}Ready"
        echo -e "${GREEN}• External Access: ${NC}Possible"
    else
        echo -e "${YELLOW}• SSL Ready: ${NC}No (localhost or invalid FQDN)"
        echo -e "${YELLOW}• Domain Configuration: ${NC}Manual setup required"
        echo -e "${YELLOW}• External Access: ${NC}Limited"
    fi
    echo ""
    
    if [[ ${#VALIDATION_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}Validation Details:${NC}"
        for result in "${VALIDATION_RESULTS[@]}"; do
            local check="${result%%:*}"
            local status="${result#*:}"
            local icon="✓"
            local color="$GREEN"
            
            if [[ "$status" == "failed" ]] || [[ "$status" == "not_ready" ]] || [[ "$status" == "blocking" ]]; then
                icon="✗"
                color="$RED"
            elif [[ "$status" == "warning" ]]; then
                icon="⚠"
                color="$YELLOW"
            fi
            
            echo -e "${color}  $icon $check: $status${NC}"
        done
        echo ""
    fi
    
    if [[ ${#CAA_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}CAA Record Analysis:${NC}"
        for result in "${CAA_RESULTS[@]}"; do
            local type="${result%%:*}"
            local domain="${result#*:}"
            domain="${domain%%:*}"
            local details="${result##*:}"
            
            local icon="ℹ"
            local color="$BLUE"
            
            case "$type" in
                "blocking")
                    icon="✗"
                    color="$RED"
                    echo -e "${color}  $icon Domain $domain blocks CA: $details${NC}"
                    ;;
                "allowed")
                    icon="✓"
                    color="$GREEN"
                    echo -e "${color}  $icon Domain $domain allows CA: $details${NC}"
                    ;;
                "no_caa")
                    icon="○"
                    color="$BLUE"
                    echo -e "${color}  $icon No CAA records for: $domain${NC}"
                    ;;
                "iodef")
                    icon="📧"
                    color="$CYAN"
                    echo -e "${color}  $icon Incident reporting configured for $domain: $details${NC}"
                    ;;
            esac
        done
        echo ""
    fi
    
    if [[ ${#DETECTION_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}Detection Attempts:${NC}"
        for result in "${DETECTION_RESULTS[@]}"; do
            local method="${result%%:*}"
            local status="${result#*:}"
            status="${status%%:*}"
            local detected="${result##*:}"
            
            local icon="✓"
            local color="$GREEN"
            
            if [[ "$status" == "failed" ]]; then
                icon="✗"
                color="$RED"
                detected="N/A"
            fi
            
            echo -e "${color}  $icon $method: $status${NC}"
            [[ "$detected" != "N/A" && "$detected" != "$method" ]] && echo -e "    ${CYAN}→ $detected${NC}"
        done
        echo ""
    fi
    
    echo -e "${CYAN}Current Configuration:${NC}"
    echo -e "${BLUE}• Require SSL: ${NC}$REQUIRE_SSL"
    echo -e "${BLUE}• Check DNS: ${NC}$CHECK_DNS"
    echo -e "${BLUE}• Allow Localhost: ${NC}$ALLOW_LOCALHOST"
    echo -e "${BLUE}• Allow IP as FQDN: ${NC}$ALLOW_IP_AS_FQDN"
    echo ""
}

# ===============================================================================
# TESTING FRAMEWORK
# ===============================================================================

# Test individual validation functions
test_validation_functions() {
    echo "Testing FQDN validation functions..."
    echo ""
    
    local test_cases=(
        "example.com:valid"
        "sub.example.com:valid"
        "very.long.domain.example.com:valid"
        "localhost:depends_on_config"
        "192.168.1.1:depends_on_config"
        "invalid:invalid"
        "test.:invalid"
        ".example.com:invalid"
        "example..com:invalid"
        "ex ample.com:invalid"
        "example-.com:invalid"
        "-example.com:invalid"
    )
    
    for test_case in "${test_cases[@]}"; do
        local fqdn="${test_case%%:*}"
        local expected="${test_case#*:}"
        
        if is_valid_fqdn "$fqdn"; then
            echo -e "  ${GREEN}✓${NC} $fqdn - Valid"
        else
            echo -e "  ${RED}✗${NC} $fqdn - Invalid"
        fi
    done
    echo ""
}

# Test all detection methods
test_detection_methods() {
    echo "Testing FQDN detection methods..."
    echo ""
    
    local methods=(
        "detect_fqdn_hostname:hostname -f"
        "detect_fqdn_hostnamectl:hostnamectl"
        "detect_fqdn_dns_domain:dnsdomainname"
        "detect_fqdn_etc_hostname:/etc/hostname"
        "detect_fqdn_etc_hosts:/etc/hosts"
        "detect_fqdn_reverse_dns:reverse DNS"
        "detect_fqdn_cloud_metadata:cloud metadata"
    )
    
    for method_info in "${methods[@]}"; do
        local method_func="${method_info%%:*}"
        local method_desc="${method_info#*:}"
        
        echo -n "  Testing $method_desc... "
        
        if detected=$($method_func 2>/dev/null); then
            echo -e "${GREEN}✓ $detected${NC}"
        else
            echo -e "${YELLOW}- No result${NC}"
        fi
    done
    echo ""
}

# Test DNS resolution
test_dns_resolution() {
    local test_domains=("google.com" "github.com" "nonexistent.example.invalid")
    
    echo "Testing DNS resolution capabilities..."
    echo ""
    
    for domain in "${test_domains[@]}"; do
        echo -n "  Testing $domain... "
        
        if check_dns_resolution "$domain" 3; then
            echo -e "${GREEN}✓ Resolves${NC}"
        else
            echo -e "${RED}✗ Does not resolve${NC}"
        fi
    done
    echo ""
}

# Test CAA record checking
test_caa_checking() {
    local test_domains=("github.com" "google.com" "example.com")
    
    echo "Testing CAA record checking..."
    echo ""
    
    for domain in "${test_domains[@]}"; do
        echo "  Testing CAA for $domain:"
        
        if check_caa_ssl_compatibility "$domain" "letsencrypt.org"; then
            echo -e "    ${GREEN}✓ SSL certificate issuance would be allowed${NC}"
        else
            echo -e "    ${RED}✗ SSL certificate issuance might be blocked${NC}"
        fi
        
        local caa_results=($(get_caa_results))
        for result in "${caa_results[@]}"; do
            echo -e "    ${BLUE}→ $result${NC}"
        done
        
        CAA_RESULTS=()
        echo ""
    done
}

# Comprehensive test suite
run_comprehensive_tests() {
    echo -e "${BOLD}Running Comprehensive Test Suite${NC}"
    echo -e "${BOLD}=================================${NC}"
    echo ""
    
    test_validation_functions
    test_detection_methods
    test_dns_resolution
    test_caa_checking
    
    echo "Testing complete FQDN detection process..."
    detected=$(auto_detect_fqdn "" "no" "yes")
    echo "  Auto-detected FQDN: ${detected:-"None"}"
    echo ""
    
    show_fqdn_summary "$detected"
}

# ===============================================================================
# CLI INTERFACE
# ===============================================================================

# Show usage information
show_usage() {
    cat << EOF
${BOLD}$SCRIPT_NAME v$SCRIPT_VERSION${NC}
$SCRIPT_PURPOSE

${BOLD}USAGE:${NC}
  $0 [OPTIONS] [COMMAND]

${BOLD}COMMANDS:${NC}
  detect [FQDN]         Auto-detect or validate FQDN
  validate FQDN         Validate specific FQDN  
  test                  Run comprehensive tests
  check-caa FQDN [CA]   Check CAA records for SSL compatibility
  config                Show current configuration
  save-config FILE      Save configuration to file
  load-config FILE      Load configuration from file

${BOLD}OPTIONS:${NC}
  --require-ssl         Require SSL-compatible FQDN
  --no-dns-check        Skip DNS resolution check
  --allow-localhost     Allow localhost as valid FQDN
  --allow-ip            Allow IP addresses as FQDN
  --min-parts N         Minimum domain parts required (default: $DEFAULT_MIN_DOMAIN_PARTS)
  --log-level LEVEL     Set log level (DEBUG|INFO|WARNING|ERROR)
  --output FORMAT       Output format (text|json|xml)
  --config FILE         Load configuration from file
  --no-colors           Disable colored output
  --strict              Enable strict validation mode
  --timeout N           Set DNS timeout in seconds

${BOLD}EXAMPLES:${NC}
  $0 detect                           # Auto-detect FQDN
  $0 detect example.com               # Validate provided FQDN
  $0 validate example.com             # Validate specific FQDN
  $0 check-caa example.com            # Check CAA records for Let's Encrypt
  $0 check-caa example.com digicert.com # Check CAA for specific CA
  $0 --require-ssl detect             # Require SSL-compatible FQDN
  $0 --output json detect             # Output in JSON format
  $0 test                             # Run test suite

${BOLD}RETURN CODES:${NC}
  0  Success
  1  FQDN validation/detection failed
  2  Configuration error
  3  Invalid arguments
EOF
}

# Parse command line arguments
parse_cli_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --require-ssl)
                REQUIRE_SSL="yes"
                shift
                ;;
            --no-dns-check)
                CHECK_DNS="no"
                shift
                ;;
            --allow-localhost)
                ALLOW_LOCALHOST="yes"
                shift
                ;;
            --allow-ip)
                ALLOW_IP_AS_FQDN="yes"
                shift
                ;;
            --min-parts)
                MIN_DOMAIN_PARTS="$2"
                shift 2
                ;;
            --log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            --output)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            --config)
                load_config "$2" || exit 2
                shift 2
                ;;
            --no-colors)
                USE_COLORS="no"
                shift
                ;;
            --strict)
                STRICT_MODE="yes"
                shift
                ;;
            --timeout)
                DNS_TIMEOUT="$2"
                PING_TIMEOUT="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            --)
                shift
                break
                ;;
            -*)
                log_error "Unknown option: $1"
                show_usage
                exit 3
                ;;
            *)
                break
                ;;
        esac
    done
    
    CLI_ARGS=("$@")
}

# Main CLI function
main_cli() {
    local command="${1:-detect}"
    shift || true
    
    case "$command" in
        detect)
            local fqdn="$1"
            local detected_fqdn=""
            
            if detected_fqdn=$(auto_detect_fqdn "$fqdn" "$REQUIRE_SSL" "$CHECK_DNS"); then
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "$detected_fqdn" "success"
                        ;;
                    xml)
                        generate_xml_output "$detected_fqdn" "success"
                        ;;
                    *)
                        echo "$detected_fqdn"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary "$detected_fqdn"
                        ;;
                esac
                return 0
            else
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "" "failed"
                        ;;
                    xml)
                        generate_xml_output "" "failed"
                        ;;
                    *)
                        log_error "FQDN detection failed"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary ""
                        ;;
                esac
                return 1
            fi
            ;;
        validate)
            local fqdn="$1"
            if [[ -z "$fqdn" ]]; then
                log_error "FQDN required for validation"
                return 3
            fi
            
            if validate_fqdn_comprehensive "$fqdn" "$CHECK_DNS" "${STRICT_MODE:-no}"; then
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "$fqdn" "valid"
                        ;;
                    xml)
                        generate_xml_output "$fqdn" "valid"
                        ;;
                    *)
                        echo "valid"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary "$fqdn"
                        ;;
                esac
                return 0
            else
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "$fqdn" "invalid"
                        ;;
                    xml)
                        generate_xml_output "$fqdn" "invalid"
                        ;;
                    *)
                        echo "invalid"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary "$fqdn"
                        ;;
                esac
                return 1
            fi
            ;;
        check-caa)
            local fqdn="$1"
            local ca_identifier="${2:-letsencrypt.org}"
            
            if [[ -z "$fqdn" ]]; then
                log_error "FQDN required for CAA checking"
                return 3
            fi
            
            if check_caa_ssl_compatibility "$fqdn" "$ca_identifier"; then
                echo "CAA records allow SSL certificate issuance for $ca_identifier"
                return 0
            else
                echo "CAA records may block SSL certificate issuance for $ca_identifier"
                return 1
            fi
            ;;
        test)
            run_comprehensive_tests
            ;;
        config)
            show_config
            ;;
        save-config)
            local config_file="$1"
            if [[ -z "$config_file" ]]; then
                log_error "Configuration file path required"
                return 3
            fi
            save_config "$config_file"
            ;;
        load-config)
            local config_file="$1"
            if [[ -z "$config_file" ]]; then
                log_error "Configuration file path required"
                return 3
            fi
            load_config "$config_file"
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            return 3
            ;;
    esac
}

# ===============================================================================
# MAIN EXECUTION
# ===============================================================================

# Main execution logic
main() {
    if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
        log_debug "Script sourced, functions available"
        return 0
    fi
    
    parse_cli_arguments "$@"
    main_cli "${CLI_ARGS[@]}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi || echo "")
        if [[ -n "$hostname_ips" ]]; then
            while IFS= read -r ip; do
                [[ -n "$ip" ]] && local_ips+=("$ip")
                log_debug "Found local IP via hostname -I: $ip"
            done <<< "$hostname_ips"
        fi
    fi
    
    # Method 2: ip route (for primary interface)
    if command_exists ip; then
        local route_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[^ ]+' || echo "")
        if [[ -n "$route_ip" ]] && [[ ! " ${local_ips[*]} " =~ " ${route_ip} " ]]; then
            local_ips+=("$route_ip")
            log_debug "Found local IP via ip route: $route_ip"
        fi
    fi
    
    # Method 3: ifconfig (fallback)
    if command_exists ifconfig && [[ ${#local_ips[@]} -eq 0 ]]; then
        local ifconfig_ips=$(ifconfig 2>/dev/null | grep -oE 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | grep -v '^127\.' || echo "")
        if [[ -n "$ifconfig_ips" ]]; then
            while IFS= read -r ip; do
                [[ -n "$ip" ]] && [[ ! " ${local_ips[*]} " =~ " ${ip} " ]] && local_ips+=("$ip")
                log_debug "Found local IP via ifconfig: $ip"
            done <<< "$ifconfig_ips"
        fi
    fi
    
    # Filter out obviously invalid IPs
    local filtered_ips=()
    for ip in "${local_ips[@]}"; do
        if [[ "$ip" != "0.0.0.0" && "$ip" != "255.255.255.255" ]]; then
            filtered_ips+=("$ip")
        fi
    done
    
    if [[ ${#filtered_ips[@]} -gt 0 ]]; then
        printf '%s\n' "${filtered_ips[@]}"
        return 0
    else
        log_debug "No local IP addresses found"
        return 1
    fi
}

# Get external/public IP address using multiple services
get_external_ip_address() {
    local timeout="${1:-5}"
    local external_ip=""
    
    log_debug "Detecting external IP address..."
    
    # List of reliable IP detection services
    local ip_services=(
        "https://icanhazip.com"
        "https://ipinfo.io/ip"
        "https://api.ipify.org"
        "https://checkip.amazonaws.com"
        "https://ifconfig.me/ip"
        "https://ipecho.net/plain"
        "https://myexternalip.com/raw"
        "https://wtfismyip.com/text"
    )
    
    if ! command_exists curl; then
        log_debug "curl not available - cannot detect external IP"
        return 1
    fi
    
    # Try each service until we get a valid response
    for service in "${ip_services[@]}"; do
        log_debug "Trying IP detection service: $service"
        
        external_ip=$(timeout "$timeout" curl -s -4 --max-time "$timeout" --connect-timeout "$timeout" "$service" 2>/dev/null | tr -d '\n\r' || echo "")
        
        # Validate the response looks like an IP address
        if [[ -n "$external_ip" ]] && [[ "$external_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Additional validation - check if it's a valid public IP
            if ! is_private_ip "$external_ip"; then
                log_debug "External IP detected via $service: $external_ip"
                echo "$external_ip"
                return 0
            else
                log_debug "Service $service returned private IP: $external_ip"
            fi
        else
            log_debug "Service $service returned invalid response: ${external_ip:0:50}"
        fi
    done
    
    log_debug "Failed to detect external IP address"
    return 1
}

# Comprehensive IP address detection and NAT analysis
detect_ip_configuration() {
    log_info "Performing comprehensive IP address detection..."
    
    # Clear previous results
    IP_DETECTION_RESULTS=()
    
    # Get local IP addresses
    local local_ips=($(get_local_ip_addresses))
    local external_ip=""
    local behind_nat=false
    local nat_type="none"
    
    # Get external IP address
    if external_ip=$(get_external_ip_address); then
        log_success "External IP detected: $external_ip"
    else
        log_warning "Could not detect external IP address"
    fi
    
    # Analyze NAT configuration
    if [[ -n "$external_ip" && ${#local_ips[@]} -gt 0 ]]; then
        local found_matching_ip=false
        
        for local_ip in "${local_ips[@]}"; do
            if [[ "$local_ip" == "$external_ip" ]]; then
                found_matching_ip=true
                break
            fi
        done
        
        if [[ "$found_matching_ip" == "false" ]]; then
            behind_nat=true
            
            # Determine NAT type based on local IP ranges
            for local_ip in "${local_ips[@]}"; do
                if [[ "$local_ip" =~ ^10\. ]]; then
                    nat_type="private_class_a"
                    break
                elif [[ "$local_ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
                    nat_type="private_class_b"
                    break
                elif [[ "$local_ip" =~ ^192\.168\. ]]; then
                    nat_type="private_class_c"
                    break
                elif [[ "$local_ip" =~ ^169\.254\. ]]; then
                    nat_type="link_local"
                    break
                else
                    nat_type="unknown_private"
                fi
            done
            
            log_info "Server is behind NAT ($nat_type)"
        else
            log_info "Server has direct public IP access"
        fi
    fi
    
    # Store results for reporting
    for local_ip in "${local_ips[@]}"; do
        local ip_type="private"
        if ! is_private_ip "$local_ip"; then
            ip_type="public"
        fi
        IP_DETECTION_RESULTS+=("local:$local_ip:$ip_type")
    done
    
    if [[ -n "$external_ip" ]]; then
        IP_DETECTION_RESULTS+=("external:$external_ip:public")
    fi
    
    IP_DETECTION_RESULTS+=("behind_nat:$behind_nat")
    IP_DETECTION_RESULTS+=("nat_type:$nat_type")
    
    # Log structured data
    local ip_data="{\"local_ips\":[\"$(printf '%s",' "${local_ips[@]}" | sed 's/,$//')\"],\"external_ip\":\"$external_ip\",\"behind_nat\":$behind_nat,\"nat_type\":\"$nat_type\"}"
    log_structured "ip_detection" "$ip_data" "INFO"
    
    # Return the results
    echo "local_ips:${local_ips[*]}"
    echo "external_ip:$external_ip"
    echo "behind_nat:$behind_nat"
    echo "nat_type:$nat_type"
    
    return 0
}

# Get IP detection results
get_ip_detection_results() {
    printf '%s\n' "${IP_DETECTION_RESULTS[@]}"
}

# Enhanced reverse DNS validation with both local and external IPs
validate_reverse_dns_comprehensive() {
    local fqdn="$1"
    local timeout="${2:-$DNS_TIMEOUT}"
    
    log_info "Validating comprehensive reverse DNS for: $fqdn"
    
    # Get all IP addresses (local and external)
    local all_ips=()
    
    # Add FQDN resolution IPs
    local fqdn_ips=($(get_ip_addresses "$fqdn" "$timeout"))
    all_ips+=("${fqdn_ips[@]}")
    
    # Add local IPs
    local local_ips=($(get_local_ip_addresses))
    for ip in "${local_ips[@]}"; do
        if [[ ! " ${all_ips[*]} " =~ " ${ip} " ]]; then
            all_ips+=("$ip")
        fi
    done
    
    # Add external IP
    local external_ip=""
    if external_ip=$(get_external_ip_address); then
        if [[ ! " ${all_ips[*]} " =~ " ${external_ip} " ]]; then
            all_ips+=("$external_ip")
        fi
    fi
    
    if [[ ${#all_ips[@]} -eq 0 ]]; then
        log_warning "Cannot validate reverse DNS - no IP addresses found"
        return 1
    fi
    
    local reverse_dns_results=()
    local reverse_dns_matches=0
    local reverse_dns_mismatches=0
    local reverse_dns_failures=0
    
    # Check reverse DNS for each IP address
    for ip in "${all_ips[@]}"; do
        log_debug "Checking comprehensive reverse DNS for IP: $ip"
        
        local reverse_hostname=""
        if reverse_hostname=$(reverse_dns_lookup "$ip" "$timeout"); then
            reverse_dns_results+=("$ip:$reverse_hostname")
            
            # Check if reverse DNS matches the original FQDN
            if [[ "$reverse_hostname" == "$fqdn" ]]; then
                log_success "Reverse DNS matches for $ip: $reverse_hostname"
                ((reverse_dns_matches++))
            else
                log_warning "Reverse DNS mismatch for $ip: expected '$fqdn', got '$reverse_hostname'"
                ((reverse_dns_mismatches++))
            fi
        else
            log_warning "Reverse DNS lookup failed for IP: $ip"
            reverse_dns_results+=("$ip:no_reverse_dns")
            ((reverse_dns_failures++))
        fi
    done
    
    # Store results in global variable for reporting
    REVERSE_DNS_RESULTS=("${reverse_dns_results[@]}")
    
    # Generate summary
    local total_ips=${#all_ips[@]}
    log_info "Comprehensive reverse DNS validation summary:"
    log_info "  Total IPs checked: $total_ips"
    log_info "  Matches: $reverse_dns_matches"
    log_info "  Mismatches: $reverse_dns_mismatches"
    log_info "  Failures: $reverse_dns_failures"
    
    # Return success if at least one IP has matching reverse DNS
    if [[ $reverse_dns_matches -gt 0 ]]; then
        return 0
    else
        return 1
    fi
}

# ===============================================================================
# CAA RECORD VALIDATION FUNCTIONS
# ===============================================================================

# Extract domain hierarchy from FQDN
get_domain_hierarchy() {
    local fqdn="$1"
    local domains=()
    
    # Remove trailing dot if present
    fqdn="${fqdn%.}"
    
    # Split domain into parts
    local IFS='.'
    local parts=($fqdn)
    
    # Build domain hierarchy from specific to general
    for ((i=0; i<${#parts[@]}; i++)); do
        local domain=""
        for ((j=i; j<${#parts[@]}; j++)); do
            if [[ -n "$domain" ]]; then
                domain="$domain.${parts[j]}"
            else
                domain="${parts[j]}"
            fi
        done
        domains+=("$domain")
    done
    
    printf '%s\n' "${domains[@]}"
}

# Check CAA record for a specific domain
check_caa_record() {
    local domain="$1"
    local timeout="${2:-$DNS_TIMEOUT}"
    
    log_debug "Checking CAA record for domain: $domain"
    
    local caa_records=""
    local query_method=""
    
    # Try different DNS tools to query CAA records
    if command_exists dig; then
        caa_records=$(timeout "$timeout" dig +short CAA "$domain" 2>/dev/null || echo "")
        query_method="dig"
    elif command_exists nslookup; then
        # nslookup doesn't support CAA records directly, but we can try
        caa_records=$(timeout "$timeout" nslookup -type=CAA "$domain" 2>/dev/null | grep -E "issue|issuewild|iodef" || echo "")
        query_method="nslookup"
    elif command_exists host; then
        caa_records=$(timeout "$timeout" host -t CAA "$domain" 2>/dev/null || echo "")
        query_method="host"
    fi
    
    if [[ -n "$caa_records" ]]; then
        log_debug "CAA records found for $domain via $query_method"
        echo "$caa_records"
        return 0
    else
        log_debug "No CAA records found for $domain"
        return 1
    fi
}

# Parse CAA record and check if CA is allowed
is_ca_allowed_by_caa() {
    local caa_record="$1"
    local ca_identifier="$2"
    
    # Common CA identifiers
    local common_cas=(
        "letsencrypt.org"
        "amazon.com"
        "digicert.com"
        "globalsign.com"
        "sectigo.com"
        "godaddy.com"
        "comodo.com"
    )
    
    # If no specific CA provided, check against common ones
    if [[ -z "$ca_identifier" ]]; then
        for ca in "${common_cas[@]}"; do
            if echo "$caa_record" | grep -q "issue.*$ca"; then
                return 0
            fi
        done
        return 1
    fi
    
    # Check if specific CA is allowed
    if echo "$caa_record" | grep -q "issue.*$ca_identifier"; then
        return 0
    fi
    
    return 1
}

# Comprehensive CAA record checking for SSL certificate rollout
check_caa_ssl_compatibility() {
    local fqdn="$1"
    local ca_identifier="${2:-letsencrypt.org}"
    
    log_info "Checking CAA records for SSL certificate compatibility: $fqdn"
    
    # Clear previous CAA results
    CAA_RESULTS=()
    
    local domains=($(get_domain_hierarchy "$fqdn"))
    local caa_blocking=false
    local caa_found=false
    local blocking_domain=""
    local allowed_cas=()
    
    log_debug "Domain hierarchy: ${domains[*]}"
    
    # Check each domain in the hierarchy
    for domain in "${domains[@]}"; do
        log_debug "Checking CAA for domain level: $domain"
        
        local caa_records=""
        if caa_records=$(check_caa_record "$domain"); then
            caa_found=true
            log_info "CAA records found for $domain"
            
            # Parse CAA records
            local has_issue_restriction=false
            local ca_allowed=false
            local wildcard_allowed=false
            
            while IFS= read -r record; do
                if [[ -n "$record" ]]; then
                    log_debug "CAA record: $record"
                    
                    # Check for issue restriction
                    if echo "$record" | grep -q "issue"; then
                        has_issue_restriction=true
                        
                        # Check if our CA is allowed
                        if is_ca_allowed_by_caa "$record" "$ca_identifier"; then
                            ca_allowed=true
                            log_success "CA $ca_identifier is allowed by CAA record"
                        fi
                        
                        # Extract allowed CAs
                        local allowed_ca=$(echo "$record" | grep -oE 'issue[[:space:]]+"[^"]+"' | cut -d'"' -f2)
                        if [[ -n "$allowed_ca" ]]; then
                            allowed_cas+=("$allowed_ca")
                        fi
                    fi
                    
                    # Check for wildcard restrictions
                    if echo "$record" | grep -q "issuewild"; then
                        if is_ca_allowed_by_caa "$record" "$ca_identifier"; then
                            wildcard_allowed=true
                            log_success "Wildcard certificates allowed for $ca_identifier"
                        fi
                    fi
                    
                    # Check for iodef (incident reporting)
                    if echo "$record" | grep -q "iodef"; then
                        local iodef_contact=$(echo "$record" | grep -oE 'iodef[[:space:]]+"[^"]+"' | cut -d'"' -f2)
                        log_info "CAA incident reporting configured: $iodef_contact"
                        CAA_RESULTS+=("iodef:$domain:$iodef_contact")
                    fi
                fi
            done <<< "$caa_records"
            
            # If issue restriction exists but CA not allowed, it's blocking
            if [[ "$has_issue_restriction" == "true" && "$ca_allowed" == "false" ]]; then
                caa_blocking=true
                blocking_domain="$domain"
                log_warning "CAA records at $domain would block $ca_identifier"
                CAA_RESULTS+=("blocking:$domain:$ca_identifier")
                break
            elif [[ "$has_issue_restriction" == "true" && "$ca_allowed" == "true" ]]; then
                log_success "CAA records at $domain allow $ca_identifier"
                CAA_RESULTS+=("allowed:$domain:$ca_identifier")
            fi
        else
            log_debug "No CAA records found for $domain"
            CAA_RESULTS+=("no_caa:$domain")
        fi
    done
    
    # Generate summary
    if [[ "$caa_blocking" == "true" ]]; then
        log_error "CAA records would block SSL certificate issuance"
        log_error "Blocking domain: $blocking_domain"
        if [[ ${#allowed_cas[@]} -gt 0 ]]; then
            log_info "Allowed CAs: ${allowed_cas[*]}"
        fi
        return 1
    elif [[ "$caa_found" == "true" ]]; then
        log_success "CAA records found but do not block $ca_identifier"
        return 0
    else
        log_info "No CAA records found - certificate issuance should proceed normally"
        return 0
    fi
}

# Get CAA checking results
get_caa_results() {
    printf '%s\n' "${CAA_RESULTS[@]}"
}

# ===============================================================================
# MAIN DETECTION FUNCTION
# ===============================================================================

# Main FQDN detection function with comprehensive reporting
auto_detect_fqdn() {
    local provided_fqdn="$1"
    local require_ssl="${2:-$REQUIRE_SSL}"
    local check_dns="${3:-$CHECK_DNS}"
    
    DETECTED_FQDN=""
    DETECTION_METHOD=""
    DETECTION_RESULTS=()
    VALIDATION_RESULTS=()
    
    log_info "Starting FQDN detection process..."
    log_debug "Parameters: provided_fqdn='$provided_fqdn', require_ssl='$require_ssl', check_dns='$check_dns'"
    
    if [[ -n "$provided_fqdn" ]]; then
        log_info "Validating provided FQDN: $provided_fqdn"
        
        if is_valid_fqdn "$provided_fqdn"; then
            log_success "Provided FQDN is valid: $provided_fqdn"
            DETECTED_FQDN="$provided_fqdn"
            DETECTION_METHOD="user-provided"
            
            if [[ "$check_dns" == "yes" ]]; then
                if check_dns_resolution "$provided_fqdn"; then
                    log_success "Provided FQDN resolves correctly"
                    VALIDATION_RESULTS+=("dns:success")
                else
                    log_warning "Provided FQDN does not resolve (may be expected for new domains)"
                    VALIDATION_RESULTS+=("dns:failed")
                fi
            fi
            
            # Check CAA records if SSL is required
            if [[ "$require_ssl" == "yes" ]]; then
                if check_caa_ssl_compatibility "$provided_fqdn"; then
                    log_success "CAA records do not block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:compatible")
                else
                    log_warning "CAA records may block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:blocking")
                fi
            fi
            
            echo "$provided_fqdn"
            return 0
        else
            log_error "Provided FQDN is invalid: $provided_fqdn"
            if [[ "$require_ssl" == "yes" ]]; then
                log_error "Valid FQDN is required for SSL certificate enrollment"
                return 1
            fi
        fi
    fi
    
    log_info "Auto-detecting FQDN using multiple methods..."
    
    local methods=(
        "detect_fqdn_hostname:hostname -f command:system"
        "detect_fqdn_hostnamectl:systemd hostnamectl:system"
        "detect_fqdn_dns_domain:dnsdomainname + hostname:dns"
        "detect_fqdn_etc_hostname:/etc/hostname file:file"
        "detect_fqdn_etc_hosts:/etc/hosts file:file"
        "detect_fqdn_reverse_dns:reverse DNS lookup:dns"
        "detect_fqdn_cloud_metadata:cloud metadata services:cloud"
    )
    
    for method_info in "${methods[@]}"; do
        local method_func="${method_info%%:*}"
        local method_desc="${method_info#*:}"
        method_desc="${method_desc%:*}"
        local method_type="${method_info##*:}"
        
        log_info "Trying: $method_desc"
        
        if detected_fqdn=$($method_func); then
            log_success "FQDN detected via $method_desc: $detected_fqdn"
            DETECTED_FQDN="$detected_fqdn"
            DETECTION_METHOD="$method_func"
            DETECTION_RESULTS+=("$method_func:success:$detected_fqdn")
            
            if [[ "$check_dns" == "yes" ]]; then
                if check_dns_resolution "$detected_fqdn"; then
                    log_success "Detected FQDN resolves correctly"
                    VALIDATION_RESULTS+=("dns:success")
                else
                    log_warning "Detected FQDN does not resolve"
                    VALIDATION_RESULTS+=("dns:failed")
                fi
            fi
            
            # Check CAA records if SSL is required
            if [[ "$require_ssl" == "yes" ]]; then
                if check_caa_ssl_compatibility "$detected_fqdn"; then
                    log_success "CAA records do not block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:compatible")
                else
                    log_warning "CAA records may block SSL certificate issuance"
                    VALIDATION_RESULTS+=("caa:blocking")
                fi
            fi
            
            echo "$detected_fqdn"
            return 0
        else
            log_warning "No valid FQDN found via $method_desc"
            DETECTION_RESULTS+=("$method_func:failed")
        fi
    done
    
    log_warning "Could not auto-detect valid FQDN using any method"
    
    if [[ "$require_ssl" == "yes" ]]; then
        log_error "FQDN is required for SSL certificate enrollment"
        log_info "Please provide a valid FQDN using appropriate parameters"
        return 1
    elif [[ "$ALLOW_LOCALHOST" == "yes" ]]; then
        log_info "Using localhost as fallback"
        DETECTED_FQDN="localhost"
        DETECTION_METHOD="fallback"
        echo "localhost"
        return 0
    else
        log_error "No valid FQDN found and localhost not allowed"
        return 1
    fi
}

# ===============================================================================
# OUTPUT AND REPORTING FUNCTIONS
# ===============================================================================

# Generate JSON output
generate_json_output() {
    local fqdn="$1"
    local status="$2"
    
    cat << EOF
{
  "timestamp": "$(get_timestamp)",
  "script": {
    "name": "$SCRIPT_NAME",
    "version": "$SCRIPT_VERSION"
  },
  "detection": {
    "fqdn": "$fqdn",
    "method": "$DETECTION_METHOD",
    "status": "$status"
  },
  "validation": {
    "dns_check": "$CHECK_DNS",
    "results": [$(printf '"%s",' "${VALIDATION_RESULTS[@]}" | sed 's/,$//')"]
  },
  "caa_check": {
    "results": [$(printf '"%s",' "${CAA_RESULTS[@]}" | sed 's/,$//')"]
  },
  "config": {
    "require_ssl": "$REQUIRE_SSL",
    "allow_localhost": "$ALLOW_LOCALHOST",
    "allow_ip_as_fqdn": "$ALLOW_IP_AS_FQDN",
    "min_domain_parts": "$MIN_DOMAIN_PARTS"
  },
  "detection_attempts": [$(printf '"%s",' "${DETECTION_RESULTS[@]}" | sed 's/,$//')")]
}
EOF
}

# Generate XML output
generate_xml_output() {
    local fqdn="$1"
    local status="$2"
    
    cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<fqdn_detection>
  <timestamp>$(get_timestamp)</timestamp>
  <script>
    <name>$SCRIPT_NAME</name>
    <version>$SCRIPT_VERSION</version>
  </script>
  <detection>
    <fqdn>$fqdn</fqdn>
    <method>$DETECTION_METHOD</method>
    <status>$status</status>
  </detection>
  <validation>
    <dns_check>$CHECK_DNS</dns_check>
    <results>
$(for result in "${VALIDATION_RESULTS[@]}"; do echo "      <result>$result</result>"; done)
    </results>
  </validation>
  <caa_check>
    <results>
$(for result in "${CAA_RESULTS[@]}"; do echo "      <result>$result</result>"; done)
    </results>
  </caa_check>
  <config>
    <require_ssl>$REQUIRE_SSL</require_ssl>
    <allow_localhost>$ALLOW_LOCALHOST</allow_localhost>
    <allow_ip_as_fqdn>$ALLOW_IP_AS_FQDN</allow_ip_as_fqdn>
    <min_domain_parts>$MIN_DOMAIN_PARTS</min_domain_parts>
  </config>
  <detection_attempts>
$(for result in "${DETECTION_RESULTS[@]}"; do echo "    <attempt>$result</attempt>"; done)
  </detection_attempts>
</fqdn_detection>
EOF
}

# ===============================================================================
# GETTER FUNCTIONS
# ===============================================================================

# Get the detected FQDN
get_detected_fqdn() {
    echo "$DETECTED_FQDN"
}

# Get the detection method used
get_detection_method() {
    echo "$DETECTION_METHOD"
}

# Get all detection results
get_detection_results() {
    printf '%s\n' "${DETECTION_RESULTS[@]}"
}

# Get validation results
get_validation_results() {
    printf '%s\n' "${VALIDATION_RESULTS[@]}"
}

# ===============================================================================
# VALIDATION AND REPORTING FUNCTIONS
# ===============================================================================

# Comprehensive FQDN validation with detailed reporting
validate_fqdn_comprehensive() {
    local fqdn="$1"
    local check_dns="${2:-$CHECK_DNS}"
    local strict="${3:-no}"
    
    log_info "Performing comprehensive FQDN validation for: $fqdn"
    
    local validation_passed=true
    local validation_details=()
    
    if is_valid_fqdn "$fqdn" "$strict"; then
        log_success "FQDN format validation passed"
        validation_details+=("format:passed")
    else
        log_error "FQDN format validation failed"
        validation_details+=("format:failed")
        validation_passed=false
    fi
    
    if [[ "$check_dns" == "yes" ]]; then
        if check_dns_resolution "$fqdn"; then
            log_success "DNS resolution validation passed"
            validation_details+=("dns:passed")
        else
            log_warning "DNS resolution validation failed"
            validation_details+=("dns:failed")
            [[ "$strict" == "yes" ]] && validation_passed=false
        fi
    fi
    
    if [[ "$REQUIRE_SSL" == "yes" ]]; then
        if [[ "$fqdn" != "localhost" ]] && [[ "$fqdn" != "127.0.0.1" ]] && ! is_ip_address "$fqdn"; then
            log_success "SSL readiness validation passed"
            validation_details+=("ssl:ready")
            
            # Check CAA records for SSL compatibility
            if check_caa_ssl_compatibility "$fqdn"; then
                log_success "CAA validation passed"
                validation_details+=("caa:compatible")
            else
                log_warning "CAA validation failed"
                validation_details+=("caa:blocking")
                [[ "$strict" == "yes" ]] && validation_passed=false
            fi
        else
            log_error "SSL readiness validation failed (localhost/IP not suitable for SSL)"
            validation_details+=("ssl:not_ready")
            validation_passed=false
        fi
    fi
    
    VALIDATION_RESULTS=("${validation_details[@]}")
    
    if [[ "$validation_passed" == "true" ]]; then
        log_success "Comprehensive FQDN validation passed"
        return 0
    else
        log_error "Comprehensive FQDN validation failed"
        return 1
    fi
}

# Show detailed FQDN detection and validation summary
show_fqdn_summary() {
    local fqdn="$1"
    
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}                           FQDN DETECTION SUMMARY                              ${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${CYAN}Detection Results:${NC}"
    echo -e "${GREEN}• Detected FQDN: ${NC}${fqdn:-"Not detected"}"
    echo -e "${GREEN}• Detection Method: ${NC}${DETECTION_METHOD:-"None"}"
    echo -e "${GREEN}• Timestamp: ${NC}$(get_timestamp)"
    echo ""
    
    echo -e "${CYAN}Validation Status:${NC}"
    if [[ -n "$fqdn" && "$fqdn" != "localhost" ]]; then
        echo -e "${GREEN}• SSL Ready: ${NC}Yes"
        echo -e "${GREEN}• Domain Configuration: ${NC}Ready"
        echo -e "${GREEN}• External Access: ${NC}Possible"
    else
        echo -e "${YELLOW}• SSL Ready: ${NC}No (localhost or invalid FQDN)"
        echo -e "${YELLOW}• Domain Configuration: ${NC}Manual setup required"
        echo -e "${YELLOW}• External Access: ${NC}Limited"
    fi
    echo ""
    
    if [[ ${#VALIDATION_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}Validation Details:${NC}"
        for result in "${VALIDATION_RESULTS[@]}"; do
            local check="${result%%:*}"
            local status="${result#*:}"
            local icon="✓"
            local color="$GREEN"
            
            if [[ "$status" == "failed" ]] || [[ "$status" == "not_ready" ]] || [[ "$status" == "blocking" ]]; then
                icon="✗"
                color="$RED"
            elif [[ "$status" == "warning" ]]; then
                icon="⚠"
                color="$YELLOW"
            fi
            
            echo -e "${color}  $icon $check: $status${NC}"
        done
        echo ""
    fi
    
    if [[ ${#CAA_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}CAA Record Analysis:${NC}"
        for result in "${CAA_RESULTS[@]}"; do
            local type="${result%%:*}"
            local domain="${result#*:}"
            domain="${domain%%:*}"
            local details="${result##*:}"
            
            local icon="ℹ"
            local color="$BLUE"
            
            case "$type" in
                "blocking")
                    icon="✗"
                    color="$RED"
                    echo -e "${color}  $icon Domain $domain blocks CA: $details${NC}"
                    ;;
                "allowed")
                    icon="✓"
                    color="$GREEN"
                    echo -e "${color}  $icon Domain $domain allows CA: $details${NC}"
                    ;;
                "no_caa")
                    icon="○"
                    color="$BLUE"
                    echo -e "${color}  $icon No CAA records for: $domain${NC}"
                    ;;
                "iodef")
                    icon="📧"
                    color="$CYAN"
                    echo -e "${color}  $icon Incident reporting configured for $domain: $details${NC}"
                    ;;
            esac
        done
        echo ""
    fi
    
    if [[ ${#DETECTION_RESULTS[@]} -gt 0 ]]; then
        echo -e "${CYAN}Detection Attempts:${NC}"
        for result in "${DETECTION_RESULTS[@]}"; do
            local method="${result%%:*}"
            local status="${result#*:}"
            status="${status%%:*}"
            local detected="${result##*:}"
            
            local icon="✓"
            local color="$GREEN"
            
            if [[ "$status" == "failed" ]]; then
                icon="✗"
                color="$RED"
                detected="N/A"
            fi
            
            echo -e "${color}  $icon $method: $status${NC}"
            [[ "$detected" != "N/A" && "$detected" != "$method" ]] && echo -e "    ${CYAN}→ $detected${NC}"
        done
        echo ""
    fi
    
    echo -e "${CYAN}Current Configuration:${NC}"
    echo -e "${BLUE}• Require SSL: ${NC}$REQUIRE_SSL"
    echo -e "${BLUE}• Check DNS: ${NC}$CHECK_DNS"
    echo -e "${BLUE}• Allow Localhost: ${NC}$ALLOW_LOCALHOST"
    echo -e "${BLUE}• Allow IP as FQDN: ${NC}$ALLOW_IP_AS_FQDN"
    echo ""
}

# ===============================================================================
# TESTING FRAMEWORK
# ===============================================================================

# Test individual validation functions
test_validation_functions() {
    echo "Testing FQDN validation functions..."
    echo ""
    
    local test_cases=(
        "example.com:valid"
        "sub.example.com:valid"
        "very.long.domain.example.com:valid"
        "localhost:depends_on_config"
        "192.168.1.1:depends_on_config"
        "invalid:invalid"
        "test.:invalid"
        ".example.com:invalid"
        "example..com:invalid"
        "ex ample.com:invalid"
        "example-.com:invalid"
        "-example.com:invalid"
    )
    
    for test_case in "${test_cases[@]}"; do
        local fqdn="${test_case%%:*}"
        local expected="${test_case#*:}"
        
        if is_valid_fqdn "$fqdn"; then
            echo -e "  ${GREEN}✓${NC} $fqdn - Valid"
        else
            echo -e "  ${RED}✗${NC} $fqdn - Invalid"
        fi
    done
    echo ""
}

# Test all detection methods
test_detection_methods() {
    echo "Testing FQDN detection methods..."
    echo ""
    
    local methods=(
        "detect_fqdn_hostname:hostname -f"
        "detect_fqdn_hostnamectl:hostnamectl"
        "detect_fqdn_dns_domain:dnsdomainname"
        "detect_fqdn_etc_hostname:/etc/hostname"
        "detect_fqdn_etc_hosts:/etc/hosts"
        "detect_fqdn_reverse_dns:reverse DNS"
        "detect_fqdn_cloud_metadata:cloud metadata"
    )
    
    for method_info in "${methods[@]}"; do
        local method_func="${method_info%%:*}"
        local method_desc="${method_info#*:}"
        
        echo -n "  Testing $method_desc... "
        
        if detected=$($method_func 2>/dev/null); then
            echo -e "${GREEN}✓ $detected${NC}"
        else
            echo -e "${YELLOW}- No result${NC}"
        fi
    done
    echo ""
}

# Test DNS resolution
test_dns_resolution() {
    local test_domains=("google.com" "github.com" "nonexistent.example.invalid")
    
    echo "Testing DNS resolution capabilities..."
    echo ""
    
    for domain in "${test_domains[@]}"; do
        echo -n "  Testing $domain... "
        
        if check_dns_resolution "$domain" 3; then
            echo -e "${GREEN}✓ Resolves${NC}"
        else
            echo -e "${RED}✗ Does not resolve${NC}"
        fi
    done
    echo ""
}

# Test CAA record checking
test_caa_checking() {
    local test_domains=("github.com" "google.com" "example.com")
    
    echo "Testing CAA record checking..."
    echo ""
    
    for domain in "${test_domains[@]}"; do
        echo "  Testing CAA for $domain:"
        
        if check_caa_ssl_compatibility "$domain" "letsencrypt.org"; then
            echo -e "    ${GREEN}✓ SSL certificate issuance would be allowed${NC}"
        else
            echo -e "    ${RED}✗ SSL certificate issuance might be blocked${NC}"
        fi
        
        local caa_results=($(get_caa_results))
        for result in "${caa_results[@]}"; do
            echo -e "    ${BLUE}→ $result${NC}"
        done
        
        CAA_RESULTS=()
        echo ""
    done
}

# Comprehensive test suite
run_comprehensive_tests() {
    echo -e "${BOLD}Running Comprehensive Test Suite${NC}"
    echo -e "${BOLD}=================================${NC}"
    echo ""
    
    test_validation_functions
    test_detection_methods
    test_dns_resolution
    test_caa_checking
    
    echo "Testing complete FQDN detection process..."
    detected=$(auto_detect_fqdn "" "no" "yes")
    echo "  Auto-detected FQDN: ${detected:-"None"}"
    echo ""
    
    show_fqdn_summary "$detected"
}

# ===============================================================================
# CLI INTERFACE
# ===============================================================================

# Show usage information
show_usage() {
    cat << EOF
${BOLD}$SCRIPT_NAME v$SCRIPT_VERSION${NC}
$SCRIPT_PURPOSE

${BOLD}USAGE:${NC}
  $0 [OPTIONS] [COMMAND]

${BOLD}COMMANDS:${NC}
  detect [FQDN]         Auto-detect or validate FQDN
  validate FQDN         Validate specific FQDN  
  test                  Run comprehensive tests
  check-caa FQDN [CA]   Check CAA records for SSL compatibility
  config                Show current configuration
  save-config FILE      Save configuration to file
  load-config FILE      Load configuration from file

${BOLD}OPTIONS:${NC}
  --require-ssl         Require SSL-compatible FQDN
  --no-dns-check        Skip DNS resolution check
  --allow-localhost     Allow localhost as valid FQDN
  --allow-ip            Allow IP addresses as FQDN
  --min-parts N         Minimum domain parts required (default: $DEFAULT_MIN_DOMAIN_PARTS)
  --log-level LEVEL     Set log level (DEBUG|INFO|WARNING|ERROR)
  --output FORMAT       Output format (text|json|xml)
  --config FILE         Load configuration from file
  --no-colors           Disable colored output
  --strict              Enable strict validation mode
  --timeout N           Set DNS timeout in seconds

${BOLD}EXAMPLES:${NC}
  $0 detect                           # Auto-detect FQDN
  $0 detect example.com               # Validate provided FQDN
  $0 validate example.com             # Validate specific FQDN
  $0 check-caa example.com            # Check CAA records for Let's Encrypt
  $0 check-caa example.com digicert.com # Check CAA for specific CA
  $0 --require-ssl detect             # Require SSL-compatible FQDN
  $0 --output json detect             # Output in JSON format
  $0 test                             # Run test suite

${BOLD}RETURN CODES:${NC}
  0  Success
  1  FQDN validation/detection failed
  2  Configuration error
  3  Invalid arguments
EOF
}

# Parse command line arguments
parse_cli_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --require-ssl)
                REQUIRE_SSL="yes"
                shift
                ;;
            --no-dns-check)
                CHECK_DNS="no"
                shift
                ;;
            --allow-localhost)
                ALLOW_LOCALHOST="yes"
                shift
                ;;
            --allow-ip)
                ALLOW_IP_AS_FQDN="yes"
                shift
                ;;
            --min-parts)
                MIN_DOMAIN_PARTS="$2"
                shift 2
                ;;
            --log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            --output)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            --config)
                load_config "$2" || exit 2
                shift 2
                ;;
            --no-colors)
                USE_COLORS="no"
                shift
                ;;
            --strict)
                STRICT_MODE="yes"
                shift
                ;;
            --timeout)
                DNS_TIMEOUT="$2"
                PING_TIMEOUT="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            --)
                shift
                break
                ;;
            -*)
                log_error "Unknown option: $1"
                show_usage
                exit 3
                ;;
            *)
                break
                ;;
        esac
    done
    
    CLI_ARGS=("$@")
}

# Main CLI function
main_cli() {
    local command="${1:-detect}"
    shift || true
    
    case "$command" in
        detect)
            local fqdn="$1"
            local detected_fqdn=""
            
            if detected_fqdn=$(auto_detect_fqdn "$fqdn" "$REQUIRE_SSL" "$CHECK_DNS"); then
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "$detected_fqdn" "success"
                        ;;
                    xml)
                        generate_xml_output "$detected_fqdn" "success"
                        ;;
                    *)
                        echo "$detected_fqdn"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary "$detected_fqdn"
                        ;;
                esac
                return 0
            else
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "" "failed"
                        ;;
                    xml)
                        generate_xml_output "" "failed"
                        ;;
                    *)
                        log_error "FQDN detection failed"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary ""
                        ;;
                esac
                return 1
            fi
            ;;
        validate)
            local fqdn="$1"
            if [[ -z "$fqdn" ]]; then
                log_error "FQDN required for validation"
                return 3
            fi
            
            if validate_fqdn_comprehensive "$fqdn" "$CHECK_DNS" "${STRICT_MODE:-no}"; then
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "$fqdn" "valid"
                        ;;
                    xml)
                        generate_xml_output "$fqdn" "valid"
                        ;;
                    *)
                        echo "valid"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary "$fqdn"
                        ;;
                esac
                return 0
            else
                case "$OUTPUT_FORMAT" in
                    json)
                        generate_json_output "$fqdn" "invalid"
                        ;;
                    xml)
                        generate_xml_output "$fqdn" "invalid"
                        ;;
                    *)
                        echo "invalid"
                        [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && show_fqdn_summary "$fqdn"
                        ;;
                esac
                return 1
            fi
            ;;
        check-caa)
            local fqdn="$1"
            local ca_identifier="${2:-letsencrypt.org}"
            
            if [[ -z "$fqdn" ]]; then
                log_error "FQDN required for CAA checking"
                return 3
            fi
            
            if check_caa_ssl_compatibility "$fqdn" "$ca_identifier"; then
                echo "CAA records allow SSL certificate issuance for $ca_identifier"
                return 0
            else
                echo "CAA records may block SSL certificate issuance for $ca_identifier"
                return 1
            fi
            ;;
        test)
            run_comprehensive_tests
            ;;
        config)
            show_config
            ;;
        save-config)
            local config_file="$1"
            if [[ -z "$config_file" ]]; then
                log_error "Configuration file path required"
                return 3
            fi
            save_config "$config_file"
            ;;
        load-config)
            local config_file="$1"
            if [[ -z "$config_file" ]]; then
                log_error "Configuration file path required"
                return 3
            fi
            load_config "$config_file"
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            return 3
            ;;
    esac
}

# ===============================================================================
# MAIN EXECUTION
# ===============================================================================

# Main execution logic
main() {
    if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
        log_debug "Script sourced, functions available"
        return 0
    fi
    
    parse_cli_arguments "$@"
    main_cli "${CLI_ARGS[@]}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi