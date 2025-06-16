#!/bin/bash
#
# Generic FQDN Detection and Validation Helper Script
# Template for system administration and deployment scripts
#
# Copyright (c) 2025 Michal Koeckeis-Fresel
# 
# This software is dual-licensed under your choice of:
# - MIT License (see LICENSE-MIT)
# - GNU Affero General Public License v3.0 (see LICENSE-AGPL)
# 
# SPDX-License-Identifier: MIT OR AGPL-3.0-or-later
#

# ===============================================================================
# CONFIGURATION SECTION - Customize for your specific use case
# ===============================================================================

# Script identification (customize for your application)
SCRIPT_NAME="FQDN Detection Helper"
SCRIPT_VERSION="2.0.0"
SCRIPT_PURPOSE="Generic FQDN detection and validation for system administration"

# Default configuration values (can be overridden)
DEFAULT_REQUIRE_SSL="no"
DEFAULT_CHECK_DNS="yes"
DEFAULT_ALLOW_LOCALHOST="yes"
DEFAULT_ALLOW_IP_AS_FQDN="no"
DEFAULT_MIN_DOMAIN_PARTS="2"
DEFAULT_CONFIG_FILE=""
DEFAULT_LOG_LEVEL="INFO"
DEFAULT_OUTPUT_FORMAT="text"

# Color configuration (set to "no" to disable colors)
USE_COLORS="yes"

# Timeout settings
DNS_TIMEOUT="5"
PING_TIMEOUT="3"

# ===============================================================================
# GLOBAL VARIABLES - Script state and results
# ===============================================================================

# Results storage
DETECTED_FQDN=""
DETECTION_METHOD=""
DETECTION_RESULTS=()
VALIDATION_RESULTS=()

# Configuration variables (loaded from config file or defaults)
REQUIRE_SSL="$DEFAULT_REQUIRE_SSL"
CHECK_DNS="$DEFAULT_CHECK_DNS"
ALLOW_LOCALHOST="$DEFAULT_ALLOW_LOCALHOST"
ALLOW_IP_AS_FQDN="$DEFAULT_ALLOW_IP_AS_FQDN"
MIN_DOMAIN_PARTS="$DEFAULT_MIN_DOMAIN_PARTS"
LOG_LEVEL="$DEFAULT_LOG_LEVEL"
OUTPUT_FORMAT="$DEFAULT_OUTPUT_FORMAT"

# ===============================================================================
# UTILITY FUNCTIONS - General purpose functions
# ===============================================================================

# Color definitions (can be customized)
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

# Logging functions with different levels
log_debug() {
    [[ "$LOG_LEVEL" == "DEBUG" ]] && echo -e "${CYAN}[DEBUG]${NC} $1" >&2
}

log_info() {
    [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_warning() {
    [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO|WARNING)$ ]] && echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_success() {
    [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO|WARNING|SUCCESS)$ ]] && echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
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
# CONFIGURATION FUNCTIONS - Load and manage configuration
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
    
    # Source the config file safely
    while IFS='=' read -r key value; do
        # Skip comments and empty lines
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${key// }" ]] && continue
        
        # Remove quotes from value
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

# SSL/TLS Requirements
REQUIRE_SSL="$REQUIRE_SSL"

# DNS Validation
CHECK_DNS="$CHECK_DNS"
DNS_TIMEOUT="$DNS_TIMEOUT"

# FQDN Validation Rules
ALLOW_LOCALHOST="$ALLOW_LOCALHOST"
ALLOW_IP_AS_FQDN="$ALLOW_IP_AS_FQDN"
MIN_DOMAIN_PARTS="$MIN_DOMAIN_PARTS"

# Logging and Output
LOG_LEVEL="$LOG_LEVEL"
OUTPUT_FORMAT="$OUTPUT_FORMAT"
USE_COLORS="$USE_COLORS"

# Network Timeouts
PING_TIMEOUT="$PING_TIMEOUT"
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
}

# ===============================================================================
# VALIDATION FUNCTIONS - FQDN format and rule validation
# ===============================================================================

# Check if hostname is a valid IP address
is_ip_address() {
    local hostname="$1"
    
    # IPv4 check
    if [[ "$hostname" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        local IFS='.'
        local ip=($hostname)
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        return $?
    fi
    
    # IPv6 check (basic)
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

# Advanced FQDN validation with configurable rules
is_valid_fqdn() {
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
    
    # Check minimum domain parts requirement
    if ! has_min_domain_parts "$hostname" "$MIN_DOMAIN_PARTS"; then
        log_debug "Hostname doesn't meet minimum domain parts requirement ($MIN_DOMAIN_PARTS): $hostname"
        return 1
    fi
    
    # Basic format validation
    if [[ ! "$hostname" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        log_debug "Invalid characters in hostname: $hostname"
        return 1
    fi
    
    # Should not start or end with a dot or hyphen
    if [[ "$hostname" =~ ^[.-] ]] || [[ "$hostname" =~ [.-]$ ]]; then
        log_debug "Invalid hostname format (starts/ends with dot or hyphen): $hostname"
        return 1
    fi
    
    # Should not have consecutive dots
    if [[ "$hostname" == *".."* ]]; then
        log_debug "Invalid hostname format (consecutive dots): $hostname"
        return 1
    fi
    
    # Strict mode additional checks
    if [[ "$strict" == "yes" ]]; then
        # Each label should be 63 characters or less
        local IFS='.'
        local labels=($hostname)
        for label in "${labels[@]}"; do
            if [[ ${#label} -gt 63 ]]; then
                log_debug "Label too long (>63 chars): $label"
                return 1
            fi
            
            # Labels should not start or end with hyphen
            if [[ "$label" =~ ^- ]] || [[ "$label" =~ -$ ]]; then
                log_debug "Invalid label format (starts/ends with hyphen): $label"
                return 1
            fi
        done
        
        # Total length should be 253 characters or less
        if [[ ${#hostname} -gt 253 ]]; then
            log_debug "Hostname too long (>253 chars): $hostname"
            return 1
        fi
    fi
    
    log_debug "FQDN validation passed: $hostname"
    return 0
}

# ===============================================================================
# DETECTION FUNCTIONS - Various methods to detect FQDN
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
        # Try static hostname
        detected=$(hostnamectl --static 2>/dev/null || echo "")
        if is_valid_fqdn "$detected"; then
            log_debug "FQDN detected via hostnamectl --static: $detected"
            echo "$detected"
            return 0
        fi
        
        # Try pretty hostname
        detected=$(hostnamectl --pretty 2>/dev/null || echo "")
        if is_valid_fqdn "$detected"; then
            log_debug "FQDN detected via hostnamectl --pretty: $detected"
            echo "$detected"
            return 0
        fi
        
        # Try transient hostname
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
            # Skip comments and empty lines
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue
            
            local ip=$(echo "$line" | awk '{print $1}')
            local hostnames=$(echo "$line" | awk '{for(i=2;i<=NF;i++) print $i}')
            
            # Skip localhost entries unless explicitly allowed
            if [[ "$ip" == "127.0.0.1" || "$ip" == "::1" ]]; then
                [[ "$ALLOW_LOCALHOST" != "yes" ]] && continue
            fi
            
            # Check each hostname
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
    
    # Get primary IP address
    if command_exists hostname; then
        primary_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "")
    fi
    
    if [[ -z "$primary_ip" ]] && command_exists ip; then
        primary_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[^ ]+' || echo "")
    fi
    
    if [[ -n "$primary_ip" && "$primary_ip" != "127.0.0.1" ]]; then
        # Try different DNS tools
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
    
    # AWS metadata
    if command_exists curl; then
        detected=$(timeout 3 curl -s -f "http://169.254.169.254/latest/meta-data/public-hostname" 2>/dev/null || echo "")
        if is_valid_fqdn "$detected"; then
            log_debug "FQDN detected via AWS metadata: $detected"
            echo "$detected"
            return 0
        fi
    fi
    
    # Google Cloud metadata
    if command_exists curl; then
        detected=$(timeout 3 curl -s -f -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/hostname" 2>/dev/null || echo "")
        if is_valid_fqdn "$detected"; then
            log_debug "FQDN detected via GCP metadata: $detected"
            echo "$detected"
            return 0
        fi
    fi
    
    # Azure metadata
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
# DNS VALIDATION FUNCTIONS - Check if FQDN resolves
# ===============================================================================

# Check DNS resolution with multiple tools
check_dns_resolution() {
    local fqdn="$1"
    local timeout="${2:-$DNS_TIMEOUT}"
    
    log_debug "Checking DNS resolution for: $fqdn"
    
    # Try different DNS resolution tools
    local resolved=false
    local resolution_method=""
    
    # Method 1: nslookup
    if command_exists nslookup && [[ "$resolved" == "false" ]]; then
        if timeout "$timeout" nslookup "$fqdn" &>/dev/null; then
            resolved=true
            resolution_method="nslookup"
        fi
    fi
    
    # Method 2: dig
    if command_exists dig && [[ "$resolved" == "false" ]]; then
        if timeout "$timeout" dig +short "$fqdn" &>/dev/null; then
            resolved=true
            resolution_method="dig"
        fi
    fi
    
    # Method 3: host
    if command_exists host && [[ "$resolved" == "false" ]]; then
        if timeout "$timeout" host "$fqdn" &>/dev/null; then
            resolved=true
            resolution_method="host"
        fi
    fi
    
    # Method 4: getent (uses system resolver)
    if command_exists getent && [[ "$resolved" == "false" ]]; then
        if timeout "$timeout" getent hosts "$fqdn" &>/dev/null; then
            resolved=true
            resolution_method="getent"
        fi
    fi
    
    # Method 5: ping (as last resort)
    if command_exists ping && [[ "$resolved" == "false" ]]; then
        if timeout "$PING_TIMEOUT" ping -c 1 -W "$PING_TIMEOUT" "$fqdn" &>/dev/null; then
            resolved=true
            resolution_method="ping"
        fi
    fi
    
    if [[ "$resolved" == "true" ]]; then
        log_debug "DNS resolution successful via $resolution_method"
        return 0
    else
        log_debug "DNS resolution failed for $fqdn"
        return 1
    fi
}

# ===============================================================================
# MAIN DETECTION FUNCTION - Orchestrates all detection methods
# ===============================================================================

# Main FQDN detection function with comprehensive reporting
auto_detect_fqdn() {
    local provided_fqdn="$1"
    local require_ssl="${2:-$REQUIRE_SSL}"
    local check_dns="${3:-$CHECK_DNS}"
    
    # Clear previous results
    DETECTED_FQDN=""
    DETECTION_METHOD=""
    DETECTION_RESULTS=()
    VALIDATION_RESULTS=()
    
    log_info "Starting FQDN detection process..."
    log_debug "Parameters: provided_fqdn='$provided_fqdn', require_ssl='$require_ssl', check_dns='$check_dns'"
    
    # If FQDN is provided, validate and use it
    if [[ -n "$provided_fqdn" ]]; then
        log_info "Validating provided FQDN: $provided_fqdn"
        
        if is_valid_fqdn "$provided_fqdn"; then
            log_success "Provided FQDN is valid: $provided_fqdn"
            DETECTED_FQDN="$provided_fqdn"
            DETECTION_METHOD="user-provided"
            
            # Optional DNS check
            if [[ "$check_dns" == "yes" ]]; then
                if check_dns_resolution "$provided_fqdn"; then
                    log_success "Provided FQDN resolves correctly"
                    VALIDATION_RESULTS+=("dns:success")
                else
                    log_warning "Provided FQDN does not resolve (may be expected for new domains)"
                    VALIDATION_RESULTS+=("dns:failed")
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
    
    # Array of detection methods with metadata
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
            
            # Validate with DNS if requested
            if [[ "$check_dns" == "yes" ]]; then
                if check_dns_resolution "$detected_fqdn"; then
                    log_success "Detected FQDN resolves correctly"
                    VALIDATION_RESULTS+=("dns:success")
                else
                    log_warning "Detected FQDN does not resolve"
                    VALIDATION_RESULTS+=("dns:failed")
                fi
            fi
            
            echo "$detected_fqdn"
            return 0
        else
            log_warning "No valid FQDN found via $method_desc"
            DETECTION_RESULTS+=("$method_func:failed")
        fi
    done
    
    # No valid FQDN found
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
# OUTPUT AND REPORTING FUNCTIONS - Generate various output formats
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
# GETTER FUNCTIONS - Access results and state
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
    
    # Basic format validation
    if is_valid_fqdn "$fqdn" "$strict"; then
        log_success "FQDN format validation passed"
        validation_details+=("format:passed")
    else
        log_error "FQDN format validation failed"
        validation_details+=("format:failed")
        validation_passed=false
    fi
    
    # DNS resolution check
    if [[ "$check_dns" == "yes" ]]; then
        if check_dns_resolution "$fqdn"; then
            log_success "DNS resolution validation passed"
            validation_details+=("dns:passed")
        else
            log_warning "DNS resolution validation failed"
            validation_details+=("dns:failed")
            # Don't fail validation for DNS issues unless strict mode
            [[ "$strict" == "yes" ]] && validation_passed=false
        fi
    fi
    
    # SSL readiness check
    if [[ "$REQUIRE_SSL" == "yes" ]]; then
        if [[ "$fqdn" != "localhost" ]] && [[ "$fqdn" != "127.0.0.1" ]] && ! is_ip_address "$fqdn"; then
            log_success "SSL readiness validation passed"
            validation_details+=("ssl:ready")
        else
            log_error "SSL readiness validation failed (localhost/IP not suitable for SSL)"
            validation_details+=("ssl:not_ready")
            validation_passed=false
        fi
    fi
    
    # Store validation results
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
            
            if [[ "$status" == "failed" ]] || [[ "$status" == "not_ready" ]]; then
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
# TESTING FRAMEWORK - Comprehensive testing capabilities
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

# Comprehensive test suite
run_comprehensive_tests() {
    echo -e "${BOLD}Running Comprehensive Test Suite${NC}"
    echo -e "${BOLD}=================================${NC}"
    echo ""
    
    test_validation_functions
    test_detection_methods
    test_dns_resolution
    
    echo "Testing complete FQDN detection process..."
    detected=$(auto_detect_fqdn "" "no" "yes")
    echo "  Auto-detected FQDN: ${detected:-"None"}"
    echo ""
    
    show_fqdn_summary "$detected"
}

# ===============================================================================
# CLI INTERFACE - Command line interface for standalone usage
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
  $0 --require-ssl detect             # Require SSL-compatible FQDN
  $0 --output json detect             # Output in JSON format
  $0 --config /etc/fqdn.conf detect   # Use configuration file
  $0 test                             # Run test suite

${BOLD}TEMPLATE USAGE:${NC}
To use this script as a template for other projects:
1. Copy this script to your project
2. Modify the configuration section at the top
3. Customize the detection methods as needed
4. Source the script: source helper_fqdn_lookup.sh
5. Call functions: auto_detect_fqdn "\$provided_fqdn"

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
    
    # Store remaining arguments
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
# MAIN EXECUTION - Handle script execution
# ===============================================================================

# Main execution logic
main() {
    # If script is sourced, don't run CLI
    if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
        log_debug "Script sourced, functions available"
        return 0
    fi
    
    # Parse CLI arguments
    parse_cli_arguments "$@"
    
    # Run CLI with remaining arguments
    main_cli "${CLI_ARGS[@]}"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi