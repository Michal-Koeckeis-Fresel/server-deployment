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

# ZeroSSL Certificate Deployment Script
# This script deploys ZeroSSL ECC certificates using certbot with DNS or HTTP validation

set -e

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="/etc/letsencrypt"
ZEROSSL_API_KEY=""
DOMAIN=""
DOMAIN_AUTO_DETECTED=""
EMAIL=""
VALIDATION_METHOD="http"
DRY_RUN="no"
FORCE_RENEWAL="no"
WILDCARD="no"
STAGING="no"
DNS_PROVIDER=""
DNS_CREDENTIALS=""
ECC_CURVE="secp384r1"  # Default to P-384
CERT_FOR_IP="no"       # Certificate for IP address
EXTERNAL_IP=""         # Detected external IP
DEBUG="no"             # Debug mode

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

# Function to display usage
show_usage() {
    echo -e "${BLUE}ZeroSSL ECC Certificate Deployment Script${NC}"
    echo ""
    echo -e "${YELLOW}Usage: $0 --apikey <API_KEY> --email <EMAIL> [--domain <DOMAIN>] [OPTIONS]${NC}"
    echo ""
    echo -e "${BLUE}This script generates ECC certificates with selectable key sizes${NC}"
    echo ""
    echo -e "${YELLOW}Required Options:${NC}"
    echo -e "  --apikey <KEY>       ZeroSSL API key (REQUIRED)"
    echo -e "  --email <EMAIL>      Contact email for certificate"
    echo ""
    echo -e "${YELLOW}Domain Configuration:${NC}"
    echo -e "  --domain <DOMAIN>    Domain name for certificate (auto-detected if not provided)"
    echo -e "  --cert_for_IP        Create certificate for external IP address instead of domain"
    echo ""
    echo -e "${YELLOW}Optional Parameters:${NC}"
    echo -e "  --ecc-curve <CURVE>      ECC curve: p256, p384, p521 (default: p384)"
    echo -e "                          • p256 = secp256r1 (equivalent to RSA 3072-bit)"
    echo -e "                          • p384 = secp384r1 (equivalent to RSA 7680-bit)"
    echo -e "                          • p521 = secp521r1 (equivalent to RSA 15360-bit)"
    echo -e "  --validation <METHOD>    Validation method: http or dns (default: http)"
    echo -e "                          Note: HTTP uses standalone mode (port 80 must be free)"
    echo -e "  --dns-provider <PROVIDER> DNS provider for DNS validation (cloudflare, route53, etc.)"
    echo -e "  --dns-credentials <FILE>  Path to DNS credentials file"
    echo -e "  --wildcard              Request wildcard certificate (requires DNS validation)"
    echo -e "  --staging               Use staging environment for testing"
    echo -e "  --dry-run               Test configuration without issuing certificate"
    echo -e "  --force-renewal         Force certificate renewal even if not near expiry"
    echo -e "  --debug                 Enable verbose debug output"
    echo ""
    echo -e "${YELLOW}Help:${NC}"
    echo -e "  -h, --help              Show this help message"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo -e "  # Auto-detect domain with default ECC P-384"
    echo -e "  $0 --apikey abc123 --email admin@example.com"
    echo ""
    echo -e "  # Certificate for external IP address (auto-detected)"
    echo -e "  $0 --apikey abc123 --email admin@example.com --cert_for_IP"
    echo ""
    echo -e "  # Certificate for specific IP address"
    echo -e "  $0 --apikey abc123 --email admin@example.com --cert_for_IP --domain 203.0.113.10"
    echo ""
    echo -e "  # High security ECC P-521 certificate"
    echo -e "  $0 --apikey abc123 --email admin@example.com --ecc-curve p521"
    echo ""
    echo -e "  # Fast ECC P-256 certificate for IP"
    echo -e "  $0 --apikey abc123 --email admin@example.com --cert_for_IP --ecc-curve p256"
    echo ""
    echo -e "  # DNS validation with custom curve"
    echo -e "  $0 --apikey abc123 --domain example.com --email admin@example.com \\"
    echo -e "     --ecc-curve p384 --validation dns --dns-provider cloudflare"
    echo ""
    echo -e "  # Wildcard certificate with maximum security"
    echo -e "  $0 --apikey abc123 --email admin@example.com \\"
    echo -e "     --ecc-curve p521 --wildcard --validation dns --dns-provider cloudflare"
    echo ""
    echo -e "  # Test IP certificate configuration (dry run)"
    echo -e "  $0 --apikey abc123 --email admin@example.com --cert_for_IP --dry-run"
    echo ""
    echo -e "${BLUE}ZeroSSL API Key:${NC}"
    echo -e "  Get your API key from: https://app.zerossl.com/developer"
    echo ""
    echo -e "${BLUE}DNS Providers:${NC}"
    echo -e "  Supported: cloudflare, route53, digitalocean, namecheap, godaddy"
    echo -e "  See: https://certbot-dns-plugins.readthedocs.io/"
    echo ""
    echo -e "${BLUE}FQDN Auto-Detection:${NC}"
    echo -e "  If --domain is not provided, the script will:"
    echo -e "  • Download and use helper_fqdn.sh for advanced detection"
    echo -e "  • Try multiple detection methods (hostname, DNS, config files)"
    echo -e "  • Validate the detected FQDN for SSL compatibility"
    echo -e "  • Fall back to manual fallback methods if needed"
    echo ""
    echo -e "${BLUE}ECC Curve Comparison:${NC}"
    echo -e "  Curve    | Security Level     | RSA Equivalent | Performance"
    echo -e "  ---------|-------------------|----------------|------------"
    echo -e "  P-256    | 128-bit security  | RSA 3072-bit   | Fastest"
    echo -e "  P-384    | 192-bit security  | RSA 7680-bit   | Balanced (Default)"
    echo -e "  P-521    | 256-bit security  | RSA 15360-bit  | Highest Security"
    echo ""
    echo -e "${BLUE}IP Address Certificates:${NC}"
    echo -e "  • Use --cert_for_IP to create certificates for IP addresses"
    echo -e "  • Automatically detects external IP or specify with --domain <IP>"
    echo -e "  • Only HTTP validation supported (DNS validation not available for IPs)"
    echo -e "  • Wildcard certificates not supported for IP addresses"
    echo -e "  • May have compatibility issues with some browsers/applications"
    echo -e "  • Consider using domain names for better compatibility"
    echo ""
    echo -e "${BLUE}ECC Benefits:${NC}"
    echo -e "  • Smaller certificate size (faster TLS handshakes)"
    echo -e "  • Lower CPU usage and better performance"
    echo -e "  • Modern cryptographic standard"
    echo -e "  • Future-proof against quantum computing (especially P-384/P-521)"
}

# Parse command line arguments
parse_arguments() {
    if [[ $# -eq 0 ]]; then
        log_error "No arguments provided"
        show_usage
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --apikey)
                ZEROSSL_API_KEY="$2"
                shift 2
                ;;
            --domain)
                DOMAIN="$2"
                shift 2
                ;;
            --cert_for_IP)
                CERT_FOR_IP="yes"
                VALIDATION_METHOD="http"  # IP certificates typically use HTTP validation
                shift
                ;;
            --email)
                EMAIL="$2"
                shift 2
                ;;
            --ecc-curve)
                case "$2" in
                    p256|P256)
                        ECC_CURVE="secp256r1"
                        ;;
                    p384|P384)
                        ECC_CURVE="secp384r1"
                        ;;
                    p521|P521)
                        ECC_CURVE="secp521r1"
                        ;;
                    *)
                        log_error "Invalid ECC curve: $2 (valid options: p256, p384, p521)"
                        exit 1
                        ;;
                esac
                shift 2
                ;;
            --validation)
                VALIDATION_METHOD="$2"
                shift 2
                ;;
            --dns-provider)
                DNS_PROVIDER="$2"
                shift 2
                ;;
            --dns-credentials)
                DNS_CREDENTIALS="$2"
                shift 2
                ;;
            --wildcard)
                WILDCARD="yes"
                VALIDATION_METHOD="dns"  # Wildcard requires DNS validation
                shift
                ;;
            --staging)
                STAGING="yes"
                shift
                ;;
            --dry-run)
                DRY_RUN="yes"
                shift
                ;;
            --force-renewal)
                FORCE_RENEWAL="yes"
                shift
                ;;
            --debug)
                DEBUG="yes"
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option '$1'"
                show_usage
                exit 1
                ;;
        esac
    done

    # Validate required parameters
    if [[ -z "$ZEROSSL_API_KEY" ]]; then
        log_error "ZeroSSL API key is required (--apikey)"
        show_usage
        exit 1
    fi

    if [[ -z "$EMAIL" ]]; then
        log_error "Email is required (--email)"
        show_usage
        exit 1
    fi

    # Note: DOMAIN validation is handled in detect_fqdn() function

    # Validate validation method
    if [[ "$VALIDATION_METHOD" != "http" && "$VALIDATION_METHOD" != "dns" ]]; then
        log_error "Invalid validation method: $VALIDATION_METHOD (must be 'http' or 'dns')"
        exit 1
    fi

    # IP certificate specific validations
    if [[ "$CERT_FOR_IP" == "yes" ]]; then
        if [[ "$WILDCARD" == "yes" ]]; then
            log_error "Wildcard certificates cannot be used with IP addresses"
            exit 1
        fi
        
        if [[ "$VALIDATION_METHOD" == "dns" ]]; then
            log_error "DNS validation is not supported for IP address certificates"
            log_error "IP certificates must use HTTP validation"
            exit 1
        fi
        
        log_warning "Note: ZeroSSL may have restrictions on IP address certificates"
        log_warning "Ensure your ZeroSSL account supports IP certificate issuance"
    fi

    # DNS validation specific validations
    if [[ "$VALIDATION_METHOD" == "dns" ]]; then
        if [[ -z "$DNS_PROVIDER" ]]; then
            log_error "DNS provider is required for DNS validation (--dns-provider)"
            exit 1
        fi
        if [[ -n "$DNS_CREDENTIALS" && ! -f "$DNS_CREDENTIALS" ]]; then
            log_error "DNS credentials file not found: $DNS_CREDENTIALS"
            exit 1
        fi
    fi

    # Wildcard validation
    if [[ "$WILDCARD" == "yes" && "$VALIDATION_METHOD" != "dns" ]]; then
        log_error "Wildcard certificates require DNS validation"
        exit 1
    fi
    
    # Additional validation for wildcard with detected domain/IP
    if [[ "$WILDCARD" == "yes" ]]; then
        if [[ "$CERT_FOR_IP" == "yes" ]]; then
            log_error "Wildcard certificates cannot be issued for IP addresses"
            exit 1
        elif [[ "$DOMAIN" == "localhost" ]] || [[ "$DOMAIN" == *"127.0.0.1"* ]]; then
            log_error "Wildcard certificates cannot be issued for localhost or IP addresses"
            log_error "Please provide a valid domain name using --domain parameter"
            exit 1
        fi
    fi
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect external IP address
detect_external_ip() {
    log_step "Detecting external IP address..."
    
    local detected_ip=""
    local ip_services=(
        "https://ifconfig.me"
        "https://icanhazip.com"
        "https://ipecho.net/plain"
        "https://checkip.amazonaws.com"
        "https://api.ipify.org"
    )
    
    for service in "${ip_services[@]}"; do
        log_info "Trying IP detection service: $service"
        
        if command_exists curl; then
            detected_ip=$(timeout 10 curl -s -4 "$service" 2>/dev/null | tr -d '\n\r' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
        elif command_exists wget; then
            detected_ip=$(timeout 10 wget -qO- "$service" 2>/dev/null | tr -d '\n\r' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
        fi
        
        if [[ -n "$detected_ip" && "$detected_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Validate it's not a private IP
            local first_octet=$(echo "$detected_ip" | cut -d. -f1)
            local second_octet=$(echo "$detected_ip" | cut -d. -f2)
            
            # Skip private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x
            if [[ "$first_octet" -eq 10 ]] || \
               [[ "$first_octet" -eq 172 && "$second_octet" -ge 16 && "$second_octet" -le 31 ]] || \
               [[ "$first_octet" -eq 192 && "$second_octet" -eq 168 ]] || \
               [[ "$first_octet" -eq 127 ]]; then
                log_warning "Detected private IP ($detected_ip), trying next service..."
                continue
            fi
            
            EXTERNAL_IP="$detected_ip"
            log_success "External IP detected: $EXTERNAL_IP"
            return 0
        else
            log_warning "Failed to detect IP from $service"
        fi
    done
    
    log_error "Could not detect external IP address from any service"
    log_error "Available services tried: ${ip_services[*]}"
    return 1
}

# Auto-detect FQDN if not provided using helper script
detect_fqdn() {
    # Handle IP certificate mode
    if [[ "$CERT_FOR_IP" == "yes" ]]; then
        if [[ -n "$DOMAIN" ]]; then
            # User provided IP address via --domain
            if [[ "$DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                EXTERNAL_IP="$DOMAIN"
                log_success "Using provided IP address: $EXTERNAL_IP"
                return 0
            else
                log_error "When using --cert_for_IP, --domain must be an IP address or omitted for auto-detection"
                return 1
            fi
        else
            # Auto-detect external IP
            if detect_external_ip; then
                DOMAIN="$EXTERNAL_IP"
                DOMAIN_AUTO_DETECTED="yes (IP)"
                log_success "Will create certificate for IP: $EXTERNAL_IP"
                
                # Show important warnings about IP certificates
                echo ""
                log_warning "IMPORTANT: IP Address Certificate Limitations"
                log_warning "• IP certificates are less common and may not be supported by all applications"
                log_warning "• Browsers may show warnings for IP certificates"
                log_warning "• IP addresses can change, making certificates invalid"
                log_warning "• Consider using a domain name for better compatibility"
                echo ""
                
                return 0
            else
                return 1
            fi
        fi
    fi
    
    # Original domain-based logic
    if [[ -n "$DOMAIN" ]]; then
        log_success "Using provided domain: $DOMAIN"
        return 0
    fi
    
    log_step "Auto-detecting FQDN using helper script..."
    
    local helper_script="$SCRIPT_DIR/helper_fqdn.sh"
    local helper_url="https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/deploy_scripts/helper-scripts/helper_fqdn.sh"
    
    # Download helper script if not present
    if [[ ! -f "$helper_script" ]]; then
        log_info "Downloading FQDN detection helper script..."
        
        if command_exists wget; then
            if wget -q "$helper_url" -O "$helper_script"; then
                chmod +x "$helper_script"
                log_success "Helper script downloaded successfully"
            else
                log_error "Failed to download helper script via wget"
                return 1
            fi
        elif command_exists curl; then
            if curl -s "$helper_url" -o "$helper_script"; then
                chmod +x "$helper_script"
                log_success "Helper script downloaded successfully"
            else
                log_error "Failed to download helper script via curl"
                return 1
            fi
        else
            log_error "Neither wget nor curl available for downloading helper script"
            return 1
        fi
    else
        log_info "Using existing helper script: $helper_script"
    fi
    
    # Determine SSL requirement based on AUTO_CERT_TYPE
    local require_ssl_flag=""
    if [[ -n "$AUTO_CERT_TYPE" ]] || [[ "$VALIDATION_METHOD" != "dns" ]]; then
        require_ssl_flag="--require-ssl"
        log_info "SSL certificate required - enabling strict FQDN validation"
    fi
    
    # Run helper script to detect FQDN
    log_info "Running FQDN detection..."
    
    local detected_fqdn=""
    if detected_fqdn=$("$helper_script" $require_ssl_flag --log-level WARNING detect 2>/dev/null); then
        if [[ -n "$detected_fqdn" && "$detected_fqdn" != "localhost" ]]; then
            DOMAIN="$detected_fqdn"
            DOMAIN_AUTO_DETECTED="yes"
            log_success "FQDN auto-detected: $DOMAIN"
            return 0
        else
            log_warning "Helper script returned localhost or empty result"
        fi
    else
        log_warning "FQDN detection helper script failed"
    fi
    
    # Fallback detection methods if helper script fails
    log_info "Trying fallback FQDN detection methods..."
    
    # Method 1: hostname -f
    if command_exists hostname; then
        detected_fqdn=$(hostname -f 2>/dev/null || echo "")
        if [[ -n "$detected_fqdn" && "$detected_fqdn" != "localhost" && "$detected_fqdn" == *.* ]]; then
            DOMAIN="$detected_fqdn"
            DOMAIN_AUTO_DETECTED="yes"
            log_success "FQDN detected via hostname -f: $DOMAIN"
            return 0
        fi
    fi
    
    # Method 2: Check /etc/hostname
    if [[ -f "/etc/hostname" ]]; then
        detected_fqdn=$(cat /etc/hostname 2>/dev/null | head -1 | tr -d '\n\r')
        if [[ -n "$detected_fqdn" && "$detected_fqdn" != "localhost" && "$detected_fqdn" == *.* ]]; then
            DOMAIN="$detected_fqdn"
            DOMAIN_AUTO_DETECTED="yes"
            log_success "FQDN detected via /etc/hostname: $DOMAIN"
            return 0
        fi
    fi
    
    # If SSL is required, fail here
    if [[ -n "$require_ssl_flag" ]]; then
        log_error "Could not auto-detect valid FQDN suitable for SSL certificates"
        log_error "Please provide a domain name using --domain parameter"
        return 1
    else
        log_warning "Could not auto-detect valid FQDN, using localhost"
        DOMAIN="localhost"
        return 0
    fi
}

# Install required packages
install_dependencies() {
    log_step "Installing dependencies..."

    # Update package list
    apt-get update -qq

    # Install base packages
    local packages=(
        "certbot"
        "curl"
        "jq"
        "dnsutils"  # For dig command
    )

    # Add DNS-specific packages
    if [[ "$VALIDATION_METHOD" == "dns" ]]; then
        case "$DNS_PROVIDER" in
            cloudflare)
                packages+=("python3-certbot-dns-cloudflare")
                ;;
            route53)
                packages+=("python3-certbot-dns-route53")
                ;;
            digitalocean)
                packages+=("python3-certbot-dns-digitalocean")
                ;;
            namecheap)
                packages+=("python3-certbot-dns-namecheap")
                ;;
            godaddy)
                packages+=("python3-certbot-dns-godaddy")
                ;;
            *)
                log_warning "Unknown DNS provider: $DNS_PROVIDER"
                log_info "Installing generic DNS plugins..."
                packages+=("python3-certbot-dns-*")
                ;;
        esac
    fi

    # Install packages
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package"; then
            log_info "Installing $package..."
            apt-get install -y "$package" || {
                log_warning "Failed to install $package via apt, trying pip..."
                pip3 install "certbot-dns-$DNS_PROVIDER" 2>/dev/null || true
            }
        else
            log_info "$package is already installed"
        fi
    done

    log_success "Dependencies installed successfully"
}

# Configure ZeroSSL with certbot
configure_zerossl() {
    log_step "Configuring ZeroSSL with certbot..."

    # Create ZeroSSL configuration directory
    mkdir -p /etc/letsencrypt/zerossl

    # Register ZeroSSL API key with certbot
    log_info "Registering ZeroSSL API key..."
    
    # Get EAB credentials from ZeroSSL API
    log_info "Fetching EAB credentials from ZeroSSL API..."
    
    if [[ "$DEBUG" == "yes" ]]; then
        log_info "Using API key: ${ZEROSSL_API_KEY:0:10}..."
        log_info "Using email: $EMAIL"
    fi
    
    local eab_response=""
    local curl_exit_code=0
    
    if command_exists curl; then
        if [[ "$DEBUG" == "yes" ]]; then
            log_info "Making API call to ZeroSSL..."
            eab_response=$(curl -v -X POST "https://api.zerossl.com/acme/eab-credentials-email" \
                           -H "Authorization: Bearer $ZEROSSL_API_KEY" \
                           -d "email=$EMAIL" 2>&1)
            curl_exit_code=$?
        else
            eab_response=$(curl -s -X POST "https://api.zerossl.com/acme/eab-credentials-email" \
                           -H "Authorization: Bearer $ZEROSSL_API_KEY" \
                           -d "email=$EMAIL" 2>/dev/null)
            curl_exit_code=$?
        fi
    else
        log_error "curl is required for ZeroSSL API calls"
        return 1
    fi
    
    if [[ $curl_exit_code -ne 0 ]]; then
        log_error "Failed to connect to ZeroSSL API (curl exit code: $curl_exit_code)"
        log_error "Please check your network connectivity"
        return 1
    fi
    
    if [[ -z "$eab_response" ]]; then
        log_error "Empty response from ZeroSSL API"
        log_error "Please check your API key and network connectivity"
        return 1
    fi
    
    if [[ "$DEBUG" == "yes" ]]; then
        log_info "ZeroSSL API Response: $eab_response"
    fi
    
    # Parse EAB credentials
    local eab_kid=$(echo "$eab_response" | jq -r '.eab_kid' 2>/dev/null)
    local eab_hmac_key=$(echo "$eab_response" | jq -r '.eab_hmac_key' 2>/dev/null)
    
    if [[ "$eab_kid" == "null" || "$eab_hmac_key" == "null" || -z "$eab_kid" || -z "$eab_hmac_key" ]]; then
        log_error "Failed to parse EAB credentials from ZeroSSL API response"
        
        # Check for specific error conditions
        local error_code=$(echo "$eab_response" | jq -r '.error.code' 2>/dev/null)
        local error_msg=$(echo "$eab_response" | jq -r '.error.message' 2>/dev/null)
        
        if [[ "$error_code" != "null" && -n "$error_code" ]]; then
            log_error "ZeroSSL API Error Code: $error_code"
            
            case "$error_code" in
                7100)
                    log_error "Invalid API key"
                    log_info "Please verify your ZeroSSL API key at https://app.zerossl.com/developer"
                    ;;
                7101)
                    log_error "API key not found or inactive"
                    log_info "Please check that your API key is active in your ZeroSSL dashboard"
                    ;;
                7103)
                    log_error "Insufficient API permissions"
                    log_info "Please ensure your API key has certificate management permissions"
                    ;;
                *)
                    if [[ "$error_msg" != "null" && -n "$error_msg" ]]; then
                        log_error "ZeroSSL API Error: $error_msg"
                    fi
                    ;;
            esac
        else
            # Try to extract error message from different response formats
            local alt_error=$(echo "$eab_response" | jq -r '.message' 2>/dev/null)
            if [[ "$alt_error" != "null" && -n "$alt_error" ]]; then
                log_error "ZeroSSL Error: $alt_error"
            else
                log_error "Unexpected API response format"
                if [[ "$DEBUG" == "yes" ]]; then
                    log_error "Raw response: $eab_response"
                fi
            fi
        fi
        
        return 1
    fi
    
    log_success "EAB credentials obtained successfully"
    log_info "EAB Kid: ${eab_kid:0:20}..."
    log_info "EAB HMAC Key: ${eab_hmac_key:0:20}..."
    
    # Create ZeroSSL external account binding
    log_info "Registering with ZeroSSL ACME server..."
    
    local certbot_register_cmd="certbot register --server https://acme.zerossl.com/v2/DV90 --email $EMAIL --agree-tos --eab-kid $eab_kid --eab-hmac-key $eab_hmac_key --non-interactive"
    
    if [[ "$DEBUG" == "yes" ]]; then
        certbot_register_cmd="$certbot_register_cmd --verbose"
        log_info "Registration command: $certbot_register_cmd"
    fi
    
    if eval "$certbot_register_cmd"; then
        log_success "ZeroSSL account registration successful"
    else
        # Check if account already exists
        log_warning "Registration failed - account may already exist"
        log_info "Attempting to use existing account..."
        
        # Test if we can use the existing account by doing a simple query
        local test_cmd="certbot certificates --cert-name nonexistent-test"
        if [[ "$DEBUG" == "yes" ]]; then
            test_cmd="$test_cmd --verbose"
        fi
        
        if eval "$test_cmd" 2>/dev/null; then
            log_success "Existing ZeroSSL account verified"
        else
            log_error "Cannot verify ZeroSSL account access"
            log_error "Please check your API key and account status"
            
            if [[ "$DEBUG" == "yes" ]]; then
                log_info "Try running with --debug for more detailed output"
                log_info "Check certbot logs: /var/log/letsencrypt/letsencrypt.log"
            fi
            
            return 1
        fi
    fi

    log_success "ZeroSSL configuration completed"
}

# Create DNS credentials file if needed
setup_dns_credentials() {
    if [[ "$VALIDATION_METHOD" != "dns" ]]; then
        return 0
    fi

    log_step "Setting up DNS credentials..."

    if [[ -z "$DNS_CREDENTIALS" ]]; then
        # Create default credentials file
        DNS_CREDENTIALS="/etc/letsencrypt/dns-credentials.ini"
        
        log_info "Creating DNS credentials file: $DNS_CREDENTIALS"
        
        case "$DNS_PROVIDER" in
            cloudflare)
                cat > "$DNS_CREDENTIALS" << EOF
# Cloudflare API credentials
# Get these from: https://dash.cloudflare.com/profile/api-tokens
dns_cloudflare_email = your-email@example.com
dns_cloudflare_api_key = your-global-api-key

# OR use API token (recommended)
# dns_cloudflare_api_token = your-api-token
EOF
                ;;
            route53)
                cat > "$DNS_CREDENTIALS" << EOF
# AWS Route53 credentials
# Use IAM user with Route53 permissions
[default]
aws_access_key_id = YOUR_ACCESS_KEY_ID
aws_secret_access_key = YOUR_SECRET_ACCESS_KEY
EOF
                ;;
            digitalocean)
                cat > "$DNS_CREDENTIALS" << EOF
# DigitalOcean API credentials
# Get token from: https://cloud.digitalocean.com/account/api/tokens
dns_digitalocean_token = your-api-token
EOF
                ;;
            *)
                cat > "$DNS_CREDENTIALS" << EOF
# DNS provider credentials for $DNS_PROVIDER
# Please refer to the certbot-dns-$DNS_PROVIDER documentation
# for the correct credential format
EOF
                ;;
        esac
        
        chmod 600 "$DNS_CREDENTIALS"
        
        log_warning "DNS credentials file created: $DNS_CREDENTIALS"
        log_warning "Please edit this file with your actual credentials before proceeding"
        
        if [[ "$DRY_RUN" != "yes" ]]; then
            read -p "Press Enter after editing the credentials file..."
        fi
    else
        log_info "Using provided DNS credentials file: $DNS_CREDENTIALS"
        chmod 600 "$DNS_CREDENTIALS"
    fi
}

# Build certbot command
build_certbot_command() {
    local cmd="certbot certonly"
    
    # ZeroSSL server
    cmd="$cmd --server https://acme.zerossl.com/v2/DV90"
    
    # Basic options
    cmd="$cmd --email $EMAIL"
    cmd="$cmd --agree-tos"
    cmd="$cmd --non-interactive"
    
    # ECC key configuration
    cmd="$cmd --key-type ecdsa"
    cmd="$cmd --elliptic-curve $ECC_CURVE"
    
    # Domain configuration
    if [[ "$WILDCARD" == "yes" ]]; then
        cmd="$cmd -d *.$DOMAIN -d $DOMAIN"
    else
        cmd="$cmd -d $DOMAIN"
    fi
    
    # Validation method
    if [[ "$VALIDATION_METHOD" == "http" ]]; then
        cmd="$cmd --standalone"
    else
        cmd="$cmd --dns-$DNS_PROVIDER"
        if [[ -n "$DNS_CREDENTIALS" ]]; then
            cmd="$cmd --dns-$DNS_PROVIDER-credentials $DNS_CREDENTIALS"
        fi
    fi
    
    # Additional options
    if [[ "$STAGING" == "yes" ]]; then
        cmd="$cmd --staging"
    fi
    
    if [[ "$DRY_RUN" == "yes" ]]; then
        cmd="$cmd --dry-run"
    fi
    
    if [[ "$FORCE_RENEWAL" == "yes" ]]; then
        cmd="$cmd --force-renewal"
    fi
    
    if [[ "$DEBUG" == "yes" ]]; then
        cmd="$cmd --verbose"
    fi
    
    echo "$cmd"
}

# Validate domain accessibility for HTTP validation
validate_http_domain() {
    if [[ "$VALIDATION_METHOD" != "http" ]]; then
        return 0
    fi

    log_step "Validating target accessibility for HTTP validation..."
    
    if [[ "$CERT_FOR_IP" == "yes" ]]; then
        log_warning "IP certificate validation requires port 80 to be accessible on IP: $DOMAIN"
        log_info "Make sure no firewall blocks port 80 and the IP is publicly accessible"
        
        # Test if we can reach the IP
        if command_exists ping; then
            if ping -c 1 -W 3 "$DOMAIN" >/dev/null 2>&1; then
                log_success "IP address $DOMAIN is reachable"
            else
                log_warning "IP address $DOMAIN is not responding to ping (may be normal if ICMP is blocked)"
            fi
        fi
        
        return 0
    else
        log_warning "HTTP validation requires a web server to be running on port 80"
        log_info "Make sure your web server serves files from a webroot directory"
        log_info "The domain $DOMAIN must point to this server and be accessible on port 80"
        
        # Check domain resolution - try both IPv4 and IPv6
        local server_ipv4=$(curl -s -4 ifconfig.me 2>/dev/null || echo "")
        local server_ipv6=$(curl -s -6 ifconfig.me 2>/dev/null || echo "")
        local domain_ipv4=$(dig +short A "$DOMAIN" 2>/dev/null | head -1 || echo "")
        local domain_ipv6=$(dig +short AAAA "$DOMAIN" 2>/dev/null | head -1 || echo "")
        
        log_info "Network connectivity check:"
        
        if [[ -n "$server_ipv4" ]]; then
            log_info "Server IPv4: $server_ipv4"
        fi
        
        if [[ -n "$server_ipv6" ]]; then
            log_info "Server IPv6: $server_ipv6"
        fi
        
        if [[ -n "$domain_ipv4" ]]; then
            log_info "Domain IPv4: $domain_ipv4"
            if [[ "$domain_ipv4" == "$server_ipv4" ]]; then
                log_success "✓ IPv4 addresses match"
            else
                log_warning "✗ IPv4 addresses don't match"
            fi
        fi
        
        if [[ -n "$domain_ipv6" ]]; then
            log_info "Domain IPv6: $domain_ipv6"
            if [[ "$domain_ipv6" == "$server_ipv6" ]]; then
                log_success "✓ IPv6 addresses match"
            else
                log_warning "✗ IPv6 addresses don't match"
            fi
        fi
        
        # Check if port 80 is available
        if command_exists netstat; then
            local port80_check=$(netstat -tuln | grep ":80 " || echo "")
            if [[ -n "$port80_check" ]]; then
                log_warning "Port 80 appears to be in use:"
                echo "$port80_check" | while read line; do
                    log_info "  $line"
                done
                log_warning "You may need to stop the service using port 80 before validation"
            else
                log_success "Port 80 appears to be available"
            fi
        elif command_exists ss; then
            local port80_check=$(ss -tuln | grep ":80 " || echo "")
            if [[ -n "$port80_check" ]]; then
                log_warning "Port 80 appears to be in use:"
                echo "$port80_check" | while read line; do
                    log_info "  $line"
                done
                log_warning "You may need to stop the service using port 80 before validation"
            else
                log_success "Port 80 appears to be available"
            fi
        fi
        
        # Check if at least one IP version matches
        local ip_match=false
        if [[ -n "$domain_ipv4" && "$domain_ipv4" == "$server_ipv4" ]]; then
            ip_match=true
        elif [[ -n "$domain_ipv6" && "$domain_ipv6" == "$server_ipv6" ]]; then
            ip_match=true
        fi
        
        if [[ "$ip_match" == "true" ]]; then
            log_success "Domain resolution looks good for HTTP validation"
        else
            log_warning "Domain resolution mismatch detected"
            log_warning "This may cause HTTP validation to fail"
            log_info "Consider using DNS validation if HTTP validation fails"
        fi
    fi
}

# Request certificate
request_certificate() {
    local curve_name=""
    case "$ECC_CURVE" in
        secp256r1) curve_name="ECC P-256" ;;
        secp384r1) curve_name="ECC P-384" ;;
        secp521r1) curve_name="ECC P-521" ;;
    esac
    
    log_step "Requesting ZeroSSL $curve_name certificate..."

    # Show validation method warnings
    if [[ "$VALIDATION_METHOD" == "http" ]]; then
        log_warning "Using standalone mode - will temporarily bind to port 80"
        log_warning "Make sure no web server is running on port 80 during validation"
    fi

    local certbot_cmd=$(build_certbot_command)
    
    log_info "Certbot command: $certbot_cmd"
    
    if [[ "$DRY_RUN" == "yes" ]]; then
        log_info "Running in dry-run mode..."
    fi

    # Execute certbot command
    if eval "$certbot_cmd"; then
        if [[ "$DRY_RUN" == "yes" ]]; then
            log_success "Dry run completed successfully - $curve_name certificate would be issued"
        else
            log_success "$curve_name certificate issued successfully"
            show_certificate_info
        fi
        return 0
    else
        log_error "Certificate request failed"
        
        # Show additional troubleshooting info
        echo ""
        log_error "Troubleshooting Information:"
        
        if [[ "$VALIDATION_METHOD" == "http" ]]; then
            log_info "For HTTP validation issues:"
            log_info "• Ensure port 80 is not blocked by firewall"
            log_info "• Stop any web server running on port 80"
            log_info "• Check if domain resolves to this server"
            
            # Show network info
            local server_ip=$(curl -s ifconfig.me 2>/dev/null || echo "unknown")
            local domain_ip=$(dig +short "$DOMAIN" 2>/dev/null | head -1 || echo "unknown")
            log_info "Server IP: $server_ip"
            log_info "Domain resolves to: $domain_ip"
        fi
        
        log_info "• Check certbot logs: /var/log/letsencrypt/letsencrypt.log"
        log_info "• Verify ZeroSSL API key permissions"
        log_info "• Try with --staging flag first for testing"
        
        return 1
    fi
}

# Show certificate information
show_certificate_info() {
    if [[ "$DRY_RUN" == "yes" ]]; then
        return 0
    fi

    log_step "Certificate Information:"
    
    local cert_path="/etc/letsencrypt/live/$DOMAIN"
    
    if [[ -d "$cert_path" ]]; then
        echo -e "${GREEN}Certificate Path: $cert_path${NC}"
        echo -e "${GREEN}Certificate Files:${NC}"
        echo -e "${BLUE}• Certificate: $cert_path/fullchain.pem${NC}"
        echo -e "${BLUE}• Private Key: $cert_path/privkey.pem${NC}"
        echo -e "${BLUE}• Certificate Chain: $cert_path/chain.pem${NC}"
        echo -e "${BLUE}• Certificate Only: $cert_path/cert.pem${NC}"
        
        # Show certificate details
        echo ""
        echo -e "${GREEN}Certificate Details:${NC}"
        openssl x509 -in "$cert_path/cert.pem" -text -noout | grep -E "(Subject:|Issuer:|Not Before:|Not After:|DNS:)" || true
        
        # Check expiration
        local expiry_date=$(openssl x509 -in "$cert_path/cert.pem" -noout -enddate | cut -d= -f2)
        echo -e "${BLUE}• Expires: $expiry_date${NC}"
        
        # Calculate days until expiry
        local expiry_epoch=$(date -d "$expiry_date" +%s)
        local current_epoch=$(date +%s)
        local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
        
        if [[ $days_until_expiry -gt 30 ]]; then
            echo -e "${GREEN}• Days until expiry: $days_until_expiry${NC}"
        elif [[ $days_until_expiry -gt 7 ]]; then
            echo -e "${YELLOW}• Days until expiry: $days_until_expiry${NC}"
        else
            echo -e "${RED}• Days until expiry: $days_until_expiry${NC}"
        fi
    fi
}

# Configure automatic renewal
setup_auto_renewal() {
    if [[ "$DRY_RUN" == "yes" ]]; then
        return 0
    fi

    log_step "Setting up automatic certificate renewal..."

    # Create renewal configuration
    local renewal_config="/etc/letsencrypt/renewal/$DOMAIN.conf"
    
    if [[ -f "$renewal_config" ]]; then
        # Update renewal config to use ZeroSSL
        sed -i 's|server = .*|server = https://acme.zerossl.com/v2/DV90|g' "$renewal_config"
        log_info "Updated renewal configuration for ZeroSSL"
    fi

    # Create renewal script
    cat > "/etc/cron.daily/zerossl-renewal" << 'EOF'
#!/bin/bash
#
# ZeroSSL Certificate Renewal Script
#

# Attempt renewal
/usr/bin/certbot renew --quiet --server https://acme.zerossl.com/v2/DV90

# Log renewal status
if [[ $? -eq 0 ]]; then
    echo "$(date): ZeroSSL certificates renewed successfully" >> /var/log/zerossl-renewal.log
else
    echo "$(date): ZeroSSL certificate renewal failed" >> /var/log/zerossl-renewal.log
fi
EOF

    chmod +x "/etc/cron.daily/zerossl-renewal"
    log_success "Automatic renewal configured"
}

# Main execution
main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}     ZeroSSL ECC Certificate Deployment${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""

    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        echo -e "${YELLOW}Please run: sudo $0 [options]${NC}"
        exit 1
    fi

    # Parse arguments
    parse_arguments "$@"
    
    # Auto-detect FQDN if not provided
    if ! detect_fqdn; then
        log_error "FQDN detection failed"
        exit 1
    fi

    # Get curve display name and security info
    local curve_display=""
    local security_level=""
    case "$ECC_CURVE" in
        secp256r1)
            curve_display="ECC P-256"
            security_level="128-bit security (RSA 3072-bit equivalent)"
            ;;
        secp384r1)
            curve_display="ECC P-384"
            security_level="192-bit security (RSA 7680-bit equivalent)"
            ;;
        secp521r1)
            curve_display="ECC P-521"
            security_level="256-bit security (RSA 15360-bit equivalent)"
            ;;
    esac

    # Display configuration
    echo -e "${GREEN}Configuration Summary:${NC}"
    if [[ "$CERT_FOR_IP" == "yes" ]]; then
        echo -e "${GREEN}• Target: IP Address Certificate${NC}"
        echo -e "${GREEN}• IP Address: $DOMAIN${NC}${DOMAIN_AUTO_DETECTED:+ (auto-detected)}"
    else
        echo -e "${GREEN}• Target: Domain Certificate${NC}"
        echo -e "${GREEN}• Domain: $DOMAIN${NC}${DOMAIN_AUTO_DETECTED:+ (auto-detected)}"
    fi
    echo -e "${GREEN}• Email: $EMAIL${NC}"
    echo -e "${GREEN}• Key Type: $curve_display ($ECC_CURVE)${NC}"
    echo -e "${GREEN}• Security Level: $security_level${NC}"
    echo -e "${GREEN}• Validation: $VALIDATION_METHOD${NC}"
    if [[ "$VALIDATION_METHOD" == "dns" ]]; then
        echo -e "${GREEN}• DNS Provider: $DNS_PROVIDER${NC}"
        if [[ -n "$DNS_CREDENTIALS" ]]; then
            echo -e "${GREEN}• DNS Credentials: $DNS_CREDENTIALS${NC}"
        fi
    fi
    echo -e "${GREEN}• Wildcard: $WILDCARD${NC}"
    echo -e "${GREEN}• Staging: $STAGING${NC}"
    echo -e "${GREEN}• Dry Run: $DRY_RUN${NC}"
    echo ""

    # Confirmation
    if [[ "$DRY_RUN" != "yes" ]]; then
        local curve_name=""
        case "$ECC_CURVE" in
            secp256r1) curve_name="ECC P-256" ;;
            secp384r1) curve_name="ECC P-384" ;;
            secp521r1) curve_name="ECC P-521" ;;
        esac
        
        if [[ "$CERT_FOR_IP" == "yes" ]]; then
            echo -e "${YELLOW}This will request a ZeroSSL $curve_name certificate for IP address: $DOMAIN${NC}"
            echo -e "${YELLOW}Note: IP certificates may have compatibility limitations${NC}"
        else
            echo -e "${YELLOW}This will request a ZeroSSL $curve_name certificate for domain: $DOMAIN${NC}"
        fi
        
        if [[ "$VALIDATION_METHOD" == "http" ]]; then
            echo -e "${YELLOW}HTTP validation will temporarily use port 80 - ensure no web server is running${NC}"
        fi
        read -p "Continue? (y/N): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Operation cancelled"
            exit 0
        fi
        echo ""
    fi

    # Execute deployment steps
    install_dependencies
    configure_zerossl
    setup_dns_credentials
    validate_http_domain
    request_certificate
    setup_auto_renewal

    # Show summary
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}        Deployment Complete!${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""

    if [[ "$DRY_RUN" == "yes" ]]; then
        echo -e "${BLUE}🧪 Dry Run Summary:${NC}"
        if [[ "$CERT_FOR_IP" == "yes" ]]; then
            echo -e "${GREEN}✓ ECC $curve_display IP certificate configuration validated${NC}"
        else
            echo -e "${GREEN}✓ ECC $curve_display certificate configuration validated${NC}"
        fi
        echo -e "${GREEN}✓ Dependencies checked${NC}"
        echo -e "${GREEN}✓ ZeroSSL registration tested${NC}"
        echo -e "${BLUE}Re-run without --dry-run to issue the actual ECC certificate${NC}"
    else
        echo -e "${BLUE}🎉 Certificate Deployment Summary:${NC}"
        if [[ "$CERT_FOR_IP" == "yes" ]]; then
            echo -e "${GREEN}✓ ZeroSSL $curve_display IP certificate issued for: $DOMAIN${NC}"
        else
            echo -e "${GREEN}✓ ZeroSSL $curve_display certificate issued for: $DOMAIN${NC}"
        fi
        echo -e "${GREEN}✓ Certificate files available in: /etc/letsencrypt/live/$DOMAIN${NC}"
        echo -e "${GREEN}✓ Automatic renewal configured${NC}"
        echo -e "${BLUE}✓ $curve_display provides $security_level with excellent performance${NC}"
        
        echo -e "${BLUE}📋 Next Steps:${NC}"
        echo -e "${BLUE}1. Configure your application/web server to use the certificate:${NC}"
        echo -e "${CYAN}   Certificate: /etc/letsencrypt/live/$DOMAIN/fullchain.pem${NC}"
        echo -e "${CYAN}   Private Key: /etc/letsencrypt/live/$DOMAIN/privkey.pem${NC}"
        echo -e "${BLUE}2. Restart your web server/application to load the certificate${NC}"
        echo -e "${BLUE}3. Test your SSL certificate:${NC}"
        if [[ "$CERT_FOR_IP" == "yes" ]]; then
            echo -e "${CYAN}   curl -I https://$DOMAIN${NC}"
            echo -e "${CYAN}   openssl s_client -connect $DOMAIN:443 < /dev/null 2>/dev/null | openssl x509 -text -noout | grep -E '(Subject:|DNS:|IP Address:)'${NC}"
            echo -e "${YELLOW}   Note: Browsers may show warnings for IP certificates${NC}"
        else
            echo -e "${CYAN}   curl -I https://$DOMAIN${NC}"
            echo -e "${CYAN}   openssl s_client -connect $DOMAIN:443 -servername $DOMAIN < /dev/null 2>/dev/null | openssl x509 -text -noout | grep 'Public-Key'${NC}"
        fi
        echo -e "${BLUE}4. Check certificate expiry and renewal:${NC}"
        echo -e "${CYAN}   certbot certificates${NC}"
        echo -e "${CYAN}   tail -f /var/log/zerossl-renewal.log${NC}"
        
        if [[ "$CERT_FOR_IP" == "yes" ]]; then
            echo ""
            echo -e "${YELLOW}⚠ IP Certificate Important Notes:${NC}"
            echo -e "${YELLOW}• IP certificates may show browser security warnings${NC}"
            echo -e "${YELLOW}• Some applications may not accept IP certificates${NC}"
            echo -e "${YELLOW}• If your IP changes, the certificate becomes invalid${NC}"
            echo -e "${YELLOW}• Consider using a domain name for better compatibility${NC}"
        fi

        if [[ "$VALIDATION_METHOD" == "dns" ]]; then
            echo ""
            echo -e "${BLUE}🔒 DNS Credentials Security:${NC}"
            echo -e "${YELLOW}• DNS credentials stored at: $DNS_CREDENTIALS${NC}"
            echo -e "${YELLOW}• File permissions set to 600 (owner read/write only)${NC}"
            echo -e "${YELLOW}• Consider using IAM roles or API tokens with minimal permissions${NC}"
        fi
    fi

    echo ""
    log_success "ZeroSSL ECC certificate deployment completed successfully!"
}

# Run main function with all arguments
main "$@"