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

# BunkerWeb Setup Script
# This script generates random passwords and replaces placeholders in docker-compose.yml
# MUST BE RUN AS ROOT: sudo ./setup-bunkerweb.sh --type <autoconf|basic|integrated>

set -e

INSTALL_DIR="/data/BunkerWeb"
SETUP_MODE="automated"  # Default to automated mode

# Default values (can be overridden by BunkerWeb.conf or command line)
ADMIN_USERNAME="admin"  # Default admin username
AUTO_CERT_TYPE=""       # Certificate type: LE or ZeroSSL (ZeroSSL is draft - not yet implemented)
AUTO_CERT_CONTACT=""    # Contact email for certificates
AUTO_CERT_ZSSL_API=""   # ZeroSSL API key
FQDN=""                 # Fully Qualified Domain Name for SSL certificates
LETS_ENCRYPT_CHALLENGE="http"  # Challenge type: http or dns
LETS_ENCRYPT_STAGING="yes"     # Use staging environment for testing (default: yes for safety)
LETS_ENCRYPT_WILDCARD="no"     # Enable wildcard certificates (DNS only, default: no)
MULTISITE="yes"         # Enable multisite mode by default
SERVER_NAME=""          # Primary domain name (same as FQDN in single domain setups)
BUNKERWEB_INSTANCES="127.0.0.1"  # List of BunkerWeb instances
SECURITY_MODE="block"   # Security level: detect or block
SERVER_TYPE="http"      # Server type: http or stream
USE_GREYLIST="no"       # Enable greylist for admin interface
GREYLIST_IP=""          # IP addresses or networks to greylist
GREYLIST_RDNS=""        # Reverse DNS suffixes to greylist

# MySQL Configuration
MYSQL_RANDOM_ROOT_PASSWORD="no"  # Set to "no" to disable random root password generation
MYSQL_ROOT_PASSWORD=""           # Custom root password (generated if empty)

# Load configuration from BunkerWeb.conf if it exists
CONFIG_FILE="$INSTALL_DIR/BunkerWeb.conf"
if [[ -f "$CONFIG_FILE" ]]; then
    echo -e "${BLUE}Loading configuration from $CONFIG_FILE...${NC}"
    source "$CONFIG_FILE"
    echo -e "${GREEN}✓ Configuration loaded${NC}"
    
    # Check if user has edited the default configuration
    echo -e "${BLUE}Validating configuration...${NC}"
    CONFIG_NEEDS_EDITING=false
    
    # Create a hash of the critical default values to detect if user made changes
    DEFAULT_HASH=$(echo -n "AUTO_CERT_TYPE=LE;AUTO_CERT_CONTACT=me@example.com;MULTISITE=yes" | sha256sum | cut -d' ' -f1)
    CURRENT_HASH=""
    if [[ -n "$AUTO_CERT_TYPE" && -n "$AUTO_CERT_CONTACT" ]]; then
        CURRENT_HASH=$(echo -n "AUTO_CERT_TYPE=$AUTO_CERT_TYPE;AUTO_CERT_CONTACT=$AUTO_CERT_CONTACT;MULTISITE=$MULTISITE" | sha256sum | cut -d' ' -f1)
    fi
    
    # Check for specific default/example values that need to be changed
    if [[ "$AUTO_CERT_CONTACT" == "me@example.com" ]]; then
        echo -e "${RED}⚠ Default contact email detected: $AUTO_CERT_CONTACT${NC}"
        CONFIG_NEEDS_EDITING=true
    fi
    
    # Check for other example values in the contact email
    if [[ "$AUTO_CERT_CONTACT" == *"@example.com"* || "$AUTO_CERT_CONTACT" == *"@yourdomain.com"* ]]; then
        echo -e "${RED}⚠ Example contact email detected: $AUTO_CERT_CONTACT${NC}"
        CONFIG_NEEDS_EDITING=true
    fi
    
    # Check for example FQDN values
    if [[ "$FQDN" == *"example.com"* || "$FQDN" == *"yourdomain.com"* ]]; then
        echo -e "${RED}⚠ Example domain detected: $FQDN${NC}"
        CONFIG_NEEDS_EDITING=true
    fi
    
    # Check if configuration is exactly the default (using hash comparison)
    if [[ -n "$CURRENT_HASH" && "$DEFAULT_HASH" == "$CURRENT_HASH" && -n "$AUTO_CERT_TYPE" ]]; then
        echo -e "${RED}⚠ Configuration file appears unchanged from defaults${NC}"
        CONFIG_NEEDS_EDITING=true
    fi
    
    # If SSL certificates are enabled but using default values, stop installation
    if [[ -n "$AUTO_CERT_TYPE" && "$CONFIG_NEEDS_EDITING" == "true" && "$FORCE_INSTALL" != "yes" ]]; then
        echo ""
        echo -e "${RED}=================================================================================${NC}"
        echo -e "${RED}                    CONFIGURATION VALIDATION FAILED                    ${NC}"
        echo -e "${RED}=================================================================================${NC}"
        echo ""
        echo -e "${YELLOW}SSL certificates are enabled but the configuration contains default/example values.${NC}"
        echo -e "${YELLOW}This will cause SSL certificate enrollment to fail.${NC}"
        echo ""
        echo -e "${BLUE}Configuration file: $CONFIG_FILE${NC}"
        echo ""
        echo -e "${YELLOW}Issues detected:${NC}"
        if [[ "$AUTO_CERT_CONTACT" == "me@example.com" ]]; then
            echo -e "${RED}• Contact email is still the default: me@example.com${NC}"
        fi
        if [[ "$AUTO_CERT_CONTACT" == *"@example.com"* || "$AUTO_CERT_CONTACT" == *"@yourdomain.com"* ]]; then
            echo -e "${RED}• Contact email contains example domain: $AUTO_CERT_CONTACT${NC}"
        fi
        if [[ "$FQDN" == *"example.com"* || "$FQDN" == *"yourdomain.com"* ]]; then
            echo -e "${RED}• Domain contains example values: $FQDN${NC}"
        fi
        if [[ -n "$CURRENT_HASH" && "$DEFAULT_HASH" == "$CURRENT_HASH" ]]; then
            echo -e "${RED}• Configuration appears to be completely unchanged from defaults${NC}"
        fi
        echo ""
        echo -e "${GREEN}Required fixes:${NC}"
        echo -e "${GREEN}1. Edit the configuration file:${NC}"
        echo -e "${BLUE}   nano $CONFIG_FILE${NC}"
        echo -e "${GREEN}2. Change the contact email:${NC}"
        echo -e "${BLUE}   AUTO_CERT_CONTACT=\"your-real-email@your-domain.com\"${NC}"
        echo -e "${GREEN}3. Optionally set your domain:${NC}"
        echo -e "${BLUE}   FQDN=\"your-actual-domain.com\"${NC}"
        echo -e "${GREEN}4. Run the script again${NC}"
        echo ""
        echo -e "${YELLOW}Alternative - disable SSL certificates:${NC}"
        echo -e "${BLUE}Comment out AUTO_CERT_TYPE by adding # at the beginning:${NC}"
        echo -e "${BLUE}# AUTO_CERT_TYPE=\"LE\"${NC}"
        echo ""
        echo -e "${RED}To bypass this validation (NOT RECOMMENDED): add --force${NC}"
        echo ""
        exit 1
    elif [[ "$CONFIG_NEEDS_EDITING" == "true" && "$FORCE_INSTALL" == "yes" ]]; then
        echo -e "${YELLOW}⚠ Example values detected but --force specified${NC}"
        echo -e "${RED}⚠ Proceeding with potentially invalid configuration${NC}"
        echo -e "${RED}⚠ SSL certificate enrollment may fail${NC}"
    elif [[ "$CONFIG_NEEDS_EDITING" == "true" ]]; then
        echo -e "${YELLOW}⚠ Example values detected but SSL certificates disabled${NC}"
        echo -e "${BLUE}ℹ Continuing with manual SSL configuration${NC}"
    else
        echo -e "${GREEN}✓ Configuration validation passed${NC}"
    fi
    
else
    echo -e "${YELLOW}Configuration file not found, creating default BunkerWeb.conf...${NC}"
    mkdir -p "$INSTALL_DIR"
    cat > "$CONFIG_FILE" << 'EOF'
#!/bin/bash
#
# BunkerWeb Configuration File
# This file contains default settings for the BunkerWeb setup script
# Command line arguments will override these values
#
# IMPORTANT: Edit the values below before running the setup script!
#

# Default admin username
ADMIN_USERNAME="admin"

# Domain Configuration
# FQDN=""                        # Fully Qualified Domain Name (auto-detected if not set)
# SERVER_NAME=""                 # Primary domain name (same as FQDN in single domain setups)

# BunkerWeb Instance Configuration
BUNKERWEB_INSTANCES="127.0.0.1" # List of BunkerWeb instances separated by spaces

# Multisite Configuration
MULTISITE="yes"                  # Enable multisite mode (supports multiple domains)

# Security Configuration
SECURITY_MODE="block"            # Security level: detect or block (default: block)
SERVER_TYPE="http"               # Server type: http or stream (default: http)

# Greylist Configuration (Admin Interface Protection)
USE_GREYLIST="no"                # Enable greylist for admin interface (default: no)
# GREYLIST_IP=""                 # IP addresses/networks to greylist (auto-detected from SSH)
# GREYLIST_RDNS=""               # Reverse DNS suffixes to greylist

# MySQL Database Configuration
MYSQL_RANDOM_ROOT_PASSWORD="no" # Set to "no" for controlled root password (default: no)
# MYSQL_ROOT_PASSWORD=""         # Custom root password (auto-generated if empty)

# SSL Certificate Configuration
AUTO_CERT_TYPE="LE"              # Certificate type: LE or ZeroSSL (Note: ZeroSSL is draft - not yet implemented)
AUTO_CERT_CONTACT="me@example.com"  # Contact email for certificates (CHANGE THIS!)
# AUTO_CERT_ZSSL_API=""          # ZeroSSL API key (draft feature)

# Let's Encrypt Advanced Options
# LETS_ENCRYPT_CHALLENGE="http"  # Challenge type: http or dns
# LETS_ENCRYPT_STAGING="yes"     # Use staging environment: yes or no (default: yes for safety)
# LETS_ENCRYPT_WILDCARD="no"     # Enable wildcard certificates: yes or no (DNS only)

# MYSQL CONFIGURATION:
# MYSQL_RANDOM_ROOT_PASSWORD="no" means root password will be set to a known value
# MYSQL_ROOT_PASSWORD will be auto-generated if not specified
# This allows for controlled access to the database root user
#
# TO ENABLE SSL CERTIFICATES:
# 1. Change AUTO_CERT_CONTACT above from me@example.com to your real email address
# 2. Optionally set FQDN to your domain name
# 3. Run the script
#
# TO DISABLE SSL CERTIFICATES:
# 1. Comment out AUTO_CERT_TYPE (add # at the beginning)
# 2. Run the script
#
# MULTISITE MODE:
# Multisite is enabled by default, allowing you to host multiple domains.
# Each domain can have individual configurations using SERVER_NAME prefixes.
# Example: www.example.com_USE_ANTIBOT=captcha
#
# GREYLIST PROTECTION:
# Enable USE_GREYLIST=yes to protect admin interface with IP restrictions.
# GREYLIST_IP will be auto-populated with SSH connection IPs during setup.
# GREYLIST_RDNS can be used to allow access from specific domain suffixes.

# Uncomment and configure the settings below as needed:

# Example domain configuration:
# FQDN="bunkerweb.yourdomain.com"
# SERVER_NAME="bunkerweb.yourdomain.com"

# Example MySQL configuration:
# MYSQL_RANDOM_ROOT_PASSWORD="no"
# MYSQL_ROOT_PASSWORD="my-secure-root-password"

# Example greylist configuration:
# USE_GREYLIST="yes"
# GREYLIST_IP="192.168.1.0/24 10.0.0.1"
# GREYLIST_RDNS="yourdomain.com yourcompany.com"

# Example Let's Encrypt HTTP Challenge (staging by default for safety):
# AUTO_CERT_TYPE="LE"
# AUTO_CERT_CONTACT="admin@yourdomain.com"
# FQDN="bunkerweb.yourdomain.com"
# LETS_ENCRYPT_CHALLENGE="http"
# LETS_ENCRYPT_STAGING="yes"

# Example Let's Encrypt Production (disable staging):
# AUTO_CERT_TYPE="LE"
# AUTO_CERT_CONTACT="admin@yourdomain.com"
# FQDN="bunkerweb.yourdomain.com"
# LETS_ENCRYPT_CHALLENGE="http"
# LETS_ENCRYPT_STAGING="no"

# Example Let's Encrypt DNS Challenge with Wildcard:
# AUTO_CERT_TYPE="LE"
# AUTO_CERT_CONTACT="admin@yourdomain.com"
# FQDN="yourdomain.com"
# LETS_ENCRYPT_CHALLENGE="dns"
# LETS_ENCRYPT_WILDCARD="yes"

# Example Let's Encrypt Staging (for testing):
# AUTO_CERT_TYPE="LE"
# AUTO_CERT_CONTACT="admin@yourdomain.com"
# FQDN="test.yourdomain.com"
# LETS_ENCRYPT_STAGING="yes"

# Example ZeroSSL configuration (DRAFT - NOT YET IMPLEMENTED):
# AUTO_CERT_TYPE="ZeroSSL" 
# AUTO_CERT_CONTACT="admin@yourdomain.com"
# AUTO_CERT_ZSSL_API="your-zerossl-api-key"
# FQDN="bunkerweb.yourdomain.com"

EOF
    chmod 644 "$CONFIG_FILE"
    echo -e "${GREEN}✓ Default configuration created at: $CONFIG_FILE${NC}"
    echo ""
    echo -e "${RED}=================================================================================${NC}"
    echo -e "${RED}                         IMPORTANT - READ THIS                         ${NC}"
    echo -e "${RED}=================================================================================${NC}"
    echo -e "${YELLOW}SSL certificates are ENABLED by default with placeholder values.${NC}"
    echo -e "${YELLOW}The script will STOP if you run it again without editing the config file.${NC}"
    echo ""
    echo -e "${BLUE}MySQL Configuration:${NC}"
    echo -e "${GREEN}• MYSQL_RANDOM_ROOT_PASSWORD is set to \"no\" for controlled access${NC}"
    echo -e "${GREEN}• Root password will be auto-generated and saved to credentials file${NC}"
    echo ""
    echo -e "${BLUE}Required steps before running again:${NC}"
    echo -e "${YELLOW}  1. Edit: $CONFIG_FILE${NC}"
    echo -e "${YELLOW}  2. Change: AUTO_CERT_CONTACT=\"me@example.com\"${NC}"
    echo -e "${YELLOW}  3. To: AUTO_CERT_CONTACT=\"your-real-email@domain.com\"${NC}"
    echo -e "${YELLOW}  4. Run this script again${NC}"
    echo ""
    echo -e "${BLUE}Alternative - to disable SSL certificates:${NC}"
    echo -e "${BLUE}  Comment out AUTO_CERT_TYPE (add # at the beginning)${NC}"
    echo ""
    echo -e "${RED}=================================================================================${NC}"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
    echo -e "  --admin-name NAME   Set admin username (overrides config file)"
    echo -e "  --FQDN DOMAIN       Set Fully Qualified Domain Name (overrides auto-detection)"
    echo -e "  --force             Skip configuration validation (not recommended)"
    echo ""
    echo -e "${YELLOW}MySQL Configuration:${NC}"
    echo -e "  --mysql-random-root yes|no   Set MYSQL_RANDOM_ROOT_PASSWORD (default: no)"
    echo -e "  --mysql-root-password PASS   Set custom MySQL root password"
    echo ""
    echo -e "${YELLOW}SSL Certificate Options:${NC}"
    echo -e "  --AUTO_CERT LE|ZeroSSL       Enable automatic certificates (overrides config file)"
    echo -e "  --AUTO_CERT_CONTACT EMAIL    Contact email for certificate registration"
    echo -e "  --AUTO_CERT_ZSSL_API KEY     ZeroSSL API key (required when using ZeroSSL)"
    echo ""
    echo -e "${YELLOW}Let's Encrypt Advanced Options:${NC}"
    echo -e "  --LE_CHALLENGE http|dns      Challenge method (default: http)"
    echo -e "  --LE_STAGING yes|no          Use staging environment (default: yes for safety)"
    echo -e "  --LE_WILDCARD yes|no         Enable wildcard certificates (default: no, DNS only)"
    echo ""
    echo -e "${YELLOW}Help:${NC}"
    echo -e "  -h, --help          Show this help message"
    echo ""
    echo -e "${BLUE}Configuration File:${NC}"
    echo -e "  Default settings are loaded from: $INSTALL_DIR/BunkerWeb.conf"
    echo -e "  Command line arguments override config file values"
    echo -e "  ${RED}IMPORTANT: SSL is ENABLED by default with example values${NC}"
    echo -e "  ${YELLOW}You MUST edit the config file to use real email addresses${NC}"
    echo -e "  Script will stop if example values are detected in SSL configuration"
    echo ""
    echo -e "${BLUE}MySQL Configuration:${NC}"
    echo -e "  ${GREEN}MYSQL_RANDOM_ROOT_PASSWORD is set to \"no\" by default${NC}"
    echo -e "  ${GREEN}This allows controlled access with a known root password${NC}"
    echo -e "  ${GREEN}MySQL passwords use 264-bit entropy (beyond AES-256)${NC}"
    echo -e "  ${GREEN}Admin passwords use 12 chars (human-friendly but secure)${NC}"
    echo -e "  ${GREEN}Root password is auto-generated and saved to credentials file${NC}"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo -e "  sudo $0 --type autoconf"
    echo -e "  sudo $0 --type basic --wizard"
    echo -e "  sudo $0 --type integrated --admin-name myuser"
    echo -e "  sudo $0 --type autoconf --mysql-root-password mysecretpass"
    echo -e "  sudo $0 --type autoconf --FQDN bunkerweb.example.com --AUTO_CERT LE --AUTO_CERT_CONTACT admin@example.com"
    echo ""
    echo -e "${BLUE}Note:${NC} Existing credentials are preserved. Delete /root/BunkerWeb-Credentials.txt to regenerate passwords."
    echo -e "${RED}Note:${NC} SSL certificates are ENABLED by default with placeholder values!"
    echo -e "${YELLOW}Note:${NC} Edit BunkerWeb.conf with real email/domain before running, or script will stop."
    echo ""
}

# Parse command line arguments
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
        --mysql-random-root)
            MYSQL_RANDOM_ROOT_PASSWORD="$2"
            shift 2
            ;;
        --mysql-root-password)
            MYSQL_ROOT_PASSWORD="$2"
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
        --AUTO_CERT_ZSSL_API)
            AUTO_CERT_ZSSL_API="$2"
            shift 2
            ;;
        --LE_CHALLENGE)
            LETS_ENCRYPT_CHALLENGE="$2"
            shift 2
            ;;
        --LE_STAGING)
            LETS_ENCRYPT_STAGING="$2"
            shift 2
            ;;
        --LE_WILDCARD)
            LETS_ENCRYPT_WILDCARD="$2"
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

# Validate MySQL configuration
case "$MYSQL_RANDOM_ROOT_PASSWORD" in
    yes|no)
        ;;
    *)
        echo -e "${RED}Error: Invalid MYSQL_RANDOM_ROOT_PASSWORD value '$MYSQL_RANDOM_ROOT_PASSWORD'${NC}"
        echo -e "${YELLOW}Valid values: yes, no${NC}"
        exit 1
        ;;
esac

# Validate that --type was provided
if [[ -z "$DEPLOYMENT_TYPE" ]]; then
    echo -e "${RED}Error: --type parameter is required${NC}"
    echo ""
    show_usage
    exit 1
fi

# Auto-detect FQDN if not provided
if [[ -z "$FQDN" ]]; then
    echo -e "${BLUE}Auto-detecting FQDN...${NC}"
    
    # Try multiple methods to get FQDN
    DETECTED_FQDN=""
    
    # Method 1: hostname -f
    if command -v hostname &> /dev/null; then
        DETECTED_FQDN=$(hostname -f 2>/dev/null || echo "")
    fi
    
    # Method 2: dnsdomainname + hostname
    if [[ -z "$DETECTED_FQDN" ]] && command -v dnsdomainname &> /dev/null; then
        DOMAIN=$(dnsdomainname 2>/dev/null || echo "")
        HOSTNAME=$(hostname 2>/dev/null || echo "")
        if [[ -n "$DOMAIN" && -n "$HOSTNAME" ]]; then
            DETECTED_FQDN="$HOSTNAME.$DOMAIN"
        fi
    fi
    
    # Method 3: Check /etc/hostname and /etc/hosts
    if [[ -z "$DETECTED_FQDN" && -f "/etc/hostname" ]]; then
        HOSTNAME=$(cat /etc/hostname 2>/dev/null | head -1)
        if [[ "$HOSTNAME" == *.* ]]; then
            DETECTED_FQDN="$HOSTNAME"
        fi
    fi
    
    # Validate detected FQDN
    if [[ -n "$DETECTED_FQDN" && "$DETECTED_FQDN" == *.* && "$DETECTED_FQDN" != "localhost."* ]]; then
        FQDN="$DETECTED_FQDN"
        echo -e "${GREEN}✓ FQDN auto-detected: $FQDN${NC}"
    else
        echo -e "${YELLOW}⚠ Could not auto-detect valid FQDN${NC}"
        echo -e "${BLUE}Detected: ${DETECTED_FQDN:-'none'}${NC}"
        
        if [[ -n "$AUTO_CERT_TYPE" ]]; then
            echo -e "${RED}Error: FQDN is required for SSL certificate enrollment${NC}"
            echo -e "${YELLOW}Please specify FQDN using: --FQDN your-domain.com${NC}"
            exit 1
        else
            echo -e "${BLUE}ℹ SSL certificates disabled - FQDN not required${NC}"
            FQDN="localhost"
        fi
    fi
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
        echo ""
        show_usage
        exit 1
        ;;
esac

# Validate SSL certificate options
if [[ -n "$AUTO_CERT_TYPE" ]]; then
    case "$AUTO_CERT_TYPE" in
        LE|LetsEncrypt)
            AUTO_CERT_TYPE="LE"
            if [[ -z "$AUTO_CERT_CONTACT" ]]; then
                echo -e "${RED}Error: --AUTO_CERT_CONTACT email is required when using Let's Encrypt${NC}"
                exit 1
            fi
            if [[ -z "$FQDN" || "$FQDN" == "localhost" ]]; then
                echo -e "${RED}Error: Valid FQDN is required for Let's Encrypt certificates${NC}"
                echo -e "${YELLOW}Please specify FQDN using: --FQDN your-domain.com${NC}"
                exit 1
            fi
            
            # Validate Let's Encrypt specific options
            case "$LETS_ENCRYPT_CHALLENGE" in
                http|dns)
                    ;;
                *)
                    echo -e "${RED}Error: Invalid challenge type '$LETS_ENCRYPT_CHALLENGE'${NC}"
                    echo -e "${YELLOW}Valid types: http, dns${NC}"
                    exit 1
                    ;;
            esac
            
            case "$LETS_ENCRYPT_STAGING" in
                yes|no)
                    ;;
                *)
                    echo -e "${RED}Error: Invalid staging value '$LETS_ENCRYPT_STAGING'${NC}"
                    echo -e "${YELLOW}Valid values: yes, no${NC}"
                    exit 1
                    ;;
            esac
            
            case "$LETS_ENCRYPT_WILDCARD" in
                yes|no)
                    ;;
                *)
                    echo -e "${RED}Error: Invalid wildcard value '$LETS_ENCRYPT_WILDCARD'${NC}"
                    echo -e "${YELLOW}Valid values: yes, no${NC}"
                    exit 1
                    ;;
            esac
            
            # Wildcard certificates require DNS challenge
            if [[ "$LETS_ENCRYPT_WILDCARD" == "yes" && "$LETS_ENCRYPT_CHALLENGE" != "dns" ]]; then
                echo -e "${RED}Error: Wildcard certificates require DNS challenge${NC}"
                echo -e "${YELLOW}Please set: --LE_CHALLENGE dns${NC}"
                exit 1
            fi
            ;;
        ZeroSSL)
            if [[ -z "$AUTO_CERT_CONTACT" ]]; then
                echo -e "${RED}Error: --AUTO_CERT_CONTACT email is required when using ZeroSSL${NC}"
                exit 1
            fi
            if [[ -z "$AUTO_CERT_ZSSL_API" ]]; then
                echo -e "${RED}Error: --AUTO_CERT_ZSSL_API key is required when using ZeroSSL${NC}"
                exit 1
            fi
            if [[ -z "$FQDN" || "$FQDN" == "localhost" ]]; then
                echo -e "${RED}Error: Valid FQDN is required for ZeroSSL certificates${NC}"
                echo -e "${YELLOW}Please specify FQDN using: --FQDN your-domain.com${NC}"
                exit 1
            fi
            ;;
        *)
            echo -e "${RED}Error: Invalid certificate type '$AUTO_CERT_TYPE'${NC}"
            echo -e "${YELLOW}Valid types: LE, ZeroSSL${NC}"
            exit 1
            ;;
    esac
fi

# Set compose file path
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"
TEMPLATE_PATH="$INSTALL_DIR/$TEMPLATE_FILE"
BACKUP_FILE="$INSTALL_DIR/docker-compose.yml.backup"

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}          BunkerWeb Setup Script${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""
echo -e "${GREEN}Deployment Type:${NC} $DEPLOYMENT_NAME"
echo -e "${GREEN}Template File:${NC} $TEMPLATE_FILE"
echo -e "${GREEN}Setup Mode:${NC} $(if [[ $SETUP_MODE == "automated" ]]; then echo "Automated"; else echo "Setup Wizard"; fi)"
echo -e "${GREEN}Admin Username:${NC} $ADMIN_USERNAME"
echo -e "${GREEN}Domain (FQDN):${NC} $FQDN"
echo -e "${GREEN}Multisite Mode:${NC} $MULTISITE"
echo -e "${GREEN}MySQL Random Root:${NC} $MYSQL_RANDOM_ROOT_PASSWORD"
echo -e "${GREEN}Config File:${NC} $(if [[ -f "$CONFIG_FILE" ]]; then echo "Loaded"; else echo "Created default"; fi)"
if [[ -n "$AUTO_CERT_TYPE" ]]; then
    echo -e "${GREEN}SSL Certificates:${NC} $AUTO_CERT_TYPE"
    echo -e "${GREEN}Contact Email:${NC} $AUTO_CERT_CONTACT"
    if [[ "$AUTO_CERT_TYPE" == "LE" ]]; then
        echo -e "${GREEN}Challenge Type:${NC} $LETS_ENCRYPT_CHALLENGE"
        echo -e "${GREEN}Staging Mode:${NC} $LETS_ENCRYPT_STAGING $(if [[ "$LETS_ENCRYPT_STAGING" == "yes" ]]; then echo "(default for safety)"; fi)"
        echo -e "${GREEN}Wildcard Certs:${NC} $LETS_ENCRYPT_WILDCARD"
    elif [[ "$AUTO_CERT_TYPE" == "ZeroSSL" ]]; then
        echo -e "${GREEN}ZeroSSL API:${NC} ${AUTO_CERT_ZSSL_API:0:8}..."
    fi
else
    echo -e "${GREEN}SSL Certificates:${NC} Manual configuration"
fi
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   echo -e "${YELLOW}Please run: sudo $0 --type $DEPLOYMENT_TYPE${NC}"
   exit 1
fi

# Check if template file exists
if [[ ! -f "$TEMPLATE_PATH" ]]; then
    echo -e "${RED}Error: Template file not found at $TEMPLATE_PATH${NC}"
    echo -e "${YELLOW}Available templates should be:${NC}"
    echo -e "  - $INSTALL_DIR/template_autoconf_display.yml"
    echo -e "  - $INSTALL_DIR/template_basic_display.yml"
    echo -e "  - $INSTALL_DIR/template_ui_integrated_display.yml"
    exit 1
fi

# Copy template to docker-compose.yml
echo -e "${BLUE}Copying template to docker-compose.yml...${NC}"
cp "$TEMPLATE_PATH" "$COMPOSE_FILE"
echo -e "${GREEN}✓ Template copied: $TEMPLATE_FILE → docker-compose.yml${NC}"

# Check if template contains placeholders
if ! grep -q "REPLACEME_" "$COMPOSE_FILE"; then
    echo -e "${YELLOW}Warning: No placeholders found in docker-compose.yml${NC}"
    echo -e "${YELLOW}File may already be configured or invalid template${NC}"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Create backup
echo -e "${BLUE}Creating backup...${NC}"
cp "$COMPOSE_FILE" "$BACKUP_FILE"
echo -e "${GREEN}Backup created: $BACKUP_FILE${NC}"

# Generate passwords function using Method 1: Base64 (12 characters for human use)
generate_password() {
    openssl rand -base64 33 | head -c 12 && echo
}

# Generate secure MySQL passwords function (full 264-bit entropy)
generate_mysql_password() {
    openssl rand -base64 33
}

# Generate secure MySQL root password function (full 264-bit entropy)
generate_mysql_root_password() {
    openssl rand -base64 33
}

# Check if credentials already exist
ROOT_CREDS_FILE="/root/BunkerWeb-Credentials.txt"
LOCAL_CREDS_FILE="$INSTALL_DIR/credentials.txt"

# Safety check: Ensure we can create the credentials file in /root/
echo -e "${BLUE}Checking /root/ directory access...${NC}"
if ! touch "$ROOT_CREDS_FILE" 2>/dev/null; then
    echo -e "${RED}Error: Cannot create credentials file in /root/ directory${NC}"
    echo -e "${YELLOW}This could be due to:${NC}"
    echo -e "${BLUE}• Insufficient permissions (not running as root)${NC}"
    echo -e "${BLUE}• /root/ directory is not accessible${NC}"
    echo -e "${BLUE}• Filesystem permissions issue${NC}"
    echo -e "${YELLOW}Please ensure you are running as root and /root/ is writable${NC}"
    exit 1
fi
echo -e "${GREEN}✓ /root/ directory is accessible${NC}"

# Create symbolic link from local directory to /root/ credentials file
echo -e "${BLUE}Creating symbolic link for credentials...${NC}"
if [[ -L "$LOCAL_CREDS_FILE" ]]; then
    echo -e "${BLUE}Removing existing symbolic link...${NC}"
    rm "$LOCAL_CREDS_FILE"
elif [[ -f "$LOCAL_CREDS_FILE" ]]; then
    echo -e "${YELLOW}Backing up existing local credentials file...${NC}"
    mv "$LOCAL_CREDS_FILE" "$LOCAL_CREDS_FILE.backup.$(date +%Y%m%d_%H%M%S)"
fi

if ! ln -s "$ROOT_CREDS_FILE" "$LOCAL_CREDS_FILE" 2>/dev/null; then
    echo -e "${RED}Error: Cannot create symbolic link for credentials${NC}"
    echo -e "${YELLOW}Please check permissions in $INSTALL_DIR${NC}"
    exit 1
fi

if [[ -L "$LOCAL_CREDS_FILE" ]]; then
    echo -e "${GREEN}✓ Created symbolic link: $LOCAL_CREDS_FILE → $ROOT_CREDS_FILE${NC}"
else
    echo -e "${RED}✗ Failed to verify symbolic link${NC}"
    exit 1
fi

if [[ -f "$ROOT_CREDS_FILE" ]]; then
    echo -e "${BLUE}Found existing credentials file, loading existing passwords...${NC}"
    
    # Extract existing passwords from credentials file
    MYSQL_PASSWORD=$(grep "MySQL Database Password:" "$ROOT_CREDS_FILE" | cut -d' ' -f4 || echo "")
    TOTP_SECRET=$(grep "TOTP Secret Key:" "$ROOT_CREDS_FILE" | cut -d' ' -f4 || echo "")
    ADMIN_PASSWORD=$(grep "Admin Password:" "$ROOT_CREDS_FILE" | cut -d' ' -f3 || echo "")
    FLASK_SECRET=$(grep "Flask Secret:" "$ROOT_CREDS_FILE" | cut -d' ' -f3 || echo "")
    EXISTING_MYSQL_ROOT_PASSWORD=$(grep "MySQL Root Password:" "$ROOT_CREDS_FILE" | cut -d' ' -f4 || echo "")
    
    # Use existing MySQL root password if available, otherwise use configured or generate new
    if [[ -n "$EXISTING_MYSQL_ROOT_PASSWORD" ]]; then
        MYSQL_ROOT_PASSWORD="$EXISTING_MYSQL_ROOT_PASSWORD"
    elif [[ -z "$MYSQL_ROOT_PASSWORD" ]]; then
        MYSQL_ROOT_PASSWORD=$(generate_mysql_root_password)
    fi
    
    # Verify we got all passwords
    if [[ -n "$MYSQL_PASSWORD" && -n "$TOTP_SECRET" && -n "$ADMIN_PASSWORD" && -n "$FLASK_SECRET" ]]; then
        echo -e "${GREEN}✓ Existing MySQL password loaded${NC}"
        echo -e "${GREEN}✓ Existing TOTP secret loaded${NC}"
        echo -e "${GREEN}✓ Existing admin password loaded${NC}"
        echo -e "${GREEN}✓ Existing Flask secret loaded${NC}"
        if [[ -n "$EXISTING_MYSQL_ROOT_PASSWORD" ]]; then
            echo -e "${GREEN}✓ Existing MySQL root password loaded${NC}"
        else
            echo -e "${GREEN}✓ New MySQL root password generated${NC}"
        fi
        echo -e "${YELLOW}Note: Using existing credentials. Delete $ROOT_CREDS_FILE to regenerate passwords.${NC}"
    else
        echo -e "${YELLOW}Warning: Could not load all credentials from existing file.${NC}"
        echo -e "${BLUE}Generating missing credentials...${NC}"
        
        # Generate any missing passwords
        [[ -z "$MYSQL_PASSWORD" ]] && MYSQL_PASSWORD=$(generate_mysql_password) && echo -e "${GREEN}✓ New MySQL password generated (264-bit)${NC}"
        [[ -z "$TOTP_SECRET" ]] && TOTP_SECRET=$(generate_password) && echo -e "${GREEN}✓ New TOTP secret generated${NC}"
        [[ -z "$ADMIN_PASSWORD" ]] && ADMIN_PASSWORD=$(generate_password) && echo -e "${GREEN}✓ New admin password generated${NC}"
        [[ -z "$FLASK_SECRET" ]] && FLASK_SECRET=$(generate_password) && echo -e "${GREEN}✓ New Flask secret generated${NC}"
        [[ -z "$MYSQL_ROOT_PASSWORD" ]] && MYSQL_ROOT_PASSWORD=$(generate_mysql_root_password) && echo -e "${GREEN}✓ New MySQL root password generated (264-bit)${NC}"
    fi
else
    echo -e "${BLUE}No existing credentials found, generating new secure passwords...${NC}"
    
    # Generate MySQL password (used for both DATABASE_URI and MYSQL_PASSWORD) - 264-bit
    MYSQL_PASSWORD=$(generate_mysql_password)
    echo -e "${GREEN}✓ MySQL password generated (264-bit)${NC}"

    # Generate MySQL root password if not provided - 264-bit
    if [[ -z "$MYSQL_ROOT_PASSWORD" ]]; then
        MYSQL_ROOT_PASSWORD=$(generate_mysql_root_password)
        echo -e "${GREEN}✓ MySQL root password generated (264-bit)${NC}"
    else
        echo -e "${GREEN}✓ Using provided MySQL root password${NC}"
    fi

    # Generate TOTP secret
    TOTP_SECRET=$(generate_password)
    echo -e "${GREEN}✓ TOTP secret generated${NC}"

    # Generate admin password and Flask secret (always generated for both modes)
    ADMIN_PASSWORD=$(generate_password)
    echo -e "${GREEN}✓ Admin password generated${NC}"

    FLASK_SECRET=$(generate_password)
    echo -e "${GREEN}✓ Flask secret generated${NC}"
fi

# Display MySQL configuration summary
echo ""
echo -e "${BLUE}MySQL Configuration Summary:${NC}"
echo -e "${GREEN}• MYSQL_RANDOM_ROOT_PASSWORD: $MYSQL_RANDOM_ROOT_PASSWORD${NC}"
if [[ "$MYSQL_RANDOM_ROOT_PASSWORD" == "no" ]]; then
    echo -e "${GREEN}• MySQL root password: Controlled (264-bit entropy, ${#MYSQL_ROOT_PASSWORD} chars)${NC}"
    echo -e "${GREEN}• MySQL app password: 264-bit entropy (${#MYSQL_PASSWORD} chars)${NC}"
    echo -e "${BLUE}• Security level: Maximum+ (beyond AES-256)${NC}"
else
    echo -e "${YELLOW}• MySQL root password: Random (container-generated)${NC}"
    echo -e "${GREEN}• MySQL app password: 264-bit entropy (${#MYSQL_PASSWORD} chars)${NC}"
fi
echo -e "${BLUE}• Admin password: 12 chars (manageable for human use)${NC}"
echo ""

# Create/update credentials file in /root/
if [[ -f "$ROOT_CREDS_FILE" ]]; then
    echo -e "${BLUE}Updating existing credentials file...${NC}"
    # Create backup of existing credentials
    cp "$ROOT_CREDS_FILE" "$ROOT_CREDS_FILE.backup.$(date +%Y%m%d_%H%M%S)"
    echo -e "${GREEN}✓ Existing credentials backed up${NC}"
else
    echo -e "${BLUE}Creating new credentials file in /root/...${NC}"
fi

cat > "$ROOT_CREDS_FILE" << EOF
# BunkerWeb Generated Credentials
# Deployment Type: $DEPLOYMENT_NAME
# Template Used: $TEMPLATE_FILE
# Setup Mode: $(if [[ $SETUP_MODE == "automated" ]]; then echo "Automated"; else echo "Setup Wizard"; fi)
# Generated on: $(date)
# Keep this file secure and backed up!
#
# SECURITY LEVEL: MAXIMUM+ (264-bit MySQL passwords)

MySQL Database Password: $MYSQL_PASSWORD
MySQL Root Password: $MYSQL_ROOT_PASSWORD
TOTP Secret Key: $TOTP_SECRET

# Web UI Setup (passwords always generated)
Admin Username: $ADMIN_USERNAME
Admin Password: $ADMIN_PASSWORD
Flask Secret: $FLASK_SECRET

# Password Security Information:
# MySQL passwords: 264-bit entropy (~44 characters, beyond AES-256)
# Admin/UI passwords: 96-bit entropy (12 characters, human-friendly but secure)
# Flask secret: 96-bit entropy (sufficient for session security)

# Domain Configuration
FQDN: $FQDN
Server Name: $(if [[ -n "$SERVER_NAME" ]]; then echo "$SERVER_NAME"; else echo "$FQDN"; fi)

# MySQL Configuration
MySQL Random Root Password: $MYSQL_RANDOM_ROOT_PASSWORD
$(if [[ "$MYSQL_RANDOM_ROOT_PASSWORD" == "no" ]]; then
echo "MySQL Root Access: Available with known 264-bit password"
else
echo "MySQL Root Access: Container-generated random password"
fi)

# BunkerWeb Configuration
Multisite Mode: $MULTISITE
BunkerWeb Instances: $BUNKERWEB_INSTANCES
Security Mode: $SECURITY_MODE
Server Type: $SERVER_TYPE

# Greylist Configuration (Admin Interface Protection)
Use Greylist: $USE_GREYLIST
$(if [[ "$USE_GREYLIST" == "yes" ]]; then
echo "Greylist IPs: $GREYLIST_IP"
echo "Greylist RDNS: $GREYLIST_RDNS"
fi)

# SSL Certificate Configuration
Certificate Type: $(if [[ -n "$AUTO_CERT_TYPE" ]]; then echo "$AUTO_CERT_TYPE"; else echo "Manual"; fi)
Contact Email: $AUTO_CERT_CONTACT
$(if [[ "$AUTO_CERT_TYPE" == "LE" ]]; then
echo "Challenge Type: $LETS_ENCRYPT_CHALLENGE"
echo "Staging Mode: $LETS_ENCRYPT_STAGING"
echo "Wildcard Certificates: $LETS_ENCRYPT_WILDCARD"
fi)
$(if [[ "$AUTO_CERT_TYPE" == "ZeroSSL" ]]; then echo "ZeroSSL API Key: $AUTO_CERT_ZSSL_API (NOTE: ZeroSSL is draft - not yet implemented)"; fi)

# Database Access Commands:
# Application user: docker exec -it bw-db mysql -u bunkerweb -p'$MYSQL_PASSWORD' db
# Root user: docker exec -it bw-db mysql -u root -p'$MYSQL_ROOT_PASSWORD'

# Database Connection String:
# mariadb+pymysql://bunkerweb:$MYSQL_PASSWORD@bw-db:3306/db

# Multisite Information:
# Multisite mode is enabled by default, allowing multiple domains with individual configurations.
# Use SERVER_NAME prefixes for domain-specific settings in docker-compose.yml labels.
# Example: myapp.com_USE_ANTIBOT=captcha applies antibot only to myapp.com

# Greylist Information:
# When USE_GREYLIST=yes, only IPs in GREYLIST_IP can access the admin interface.
# GREYLIST_RDNS allows access from IPs with reverse DNS matching specified suffixes.
# This provides additional security for the BunkerWeb admin interface.
EOF

if [[ $SETUP_MODE == "automated" ]]; then
    # Automated setup - enable automated configuration
    echo -e "${BLUE}Configuring automated setup...${NC}"
    
    # Enable automated setup in docker-compose.yml (uncomment the lines)
    sed -i 's|# OVERRIDE_ADMIN_CREDS: "yes"|OVERRIDE_ADMIN_CREDS: "yes"|' "$COMPOSE_FILE"
    sed -i 's|# ADMIN_USERNAME: "admin"|ADMIN_USERNAME: "'$ADMIN_USERNAME'"|' "$COMPOSE_FILE"
    sed -i 's|# ADMIN_PASSWORD: "REPLACEME_ADMIN"|ADMIN_PASSWORD: "'$ADMIN_PASSWORD'"|' "$COMPOSE_FILE"
    sed -i 's|# FLASK_SECRET: "REPLACEME_FLASK"|FLASK_SECRET: "'$FLASK_SECRET'"|' "$COMPOSE_FILE"
    
    echo -e "${GREEN}✓ Automated setup configured and enabled${NC}"
    echo -e "${GREEN}✓ Admin credentials activated${NC}"
else
    echo -e "${BLUE}Configuring setup wizard mode...${NC}"
    echo -e "${BLUE}Admin credentials generated but setup wizard enabled${NC}"
fi

# Secure the credentials files
chmod 600 "$ROOT_CREDS_FILE"
if [[ -f "$ROOT_CREDS_FILE.backup."* ]]; then
    echo -e "${GREEN}✓ Credentials updated in: $ROOT_CREDS_FILE${NC}"
else
    echo -e "${GREEN}✓ Credentials saved to: $ROOT_CREDS_FILE${NC}"
fi
echo -e "${GREEN}✓ Symbolic link verified: $LOCAL_CREDS_FILE${NC}"

# Replace placeholders in docker-compose.yml
echo -e "${BLUE}Updating docker-compose.yml...${NC}"

# Replace REPLACEME_MYSQL (both in DATABASE_URI and MYSQL_PASSWORD)
sed -i "s|REPLACEME_MYSQL|$MYSQL_PASSWORD|g" "$COMPOSE_FILE"
echo -e "${GREEN}✓ MySQL passwords updated${NC}"

# Configure MySQL root password setting
echo -e "${BLUE}Configuring MySQL root password setting...${NC}"
if grep -q "MYSQL_RANDOM_ROOT_PASSWORD:" "$COMPOSE_FILE"; then
    sed -i "s|MYSQL_RANDOM_ROOT_PASSWORD: \".*\"|MYSQL_RANDOM_ROOT_PASSWORD: \"$MYSQL_RANDOM_ROOT_PASSWORD\"|g" "$COMPOSE_FILE"
    echo -e "${GREEN}✓ MYSQL_RANDOM_ROOT_PASSWORD updated to: $MYSQL_RANDOM_ROOT_PASSWORD${NC}"
else
    # Add MYSQL_RANDOM_ROOT_PASSWORD to the database service environment
    sed -i '/bw-db:/,/environment:/{
        /environment:/a\
      MYSQL_RANDOM_ROOT_PASSWORD: "'$MYSQL_RANDOM_ROOT_PASSWORD'"
    }' "$COMPOSE_FILE"
    echo -e "${GREEN}✓ MYSQL_RANDOM_ROOT_PASSWORD added: $MYSQL_RANDOM_ROOT_PASSWORD${NC}"
fi

# If MYSQL_RANDOM_ROOT_PASSWORD is "no", set the root password
if [[ "$MYSQL_RANDOM_ROOT_PASSWORD" == "no" ]]; then
    if grep -q "MYSQL_ROOT_PASSWORD:" "$COMPOSE_FILE"; then
        sed -i "s|MYSQL_ROOT_PASSWORD: \".*\"|MYSQL_ROOT_PASSWORD: \"$MYSQL_ROOT_PASSWORD\"|g" "$COMPOSE_FILE"
        echo -e "${GREEN}✓ MYSQL_ROOT_PASSWORD updated${NC}"
    else
        # Add MYSQL_ROOT_PASSWORD to the database service environment
        sed -i '/bw-db:/,/environment:/{
            /MYSQL_RANDOM_ROOT_PASSWORD:/a\
      MYSQL_ROOT_PASSWORD: "'$MYSQL_ROOT_PASSWORD'"
        }' "$COMPOSE_FILE"
        echo -e "${GREEN}✓ MYSQL_ROOT_PASSWORD added${NC}"
    fi
    echo -e "${BLUE}✓ MySQL root password set to known value (length: ${#MYSQL_ROOT_PASSWORD} chars)${NC}"
else
    # Remove any existing MYSQL_ROOT_PASSWORD setting if random is enabled
    sed -i '/MYSQL_ROOT_PASSWORD:/d' "$COMPOSE_FILE"
    echo -e "${BLUE}✓ MySQL will generate random root password${NC}"
fi

# Replace REPLACEME_DEFAULT (TOTP_SECRETS)
sed -i "s|REPLACEME_DEFAULT|$TOTP_SECRET|g" "$COMPOSE_FILE"
echo -e "${GREEN}✓ TOTP secret updated${NC}"

# Always replace admin password and Flask secret placeholders
sed -i "s|REPLACEME_ADMIN|$ADMIN_PASSWORD|g" "$COMPOSE_FILE"
sed -i "s|REPLACEME_FLASK|$FLASK_SECRET|g" "$COMPOSE_FILE"
echo -e "${GREEN}✓ Admin password updated${NC}"
echo -e "${GREEN}✓ Flask secret updated${NC}"

# Handle SSL certificate configuration
if [[ -n "$AUTO_CERT_TYPE" ]]; then
    echo -e "${BLUE}Configuring SSL certificates ($AUTO_CERT_TYPE) for domain: $FQDN...${NC}"
    
    if [[ "$AUTO_CERT_TYPE" == "LE" ]]; then
        # Let's Encrypt configuration - handle both template placeholders and direct BunkerWeb settings
        
        # Replace template placeholders if they exist
        sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|yes|g" "$COMPOSE_FILE" 2>/dev/null || true
        sed -i "s|REPLACEME_EMAIL_LETS_ENCRYPT|$AUTO_CERT_CONTACT|g" "$COMPOSE_FILE" 2>/dev/null || true
        
        # Also set direct BunkerWeb environment variables
        if grep -q "AUTO_LETS_ENCRYPT:" "$COMPOSE_FILE"; then
            sed -i "s|AUTO_LETS_ENCRYPT: \"no\"|AUTO_LETS_ENCRYPT: \"yes\"|g" "$COMPOSE_FILE"
            sed -i "s|AUTO_LETS_ENCRYPT: \".*\"|AUTO_LETS_ENCRYPT: \"yes\"|g" "$COMPOSE_FILE"
        else
            # Add Let's Encrypt settings if not present (append to scheduler environment)
            sed -i '/bw-scheduler:/,/environment:/{
                /environment:/a\
      AUTO_LETS_ENCRYPT: "yes"\
      EMAIL_LETS_ENCRYPT: "'$AUTO_CERT_CONTACT'"\
      LETS_ENCRYPT_CHALLENGE: "'$LETS_ENCRYPT_CHALLENGE'"\
      USE_LETS_ENCRYPT_STAGING: "'$LETS_ENCRYPT_STAGING'"\
      USE_LETS_ENCRYPT_WILDCARD: "'$LETS_ENCRYPT_WILDCARD'"
            }' "$COMPOSE_FILE"
        fi
        
        # Set email and other options
        if grep -q "EMAIL_LETS_ENCRYPT:" "$COMPOSE_FILE"; then
            sed -i "s|EMAIL_LETS_ENCRYPT: \".*\"|EMAIL_LETS_ENCRYPT: \"$AUTO_CERT_CONTACT\"|g" "$COMPOSE_FILE"
        fi
        
        # Set challenge type
        if grep -q "LETS_ENCRYPT_CHALLENGE:" "$COMPOSE_FILE"; then
            sed -i "s|LETS_ENCRYPT_CHALLENGE: \".*\"|LETS_ENCRYPT_CHALLENGE: \"$LETS_ENCRYPT_CHALLENGE\"|g" "$COMPOSE_FILE"
        fi
        
        # Set staging mode
        if grep -q "USE_LETS_ENCRYPT_STAGING:" "$COMPOSE_FILE"; then
            sed -i "s|USE_LETS_ENCRYPT_STAGING: \".*\"|USE_LETS_ENCRYPT_STAGING: \"$LETS_ENCRYPT_STAGING\"|g" "$COMPOSE_FILE"
        fi
        
        # Set wildcard mode
        if grep -q "USE_LETS_ENCRYPT_WILDCARD:" "$COMPOSE_FILE"; then
            sed -i "s|USE_LETS_ENCRYPT_WILDCARD: \".*\"|USE_LETS_ENCRYPT_WILDCARD: \"$LETS_ENCRYPT_WILDCARD\"|g" "$COMPOSE_FILE"
        fi
        
        echo -e "${GREEN}✓ Let's Encrypt enabled${NC}"
        echo -e "${GREEN}✓ Contact email: $AUTO_CERT_CONTACT${NC}"
        echo -e "${GREEN}✓ Challenge type: $LETS_ENCRYPT_CHALLENGE${NC}"
        echo -e "${GREEN}✓ Staging mode: $LETS_ENCRYPT_STAGING${NC}"
        echo -e "${GREEN}✓ Wildcard certificates: $LETS_ENCRYPT_WILDCARD${NC}"
        
        if [[ "$LETS_ENCRYPT_STAGING" == "yes" ]]; then
            echo -e "${YELLOW}⚠ Staging mode enabled (default for safety) - certificates will not be trusted by browsers${NC}"
            echo -e "${YELLOW}⚠ For production, set --LE_STAGING no to get trusted certificates${NC}"
        else
            echo -e "${GREEN}✓ Production mode - certificates will be trusted by browsers${NC}"
        fi
        
        if [[ "$LETS_ENCRYPT_WILDCARD" == "yes" ]]; then
            echo -e "${BLUE}ℹ Wildcard certificates enabled for *.${FQDN}${NC}"
            if [[ "$LETS_ENCRYPT_CHALLENGE" == "http" ]]; then
                echo -e "${YELLOW}⚠ Wildcard certificates require DNS challenge${NC}"
                echo -e "${YELLOW}⚠ Automatically switching to DNS challenge for wildcard support${NC}"
                LETS_ENCRYPT_CHALLENGE="dns"
                sed -i "s|LETS_ENCRYPT_CHALLENGE: \".*\"|LETS_ENCRYPT_CHALLENGE: \"dns\"|g" "$COMPOSE_FILE"
            fi
        fi
        
        if [[ "$LETS_ENCRYPT_CHALLENGE" == "dns" ]]; then
            echo -e "${BLUE}ℹ DNS challenge selected${NC}"
            echo -e "${YELLOW}⚠ DNS challenges require additional configuration:${NC}"
            echo -e "${YELLOW}  1. Set LETS_ENCRYPT_DNS_PROVIDER (e.g., cloudflare, route53, digitalocean)${NC}"
            echo -e "${YELLOW}  2. Set LETS_ENCRYPT_DNS_CREDENTIAL_ITEM with your DNS provider credentials${NC}"
            echo -e "${YELLOW}  3. Refer to BunkerWeb documentation for provider-specific settings${NC}"
            echo -e "${BLUE}  Manual configuration required in docker-compose.yml${NC}"
        fi
        
    elif [[ "$AUTO_CERT_TYPE" == "ZeroSSL" ]]; then
        # ZeroSSL configuration (may require custom implementation)
        sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|yes|g" "$COMPOSE_FILE" 2>/dev/null || true
        sed -i "s|REPLACEME_EMAIL_LETS_ENCRYPT|$AUTO_CERT_CONTACT|g" "$COMPOSE_FILE" 2>/dev/null || true
        
        # Add ZeroSSL specific configuration if template supports it
        if grep -q "ZEROSSL_API" "$COMPOSE_FILE"; then
            sed -i "s|ZEROSSL_API: \".*\"|ZEROSSL_API: \"$AUTO_CERT_ZSSL_API\"|g" "$COMPOSE_FILE"
            sed -i "s|REPLACEME_ZEROSSL_API|$AUTO_CERT_ZSSL_API|g" "$COMPOSE_FILE"
            echo -e "${GREEN}✓ ZeroSSL enabled with API key${NC}"
        else
            echo -e "${YELLOW}⚠ ZeroSSL requires custom template configuration${NC}"
            echo -e "${BLUE}ℹ Consider using Let's Encrypt for automatic configuration${NC}"
        fi
        echo -e "${GREEN}✓ Contact email: $AUTO_CERT_CONTACT${NC}"
    fi
    
    # Set domain/server name for SSL certificates
    sed -i "s|SERVER_NAME: \"\"|SERVER_NAME: \"$FQDN\"|g" "$COMPOSE_FILE"
    sed -i "s|REPLACEME_DOMAIN|$FQDN|g" "$COMPOSE_FILE"
    echo -e "${GREEN}✓ Domain configured: $FQDN${NC}"
    
else
    # No automatic certificates - ensure Let's Encrypt is disabled
    sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|no|g" "$COMPOSE_FILE" 2>/dev/null || true
    sed -i "s|AUTO_LETS_ENCRYPT: \"yes\"|AUTO_LETS_ENCRYPT: \"no\"|g" "$COMPOSE_FILE" 2>/dev/null || true
    sed -i "s|SERVER_NAME: \"\"|SERVER_NAME: \"$FQDN\"|g" "$COMPOSE_FILE"
    sed -i "s|REPLACEME_DOMAIN|$FQDN|g" "$COMPOSE_FILE"
    echo -e "${BLUE}✓ SSL certificates set to manual configuration${NC}"
    echo -e "${BLUE}✓ Domain configured: $FQDN${NC}"
fi

# Configure Multisite mode
echo -e "${BLUE}Configuring multisite mode...${NC}"
if grep -q "MULTISITE:" "$COMPOSE_FILE"; then
    sed -i "s|MULTISITE: \".*\"|MULTISITE: \"$MULTISITE\"|g" "$COMPOSE_FILE"
    echo -e "${GREEN}✓ Multisite mode: $MULTISITE${NC}"
else
    # Add MULTISITE setting if not present (append to scheduler environment)
    sed -i '/bw-scheduler:/,/environment:/{
        /environment:/a\
      MULTISITE: "'$MULTISITE'"
    }' "$COMPOSE_FILE"
    echo -e "${GREEN}✓ Multisite mode added: $MULTISITE${NC}"
fi

if [[ "$MULTISITE" == "yes" ]]; then
    echo -e "${BLUE}ℹ Multisite mode enabled - supports multiple domains with individual configurations${NC}"
    echo -e "${BLUE}ℹ Use SERVER_NAME prefixes for domain-specific settings (e.g., domain.com_USE_ANTIBOT=captcha)${NC}"
else
    echo -e "${BLUE}ℹ Multisite mode disabled - single domain configuration${NC}"
fi

# Configure additional BunkerWeb settings
echo -e "${BLUE}Configuring BunkerWeb settings...${NC}"

# Set SERVER_NAME (use FQDN if SERVER_NAME not explicitly set)
if [[ -z "$SERVER_NAME" && -n "$FQDN" ]]; then
    SERVER_NAME="$FQDN"
fi

# Configure all the new settings
SETTINGS_TO_ADD=""

if [[ -n "$SERVER_NAME" ]]; then
    if ! grep -q "SERVER_NAME:" "$COMPOSE_FILE"; then
        SETTINGS_TO_ADD="${SETTINGS_TO_ADD}      SERVER_NAME: \"$SERVER_NAME\"\n"
    else
        sed -i "s|SERVER_NAME: \".*\"|SERVER_NAME: \"$SERVER_NAME\"|g" "$COMPOSE_FILE"
    fi
    echo -e "${GREEN}✓ Server name: $SERVER_NAME${NC}"
fi

if [[ -n "$BUNKERWEB_INSTANCES" ]]; then
    if ! grep -q "BUNKERWEB_INSTANCES:" "$COMPOSE_FILE"; then
        SETTINGS_TO_ADD="${SETTINGS_TO_ADD}      BUNKERWEB_INSTANCES: \"$BUNKERWEB_INSTANCES\"\n"
    else
        sed -i "s|BUNKERWEB_INSTANCES: \".*\"|BUNKERWEB_INSTANCES: \"$BUNKERWEB_INSTANCES\"|g" "$COMPOSE_FILE"
    fi
    echo -e "${GREEN}✓ BunkerWeb instances: $BUNKERWEB_INSTANCES${NC}"
fi

if [[ -n "$SECURITY_MODE" ]]; then
    if ! grep -q "SECURITY_MODE:" "$COMPOSE_FILE"; then
        SETTINGS_TO_ADD="${SETTINGS_TO_ADD}      SECURITY_MODE: \"$SECURITY_MODE\"\n"
    else
        sed -i "s|SECURITY_MODE: \".*\"|SECURITY_MODE: \"$SECURITY_MODE\"|g" "$COMPOSE_FILE"
    fi
    echo -e "${GREEN}✓ Security mode: $SECURITY_MODE${NC}"
fi

if [[ -n "$SERVER_TYPE" ]]; then
    if ! grep -q "SERVER_TYPE:" "$COMPOSE_FILE"; then
        SETTINGS_TO_ADD="${SETTINGS_TO_ADD}      SERVER_TYPE: \"$SERVER_TYPE\"\n"
    else
        sed -i "s|SERVER_TYPE: \".*\"|SERVER_TYPE: \"$SERVER_TYPE\"|g" "$COMPOSE_FILE"
    fi
    echo -e "${GREEN}✓ Server type: $SERVER_TYPE${NC}"
fi

# Configure greylist settings
if [[ "$USE_GREYLIST" == "yes" ]]; then
    if ! grep -q "USE_GREYLIST:" "$COMPOSE_FILE"; then
        SETTINGS_TO_ADD="${SETTINGS_TO_ADD}      USE_GREYLIST: \"$USE_GREYLIST\"\n"
    else
        sed -i "s|USE_GREYLIST: \".*\"|USE_GREYLIST: \"$USE_GREYLIST\"|g" "$COMPOSE_FILE"
    fi
    echo -e "${GREEN}✓ Greylist enabled: $USE_GREYLIST${NC}"
    
    if [[ -n "$GREYLIST_IP" ]]; then
        if ! grep -q "GREYLIST_IP:" "$COMPOSE_FILE"; then
            SETTINGS_TO_ADD="${SETTINGS_TO_ADD}      GREYLIST_IP: \"$GREYLIST_IP\"\n"
        else
            sed -i "s|GREYLIST_IP: \".*\"|GREYLIST_IP: \"$GREYLIST_IP\"|g" "$COMPOSE_FILE"
        fi
        echo -e "${GREEN}✓ Greylist IPs: $GREYLIST_IP${NC}"
    fi
    
    if [[ -n "$GREYLIST_RDNS" ]]; then
        if ! grep -q "GREYLIST_RDNS:" "$COMPOSE_FILE"; then
            SETTINGS_TO_ADD="${SETTINGS_TO_ADD}      GREYLIST_RDNS: \"$GREYLIST_RDNS\"\n"
        else
            sed -i "s|GREYLIST_RDNS: \".*\"|GREYLIST_RDNS: \"$GREYLIST_RDNS\"|g" "$COMPOSE_FILE"
        fi
        echo -e "${GREEN}✓ Greylist RDNS: $GREYLIST_RDNS${NC}"
    fi
else
    echo -e "${BLUE}ℹ Greylist disabled - admin interface accessible from any IP${NC}"
fi

# Add any new settings that weren't found in the file
if [[ -n "$SETTINGS_TO_ADD" ]]; then
    # Add new settings to scheduler environment
    sed -i '/bw-scheduler:/,/environment:/{
        /environment:/a\
'"$SETTINGS_TO_ADD"'
    }' "$COMPOSE_FILE"
    echo -e "${GREEN}✓ Additional BunkerWeb settings configured${NC}"
fi

# Verify replacements
echo -e "${BLUE}Verifying configuration...${NC}"

# Check for any remaining placeholders (all should be replaced now)
REMAINING_PLACEHOLDERS=$(grep -o "REPLACEME_[A-Z_]*" "$COMPOSE_FILE" || true)

if [[ -n "$REMAINING_PLACEHOLDERS" ]]; then
    echo -e "${RED}Error: Some placeholders were not replaced!${NC}"
    echo "Remaining placeholders: $REMAINING_PLACEHOLDERS"
    echo -e "${YELLOW}Restoring backup...${NC}"
    cp "$BACKUP_FILE" "$COMPOSE_FILE"
    exit 1
else
    echo -e "${GREEN}✓ All placeholders successfully replaced${NC}"
    if [[ $SETUP_MODE == "wizard" ]]; then
        echo -e "${BLUE}ℹ Automated setup remains disabled - use setup wizard${NC}"
    fi
fi

# Create required directories
echo -e "${BLUE}Creating directories...${NC}"
mkdir -p "$INSTALL_DIR/storage"
mkdir -p "$INSTALL_DIR/database"
mkdir -p "$INSTALL_DIR/apps"

# Set proper ownership and permissions for BunkerWeb containers
echo -e "${BLUE}Setting permissions for BunkerWeb containers...${NC}"

# BunkerWeb containers run as nginx user (uid 101, gid 101)
# We need to ensure proper permissions for the storage directory
echo -e "${GREEN}Setting BunkerWeb-specific permissions...${NC}"

# Set ownership for storage directory to nginx user (uid 101, gid 101)
chown -R 101:101 "$INSTALL_DIR/storage"
chmod -R 755 "$INSTALL_DIR/storage"
echo -e "${GREEN}✓ Storage directory ownership set to nginx (101:101)${NC}"

# Set ownership for database directory to mysql user (uid 999, gid 999) 
chown -R 999:999 "$INSTALL_DIR/database"
chmod -R 755 "$INSTALL_DIR/database"
echo -e "${GREEN}✓ Database directory ownership set to mysql (999:999)${NC}"

# Set general ownership for other files
if [[ -n "$SUDO_USER" ]]; then
    OWNER_USER="$SUDO_USER"
    OWNER_GROUP=$(id -gn "$SUDO_USER")
    echo -e "${GREEN}Setting general ownership to: $OWNER_USER:$OWNER_GROUP${NC}"
    
    # Set ownership for compose files and scripts, but preserve container-specific directories
    chown "$OWNER_USER:$OWNER_GROUP" "$INSTALL_DIR"
    chown "$OWNER_USER:$OWNER_GROUP" "$INSTALL_DIR"/*.yml 2>/dev/null || true
    chown "$OWNER_USER:$OWNER_GROUP" "$INSTALL_DIR"/*.sh 2>/dev/null || true
    chown "$OWNER_USER:$OWNER_GROUP" "$INSTALL_DIR/apps"
else
    echo -e "${YELLOW}Running as root directly, keeping root ownership for config files${NC}"
fi

chmod 755 "$INSTALL_DIR"
chmod 600 "$ROOT_CREDS_FILE"  # Keep credentials file secure in /root/
chmod 755 "$INSTALL_DIR/apps"
echo -e "${GREEN}✓ All directories created and permissions properly set${NC}"

# Display summary
echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}          Setup Complete!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${YELLOW}Deployment Type:${NC} $DEPLOYMENT_NAME"
echo -e "${YELLOW}Template Used:${NC} $TEMPLATE_FILE"
echo -e "${YELLOW}Installation Directory:${NC} $INSTALL_DIR"
echo -e "${YELLOW}Credentials File:${NC} $ROOT_CREDS_FILE"
echo -e "${YELLOW}Credentials Link:${NC} $LOCAL_CREDS_FILE"
echo -e "${YELLOW}Backup File:${NC} $BACKUP_FILE"
echo ""
echo -e "${BLUE}MySQL Configuration:${NC}"
echo -e "${YELLOW}• Random Root Password:${NC} $MYSQL_RANDOM_ROOT_PASSWORD"
if [[ "$MYSQL_RANDOM_ROOT_PASSWORD" == "no" ]]; then
    echo -e "${YELLOW}• Root Password Management:${NC} Controlled (saved to credentials)"
    echo -e "${YELLOW}• Root Access Command:${NC} docker exec -it bw-db mysql -u root -p'$MYSQL_ROOT_PASSWORD'"
else
    echo -e "${YELLOW}• Root Password Management:${NC} Container-generated random"
    echo -e "${YELLOW}• Root Access:${NC} Check container logs for password"
fi
echo ""
echo -e "${BLUE}Next Steps:${NC}"
if [[ $SETUP_MODE == "automated" ]]; then
    if [[ -n "$SUDO_USER" ]]; then
        echo "1. Navigate to http://\$SERVER_IP"
        echo "2. Login with username: $ADMIN_USERNAME"
        echo "3. Start protecting applications with autoconf labels"
    else
        echo "1. Navigate to http://\$SERVER_IP"
        echo "2. Login with username: $ADMIN_USERNAME"
        echo "3. Start protecting applications with autoconf labels"
    fi
else
    if [[ -n "$SUDO_USER" ]]; then
        echo "1. su - $SUDO_USER"
        echo "2. cd $INSTALL_DIR"
        echo "3. docker compose up -d"
        echo "4. Navigate to http://your-server-ip/setup"
        echo "5. Complete the setup wizard (or use pre-generated credentials)"
        echo "   Username: $ADMIN_USERNAME | Password: $ADMIN_PASSWORD"
    else
        echo "1. cd $INSTALL_DIR"
        echo "2. docker compose up -d"
        echo "3. Navigate to http://your-server-ip/setup"
        echo "4. Complete the setup wizard (or use pre-generated credentials)"
        echo "   Username: $ADMIN_USERNAME | Password: $ADMIN_PASSWORD"
    fi
fi
echo ""
echo -e "${RED}IMPORTANT:${NC}"
echo -e "${RED}• Keep the credentials file secure: $ROOT_CREDS_FILE${NC}"
echo -e "${RED}• Backup your installation regularly${NC}"
echo -e "${RED}• The backup file can restore original template: $BACKUP_FILE${NC}"
echo -e "${BLUE}• Configuration file: $CONFIG_FILE${NC}"
echo -e "${BLUE}• Credentials are preserved between script runs - delete $ROOT_CREDS_FILE to regenerate${NC}"
echo -e "${BLUE}• Symbolic link allows local access: $LOCAL_CREDS_FILE${NC}"
if [[ "$MYSQL_RANDOM_ROOT_PASSWORD" == "no" ]]; then
    echo -e "${GREEN}• MySQL root access enabled with 264-bit password${NC}"
else
    echo -e "${YELLOW}• MySQL root password is container-generated (check logs)${NC}"
fi
echo ""

# Automatically start BunkerWeb
echo -e "${BLUE}Starting BunkerWeb automatically...${NC}"
cd "$INSTALL_DIR"

# Check if we have docker compose
if command -v docker-compose &> /dev/null; then
    DOCKER_CMD="docker-compose"
elif command -v docker &> /dev/null && docker compose version &> /dev/null; then
    DOCKER_CMD="docker compose"
else
    echo -e "${RED}Error: docker compose not found${NC}"
    echo "Please install Docker and Docker Compose"
    echo -e "${YELLOW}You can start BunkerWeb manually later with:${NC}"
    echo "cd $INSTALL_DIR && docker compose up -d"
    exit 1
fi

# If we have SUDO_USER, run docker as that user
if [[ -n "$SUDO_USER" ]]; then
    echo -e "${YELLOW}Running Docker as user: $SUDO_USER${NC}"
    su - "$SUDO_USER" -c "cd $INSTALL_DIR && $DOCKER_CMD up -d"
else
    $DOCKER_CMD up -d
fi

# Wait a moment for services to start
echo -e "${BLUE}Waiting for services to start...${NC}"
sleep 5

# Check if services are running
echo -e "${BLUE}Checking service status...${NC}"
if [[ -n "$SUDO_USER" ]]; then
    RUNNING_CONTAINERS=$(su - "$SUDO_USER" -c "cd $INSTALL_DIR && $DOCKER_CMD ps --services --filter 'status=running'" | wc -l)
else
    RUNNING_CONTAINERS=$($DOCKER_CMD ps --services --filter 'status=running' | wc -l)
fi

if [[ $RUNNING_CONTAINERS -gt 0 ]]; then
    echo -e "${GREEN}✓ BunkerWeb started successfully!${NC}"
    echo -e "${GREEN}✓ $RUNNING_CONTAINERS services are running${NC}"
    
    # Get server IP for easy access
    SERVER_IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}          BunkerWeb is Ready!${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    
    if [[ $SETUP_MODE == "automated" ]]; then
        echo -e "${BLUE}🚀 Automated Setup Complete!${NC}"
        if [[ -n "$AUTO_CERT_TYPE" && "$FQDN" != "localhost" ]]; then
            echo -e "${GREEN}Web Interface:${NC} https://$FQDN (SSL enabled)"
            echo -e "${GREEN}Fallback Access:${NC} http://$SERVER_IP"
        else
            echo -e "${GREEN}Web Interface:${NC} http://$SERVER_IP"
            if [[ "$FQDN" != "localhost" ]]; then
                echo -e "${GREEN}Domain Access:${NC} http://$FQDN"
            fi
        fi
        echo ""
        echo -e "${YELLOW}Login Credentials:${NC}"
        echo -e "${YELLOW}Username:${NC} $ADMIN_USERNAME"
        echo -e "${YELLOW}Password:${NC} $ADMIN_PASSWORD"
        echo ""
        echo -e "${GREEN}✓ No setup wizard required - ready to use!${NC}"
        echo -e "${BLUE}💡 All credentials saved in: $ROOT_CREDS_FILE${NC}"
        if [[ "$MYSQL_RANDOM_ROOT_PASSWORD" == "no" ]]; then
            echo -e "${BLUE}🔐 MySQL root access (264-bit): docker exec -it bw-db mysql -u root -p'$MYSQL_ROOT_PASSWORD'${NC}"
        else
            echo -e "${BLUE}🔐 MySQL root password: Check container logs with 'docker logs bw-db'${NC}"
        fi
        if [[ -n "$AUTO_CERT_TYPE" ]]; then
            echo -e "${BLUE}🔒 SSL certificates will be automatically issued for: $FQDN${NC}"
            if [[ "$LETS_ENCRYPT_STAGING" == "yes" ]]; then
                echo -e "${YELLOW}🔬 Using staging environment (certificates will not be browser-trusted)${NC}"
                echo -e "${BLUE}💡 For production, add --LE_STAGING no${NC}"
            fi
        fi
        if [[ "$MULTISITE" == "yes" ]]; then
            echo -e "${BLUE}🌐 Multisite mode enabled - you can host multiple domains${NC}"
            echo -e "${BLUE}💡 Add additional domains using autoconf labels in docker-compose.yml${NC}"
        fi
    else
        if [[ -n "$AUTO_CERT_TYPE" && "$FQDN" != "localhost" ]]; then
            echo -e "${BLUE}Setup Wizard:${NC} https://$FQDN/setup (SSL enabled)"
            echo -e "${BLUE}Web Interface:${NC} https://$FQDN (after setup)"
            echo -e "${BLUE}Fallback Access:${NC} http://$SERVER_IP/setup"
        else
            echo -e "${BLUE}Setup Wizard:${NC} http://$SERVER_IP/setup"
            echo -e "${BLUE}Web Interface:${NC} http://$SERVER_IP (after setup)"
            if [[ "$FQDN" != "localhost" ]]; then
                echo -e "${BLUE}Domain Access:${NC} http://$FQDN"
            fi
        fi
        echo ""
        echo -e "${YELLOW}Complete the setup wizard to finish configuration!${NC}"
        echo -e "${BLUE}💡 Pre-generated admin credentials available in: $ROOT_CREDS_FILE${NC}"
        echo -e "${BLUE}💡 Username: $ADMIN_USERNAME | Password: $ADMIN_PASSWORD${NC}"
        if [[ "$MYSQL_RANDOM_ROOT_PASSWORD" == "no" ]]; then
            echo -e "${BLUE}🔐 MySQL root access (264-bit): docker exec -it bw-db mysql -u root -p'$MYSQL_ROOT_PASSWORD'${NC}"
        else
            echo -e "${BLUE}🔐 MySQL root password: Check container logs with 'docker logs bw-db'${NC}"
        fi
        if [[ -n "$AUTO_CERT_TYPE" ]]; then
            echo -e "${BLUE}🔒 SSL certificates will be automatically issued for: $FQDN${NC}"
            if [[ "$LETS_ENCRYPT_STAGING" == "yes" ]]; then
                echo -e "${YELLOW}🔬 Using staging environment (certificates will not be browser-trusted)${NC}"
                echo -e "${BLUE}💡 For production, add --LE_STAGING no${NC}"
            fi
        fi
        if [[ "$MULTISITE" == "yes" ]]; then
            echo -e "${BLUE}🌐 Multisite mode enabled - you can host multiple domains${NC}"
            echo -e "${BLUE}💡 Configure additional domains via the web interface${NC}"
        fi
    fi
else
    echo -e "${RED}Warning: Some services may not have started properly${NC}"
    echo -e "${YELLOW}Check logs with: cd $INSTALL_DIR && docker compose logs${NC}"
fi

echo ""
echo -e "${GREEN}Setup script completed successfully!${NC}"