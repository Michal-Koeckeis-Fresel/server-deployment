#!/bin/bash
#
# BunkerWeb Password Manager Script
# Handles all password generation, loading, and credential management
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables for passwords
MYSQL_PASSWORD=""
REDIS_PASSWORD=""
TOTP_SECRET=""
ADMIN_PASSWORD=""
FLASK_SECRET=""
ADMIN_USERNAME="admin"

# Password generation functions
generate_admin_password() {
    openssl rand -base64 33 | head -c 12 && echo
}

generate_secure_password() {
    openssl rand -base64 33
}

# Function to load existing credentials from file
load_existing_credentials() {
    local creds_file="$1"
    
    if [[ ! -f "$creds_file" ]]; then
        echo -e "${YELLOW}No existing credentials file found${NC}" >&2
        return 1
    fi
    
    echo -e "${BLUE}Loading existing credentials from: $creds_file${NC}" >&2
    
    MYSQL_PASSWORD=$(grep "MySQL Database Password:" "$creds_file" | cut -d' ' -f4 2>/dev/null || echo "")
    REDIS_PASSWORD=$(grep "Redis Password:" "$creds_file" | cut -d' ' -f3 2>/dev/null || echo "")
    TOTP_SECRET=$(grep "TOTP Secret Key:" "$creds_file" | cut -d' ' -f4 2>/dev/null || echo "")
    ADMIN_PASSWORD=$(grep "Admin Password:" "$creds_file" | cut -d' ' -f3 2>/dev/null || echo "")
    FLASK_SECRET=$(grep "Flask Secret:" "$creds_file" | cut -d' ' -f3 2>/dev/null || echo "")
    ADMIN_USERNAME=$(grep "Admin Username:" "$creds_file" | cut -d' ' -f3 2>/dev/null || echo "admin")
    
    local loaded_count=0
    [[ -n "$MYSQL_PASSWORD" ]] && ((loaded_count++))
    [[ -n "$REDIS_PASSWORD" ]] && ((loaded_count++))
    [[ -n "$TOTP_SECRET" ]] && ((loaded_count++))
    [[ -n "$ADMIN_PASSWORD" ]] && ((loaded_count++))
    [[ -n "$FLASK_SECRET" ]] && ((loaded_count++))
    
    if [[ $loaded_count -ge 4 ]]; then
        echo -e "${GREEN}✓ Successfully loaded $loaded_count existing credentials${NC}" >&2
        return 0
    else
        echo -e "${YELLOW}⚠ Only loaded $loaded_count credentials, some may be missing${NC}" >&2
        return 1
    fi
}

# Function to generate missing credentials
generate_missing_credentials() {
    local redis_enabled="$1"
    local generated_count=0
    
    echo -e "${BLUE}Generating missing credentials...${NC}" >&2
    
    if [[ -z "$MYSQL_PASSWORD" ]]; then
        MYSQL_PASSWORD=$(generate_secure_password)
        echo -e "${GREEN}✓ Generated MySQL password${NC}" >&2
        ((generated_count++))
    fi
    
    if [[ "$redis_enabled" == "yes" && -z "$REDIS_PASSWORD" ]]; then
        REDIS_PASSWORD=$(generate_secure_password)
        echo -e "${GREEN}✓ Generated Redis password${NC}" >&2
        ((generated_count++))
    fi
    
    if [[ -z "$TOTP_SECRET" ]]; then
        TOTP_SECRET=$(generate_secure_password)
        echo -e "${GREEN}✓ Generated TOTP secret${NC}" >&2
        ((generated_count++))
    fi
    
    if [[ -z "$ADMIN_PASSWORD" ]]; then
        ADMIN_PASSWORD=$(generate_admin_password)
        echo -e "${GREEN}✓ Generated admin password (12 chars - human friendly)${NC}" >&2
        ((generated_count++))
    fi
    
    if [[ -z "$FLASK_SECRET" ]]; then
        FLASK_SECRET=$(generate_secure_password)
        echo -e "${GREEN}✓ Generated Flask secret${NC}" >&2
        ((generated_count++))
    fi
    
    if [[ -z "$ADMIN_USERNAME" ]]; then
        ADMIN_USERNAME="admin"
    fi
    
    if [[ $generated_count -gt 0 ]]; then
        echo -e "${GREEN}✓ Generated $generated_count new credentials${NC}" >&2
    else
        echo -e "${BLUE}ℹ All credentials were already available${NC}" >&2
    fi
    
    return 0
}

# Function to save credentials to file
save_credentials() {
    local creds_file="$1"
    local deployment_name="$2"
    local template_file="$3"
    local setup_mode="$4"
    local fqdn="$5"
    local server_name="$6"
    local docker_subnet="$7"
    local redis_enabled="$8"
    local networks_avoided="$9"
    
    echo -e "${BLUE}Saving credentials to: $creds_file${NC}" >&2
    
    # Create backup if file exists
    if [[ -f "$creds_file" ]]; then
        cp "$creds_file" "$creds_file.backup.$(date +%Y%m%d_%H%M%S)"
        echo -e "${GREEN}✓ Existing credentials backed up${NC}" >&2
    fi
    
    cat > "$creds_file" << EOF
# BunkerWeb Generated Credentials
# Deployment Type: ${deployment_name:-"Unknown"}
# Template Used: ${template_file:-"Unknown"}
# Setup Mode: ${setup_mode:-"Unknown"}
# Generated on: $(date)
# Keep this file secure and backed up!

MySQL Database Password: $MYSQL_PASSWORD
TOTP Secret Key: $TOTP_SECRET
$(if [[ "$redis_enabled" == "yes" ]]; then echo "Redis Password: $REDIS_PASSWORD"; fi)

# Web UI Setup
Admin Username: $ADMIN_USERNAME
Admin Password: $ADMIN_PASSWORD
Flask Secret: $FLASK_SECRET

# Domain Configuration
FQDN: ${fqdn:-"localhost"}
Server Name: ${server_name:-"$fqdn"}

# Network Configuration
$(if [[ -n "$docker_subnet" ]]; then echo "Docker Subnet: $docker_subnet"; fi)
$(if [[ -n "$networks_avoided" ]]; then echo "Private Networks Avoided: $networks_avoided"; fi)

# Connection Strings
# Database: mariadb+pymysql://bunkerweb:$MYSQL_PASSWORD@bw-db:3306/db
$(if [[ "$redis_enabled" == "yes" ]]; then
echo "# Redis: redis://:$REDIS_PASSWORD@bw-redis:6379/0"
echo "# Redis CLI: docker exec -it bw-redis redis-cli -a '$REDIS_PASSWORD'"
fi)

# Security Information:
# MySQL passwords: 264-bit entropy (~44 characters)
# Admin password: 96-bit entropy (12 characters, human-friendly)
# All other secrets: 264-bit entropy for maximum security
EOF
    
    chmod 600 "$creds_file"
    
    if [[ -f "$creds_file" ]]; then
        echo -e "${GREEN}✓ Credentials successfully saved to: $creds_file${NC}" >&2
        return 0
    else
        echo -e "${RED}✗ Failed to save credentials to: $creds_file${NC}" >&2
        return 1
    fi
}

# Function to get all current password values (for external scripts)
get_passwords() {
    cat << EOF
MYSQL_PASSWORD="$MYSQL_PASSWORD"
REDIS_PASSWORD="$REDIS_PASSWORD"
TOTP_SECRET="$TOTP_SECRET"
ADMIN_PASSWORD="$ADMIN_PASSWORD"
FLASK_SECRET="$FLASK_SECRET"
ADMIN_USERNAME="$ADMIN_USERNAME"
EOF
}

# Function to validate that all required passwords are set
validate_credentials() {
    local redis_enabled="$1"
    local missing=()
    
    [[ -z "$MYSQL_PASSWORD" ]] && missing+=("MySQL password")
    [[ -z "$TOTP_SECRET" ]] && missing+=("TOTP secret")
    [[ -z "$ADMIN_PASSWORD" ]] && missing+=("Admin password")
    [[ -z "$FLASK_SECRET" ]] && missing+=("Flask secret")
    [[ -z "$ADMIN_USERNAME" ]] && missing+=("Admin username")
    
    if [[ "$redis_enabled" == "yes" && -z "$REDIS_PASSWORD" ]]; then
        missing+=("Redis password")
    fi
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}✗ Missing credentials: ${missing[*]}${NC}" >&2
        return 1
    else
        echo -e "${GREEN}✓ All required credentials are available${NC}" >&2
        return 0
    fi
}

# Function to display credential summary
show_credential_summary() {
    local redis_enabled="$1"
    
    echo -e "${BLUE}Credential Summary:${NC}" >&2
    echo -e "${GREEN}• Admin Username: $ADMIN_USERNAME${NC}" >&2
    echo -e "${GREEN}• Admin Password: ${ADMIN_PASSWORD:0:4}... (${#ADMIN_PASSWORD} chars)${NC}" >&2
    echo -e "${GREEN}• MySQL Password: ${MYSQL_PASSWORD:0:8}... (${#MYSQL_PASSWORD} chars)${NC}" >&2
    echo -e "${GREEN}• TOTP Secret: ${TOTP_SECRET:0:8}... (${#TOTP_SECRET} chars)${NC}" >&2
    echo -e "${GREEN}• Flask Secret: ${FLASK_SECRET:0:8}... (${#FLASK_SECRET} chars)${NC}" >&2
    
    if [[ "$redis_enabled" == "yes" ]]; then
        echo -e "${GREEN}• Redis Password: ${REDIS_PASSWORD:0:8}... (${#REDIS_PASSWORD} chars)${NC}" >&2
    fi
}

# Main function for complete credential management
manage_credentials() {
    local creds_file="$1"
    local redis_enabled="${2:-yes}"
    local deployment_name="$3"
    local template_file="$4"
    local setup_mode="$5"
    local fqdn="$6"
    local server_name="$7"
    local docker_subnet="$8"
    local networks_avoided="$9"
    
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo -e "${BLUE}                        CREDENTIAL MANAGEMENT                        ${NC}" >&2
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo "" >&2
    
    # Try to load existing credentials
    if load_existing_credentials "$creds_file"; then
        echo -e "${GREEN}✓ Existing credentials loaded successfully${NC}" >&2
    else
        echo -e "${BLUE}ℹ No existing credentials found or incomplete${NC}" >&2
    fi
    
    # Generate any missing credentials
    generate_missing_credentials "$redis_enabled"
    
    # Validate all credentials are present
    if ! validate_credentials "$redis_enabled"; then
        echo -e "${RED}✗ Credential validation failed${NC}" >&2
        return 1
    fi
    
    # Save credentials to file
    if ! save_credentials "$creds_file" "$deployment_name" "$template_file" "$setup_mode" "$fqdn" "$server_name" "$docker_subnet" "$redis_enabled" "$networks_avoided"; then
        echo -e "${RED}✗ Failed to save credentials${NC}" >&2
        return 1
    fi
    
    # Show summary
    show_credential_summary "$redis_enabled"
    
    echo "" >&2
    echo -e "${GREEN}✓ Credential management completed successfully${NC}" >&2
    echo "" >&2
    
    return 0
}

# If script is run directly, show usage
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "BunkerWeb Password Manager Script"
    echo ""
    echo "This script is designed to be sourced by other scripts."
    echo ""
    echo "Available functions:"
    echo "  manage_credentials <creds_file> [redis_enabled] [deployment_name] [template] [mode] [fqdn] [server_name] [subnet] [networks_avoided]"
    echo "  load_existing_credentials <creds_file>"
    echo "  generate_missing_credentials [redis_enabled]"
    echo "  save_credentials <creds_file> [deployment_name] [template] [mode] [fqdn] [server_name] [subnet] [redis_enabled] [networks_avoided]"
    echo "  validate_credentials [redis_enabled]"
    echo "  get_passwords"
    echo "  show_credential_summary [redis_enabled]"
    echo ""
    echo "Example usage:"
    echo "  source bunkerweb_password_manager.sh"
    echo "  manage_credentials \"/data/BunkerWeb/credentials.txt\" \"yes\" \"Autoconf\" \"template.yml\" \"automated\""
fi