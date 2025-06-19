#!/bin/bash
# Copyright (c) 2025 Michal Koeckeis-Fresel
# This software is dual-licensed under your choice of:
# - MIT License (see LICENSE-MIT)
# - GNU Affero General Public License v3.0 (see LICENSE-AGPL)
# SPDX-License-Identifier: MIT OR AGPL-3.0-or-later

# BunkerWeb Template Processor Script
# Handles placeholder replacement and template processing

# Load debug configuration if available
if [[ -f "/data/BunkerWeb/BunkerWeb.conf" ]]; then
    source "/data/BunkerWeb/BunkerWeb.conf" 2>/dev/null || true
elif [[ -f "/root/BunkerWeb.conf" ]]; then
    source "/root/BunkerWeb.conf" 2>/dev/null || true
fi

# Enable debug mode if requested
if [[ "${DEBUG:-no}" == "yes" ]]; then
    set -x
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables for tracking replacements
REPLACED_PLACEHOLDERS=()
FAILED_REPLACEMENTS=()

# Function to safely replace a placeholder in a file
replace_placeholder() {
    local file="$1"
    local placeholder="$2"
    local value="$3"
    local description="$4"
    
    if [[ ! -f "$file" ]]; then
        echo -e "${RED}✗ File not found: $file${NC}" >&2
        return 1
    fi
    
    if [[ -z "$placeholder" || -z "$value" ]]; then
        echo -e "${RED}✗ Empty placeholder or value provided${NC}" >&2
        return 1
    fi
    
    # Check if placeholder exists in file
    if ! grep -q "$placeholder" "$file"; then
        echo -e "${YELLOW}⚠ Placeholder '$placeholder' not found in $file${NC}" >&2
        return 0  # Not an error, just not present
    fi
    
    # Escape special characters for sed
    local escaped_value=$(printf '%s\n' "$value" | sed 's/[[\.*^$()+?{|]/\\&/g')
    
    # Perform replacement
    if sed -i "s|$placeholder|$escaped_value|g" "$file"; then
        REPLACED_PLACEHOLDERS+=("$placeholder")
        echo -e "${GREEN}✓ ${description:-$placeholder} updated${NC}" >&2
        return 0
    else
        FAILED_REPLACEMENTS+=("$placeholder")
        echo -e "${RED}✗ Failed to replace $placeholder${NC}" >&2
        return 1
    fi
}

replace_image_tag_placeholders() {
    local compose_file="$1"
    local image_tag="$2"
    local description="${3:-Docker image tags}"
    
    echo -e "${BLUE}Replacing $description with: $image_tag${NC}" >&2
    
    # Check if file exists
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${RED}✗ File not found: $compose_file${NC}" >&2
        return 1
    fi
    
    if [[ -z "$image_tag" ]]; then
        echo -e "${RED}✗ Image tag cannot be empty${NC}" >&2
        return 1
    fi
    
    # Create backup before making changes
    local backup_file="$compose_file.backup.image-tags.$(date +%Y%m%d_%H%M%S)"
    cp "$compose_file" "$backup_file"
    
    # Count existing REPLACEME_TAG placeholders
    local tag_count=$(grep -c "REPLACEME_TAG" "$compose_file" 2>/dev/null || echo "0")
    echo -e "${BLUE}Found $tag_count image tag placeholders to replace${NC}" >&2
    
    # Escape special characters for sed
    local escaped_tag=$(printf '%s\n' "$image_tag" | sed 's/[[\.*^$()+?{|]/\\&/g')
    
    # Replace REPLACEME_TAG with the actual tag
    if sed -i "s|REPLACEME_TAG|$escaped_tag|g" "$compose_file"; then
        echo -e "${GREEN}✓ $description updated to: $image_tag${NC}" >&2
        
        # Verify the replacement worked
        local remaining_tags=$(grep -c "REPLACEME_TAG" "$compose_file" 2>/dev/null || echo "0")
        
        if [[ $remaining_tags -eq 0 ]]; then
            echo -e "${GREEN}✓ All image tag placeholders successfully replaced${NC}" >&2
            
            # Show which images were updated
            echo -e "${BLUE}Updated images:${NC}" >&2
            grep "image: bunkerity" "$compose_file" | sed 's/^\s*/  /' >&2
            
            REPLACED_PLACEHOLDERS+=("REPLACEME_TAG")
            return 0
        else
            echo -e "${YELLOW}⚠ Some REPLACEME_TAG placeholders may remain: $remaining_tags${NC}" >&2
            FAILED_REPLACEMENTS+=("REPLACEME_TAG")
            return 1
        fi
    else
        echo -e "${RED}✗ Failed to replace image tags${NC}" >&2
        FAILED_REPLACEMENTS+=("REPLACEME_TAG")
        return 1
    fi
}

# Function to replace all credential placeholders
replace_credential_placeholders() {
    local compose_file="$1"
    local mysql_password="$2"
    local redis_password="$3"
    local totp_secret="$4"
    local admin_password="$5"
    local flask_secret="$6"
    local redis_enabled="$7"
    
    echo -e "${BLUE}Replacing credential placeholders in docker-compose.yml...${NC}" >&2
    
    local success=0
    
    # Replace MySQL password
    if replace_placeholder "$compose_file" "REPLACEME_MYSQL" "$mysql_password" "MySQL password"; then
        ((success++))
    fi
    
    # Replace Redis password (handle both enabled and disabled cases)
    if [[ "$redis_enabled" == "yes" && -n "$redis_password" ]]; then
        if replace_placeholder "$compose_file" "REPLACEME_REDIS_PASSWORD" "$redis_password" "Redis password"; then
            ((success++))
        fi
    else
        # Redis disabled - use a safe placeholder value
        if replace_placeholder "$compose_file" "REPLACEME_REDIS_PASSWORD" "disabled" "Redis password (disabled)"; then
            ((success++))
        fi
    fi
    
    # Replace TOTP secret
    if replace_placeholder "$compose_file" "REPLACEME_DEFAULT" "$totp_secret" "TOTP secret"; then
        ((success++))
    fi
    
    # Replace admin password
    if replace_placeholder "$compose_file" "REPLACEME_ADMIN" "$admin_password" "Admin password"; then
        ((success++))
    fi
    
    # Replace Flask secret
    if replace_placeholder "$compose_file" "REPLACEME_FLASK" "$flask_secret" "Flask secret"; then
        ((success++))
    fi
    
    if [[ $success -gt 0 ]]; then
        echo -e "${GREEN}✓ Replaced $success credential placeholders${NC}" >&2
        return 0
    else
        echo -e "${RED}✗ No credential placeholders were replaced${NC}" >&2
        return 1
    fi
}

# Function to replace SSL/domain placeholders
replace_ssl_placeholders() {
    local compose_file="$1"
    local auto_cert_type="$2"
    local auto_cert_contact="$3"
    local fqdn="$4"
    local server_name="$5"
    
    echo -e "${BLUE}Configuring SSL and domain settings...${NC}" >&2
    
    local success=0
    
    if [[ -n "$auto_cert_type" ]]; then
        echo -e "${BLUE}Configuring SSL certificates ($auto_cert_type) for domain: $fqdn${NC}" >&2
        
        if [[ "$auto_cert_type" == "LE" ]]; then
            # Let's Encrypt configuration
            if replace_placeholder "$compose_file" "REPLACEME_AUTO_LETS_ENCRYPT" "yes" "Let's Encrypt enabled"; then
                ((success++))
            fi
            
            if replace_placeholder "$compose_file" "REPLACEME_EMAIL_LETS_ENCRYPT" "$auto_cert_contact" "Let's Encrypt contact email"; then
                ((success++))
            fi
            
            # Also update direct environment variables if they exist
            if grep -q "EMAIL_LETS_ENCRYPT:" "$compose_file"; then
                if sed -i "s|EMAIL_LETS_ENCRYPT: \".*\"|EMAIL_LETS_ENCRYPT: \"$auto_cert_contact\"|g" "$compose_file"; then
                    echo -e "${GREEN}✓ Let's Encrypt email environment variable updated${NC}" >&2
                    ((success++))
                fi
            fi
            
            echo -e "${GREEN}✓ Let's Encrypt enabled with contact: $auto_cert_contact${NC}" >&2
            
        elif [[ "$auto_cert_type" == "ZeroSSL" ]]; then
            # ZeroSSL configuration
            if replace_placeholder "$compose_file" "REPLACEME_AUTO_LETS_ENCRYPT" "yes" "ZeroSSL enabled"; then
                ((success++))
            fi
            
            if replace_placeholder "$compose_file" "REPLACEME_EMAIL_LETS_ENCRYPT" "$auto_cert_contact" "ZeroSSL contact email"; then
                ((success++))
            fi
            
            echo -e "${GREEN}✓ ZeroSSL enabled with contact: $auto_cert_contact${NC}" >&2
        fi
        
        # Set domain/server name for SSL certificates
        if replace_placeholder "$compose_file" "REPLACEME_DOMAIN" "$fqdn" "Domain name"; then
            ((success++))
        fi
        
    else
        # No automatic certificates - ensure Let's Encrypt is disabled
        if replace_placeholder "$compose_file" "REPLACEME_AUTO_LETS_ENCRYPT" "no" "SSL certificates disabled"; then
            ((success++))
        fi
        
        # Also disable in environment variables if they exist
        if grep -q "AUTO_LETS_ENCRYPT: \"yes\"" "$compose_file"; then
            if sed -i "s|AUTO_LETS_ENCRYPT: \"yes\"|AUTO_LETS_ENCRYPT: \"no\"|g" "$compose_file"; then
                echo -e "${GREEN}✓ Let's Encrypt environment variable disabled${NC}" >&2
                ((success++))
            fi
        fi
        
        if replace_placeholder "$compose_file" "REPLACEME_DOMAIN" "$fqdn" "Domain name"; then
            ((success++))
        fi
        
        echo -e "${BLUE}✓ SSL certificates set to manual configuration${NC}" >&2
    fi
    
    # Set SERVER_NAME in environment variables
    if grep -q "SERVER_NAME: \"\"" "$compose_file"; then
        if sed -i "s|SERVER_NAME: \"\"|SERVER_NAME: \"$fqdn\"|g" "$compose_file"; then
            echo -e "${GREEN}✓ SERVER_NAME environment variable updated${NC}" >&2
            ((success++))
        fi
    fi
    
    return 0
}

# Function to replace network-related placeholders
replace_network_placeholders() {
    local compose_file="$1"
    local docker_subnet="$2"
    local default_subnet="${3:-10.20.30.0/24}"
    
    if [[ -n "$docker_subnet" && "$docker_subnet" != "$default_subnet" ]]; then
        echo -e "${BLUE}Updating Docker network configuration to avoid conflicts...${NC}" >&2
        
        # Escape special characters for sed
        local escaped_subnet=$(printf '%s\n' "$docker_subnet" | sed 's/[[\.*^$()+?{|]/\\&/g')
        local escaped_default=$(printf '%s\n' "$default_subnet" | sed 's/[[\.*^$()+?{|]/\\&/g')
        
        # Update the main universe subnet
        if sed -i "s|$escaped_default|$escaped_subnet|g" "$compose_file"; then
            echo -e "${GREEN}✓ Main subnet updated to: $docker_subnet${NC}" >&2
            
            # Update API whitelist to match new subnet
            local subnet_base="${docker_subnet%.*}.0/24"
            local default_base="${default_subnet%.*}.0/24"
            local escaped_subnet_base=$(printf '%s\n' "$subnet_base" | sed 's/[[\.*^$()+?{|]/\\&/g')
            local escaped_default_base=$(printf '%s\n' "$default_base" | sed 's/[[\.*^$()+?{|]/\\&/g')
            
            if sed -i "s|$escaped_default_base|$escaped_subnet_base|g" "$compose_file"; then
                echo -e "${GREEN}✓ API whitelist updated to: $subnet_base${NC}" >&2
            fi
            
            return 0
        else
            echo -e "${RED}✗ Failed to update network subnet${NC}" >&2
            return 1
        fi
    else
        echo -e "${BLUE}ℹ Using default network configuration${NC}" >&2
        return 0
    fi
}

# Function to enable/disable automated admin credentials
configure_automated_setup() {
    local compose_file="$1"
    local setup_mode="$2"
    local admin_username="$3"
    local admin_password="$4"
    local flask_secret="$5"
    
    if [[ "$setup_mode" == "automated" ]]; then
        echo -e "${BLUE}Configuring automated setup...${NC}" >&2
        
        # Enable automated setup in docker-compose.yml (uncomment the lines)
        sed -i 's|# OVERRIDE_ADMIN_CREDS: "yes"|OVERRIDE_ADMIN_CREDS: "yes"|' "$compose_file"
        sed -i 's|# ADMIN_USERNAME: "admin"|ADMIN_USERNAME: "'$admin_username'"|' "$compose_file"
        sed -i 's|# ADMIN_PASSWORD: "REPLACEME_ADMIN"|ADMIN_PASSWORD: "'$admin_password'"|' "$compose_file"
        sed -i 's|# FLASK_SECRET: "REPLACEME_FLASK"|FLASK_SECRET: "'$flask_secret'"|' "$compose_file"
        
        echo -e "${GREEN}✓ Automated setup configured and enabled${NC}" >&2
        echo -e "${GREEN}✓ Admin credentials activated${NC}" >&2
        return 0
    else
        echo -e "${BLUE}Configuring setup wizard mode...${NC}" >&2
        echo -e "${BLUE}Admin credentials generated but setup wizard enabled${NC}" >&2
        return 0
    fi
}

# Function to verify all placeholders have been replaced
verify_placeholder_replacement() {
    local compose_file="$1"
    
    echo -e "${BLUE}Verifying placeholder replacement...${NC}" >&2
    
    # Check for any remaining placeholders (all should be replaced now)
    local remaining_placeholders=$(grep -o "REPLACEME_[A-Z_]*" "$compose_file" || true)
    
    if [[ -n "$remaining_placeholders" ]]; then
        echo -e "${RED}✗ Some placeholders were not replaced!${NC}" >&2
        echo -e "${RED}Remaining placeholders:${NC}" >&2
        
        # Show each unique remaining placeholder
        echo "$remaining_placeholders" | sort -u | while read -r placeholder; do
            echo -e "${RED}  • $placeholder${NC}" >&2
        done
        
        return 1
    else
        echo -e "${GREEN}✓ All placeholders successfully replaced${NC}" >&2
        return 0
    fi
}

# Function to validate Docker Compose syntax
validate_compose_syntax() {
    local compose_file="$1"
    local install_dir="$(dirname "$compose_file")"
    
    echo -e "${BLUE}Validating Docker Compose syntax...${NC}" >&2
    
    # Change to the directory containing the compose file
    local current_dir=$(pwd)
    cd "$install_dir"
    
    if docker compose config >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Docker Compose syntax is valid${NC}" >&2
        cd "$current_dir"
        return 0
    else
        echo -e "${RED}✗ Docker Compose syntax error detected${NC}" >&2
        echo -e "${YELLOW}Docker Compose validation output:${NC}" >&2
        docker compose config 2>&1 | head -10 >&2
        cd "$current_dir"
        return 1
    fi
}

# Function to create a backup of the compose file
create_backup() {
    local compose_file="$1"
    local backup_suffix="${2:-template-processing}"
    
    local backup_file="$compose_file.backup.$backup_suffix.$(date +%Y%m%d_%H%M%S)"
    
    if cp "$compose_file" "$backup_file"; then
        echo -e "${GREEN}✓ Backup created: $backup_file${NC}" >&2
        echo "$backup_file"
        return 0
    else
        echo -e "${RED}✗ Failed to create backup${NC}" >&2
        return 1
    fi
}

# Function to show replacement summary
show_replacement_summary() {
    echo -e "${BLUE}Template Processing Summary:${NC}" >&2
    echo -e "${GREEN}• Successfully replaced: ${#REPLACED_PLACEHOLDERS[@]} placeholders${NC}" >&2
    
    if [[ ${#REPLACED_PLACEHOLDERS[@]} -gt 0 ]]; then
        for placeholder in "${REPLACED_PLACEHOLDERS[@]}"; do
            echo -e "${GREEN}  ✓ $placeholder${NC}" >&2
        done
    fi
    
    if [[ ${#FAILED_REPLACEMENTS[@]} -gt 0 ]]; then
        echo -e "${RED}• Failed replacements: ${#FAILED_REPLACEMENTS[@]} placeholders${NC}" >&2
        for placeholder in "${FAILED_REPLACEMENTS[@]}"; do
            echo -e "${RED}  ✗ $placeholder${NC}" >&2
        done
    fi
}

process_template_with_release_channel() {
    local template_file="$1"
    local compose_file="$2"
    local mysql_password="$3"
    local redis_password="$4"
    local totp_secret="$5"
    local admin_password="$6"
    local flask_secret="$7"
    local admin_username="$8"
    local auto_cert_type="$9"
    local auto_cert_contact="${10}"
    local fqdn="${11}"
    local server_name="${12}"
    local docker_subnet="${13}"
    local setup_mode="${14}"
    local redis_enabled="${15:-yes}"
    local release_channel="${16:-latest}"
    local image_tag="${17}"
    
    # Clear tracking arrays
    REPLACED_PLACEHOLDERS=()
    FAILED_REPLACEMENTS=()
    
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo -e "${BLUE}                 TEMPLATE PROCESSING WITH RELEASE CHANNEL                 ${NC}" >&2
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo "" >&2
    
    # Validate inputs
    if [[ ! -f "$template_file" ]]; then
        echo -e "${RED}✗ Template file not found: $template_file${NC}" >&2
        return 1
    fi
    
    if [[ -z "$image_tag" ]]; then
        echo -e "${RED}✗ Image tag is required${NC}" >&2
        return 1
    fi
    
    # Copy template to compose file
    echo -e "${BLUE}Copying template to docker-compose.yml...${NC}" >&2
    if cp "$template_file" "$compose_file"; then
        echo -e "${GREEN}✓ Template copied: $(basename "$template_file") → $(basename "$compose_file")${NC}" >&2
    else
        echo -e "${RED}✗ Failed to copy template${NC}" >&2
        return 1
    fi
    
    # Create backup
    local backup_file
    if backup_file=$(create_backup "$compose_file" "template-processing"); then
        echo -e "${GREEN}✓ Backup created${NC}" >&2
    else
        echo -e "${RED}✗ Failed to create backup${NC}" >&2
        return 1
    fi
    
    # Check if template contains placeholders
    if ! grep -q "REPLACEME_" "$compose_file"; then
        echo -e "${YELLOW}⚠ No placeholders found in template${NC}" >&2
        echo -e "${YELLOW}File may already be configured or invalid template${NC}" >&2
    fi
    
    # Process replacements step by step
    local processing_errors=0
    
    # 1. NEW: Replace Docker image tags first
    echo -e "${BLUE}1. Replacing Docker image tags...${NC}" >&2
    if ! replace_image_tag_placeholders "$compose_file" "$image_tag" "Docker image tags"; then
        ((processing_errors++))
        echo -e "${RED}✗ Failed to replace Docker image tags${NC}" >&2
    else
        echo -e "${GREEN}✓ Docker image tags updated to: $image_tag (release channel: $release_channel)${NC}" >&2
    fi
    
    # 2. Replace network placeholders (if needed)
    echo -e "${BLUE}2. Replacing network placeholders...${NC}" >&2
    if ! replace_network_placeholders "$compose_file" "$docker_subnet"; then
        ((processing_errors++))
    fi
    
    # 3. Replace credential placeholders
    echo -e "${BLUE}3. Replacing credential placeholders...${NC}" >&2
    if ! replace_credential_placeholders "$compose_file" "$mysql_password" "$redis_password" "$totp_secret" "$admin_password" "$flask_secret" "$redis_enabled"; then
        ((processing_errors++))
    fi
    
    # 4. Replace SSL/domain placeholders
    echo -e "${BLUE}4. Replacing SSL/domain placeholders...${NC}" >&2
    if ! replace_ssl_placeholders "$compose_file" "$auto_cert_type" "$auto_cert_contact" "$fqdn" "$server_name"; then
        ((processing_errors++))
    fi
    
    # 5. Configure automated setup if requested
    echo -e "${BLUE}5. Configuring setup mode...${NC}" >&2
    if ! configure_automated_setup "$compose_file" "$setup_mode" "$admin_username" "$admin_password" "$flask_secret"; then
        ((processing_errors++))
    fi
    
    # 6. Verify all placeholders are replaced
    echo -e "${BLUE}6. Verifying placeholder replacement...${NC}" >&2
    if ! verify_placeholder_replacement "$compose_file"; then
        echo -e "${YELLOW}⚠ Restoring backup due to placeholder issues...${NC}" >&2
        cp "$backup_file" "$compose_file"
        ((processing_errors++))
    fi
    
    # 7. Validate Docker Compose syntax
    echo -e "${BLUE}7. Validating Docker Compose syntax...${NC}" >&2
    if ! validate_compose_syntax "$compose_file"; then
        echo -e "${YELLOW}⚠ Compose syntax validation failed${NC}" >&2
        ((processing_errors++))
    fi
    
    # Show summary
    show_replacement_summary
    
    echo "" >&2
    if [[ $processing_errors -eq 0 ]]; then
        echo -e "${GREEN}✓ Template processing with release channel completed successfully${NC}" >&2
        echo -e "${GREEN}✓ Release channel: $release_channel${NC}" >&2
        echo -e "${GREEN}✓ Docker image tag: $image_tag${NC}" >&2
        echo -e "${BLUE}✓ Backup available at: $backup_file${NC}" >&2
        echo "" >&2
        return 0
    else
        echo -e "${RED}✗ Template processing completed with $processing_errors errors${NC}" >&2
        echo -e "${BLUE}✓ Backup available at: $backup_file${NC}" >&2
        echo "" >&2
        return 1
    fi
}

# Main function to process a template file completely (LEGACY - kept for compatibility)
process_template() {
    local template_file="$1"
    local compose_file="$2"
    local mysql_password="$3"
    local redis_password="$4"
    local totp_secret="$5"
    local admin_password="$6"
    local flask_secret="$7"
    local admin_username="$8"
    local auto_cert_type="$9"
    local auto_cert_contact="${10}"
    local fqdn="${11}"
    local server_name="${12}"
    local docker_subnet="${13}"
    local setup_mode="${14}"
    local redis_enabled="${15:-yes}"
    
    # Call the new function with default release channel
    process_template_with_release_channel "$template_file" "$compose_file" "$mysql_password" "$redis_password" "$totp_secret" "$admin_password" "$flask_secret" "$admin_username" "$auto_cert_type" "$auto_cert_contact" "$fqdn" "$server_name" "$docker_subnet" "$setup_mode" "$redis_enabled" "latest" "latest"
}

# If script is run directly, show usage
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "BunkerWeb Template Processor Script"
    echo ""
    echo "This script is designed to be sourced by other scripts."
    echo ""
    echo "Available functions:"
    echo "  process_template_with_release_channel <template> <compose> <mysql_pass> <redis_pass> <totp> <admin_pass> <flask> <admin_user> [ssl_type] [ssl_contact] [fqdn] [server_name] [subnet] [setup_mode] [redis_enabled] [release_channel] [image_tag]"
    echo "  process_template <template> <compose> <mysql_pass> <redis_pass> <totp> <admin_pass> <flask> <admin_user> [ssl_type] [ssl_contact] [fqdn] [server_name] [subnet] [setup_mode] [redis_enabled]"
    echo "  replace_placeholder <file> <placeholder> <value> [description]"
    echo "  replace_image_tag_placeholders <file> <image_tag> [description]"
    echo "  replace_credential_placeholders <file> <mysql> <redis> <totp> <admin> <flask> [redis_enabled]"
    echo "  replace_ssl_placeholders <file> <ssl_type> <ssl_contact> <fqdn> <server_name>"
    echo "  replace_network_placeholders <file> <subnet> [default_subnet]"
    echo "  configure_automated_setup <file> <mode> <admin_user> <admin_pass> <flask>"
    echo "  verify_placeholder_replacement <file>"
    echo "  validate_compose_syntax <file>"
    echo "  create_backup <file> [suffix]"
    echo ""
    echo "Example usage:"
    echo "  source helper_template_processor.sh"
    echo "  process_template_with_release_channel template.yml docker-compose.yml \"\$MYSQL_PASS\" \"\$REDIS_PASS\" ... \"latest\" \"1.6.1\""
fi