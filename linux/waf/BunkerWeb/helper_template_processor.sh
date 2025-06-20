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

# Safely replace a placeholder in a file
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

# Replace Docker image tag placeholders
replace_image_tag_placeholders() {
    local compose_file="$1"
    local image_tag="$2"
    local description="${3:-Docker image tags}"
    
    echo -e "${BLUE}Replacing $description with: $image_tag${NC}" >&2
    
    if [[ ! -f "$compose_file" ]]; then
        echo -e "${RED}✗ File not found: $compose_file${NC}" >&2
        return 1
    fi
    
    if [[ -z "$image_tag" ]]; then
        echo -e "${RED}✗ Image tag cannot be empty${NC}" >&2
        return 1
    fi
    
    # Replace REPLACEME_TAG with the actual tag
    if sed -i "s|REPLACEME_TAG|$image_tag|g" "$compose_file"; then
        echo -e "${GREEN}✓ $description updated to: $image_tag${NC}" >&2
        REPLACED_PLACEHOLDERS+=("REPLACEME_TAG")
        return 0
    else
        echo -e "${RED}✗ Failed to replace image tags${NC}" >&2
        FAILED_REPLACEMENTS+=("REPLACEME_TAG")
        return 1
    fi
}

# Replace credential placeholders
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
    
    if replace_placeholder "$compose_file" "REPLACEME_MYSQL" "$mysql_password" "MySQL password"; then
        ((success++))
    fi
    
    if [[ "$redis_enabled" == "yes" && -n "$redis_password" ]]; then
        if replace_placeholder "$compose_file" "REPLACEME_REDIS_PASSWORD" "$redis_password" "Redis password"; then
            ((success++))
        fi
    else
        if replace_placeholder "$compose_file" "REPLACEME_REDIS_PASSWORD" "disabled" "Redis password (disabled)"; then
            ((success++))
        fi
    fi
    
    if replace_placeholder "$compose_file" "REPLACEME_DEFAULT" "$totp_secret" "TOTP secret"; then
        ((success++))
    fi
    
    if replace_placeholder "$compose_file" "REPLACEME_ADMIN_USERNAME" "$admin_password" "Admin username"; then
        ((success++))
    fi
    
    if replace_placeholder "$compose_file" "REPLACEME_ADMIN_PASSWORD" "$admin_password" "Admin password"; then
        ((success++))
    fi
    
    if replace_placeholder "$compose_file" "REPLACEME_FLASK_SECRET" "$flask_secret" "Flask secret"; then
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

# Replace SSL/domain placeholders
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
            if replace_placeholder "$compose_file" "REPLACEME_AUTO_LETS_ENCRYPT" "yes" "Let's Encrypt enabled"; then
                ((success++))
            fi
            
            if replace_placeholder "$compose_file" "REPLACEME_EMAIL_LETS_ENCRYPT" "$auto_cert_contact" "Let's Encrypt contact email"; then
                ((success++))
            fi
            
            if grep -q "EMAIL_LETS_ENCRYPT:" "$compose_file"; then
                if sed -i "s|EMAIL_LETS_ENCRYPT: \".*\"|EMAIL_LETS_ENCRYPT: \"$auto_cert_contact\"|g" "$compose_file"; then
                    echo -e "${GREEN}✓ Let's Encrypt email environment variable updated${NC}" >&2
                    ((success++))
                fi
            fi
            
            echo -e "${GREEN}✓ Let's Encrypt enabled with contact: $auto_cert_contact${NC}" >&2
        fi
    else
        if replace_placeholder "$compose_file" "REPLACEME_AUTO_LETS_ENCRYPT" "no" "SSL certificates disabled"; then
            ((success++))
        fi
        echo -e "${BLUE}✓ SSL certificates set to manual configuration${NC}" >&2
    fi
    
    if replace_placeholder "$compose_file" "REPLACEME_DOMAIN" "$fqdn" "Domain name"; then
        ((success++))
    fi
    
    if grep -q "SERVER_NAME: \"\"" "$compose_file"; then
        if sed -i "s|SERVER_NAME: \"\"|SERVER_NAME: \"$fqdn\"|g" "$compose_file"; then
            echo -e "${GREEN}✓ SERVER_NAME environment variable updated${NC}" >&2
            ((success++))
        fi
    fi
    
    return 0
}

# Replace network-related placeholders
replace_network_placeholders() {
    local compose_file="$1"
    local docker_subnet="$2"
    local default_subnet="${3:-10.20.30.0/24}"
    
    if [[ -n "$docker_subnet" && "$docker_subnet" != "$default_subnet" ]]; then
        echo -e "${BLUE}Updating Docker network configuration to avoid conflicts...${NC}" >&2
        
        if sed -i "s|$default_subnet|$docker_subnet|g" "$compose_file"; then
            echo -e "${GREEN}✓ Main subnet updated to: $docker_subnet${NC}" >&2
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

# Replace DNS resolver placeholders
replace_dns_resolvers() {
    local compose_file="$1"
    local dns_resolvers="${2:-127.0.0.11}"
    
    echo -e "${BLUE}Replacing DNS resolver placeholders...${NC}" >&2
    
    if sed -i "s|REPLACEME_DNS_RESOLVERS|$dns_resolvers|g" "$compose_file"; then
        echo -e "${GREEN}✓ DNS resolvers updated to: $dns_resolvers${NC}" >&2
        REPLACED_PLACEHOLDERS+=("REPLACEME_DNS_RESOLVERS")
        return 0
    else
        echo -e "${RED}✗ Failed to update DNS resolvers${NC}" >&2
        FAILED_REPLACEMENTS+=("REPLACEME_DNS_RESOLVERS")
        return 1
    fi
}

# Configure setup mode (automated vs wizard)
configure_automated_setup() {
    local compose_file="$1"
    local setup_mode="$2"
    local admin_username="$3"
    local admin_password="$4"
    local flask_secret="$5"
    
    if [[ "$setup_mode" == "automated" ]]; then
        echo -e "${BLUE}Configuring automated setup...${NC}" >&2
        
        sed -i 's|# OVERRIDE_ADMIN_CREDS: "no"|OVERRIDE_ADMIN_CREDS: "yes"|' "$compose_file"
        sed -i "s|# ADMIN_USERNAME: \"REPLACEME_ADMIN_USERNAME\"|ADMIN_USERNAME: \"$admin_username\"|" "$compose_file"
        sed -i "s|# ADMIN_PASSWORD: \"REPLACEME_ADMIN_PASSWORD\"|ADMIN_PASSWORD: \"$admin_password\"|" "$compose_file"
        sed -i "s|# FLASK_SECRET: \"REPLACEME_FLASK_SECRET\"|FLASK_SECRET: \"$flask_secret\"|" "$compose_file"
        
        echo -e "${GREEN}✓ Automated setup configured and enabled${NC}" >&2
        return 0
    else
        echo -e "${BLUE}Configuring setup wizard mode...${NC}" >&2
        echo -e "${BLUE}Admin credentials generated but setup wizard enabled${NC}" >&2
        return 0
    fi
}

# Replace UI path placeholder and configure labels
replace_ui_path_placeholders() {
    local compose_file="$1"
    local fqdn="$2"
    local ui_path="${3}"
    local creds_file="${4}"
    
    echo -e "${BLUE}Configuring UI path and labels...${NC}" >&2
    
    # Generate UI path if not provided
    if [[ -z "$ui_path" ]]; then
        ui_path=$(generate_secure_ui_path 2>/dev/null || echo "bwadmin$(date +%s | tail -c 5)")
    fi
    
    # Remove leading slash if present
    ui_path="${ui_path#/}"
    
    # Replace UI path placeholder
    if sed -i "s|REPLACEME_UI_PATH|$ui_path|g" "$compose_file"; then
        echo -e "${GREEN}✓ UI path placeholder replaced with: /$ui_path${NC}" >&2
        REPLACED_PLACEHOLDERS+=("REPLACEME_UI_PATH")
    else
        echo -e "${RED}✗ Failed to replace UI path placeholder${NC}" >&2
        FAILED_REPLACEMENTS+=("REPLACEME_UI_PATH")
        return 1
    fi
    
    # Save UI access information to credentials file
    if [[ -n "$creds_file" && -f "$creds_file" ]]; then
        echo -e "${BLUE}Saving UI access information to credentials file...${NC}" >&2
        
        local hostname_ip=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "")
        
        # Add UI access information to credentials file
        {
            echo ""
            echo "# BunkerWeb UI Access Information"
            echo "UI Access Path: /$ui_path"
            if [[ -n "$fqdn" && "$fqdn" != "localhost" ]]; then
                echo "Full UI URL: https://$fqdn/$ui_path"
                echo "HTTP UI URL: http://$fqdn/$ui_path"
            fi
            if [[ -n "$hostname_ip" ]]; then
                echo "Direct Access: http://$hostname_ip/$ui_path"
            fi
            echo "UI Path Length: ${#ui_path} characters"
            echo "UI Path Security: Randomly generated alphanumeric"
            echo "# NOTE: Keep this path secret - it provides access to BunkerWeb admin interface"
        } >> "$creds_file"
        
        echo -e "${GREEN}✓ UI access information saved to credentials file${NC}" >&2
    else
        echo -e "${YELLOW}⚠ Credentials file not provided or not found - UI path not saved${NC}" >&2
    fi
    
    # Add BunkerWeb labels to bw-ui service if not already present
    if grep -q "bw-ui:" "$compose_file" && ! grep -q "bunkerweb.SERVER_NAME" "$compose_file"; then
        echo -e "${BLUE}Adding BunkerWeb labels to bw-ui service...${NC}" >&2
        
        local labels_block="    labels:
      - \"bunkerweb.SERVER_NAME=$fqdn\"
      - \"bunkerweb.USE_TEMPLATE=ui\"
      - \"bunkerweb.USE_REVERSE_PROXY=yes\"
      - \"bunkerweb.REVERSE_PROXY_URL=/$ui_path\"
      - \"bunkerweb.REVERSE_PROXY_HOST=http://bw-ui:7000\""
        
        awk -v labels="$labels_block" '
        /^  bw-ui:/ { in_ui_service = 1 }
        in_ui_service && /^    image:/ { 
            print $0
            print labels
            next
        }
        /^  [a-zA-Z]/ && !/^  bw-ui:/ { in_ui_service = 0 }
        { print }
        ' "$compose_file" > "$compose_file.tmp" && mv "$compose_file.tmp" "$compose_file"
        
        echo -e "${GREEN}✓ BunkerWeb labels added to bw-ui service${NC}" >&2
    fi
    
    # Update scheduler environment variables
    sed -i "s|REPLACEME_DOMAIN_USE_TEMPLATE|${fqdn}_USE_TEMPLATE|g" "$compose_file"
    sed -i "s|REPLACEME_DOMAIN_USE_REVERSE_PROXY|${fqdn}_USE_REVERSE_PROXY|g" "$compose_file"
    sed -i "s|REPLACEME_DOMAIN_REVERSE_PROXY_URL|${fqdn}_REVERSE_PROXY_URL|g" "$compose_file"
    sed -i "s|REPLACEME_DOMAIN_REVERSE_PROXY_HOST|${fqdn}_REVERSE_PROXY_HOST|g" "$compose_file"
    
    echo -e "${GREEN}✓ UI access path configured: /$ui_path${NC}" >&2
    echo -e "${GREEN}✓ Scheduler configuration updated for domain: $fqdn${NC}" >&2
    
    return 0
}

# Verify all placeholders have been replaced
verify_placeholder_replacement() {
    local compose_file="$1"
    
    echo -e "${BLUE}Verifying placeholder replacement...${NC}" >&2
    
    local remaining_placeholders=$(grep -o "REPLACEME_[A-Z_]*" "$compose_file" 2>/dev/null || echo "")
    if [[ -n "$remaining_placeholders" ]]; then
        echo -e "${RED}✗ Some placeholders were not replaced!${NC}" >&2
        echo -e "${RED}Remaining placeholders:${NC}" >&2
        echo "$remaining_placeholders" | sort -u | while read -r placeholder; do
            echo -e "${RED}  • $placeholder${NC}" >&2
        done
        return 1
    fi
    
    echo -e "${GREEN}✓ All placeholders successfully replaced${NC}" >&2
    return 0
}

# Validate Docker Compose syntax
validate_compose_syntax() {
    local compose_file="$1"
    local install_dir="$(dirname "$compose_file")"
    
    echo -e "${BLUE}Validating Docker Compose syntax...${NC}" >&2
    
    local current_dir=$(pwd)
    cd "$install_dir"
    
    if docker compose config >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Docker Compose syntax is valid${NC}" >&2
        cd "$current_dir"
        return 0
    else
        echo -e "${RED}✗ Docker Compose syntax error detected${NC}" >&2
        echo -e "${YELLOW}Validation output:${NC}" >&2
        docker compose config 2>&1 | head -10 >&2
        cd "$current_dir"
        return 1
    fi
}

# Create backup files with timestamp and description
create_backup() {
    local compose_file="$1"
    local backup_suffix="$2"
    
    local backup_file="${compose_file}.backup.${backup_suffix}.$(date +%Y%m%d_%H%M%S)"
    if cp "$compose_file" "$backup_file"; then
        echo -e "${GREEN}✓ Backup created: $backup_file${NC}" >&2
        echo "$backup_file"
        return 0
    else
        echo -e "${RED}✗ Failed to create backup${NC}" >&2
        return 1
    fi
}

# Show replacement summary
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
    
    echo "" >&2
}

# Comprehensive template processing with release channel support and all configurations
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
    
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}                 TEMPLATE PROCESSING WITH RELEASE CHANNEL                 ${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
    echo ""
    
    if [[ ! -f "$template_file" ]]; then
        echo -e "${RED}✗ Template file not found: $template_file${NC}"
        return 1
    fi
    
    if [[ -z "$image_tag" ]]; then
        echo -e "${RED}✗ Image tag is required${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Processing release channel: $release_channel${NC}"
    if ! validate_release_channel "$release_channel"; then
        echo -e "${RED}✗ Invalid release channel: $release_channel${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✓ Using Docker image tag: $image_tag${NC}"
    
    echo -e "${BLUE}Copying template to docker-compose.yml...${NC}"
    if cp "$template_file" "$compose_file"; then
        echo -e "${GREEN}✓ Template copied: $(basename "$template_file") → $(basename "$compose_file")${NC}"
    else
        echo -e "${RED}✗ Failed to copy template${NC}"
        return 1
    fi
    
    local backup_file=$(create_backup "$compose_file" "template-processing")
    echo -e "${GREEN}✓ Backup created${NC}"
    
    # Check if template needs processing
    if ! grep -q "REPLACEME_" "$compose_file"; then
        echo -e "${BLUE}ℹ No placeholders found in template${NC}"
        return 0
    fi
    
    local processing_errors=0
    
    echo -e "${BLUE}Processing template placeholders in correct order...${NC}"
    
    echo -e "${BLUE}1. Processing Docker image tags...${NC}"
    if replace_image_tag_placeholders "$compose_file" "$image_tag" "Docker image tags"; then
        echo -e "${GREEN}✓ Docker image tags updated to: $image_tag${NC}"
        echo -e "${GREEN}✓ Release channel: $release_channel${NC}"
    else
        echo -e "${RED}✗ Failed to update Docker image tags${NC}"
        ((processing_errors++))
    fi
    
    echo -e "${BLUE}2. Processing basic credentials...${NC}"
    if [[ -n "$mysql_password" ]]; then
        sed -i "s|REPLACEME_MYSQL|$mysql_password|g" "$compose_file"
        echo -e "${GREEN}✓ MySQL password updated${NC}"
    fi
    
    if [[ "$redis_enabled" == "yes" && -n "$redis_password" ]]; then
        sed -i "s|REPLACEME_REDIS_PASSWORD|$redis_password|g" "$compose_file"
        echo -e "${GREEN}✓ Redis password updated${NC}"
    else
        sed -i "s|REPLACEME_REDIS_PASSWORD|disabled|g" "$compose_file"
        echo -e "${GREEN}✓ Redis password set to disabled${NC}"
    fi
    
    if [[ -n "$totp_secret" ]]; then
        sed -i "s|REPLACEME_DEFAULT|$totp_secret|g" "$compose_file"
        echo -e "${GREEN}✓ TOTP secret updated${NC}"
    fi
    
    echo -e "${BLUE}3. Processing network configuration...${NC}"
    if [[ -n "$docker_subnet" ]]; then
        local default_subnet="10.20.30.0/24"
        if [[ "$docker_subnet" != "$default_subnet" ]]; then
            sed -i "s|$default_subnet|$docker_subnet|g" "$compose_file"
            echo -e "${GREEN}✓ Docker subnet updated to: $docker_subnet${NC}"
        fi
    fi
    
    echo -e "${BLUE}4. Processing DNS configuration...${NC}"
    if replace_dns_resolvers "$compose_file" "${DNS_RESOLVERS:-127.0.0.11}"; then
        echo -e "${GREEN}✓ DNS resolvers configured${NC}"
    else
        echo -e "${RED}✗ Failed to configure DNS resolvers${NC}"
        ((processing_errors++))
    fi
    
    echo -e "${BLUE}5. Processing HTTP/3 configuration...${NC}"
    if [[ -n "$HTTP3" ]]; then
        sed -i "s|HTTP3: \"yes\"|HTTP3: \"$HTTP3\"|g" "$compose_file"
        echo -e "${GREEN}✓ HTTP3 configured: $HTTP3${NC}"
    fi
    
    if [[ -n "$HTTP3_ALT_SVC_PORT" ]]; then
        sed -i "s|HTTP3_ALT_SVC_PORT: \"443\"|HTTP3_ALT_SVC_PORT: \"$HTTP3_ALT_SVC_PORT\"|g" "$compose_file"
        echo -e "${GREEN}✓ HTTP3 alternate service port: $HTTP3_ALT_SVC_PORT${NC}"
    fi
    
    echo -e "${BLUE}6. Processing Let's Encrypt configuration...${NC}"
    if [[ -n "$LETS_ENCRYPT_CHALLENGE" ]]; then
        sed -i "s|LETS_ENCRYPT_CHALLENGE: \"http\"|LETS_ENCRYPT_CHALLENGE: \"$LETS_ENCRYPT_CHALLENGE\"|g" "$compose_file"
        echo -e "${GREEN}✓ Let's Encrypt challenge type: $LETS_ENCRYPT_CHALLENGE${NC}"
    fi
    
    if [[ -n "$LETS_ENCRYPT_STAGING" ]]; then
        sed -i "s|USE_LETS_ENCRYPT_STAGING: \"yes\"|USE_LETS_ENCRYPT_STAGING: \"$LETS_ENCRYPT_STAGING\"|g" "$compose_file"
        echo -e "${GREEN}✓ Let's Encrypt staging: $LETS_ENCRYPT_STAGING${NC}"
    fi
    
    echo -e "${BLUE}7. Processing multisite configuration...${NC}"
    if [[ -n "$MULTISITE" ]]; then
        sed -i "s|MULTISITE: \"yes\"|MULTISITE: \"$MULTISITE\"|g" "$compose_file"
        echo -e "${GREEN}✓ Multisite mode: $MULTISITE${NC}"
    fi
    
    echo -e "${BLUE}8. Processing SSL configuration...${NC}"
    if [[ -n "$auto_cert_type" ]]; then
        sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|yes|g" "$compose_file"
        sed -i "s|REPLACEME_EMAIL_LETS_ENCRYPT|$auto_cert_contact|g" "$compose_file"
        echo -e "${GREEN}✓ SSL certificates configured ($auto_cert_type)${NC}"
    else
        sed -i "s|REPLACEME_AUTO_LETS_ENCRYPT|no|g" "$compose_file"
        echo -e "${GREEN}✓ SSL certificates disabled${NC}"
    fi
    
    echo -e "${BLUE}9. Processing domain configuration...${NC}"
    if [[ -n "$fqdn" ]]; then
        sed -i "s|REPLACEME_DOMAIN|$fqdn|g" "$compose_file"
        sed -i "s|SERVER_NAME: \"\"|SERVER_NAME: \"$fqdn\"|g" "$compose_file"
        echo -e "${GREEN}✓ Domain configured: $fqdn${NC}"
    fi
    
    echo -e "${BLUE}10. Configuring UI path and labels...${NC}"
    local creds_file="${compose_file%/*}/credentials.txt"
    if replace_ui_path_placeholders "$compose_file" "$fqdn" "" "$creds_file"; then
        echo -e "${GREEN}✓ UI path and labels configured successfully${NC}"
    else
        echo -e "${RED}✗ Failed to configure UI path and labels${NC}"
        ((processing_errors++))
    fi
    
    echo -e "${BLUE}11. Configuring setup mode and credentials...${NC}"
    configure_setup_mode "$compose_file" "$setup_mode" "$admin_username" "$admin_password" "$flask_secret"
    
    echo -e "${BLUE}12. Validating placeholder replacement...${NC}"
    if verify_placeholder_replacement "$compose_file"; then
        echo -e "${GREEN}✓ All placeholders replaced successfully${NC}"
    else
        echo -e "${YELLOW}⚠ Restoring backup due to placeholder issues...${NC}"
        cp "$backup_file" "$compose_file"
        ((processing_errors++))
    fi
    
    echo -e "${BLUE}13. Validating Docker Compose syntax...${NC}"
    if validate_compose_syntax "$compose_file"; then
        echo -e "${GREEN}✓ Docker Compose syntax validation passed${NC}"
    else
        echo -e "${RED}✗ Docker Compose syntax validation failed${NC}"
        ((processing_errors++))
    fi
    
    echo ""
    if [[ $processing_errors -eq 0 ]]; then
        echo -e "${GREEN}✓ Template processing completed successfully${NC}"
        echo -e "${GREEN}✓ Release channel: $release_channel${NC}"
        echo -e "${GREEN}✓ Docker image tag: $image_tag${NC}"
        echo -e "${GREEN}✓ DNS resolvers: ${DNS_RESOLVERS:-127.0.0.11}${NC}"
        echo -e "${GREEN}✓ HTTP/3 enabled: ${HTTP3:-yes}${NC}"
        echo -e "${GREEN}✓ Multisite mode: ${MULTISITE:-yes}${NC}"
        echo -e "${GREEN}✓ All placeholders properly replaced${NC}"
        echo -e "${GREEN}✓ Admin credentials correctly configured${NC}"
        echo -e "${GREEN}✓ UI path synchronized between scheduler and UI service${NC}"
        echo -e "${GREEN}✓ Setup mode properly configured: $setup_mode${NC}"
    else
        echo -e "${RED}✗ Template processing completed with $processing_errors errors${NC}"
        echo -e "${BLUE}✓ Backup available at: $backup_file${NC}"
        return 1
    fi
    
    return 0
}

# Legacy function for backwards compatibility
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
    echo "  process_template_with_release_channel - Process template with release channel support"
    echo "  replace_placeholder - Replace a single placeholder"
    echo "  replace_image_tag_placeholders - Replace Docker image tags"
    echo "  replace_credential_placeholders - Replace all credentials"
    echo "  replace_ssl_placeholders - Replace SSL/domain settings"
    echo "  replace_network_placeholders - Replace network settings"
    echo "  replace_dns_resolvers - Replace DNS resolver settings"
    echo "  replace_ui_path_placeholders - Replace UI path, configure labels, and save to credentials"
    echo "  configure_automated_setup - Configure setup mode"
    echo "  verify_placeholder_replacement - Verify all placeholders replaced"
    echo "  validate_compose_syntax - Validate Docker Compose syntax"
    echo "  create_backup - Create backup files"
    echo ""
fi