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

# BunkerWeb Directory Layout Helper Script
# Handles directory creation and permission management
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables for tracking created directories
CREATED_DIRECTORIES=()
PERMISSION_ERRORS=()

# Function to check if a user/group exists by ID
check_user_group_exists() {
    local user_id="$1"
    local group_id="$2"
    local service_name="$3"
    
    # Check if user ID exists
    if ! getent passwd "$user_id" >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠ User ID $user_id for $service_name not found in system${NC}" >&2
        echo -e "${BLUE}ℹ This is normal - Docker will create the user inside containers${NC}" >&2
    fi
    
    # Check if group ID exists
    if ! getent group "$group_id" >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠ Group ID $group_id for $service_name not found in system${NC}" >&2
        echo -e "${BLUE}ℹ This is normal - Docker will create the group inside containers${NC}" >&2
    fi
    
    return 0
}

# Function to create a directory with error handling
create_directory() {
    local dir_path="$1"
    local description="$2"
    
    if [[ -z "$dir_path" ]]; then
        echo -e "${RED}✗ Directory path is empty${NC}" >&2
        return 1
    fi
    
    echo -e "${BLUE}Creating directory: $dir_path${NC}" >&2
    
    if [[ -d "$dir_path" ]]; then
        echo -e "${GREEN}✓ Directory already exists: $dir_path${NC}" >&2
        return 0
    fi
    
    if mkdir -p "$dir_path"; then
        echo -e "${GREEN}✓ Created directory: $dir_path${NC}" >&2
        CREATED_DIRECTORIES+=("$dir_path")
        return 0
    else
        echo -e "${RED}✗ Failed to create directory: $dir_path${NC}" >&2
        return 1
    fi
}

# Function to set ownership with error handling
set_directory_ownership() {
    local dir_path="$1"
    local user_id="$2"
    local group_id="$3"
    local service_name="$4"
    local recursive="${5:-yes}"
    
    if [[ ! -d "$dir_path" ]]; then
        echo -e "${RED}✗ Directory does not exist: $dir_path${NC}" >&2
        return 1
    fi
    
    echo -e "${BLUE}Setting ownership for $service_name: $dir_path${NC}" >&2
    
    # Check if user/group exists (informational only)
    check_user_group_exists "$user_id" "$group_id" "$service_name"
    
    # Set ownership
    local chown_cmd="chown"
    [[ "$recursive" == "yes" ]] && chown_cmd="chown -R"
    
    if $chown_cmd "$user_id:$group_id" "$dir_path"; then
        echo -e "${GREEN}✓ Ownership set: $dir_path ($user_id:$group_id)${NC}" >&2
        return 0
    else
        echo -e "${RED}✗ Failed to set ownership: $dir_path${NC}" >&2
        PERMISSION_ERRORS+=("$dir_path")
        return 1
    fi
}

# Function to set directory permissions
set_directory_permissions() {
    local dir_path="$1"
    local permissions="$2"
    local recursive="${3:-yes}"
    local description="$4"
    
    if [[ ! -d "$dir_path" ]]; then
        echo -e "${RED}✗ Directory does not exist: $dir_path${NC}" >&2
        return 1
    fi
    
    echo -e "${BLUE}Setting permissions${description:+ for $description}: $dir_path${NC}" >&2
    
    local chmod_cmd="chmod"
    [[ "$recursive" == "yes" ]] && chmod_cmd="chmod -R"
    
    if $chmod_cmd "$permissions" "$dir_path"; then
        echo -e "${GREEN}✓ Permissions set: $dir_path ($permissions)${NC}" >&2
        return 0
    else
        echo -e "${RED}✗ Failed to set permissions: $dir_path${NC}" >&2
        PERMISSION_ERRORS+=("$dir_path")
        return 1
    fi
}

# Function to create BunkerWeb core directories
create_core_directories() {
    local install_dir="$1"
    
    echo -e "${BLUE}Creating BunkerWeb core directories...${NC}" >&2
    
    local core_dirs=(
        "$install_dir/storage"
        "$install_dir/database"
        "$install_dir/apps"
    )
    
    local success=0
    for dir in "${core_dirs[@]}"; do
        if create_directory "$dir"; then
            ((success++))
        fi
    done
    
    if [[ $success -eq ${#core_dirs[@]} ]]; then
        echo -e "${GREEN}✓ All core directories created successfully${NC}" >&2
        return 0
    else
        echo -e "${RED}✗ Failed to create some core directories${NC}" >&2
        return 1
    fi
}

# Function to create service-specific directories
create_service_directories() {
    local install_dir="$1"
    local redis_enabled="${2:-yes}"
    local syslog_enabled="${3:-no}"
    
    echo -e "${BLUE}Creating service-specific directories...${NC}" >&2
    
    local service_dirs=()
    
    # Add Redis directory if enabled
    if [[ "$redis_enabled" == "yes" ]]; then
        service_dirs+=("$install_dir/redis")
        echo -e "${BLUE}• Redis enabled - adding Redis data directory${NC}" >&2
    fi
    
    # Add Syslog directories if enabled
    if [[ "$syslog_enabled" == "yes" ]]; then
        service_dirs+=("$install_dir/logs" "$install_dir/syslog")
        echo -e "${BLUE}• Syslog enabled - adding log directories${NC}" >&2
    fi
    
    if [[ ${#service_dirs[@]} -eq 0 ]]; then
        echo -e "${BLUE}ℹ No additional service directories needed${NC}" >&2
        return 0
    fi
    
    local success=0
    for dir in "${service_dirs[@]}"; do
        if create_directory "$dir"; then
            ((success++))
        fi
    done
    
    if [[ $success -eq ${#service_dirs[@]} ]]; then
        echo -e "${GREEN}✓ All service directories created successfully${NC}" >&2
        return 0
    else
        echo -e "${RED}✗ Failed to create some service directories${NC}" >&2
        return 1
    fi
}

# Function to set up BunkerWeb container permissions
setup_container_permissions() {
    local install_dir="$1"
    local redis_enabled="${2:-yes}"
    local syslog_enabled="${3:-no}"
    
    echo -e "${BLUE}Setting up container permissions...${NC}" >&2
    
    local permission_errors=0
    
    # Storage directory - nginx user (uid 101, gid 101)
    if [[ -d "$install_dir/storage" ]]; then
        if ! set_directory_ownership "$install_dir/storage" "101" "101" "nginx (BunkerWeb)"; then
            ((permission_errors++))
        fi
        if ! set_directory_permissions "$install_dir/storage" "755" "yes" "storage"; then
            ((permission_errors++))
        fi
    fi
    
    # Database directory - mysql user (uid 999, gid 999)
    if [[ -d "$install_dir/database" ]]; then
        if ! set_directory_ownership "$install_dir/database" "999" "999" "mysql (MariaDB)"; then
            ((permission_errors++))
        fi
        if ! set_directory_permissions "$install_dir/database" "755" "yes" "database"; then
            ((permission_errors++))
        fi
    fi
    
    # Redis directory - redis user (uid 999, gid 999)
    if [[ "$redis_enabled" == "yes" && -d "$install_dir/redis" ]]; then
        if ! set_directory_ownership "$install_dir/redis" "999" "999" "redis (Redis)"; then
            ((permission_errors++))
        fi
        if ! set_directory_permissions "$install_dir/redis" "755" "yes" "Redis"; then
            ((permission_errors++))
        fi
    fi
    
    # Syslog directories - syslog user (varies by image)
    if [[ "$syslog_enabled" == "yes" ]]; then
        if [[ -d "$install_dir/logs" ]]; then
            if ! set_directory_ownership "$install_dir/logs" "101" "101" "syslog"; then
                ((permission_errors++))
            fi
            if ! set_directory_permissions "$install_dir/logs" "755" "yes" "syslog logs"; then
                ((permission_errors++))
            fi
        fi
        
        if [[ -d "$install_dir/syslog" ]]; then
            if ! set_directory_ownership "$install_dir/syslog" "101" "101" "syslog config"; then
                ((permission_errors++))
            fi
            if ! set_directory_permissions "$install_dir/syslog" "755" "yes" "syslog config"; then
                ((permission_errors++))
            fi
        fi
    fi
    
    if [[ $permission_errors -eq 0 ]]; then
        echo -e "${GREEN}✓ All container permissions set successfully${NC}" >&2
        return 0
    else
        echo -e "${YELLOW}⚠ $permission_errors permission errors occurred${NC}" >&2
        return 1
    fi
}

# Function to set up general file ownership
setup_general_ownership() {
    local install_dir="$1"
    
    echo -e "${BLUE}Setting up general file ownership...${NC}" >&2
    
    local owner_user="root"
    local owner_group="root"
    
    # Use sudo user if available
    if [[ -n "$SUDO_USER" ]]; then
        owner_user="$SUDO_USER"
        owner_group=$(id -gn "$SUDO_USER" 2>/dev/null || echo "root")
        echo -e "${GREEN}Setting general ownership to: $owner_user:$owner_group${NC}" >&2
    else
        echo -e "${YELLOW}Running as root directly, keeping root ownership for config files${NC}" >&2
    fi
    
    # Set ownership for main directory
    if ! chown "$owner_user:$owner_group" "$install_dir" 2>/dev/null; then
        echo -e "${YELLOW}⚠ Could not set ownership for: $install_dir${NC}" >&2
    fi
    
    # Set ownership for YAML files
    chown "$owner_user:$owner_group" "$install_dir"/*.yml 2>/dev/null || true
    
    # Set ownership for shell scripts
    chown "$owner_user:$owner_group" "$install_dir"/*.sh 2>/dev/null || true
    
    # Set ownership for apps directory
    if [[ -d "$install_dir/apps" ]]; then
        if ! chown "$owner_user:$owner_group" "$install_dir/apps" 2>/dev/null; then
            echo -e "${YELLOW}⚠ Could not set ownership for: $install_dir/apps${NC}" >&2
        fi
    fi
    
    # Set basic permissions
    chmod 755 "$install_dir" 2>/dev/null || true
    if [[ -d "$install_dir/apps" ]]; then
        chmod 755 "$install_dir/apps" 2>/dev/null || true
    fi
    
    echo -e "${GREEN}✓ General ownership configuration completed${NC}" >&2
    return 0
}

# Function to verify directory structure
verify_directory_structure() {
    local install_dir="$1"
    local redis_enabled="${2:-yes}"
    local syslog_enabled="${3:-no}"
    
    echo -e "${BLUE}Verifying directory structure...${NC}" >&2
    
    local required_dirs=(
        "$install_dir"
        "$install_dir/storage"
        "$install_dir/database"
        "$install_dir/apps"
    )
    
    # Add optional service directories
    [[ "$redis_enabled" == "yes" ]] && required_dirs+=("$install_dir/redis")
    [[ "$syslog_enabled" == "yes" ]] && required_dirs+=("$install_dir/logs" "$install_dir/syslog")
    
    local missing_dirs=()
    local permission_issues=()
    
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            missing_dirs+=("$dir")
        elif [[ ! -r "$dir" || ! -w "$dir" ]]; then
            permission_issues+=("$dir")
        fi
    done
    
    # Report results
    if [[ ${#missing_dirs[@]} -eq 0 && ${#permission_issues[@]} -eq 0 ]]; then
        echo -e "${GREEN}✓ Directory structure verification passed${NC}" >&2
        echo -e "${GREEN}✓ All required directories exist and are accessible${NC}" >&2
        return 0
    else
        if [[ ${#missing_dirs[@]} -gt 0 ]]; then
            echo -e "${RED}✗ Missing directories:${NC}" >&2
            for dir in "${missing_dirs[@]}"; do
                echo -e "${RED}  • $dir${NC}" >&2
            done
        fi
        
        if [[ ${#permission_issues[@]} -gt 0 ]]; then
            echo -e "${YELLOW}⚠ Permission issues:${NC}" >&2
            for dir in "${permission_issues[@]}"; do
                echo -e "${YELLOW}  • $dir${NC}" >&2
            done
        fi
        
        return 1
    fi
}

# Function to show directory layout summary
show_directory_summary() {
    local install_dir="$1"
    local redis_enabled="${2:-yes}"
    local syslog_enabled="${3:-no}"
    
    echo -e "${BLUE}Directory Layout Summary:${NC}" >&2
    echo -e "${GREEN}• Installation Directory: $install_dir${NC}" >&2
    echo -e "${GREEN}• Storage Directory: $install_dir/storage (nginx:101:101)${NC}" >&2
    echo -e "${GREEN}• Database Directory: $install_dir/database (mysql:999:999)${NC}" >&2
    echo -e "${GREEN}• Apps Directory: $install_dir/apps${NC}" >&2
    
    if [[ "$redis_enabled" == "yes" ]]; then
        echo -e "${GREEN}• Redis Directory: $install_dir/redis (redis:999:999)${NC}" >&2
    fi
    
    if [[ "$syslog_enabled" == "yes" ]]; then
        echo -e "${GREEN}• Logs Directory: $install_dir/logs (syslog:101:101)${NC}" >&2
        echo -e "${GREEN}• Syslog Config Directory: $install_dir/syslog (syslog:101:101)${NC}" >&2
    fi
    
    echo -e "${GREEN}• Created Directories: ${#CREATED_DIRECTORIES[@]}${NC}" >&2
    
    if [[ ${#PERMISSION_ERRORS[@]} -gt 0 ]]; then
        echo -e "${YELLOW}• Permission Errors: ${#PERMISSION_ERRORS[@]}${NC}" >&2
    fi
}

# Main function to set up complete directory structure
setup_directory_structure() {
    local install_dir="$1"
    local redis_enabled="${2:-yes}"
    local syslog_enabled="${3:-no}"
    
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo -e "${BLUE}                        DIRECTORY SETUP                        ${NC}" >&2
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo "" >&2
    
    # Clear tracking arrays
    CREATED_DIRECTORIES=()
    PERMISSION_ERRORS=()
    
    local setup_errors=0
    
    # Step 1: Create core directories
    echo -e "${BLUE}Step 1: Creating core directories${NC}" >&2
    if ! create_core_directories "$install_dir"; then
        ((setup_errors++))
    fi
    
    # Step 2: Create service directories
    echo -e "${BLUE}Step 2: Creating service directories${NC}" >&2
    if ! create_service_directories "$install_dir" "$redis_enabled" "$syslog_enabled"; then
        ((setup_errors++))
    fi
    
    # Step 3: Set up container permissions
    echo -e "${BLUE}Step 3: Setting up container permissions${NC}" >&2
    if ! setup_container_permissions "$install_dir" "$redis_enabled" "$syslog_enabled"; then
        ((setup_errors++))
    fi
    
    # Step 4: Set up general ownership
    echo -e "${BLUE}Step 4: Setting up general ownership${NC}" >&2
    if ! setup_general_ownership "$install_dir"; then
        ((setup_errors++))
    fi
    
    # Step 5: Verify structure
    echo -e "${BLUE}Step 5: Verifying directory structure${NC}" >&2
    if ! verify_directory_structure "$install_dir" "$redis_enabled" "$syslog_enabled"; then
        ((setup_errors++))
    fi
    
    # Show summary
    show_directory_summary "$install_dir" "$redis_enabled" "$syslog_enabled"
    
    echo "" >&2
    if [[ $setup_errors -eq 0 ]]; then
        echo -e "${GREEN}✓ Directory setup completed successfully${NC}" >&2
        echo "" >&2
        return 0
    else
        echo -e "${RED}✗ Directory setup completed with $setup_errors errors${NC}" >&2
        echo "" >&2
        return 1
    fi
}

# If script is run directly, show usage or run tests
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ "$1" == "test" ]]; then
        echo "Testing directory layout functions..."
        echo ""
        
        # Test directory creation
        echo "Testing directory creation:"
        TEST_DIR="/tmp/bunkerweb_test_$$"
        
        if create_directory "$TEST_DIR/test1" "test directory"; then
            echo "  ✓ Directory creation works"
            rm -rf "$TEST_DIR"
        else
            echo "  ✗ Directory creation failed"
        fi
        
        # Test ownership functions
        echo "Testing ownership functions:"
        if check_user_group_exists "0" "0" "root"; then
            echo "  ✓ User/group checking works"
        else
            echo "  ✗ User/group checking failed"
        fi
        
    else
        echo "BunkerWeb Directory Layout Helper Script"
        echo ""
        echo "This script is designed to be sourced by other scripts."
        echo ""
        echo "Available functions:"
        echo "  setup_directory_structure <install_dir> [redis_enabled] [syslog_enabled]"
        echo "  create_core_directories <install_dir>"
        echo "  create_service_directories <install_dir> [redis_enabled] [syslog_enabled]"
        echo "  setup_container_permissions <install_dir> [redis_enabled] [syslog_enabled]"
        echo "  verify_directory_structure <install_dir> [redis_enabled] [syslog_enabled]"
        echo "  show_directory_summary <install_dir> [redis_enabled] [syslog_enabled]"
        echo ""
        echo "Example usage:"
        echo "  source helper_directory_layout.sh"
        echo "  setup_directory_structure \"/data/BunkerWeb\" \"yes\" \"no\""
        echo ""
        echo "Run with 'test' argument to run diagnostic tests:"
        echo "  $0 test"
    fi
fi