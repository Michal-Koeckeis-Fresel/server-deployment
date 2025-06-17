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

# BunkerWeb Admin Password Reset Script - Auto Generation
# This script automatically generates a new admin password or allows manual entry

set -e

INSTALL_DIR="/data/BunkerWeb"
DB_CONTAINER_NAME="bw-db"
DB_USER="bunkerweb"
DB_NAME="db"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to display usage
show_usage() {
    echo -e "${BLUE}Usage: $0 [OPTIONS]${NC}"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  --auto              Auto-generate password (default)"
    echo -e "  --manual            Manually enter password"
    echo -e "  --length LENGTH     Password length for auto-generation (default: 8)"
    echo -e "  --show-only         Only show current admin users (no password change)"
    echo -e "  -h, --help          Show this help message"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo -e "  $0                  # Auto-generate 8-character password"
    echo -e "  $0 --auto --length 12   # Auto-generate 12-character password"
    echo -e "  $0 --manual         # Manually enter password"
    echo -e "  $0 --show-only      # Just show current admin users"
}

# Parse command line arguments
AUTO_GENERATE="yes"
PASSWORD_LENGTH="8"
SHOW_ONLY="no"

while [[ $# -gt 0 ]]; do
    case $1 in
        --auto)
            AUTO_GENERATE="yes"
            shift
            ;;
        --manual)
            AUTO_GENERATE="no"
            shift
            ;;
        --length)
            PASSWORD_LENGTH="$2"
            shift 2
            ;;
        --show-only)
            SHOW_ONLY="yes"
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

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}      BunkerWeb Admin Password Reset${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Check if running from correct directory
if [[ ! -f "$INSTALL_DIR/docker-compose.yml" ]]; then
    echo -e "${RED}Error: BunkerWeb not found at $INSTALL_DIR${NC}"
    echo -e "${YELLOW}Please ensure BunkerWeb is installed in $INSTALL_DIR${NC}"
    exit 1
fi

cd "$INSTALL_DIR"

# Check if containers are running
if ! docker compose ps | grep -q "$DB_CONTAINER_NAME"; then
    echo -e "${RED}Error: Database container not found or not running${NC}"
    echo -e "${YELLOW}Please start BunkerWeb first: docker compose up -d${NC}"
    exit 1
fi

# Get the actual container name/ID
CONTAINER_ID=$(docker compose ps -q "$DB_CONTAINER_NAME")
if [[ -z "$CONTAINER_ID" ]]; then
    echo -e "${RED}Error: Could not find database container${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Found database container: $CONTAINER_ID${NC}"

# Function to install bcrypt on Debian/Ubuntu systems
install_bcrypt() {
    if command -v apt >/dev/null 2>&1; then
        echo -e "${BLUE}Installing python3-bcrypt using apt...${NC}"
        if apt update && apt install -y python3-bcrypt; then
            echo -e "${GREEN}✓ python3-bcrypt installed via apt${NC}"
            return 0
        else
            echo -e "${RED}✗ Failed to install python3-bcrypt via apt${NC}"
            return 1
        fi
    elif command -v yum >/dev/null 2>&1; then
        echo -e "${BLUE}Installing python3-bcrypt using yum...${NC}"
        if yum install -y python3-bcrypt; then
            echo -e "${GREEN}✓ python3-bcrypt installed via yum${NC}"
            return 0
        else
            echo -e "${RED}✗ Failed to install python3-bcrypt via yum${NC}"
            return 1
        fi
    elif command -v dnf >/dev/null 2>&1; then
        echo -e "${BLUE}Installing python3-bcrypt using dnf...${NC}"
        if dnf install -y python3-bcrypt; then
            echo -e "${GREEN}✓ python3-bcrypt installed via dnf${NC}"
            return 0
        else
            echo -e "${RED}✗ Failed to install python3-bcrypt via dnf${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}Package manager not detected. Trying pip with virtual environment...${NC}"
        return 1
    fi
}

# Function to create virtual environment and install bcrypt
install_bcrypt_venv() {
    local venv_dir="/tmp/bunkerweb-reset-venv"
    
    echo -e "${BLUE}Creating virtual environment for bcrypt...${NC}"
    
    if python3 -m venv "$venv_dir"; then
        echo -e "${GREEN}✓ Virtual environment created${NC}"
        
        if "$venv_dir/bin/pip" install bcrypt; then
            echo -e "${GREEN}✓ bcrypt installed in virtual environment${NC}"
            PYTHON_CMD="$venv_dir/bin/python3"
            return 0
        else
            echo -e "${RED}✗ Failed to install bcrypt in virtual environment${NC}"
            return 1
        fi
    else
        echo -e "${RED}✗ Failed to create virtual environment${NC}"
        return 1
    fi
}

# Get database password from credentials file
CREDS_FILE="$INSTALL_DIR/credentials.txt"
if [[ -f "$CREDS_FILE" ]]; then
    DB_PASSWORD=$(grep "MySQL Database Password:" "$CREDS_FILE" | cut -d' ' -f4)
    echo -e "${GREEN}✓ Database password found in credentials file${NC}"
else
    echo -e "${YELLOW}Credentials file not found. Please enter database password manually.${NC}"
    echo -n "Database password: "
    read -s DB_PASSWORD
    echo
fi

# Show current admin users
echo -e "${BLUE}Current admin users:${NC}"
docker exec -u 0 -it "$CONTAINER_ID" mysql -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -e "SELECT username, email, admin, creation_date FROM bw_ui_users WHERE admin = 1;" 2>/dev/null || {
    echo -e "${RED}Error: Could not connect to database${NC}"
    echo -e "${YELLOW}Please check if the database password is correct${NC}"
    exit 1
}

# If only showing users, exit here
if [[ "$SHOW_ONLY" == "yes" ]]; then
    echo ""
    echo -e "${GREEN}Admin user information displayed successfully${NC}"
    exit 0
fi

# Check if bcrypt is available and install if needed (only if not show-only)
PYTHON_CMD="python3"

if ! python3 -c "import bcrypt" 2>/dev/null; then
    echo -e "${YELLOW}bcrypt library not found. Attempting to install...${NC}"
    
    # Try system package manager first
    if install_bcrypt; then
        echo -e "${GREEN}✓ bcrypt installed via system package manager${NC}"
    elif install_bcrypt_venv; then
        echo -e "${GREEN}✓ bcrypt installed via virtual environment${NC}"
    else
        echo -e "${RED}✗ Failed to install bcrypt${NC}"
        echo -e "${YELLOW}Manual installation options:${NC}"
        echo -e "${BLUE}1. sudo apt install python3-bcrypt${NC}"
        echo -e "${BLUE}2. python3 -m venv /tmp/venv && /tmp/venv/bin/pip install bcrypt${NC}"
        echo -e "${BLUE}3. pip3 install bcrypt --break-system-packages (not recommended)${NC}"
        exit 1
    fi
fi

# Verify bcrypt is now available
if ! $PYTHON_CMD -c "import bcrypt" 2>/dev/null; then
    echo -e "${RED}✗ bcrypt still not available after installation attempt${NC}"
    exit 1
fi

echo -e "${GREEN}✓ bcrypt library is available${NC}"

# Generate or prompt for new password
if [[ "$AUTO_GENERATE" == "yes" ]]; then
    echo ""
    echo -e "${CYAN}Auto-generating new admin password...${NC}"
    
    # Check if openssl is available
    if ! command -v openssl >/dev/null 2>&1; then
        echo -e "${RED}Error: openssl not found. Please install openssl or use --manual option${NC}"
        exit 1
    fi
    
    # Generate password using openssl
    NEW_PASSWORD=$(openssl rand -base64 "$PASSWORD_LENGTH" | tr -d "=+/" | cut -c1-"$PASSWORD_LENGTH")
    
    # Ensure minimum length of 8 characters
    while [[ ${#NEW_PASSWORD} -lt 8 ]]; do
        ADDITIONAL_CHARS=$(openssl rand -base64 4 | tr -d "=+/" | cut -c1-$((8 - ${#NEW_PASSWORD})))
        NEW_PASSWORD="$NEW_PASSWORD$ADDITIONAL_CHARS"
    done
    
    echo -e "${GREEN}✓ Generated password: ${YELLOW}$NEW_PASSWORD${NC}"
    echo -e "${CYAN}Password length: ${#NEW_PASSWORD} characters${NC}"
    echo ""
    echo -e "${YELLOW}⚠ Please save this password securely!${NC}"
    echo ""
    
else
    echo ""
    echo -e "${BLUE}Manual password entry mode${NC}"
    echo -e "${BLUE}Enter new admin password:${NC}"
    read -s NEW_PASSWORD
    echo ""
    echo -e "${BLUE}Confirm new admin password:${NC}"
    read -s CONFIRM_PASSWORD
    echo ""

    if [[ "$NEW_PASSWORD" != "$CONFIRM_PASSWORD" ]]; then
        echo -e "${RED}Error: Passwords do not match${NC}"
        exit 1
    fi
fi

# Validate password length
if [[ ${#NEW_PASSWORD} -lt 8 ]]; then
    echo -e "${RED}Error: Password must be at least 8 characters long${NC}"
    exit 1
fi

# Generate password hash using bcrypt
echo -e "${BLUE}Generating password hash...${NC}"
PASSWORD_HASH=$($PYTHON_CMD -c "from bcrypt import hashpw, gensalt; print(hashpw(b'$NEW_PASSWORD', gensalt(rounds=10)).decode('utf-8'))")

if [[ -z "$PASSWORD_HASH" ]]; then
    echo -e "${RED}✗ Failed to generate password hash${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Password hash generated${NC}"

# Confirm password update
echo ""
echo -e "${YELLOW}This will update the password for ALL admin users.${NC}"
if [[ "$AUTO_GENERATE" == "yes" ]]; then
    echo -e "${CYAN}New password: $NEW_PASSWORD${NC}"
fi
echo -e "${YELLOW}Continue? (y/N):${NC}"
read -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Password reset cancelled${NC}"
    
    # Clean up virtual environment if created
    if [[ "$PYTHON_CMD" == *"/tmp/bunkerweb-reset-venv/"* ]]; then
        rm -rf "/tmp/bunkerweb-reset-venv"
        echo -e "${BLUE}✓ Temporary virtual environment cleaned up${NC}"
    fi
    
    exit 0
fi

# Update password
echo -e "${BLUE}Updating admin password...${NC}"
docker exec -u 0 "$CONTAINER_ID" mysql -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -e "UPDATE bw_ui_users SET password = '$PASSWORD_HASH', update_date = NOW() WHERE admin = 1;" 2>/dev/null

if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}✓ Admin password updated successfully!${NC}"
    
    # Show updated admin users
    echo -e "${BLUE}Updated admin users:${NC}"
    docker exec -u 0 "$CONTAINER_ID" mysql -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -e "SELECT username, email, admin, update_date FROM bw_ui_users WHERE admin = 1;" 2>/dev/null
    
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}     Password Reset Complete!${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    
    if [[ "$AUTO_GENERATE" == "yes" ]]; then
        echo -e "${CYAN}🔑 New Admin Credentials:${NC}"
        echo -e "${CYAN}Username: admin${NC}"
        echo -e "${CYAN}Password: ${YELLOW}$NEW_PASSWORD${NC}"
        echo ""
        echo -e "${YELLOW}⚠ IMPORTANT: Save this password securely!${NC}"
        echo -e "${YELLOW}⚠ This password will not be shown again!${NC}"
        echo ""
        
        # Update credentials file with new password
        if [[ -f "$CREDS_FILE" ]]; then
            # Create backup
            cp "$CREDS_FILE" "$CREDS_FILE.backup.$(date +%Y%m%d_%H%M%S)"
            
            # Update admin password in credentials file
            sed -i "s/^Admin Password: .*/Admin Password: $NEW_PASSWORD/" "$CREDS_FILE"
            echo -e "${GREEN}✓ Credentials file updated: $CREDS_FILE${NC}"
            echo -e "${BLUE}✓ Backup created: $CREDS_FILE.backup.*${NC}"
        fi
    fi
    
    echo -e "${BLUE}You can now log in at:${NC}"
    echo -e "${BLUE}http://$(hostname -I | awk '{print $1}')${NC}"
    
else
    echo -e "${RED}Error: Failed to update password${NC}"
    exit 1
fi

# Clean up virtual environment if created
if [[ "$PYTHON_CMD" == *"/tmp/bunkerweb-reset-venv/"* ]]; then
    rm -rf "/tmp/bunkerweb-reset-venv"
    echo -e "${BLUE}✓ Temporary virtual environment cleaned up${NC}"
fi