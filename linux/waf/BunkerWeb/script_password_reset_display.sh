#!/bin/bash

# Author: Michal Koeckeis-Fresel
# License: MIT

# BunkerWeb Admin Password Reset Script
# This script helps reset the admin password in the BunkerWeb database

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
NC='\033[0m' # No Color

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

# Check if bcrypt is available
if ! python3 -c "import bcrypt" 2>/dev/null; then
    echo -e "${YELLOW}Installing bcrypt library...${NC}"
    pip3 install bcrypt
    echo -e "${GREEN}✓ bcrypt installed${NC}"
fi

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

# Prompt for new admin password
echo ""
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

if [[ ${#NEW_PASSWORD} -lt 8 ]]; then
    echo -e "${RED}Error: Password must be at least 8 characters long${NC}"
    exit 1
fi

# Generate password hash using Method 1: Base64 (32 characters)
echo -e "${BLUE}Generating password hash...${NC}"
PASSWORD_HASH=$(python3 -c "from bcrypt import hashpw, gensalt; print(hashpw(b'$NEW_PASSWORD', gensalt(rounds=10)).decode('utf-8'))")
echo -e "${GREEN}✓ Password hash generated${NC}"

# Show current admin users
echo -e "${BLUE}Current admin users:${NC}"
docker exec -u 0 -it "$CONTAINER_ID" mysql -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -e "SELECT username, email, admin, creation_date FROM bw_ui_users WHERE admin = 1;" 2>/dev/null || {
    echo -e "${RED}Error: Could not connect to database${NC}"
    echo -e "${YELLOW}Please check if the database password is correct${NC}"
    exit 1
}

# Confirm password update
echo ""
echo -e "${YELLOW}This will update the password for ALL admin users.${NC}"
echo -e "${YELLOW}Continue? (y/N):${NC}"
read -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Password reset cancelled${NC}"
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
    echo -e "${BLUE}You can now log in with your new password at:${NC}"
    echo -e "${BLUE}http://$(hostname -I | awk '{print $1}')${NC}"
    
else
    echo -e "${RED}Error: Failed to update password${NC}"
    exit 1
fi