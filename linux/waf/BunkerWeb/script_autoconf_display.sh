#!/bin/bash

# Author: Michal Koeckeis-Fresel
# License: MIT

# BunkerWeb Setup Script
# This script generates random passwords and replaces placeholders in docker-compose.yml
# MUST BE RUN AS ROOT: sudo ./setup-bunkerweb.sh --type <autoconf|basic|integrated>

set -e

INSTALL_DIR="/data/BunkerWeb"
SETUP_MODE="wizard"  # Default to wizard mode

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display usage
show_usage() {
    echo -e "${BLUE}Usage: $0 --type <autoconf|basic|integrated>${NC}"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  --type autoconf     Use template_autoconf_display.yml"
    echo -e "  --type basic        Use template_basic_display.yml"
    echo -e "  --type integrated   Use template_ui_integrated_display.yml"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo -e "  sudo $0 --type autoconf"
    echo -e "  sudo $0 --type basic"
    echo -e "  sudo $0 --type integrated"
    echo ""
}

# Parse command line arguments
DEPLOYMENT_TYPE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --type)
            DEPLOYMENT_TYPE="$2"
            shift 2
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

# Validate that --type was provided
if [[ -z "$DEPLOYMENT_TYPE" ]]; then
    echo -e "${RED}Error: --type parameter is required${NC}"
    echo ""
    show_usage
    exit 1
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

# Generate passwords function using Method 1: Base64 (32 characters)
generate_password() {
    openssl rand -base64 32 | head -c 32 && echo
}

# Generate passwords
echo -e "${BLUE}Generating secure passwords using OpenSSL Method 1 (Base64, 32 chars)...${NC}"

# Generate MySQL password (used for both DATABASE_URI and MYSQL_PASSWORD)
MYSQL_PASSWORD=$(generate_password)
echo -e "${GREEN}✓ MySQL password generated${NC}"

# Generate TOTP secret
TOTP_SECRET=$(generate_password)
echo -e "${GREEN}✓ TOTP secret generated${NC}"

# Display setup options
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}          Setup Configuration${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""
echo -e "${YELLOW}Choose your setup method:${NC}"
echo ""
echo -e "${GREEN}1. Setup Wizard (Default)${NC} - Manual configuration via web interface"
echo -e "${GREEN}2. Automated Setup${NC} - Skip wizard with pre-configured admin account"
echo ""
echo -e "${BLUE}Selection (1/2) [1]:${NC}"
read -n 1 -r SETUP_CHOICE
echo ""

# Create credentials file for backup
CREDS_FILE="$INSTALL_DIR/credentials.txt"
cat > "$CREDS_FILE" << EOF
# BunkerWeb Generated Credentials
# Deployment Type: $DEPLOYMENT_NAME
# Template Used: $TEMPLATE_FILE
# Generated on: $(date)
# Keep this file secure and backed up!

MySQL Database Password: $MYSQL_PASSWORD
TOTP Secret Key: $TOTP_SECRET

# Database Connection String:
# mariadb+pymysql://bunkerweb:$MYSQL_PASSWORD@bw-db:3306/db
EOF

if [[ $SETUP_CHOICE == "2" ]]; then
    # Automated setup
    echo -e "${BLUE}Setting up automated configuration...${NC}"
    
    # Generate additional passwords for automated setup
    ADMIN_PASSWORD=$(generate_password)
    FLASK_SECRET=$(generate_password)
    
    # Prompt for admin username
    echo -e "${BLUE}Enter admin username [admin]:${NC}"
    read ADMIN_USERNAME
    ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
    
    # Update credentials file with admin info
    cat >> "$CREDS_FILE" << EOF

# Automated Web UI Setup
Admin Username: $ADMIN_USERNAME
Admin Password: $ADMIN_PASSWORD
Flask Secret: $FLASK_SECRET
EOF
    
    # Enable automated setup in docker-compose.yml
    sed -i 's/# OVERRIDE_ADMIN_CREDS: "yes"/OVERRIDE_ADMIN_CREDS: "yes"/' "$COMPOSE_FILE"
    sed -i 's/# ADMIN_USERNAME: "admin"/ADMIN_USERNAME: "'$ADMIN_USERNAME'"/' "$COMPOSE_FILE"
    sed -i 's/# ADMIN_PASSWORD: "REPLACEME_ADMIN"/ADMIN_PASSWORD: "'$ADMIN_PASSWORD'"/' "$COMPOSE_FILE"
    sed -i 's/# FLASK_SECRET: "REPLACEME_FLASK"/FLASK_SECRET: "'$FLASK_SECRET'"/' "$COMPOSE_FILE"
    
    echo -e "${GREEN}✓ Automated setup configured${NC}"
    echo -e "${GREEN}✓ Admin credentials updated${NC}"
    
    SETUP_MODE="automated"
else
    echo -e "${BLUE}Using traditional setup wizard${NC}"
    SETUP_MODE="wizard"
fi

# Secure the credentials file
chmod 600 "$CREDS_FILE"
echo -e "${GREEN}✓ Credentials saved to: $CREDS_FILE${NC}"

# Replace placeholders in docker-compose.yml
echo -e "${BLUE}Updating docker-compose.yml...${NC}"

# Replace REPLACEME_MYSQL (both in DATABASE_URI and MYSQL_PASSWORD)
sed -i "s/REPLACEME_MYSQL/$MYSQL_PASSWORD/g" "$COMPOSE_FILE"
echo -e "${GREEN}✓ MySQL passwords updated${NC}"

# Replace REPLACEME_DEFAULT (TOTP_SECRETS)
sed -i "s/REPLACEME_DEFAULT/$TOTP_SECRET/g" "$COMPOSE_FILE"
echo -e "${GREEN}✓ TOTP secret updated${NC}"

# If automated setup was chosen, replace additional placeholders
if [[ $SETUP_MODE == "automated" ]]; then
    sed -i "s/REPLACEME_ADMIN/$ADMIN_PASSWORD/g" "$COMPOSE_FILE"
    sed -i "s/REPLACEME_FLASK/$FLASK_SECRET/g" "$COMPOSE_FILE"
    echo -e "${GREEN}✓ Admin password updated${NC}"
    echo -e "${GREEN}✓ Flask secret updated${NC}"
fi

# Verify replacements
echo -e "${BLUE}Verifying configuration...${NC}"

REMAINING_PLACEHOLDERS=$(grep -o "REPLACEME_[A-Z_]*" "$COMPOSE_FILE" || true)
if [[ -n "$REMAINING_PLACEHOLDERS" ]]; then
    echo -e "${RED}Error: Some placeholders were not replaced!${NC}"
    echo "Remaining placeholders: $REMAINING_PLACEHOLDERS"
    echo -e "${YELLOW}Restoring backup...${NC}"
    cp "$BACKUP_FILE" "$COMPOSE_FILE"
    exit 1
else
    echo -e "${GREEN}✓ All placeholders successfully replaced${NC}"
fi

# Create required directories
echo -e "${BLUE}Creating directories...${NC}"
mkdir -p "$INSTALL_DIR/storage"
mkdir -p "$INSTALL_DIR/database"
mkdir -p "$INSTALL_DIR/apps"

# Set proper ownership and permissions
echo -e "${BLUE}Setting permissions...${NC}"

# Get the user who originally ran sudo (if applicable)
if [[ -n "$SUDO_USER" ]]; then
    OWNER_USER="$SUDO_USER"
    OWNER_GROUP=$(id -gn "$SUDO_USER")
    echo -e "${GREEN}Setting ownership to: $OWNER_USER:$OWNER_GROUP${NC}"
    chown -R "$OWNER_USER:$OWNER_GROUP" "$INSTALL_DIR"
else
    echo -e "${YELLOW}Running as root directly, keeping root ownership${NC}"
fi

chmod -R 755 "$INSTALL_DIR"
chmod 600 "$CREDS_FILE"  # Keep credentials file secure
echo -e "${GREEN}✓ Directories created and permissions set${NC}"

# Display summary
echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}          Setup Complete!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${YELLOW}Deployment Type:${NC} $DEPLOYMENT_NAME"
echo -e "${YELLOW}Template Used:${NC} $TEMPLATE_FILE"
echo -e "${YELLOW}Installation Directory:${NC} $INSTALL_DIR"
echo -e "${YELLOW}Credentials File:${NC} $CREDS_FILE"
echo -e "${YELLOW}Backup File:${NC} $BACKUP_FILE"
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
        echo "5. Complete the setup wizard"
    else
        echo "1. cd $INSTALL_DIR"
        echo "2. docker compose up -d"
        echo "3. Navigate to http://your-server-ip/setup"
        echo "4. Complete the setup wizard"
    fi
fi
echo ""
echo -e "${RED}IMPORTANT:${NC}"
echo -e "${RED}• Keep the credentials file secure: $CREDS_FILE${NC}"
echo -e "${RED}• Backup your installation regularly${NC}"
echo -e "${RED}• The backup file can restore original template: $BACKUP_FILE${NC}"
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
        echo -e "${GREEN}Web Interface:${NC} http://$SERVER_IP"
        echo ""
        echo -e "${YELLOW}Login Credentials:${NC}"
        echo -e "${YELLOW}Username:${NC} $ADMIN_USERNAME"
        echo -e "${YELLOW}Password:${NC} $ADMIN_PASSWORD"
        echo ""
        echo -e "${GREEN}✓ No setup wizard required - ready to use!${NC}"
        echo -e "${BLUE}💡 All credentials saved in: $CREDS_FILE${NC}"
    else
        echo -e "${BLUE}Setup Wizard:${NC} http://$SERVER_IP/setup"
        echo -e "${BLUE}Web Interface:${NC} http://$SERVER_IP (after setup)"
        echo ""
        echo -e "${YELLOW}Complete the setup wizard to finish configuration!${NC}"
    fi
else
    echo -e "${RED}Warning: Some services may not have started properly${NC}"
    echo -e "${YELLOW}Check logs with: cd $INSTALL_DIR && docker compose logs${NC}"
fi

echo ""
echo -e "${GREEN}Setup script completed successfully!${NC}"