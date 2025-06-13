#!/bin/bash

# install_loginbanner.sh - Login Banner Update System Installer
# Author: Michal Koeckeis-Fresel
# License: MIT
# This script installs a system that automatically updates the SSH login banner
# with current hostname and IP address information

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script paths
SCRIPT_PATH="/usr/local/bin/update-login-banner.sh"
SERVICE_PATH="/etc/systemd/system/update-login-banner.service"
ISSUE_PATH="/etc/issue"
ISSUE_NET_PATH="/etc/issue.net"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Create the banner update script
create_banner_script() {
    print_status "Creating banner update script..."
    
    cat > "$SCRIPT_PATH" << 'EOF'
#!/bin/bash

# Author: Michal Koeckeis-Fresel
# License: MIT

FQDN=$(hostname -f)
IP=$(hostname -I | awk '{print $1}')

# Update both /etc/issue (console) and /etc/issue.net (network/SSH)
echo -e "\nWelcome to $FQDN\nIP Address: $IP\n" > /etc/issue
echo -e "\nWelcome to $FQDN\nIP Address: $IP\n" > /etc/issue.net
EOF

    chmod +x "$SCRIPT_PATH"
    print_success "Banner update script created at $SCRIPT_PATH"
}

# Create the systemd service
create_systemd_service() {
    print_status "Creating systemd service..."
    
    cat > "$SERVICE_PATH" << 'EOF'
[Unit]
Description=Update login banner with hostname and IP
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-login-banner.sh

[Install]
WantedBy=multi-user.target
EOF

    print_success "Systemd service created at $SERVICE_PATH"
}

# Configure SSH to use the banner
configure_ssh_banner() {
    print_status "Configuring SSH to use /etc/issue.net as banner..."
    
    # Backup original sshd_config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)
    
    # Remove any existing Banner directive
    sed -i '/^[[:space:]]*Banner[[:space:]]/d' /etc/ssh/sshd_config
    
    # Add our banner configuration to use /etc/issue.net
    echo "Banner $ISSUE_NET_PATH" >> /etc/ssh/sshd_config
    
    print_success "SSH configuration updated to use $ISSUE_NET_PATH"
}

# Enable and start the service
enable_service() {
    print_status "Enabling and starting the service..."
    
    systemctl daemon-reload
    systemctl enable update-login-banner.service
    systemctl start update-login-banner.service
    
    # Check if service ran successfully
    if systemctl is-active --quiet update-login-banner.service; then
        print_success "Service is running"
    else
        # For oneshot services, check if it completed successfully
        if systemctl show -p ActiveState update-login-banner.service | grep -q "ActiveState=inactive"; then
            if systemctl show -p Result update-login-banner.service | grep -q "Result=success"; then
                print_success "Service completed successfully"
            else
                print_error "Service failed to complete successfully"
                systemctl status update-login-banner.service --no-pager
                exit 1
            fi
        fi
    fi
}

# Test SSH configuration
test_ssh_config() {
    print_status "Testing SSH configuration..."
    
    if sshd -t; then
        print_success "SSH configuration is valid"
    else
        print_error "SSH configuration test failed"
        print_warning "Restoring backup configuration..."
        # Find the most recent backup
        BACKUP_FILE=$(ls -t /etc/ssh/sshd_config.backup.* 2>/dev/null | head -1)
        if [[ -n "$BACKUP_FILE" ]]; then
            cp "$BACKUP_FILE" /etc/ssh/sshd_config
            print_warning "Configuration restored from $BACKUP_FILE"
        fi
        exit 1
    fi
}

# Restart SSH service
restart_ssh() {
    print_status "Restarting SSH service..."
    
    if systemctl restart sshd || systemctl restart ssh; then
        print_success "SSH service restarted successfully"
    else
        print_error "Failed to restart SSH service"
        exit 1
    fi
}

# Create a timer for periodic updates
create_timer() {
    print_status "Creating timer for automatic hourly banner updates..."
    
    cat > "/etc/systemd/system/update-login-banner.timer" << 'EOF'
[Unit]
Description=Update login banner hourly
Requires=update-login-banner.service

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable update-login-banner.timer
    systemctl start update-login-banner.timer
    
    print_success "Timer created and enabled (updates banner hourly)"
}

# Main installation function
install() {
    print_status "Starting login banner system installation..."
    
    check_root
    create_banner_script
    create_systemd_service
    configure_ssh_banner
    test_ssh_config
    enable_service
    restart_ssh
    create_timer
    
    print_success "Installation completed successfully!"
    echo
    print_status "Installed features:"
    echo "• SSH login banner with hostname and IP address"
    echo "• Automatic hourly banner updates"
    echo "• Console login banner (/etc/issue)"
    echo "• SSH login banner (/etc/issue.net)"
    echo
    print_status "Next steps:"
    echo "1. Test SSH connection to verify banner appears"
    echo "2. Manually run 'systemctl start update-login-banner.service' to update banner"
    echo "3. Check banner content at: $ISSUE_PATH (console) and $ISSUE_NET_PATH (SSH)"
    echo "4. View service logs with: 'journalctl -u update-login-banner.service'"
    echo "5. Check timer status with: 'systemctl status update-login-banner.timer'"
    echo
    print_status "Current banner content:"
    echo "----------------------------------------"
    cat "$ISSUE_NET_PATH" 2>/dev/null || echo "Banner file not found"
    echo "----------------------------------------"
}

# Uninstall function
uninstall() {
    print_status "Removing login banner system..."
    
    check_root
    
    # Stop and disable services
    systemctl stop update-login-banner.service 2>/dev/null || true
    systemctl disable update-login-banner.service 2>/dev/null || true
    systemctl stop update-login-banner.timer 2>/dev/null || true
    systemctl disable update-login-banner.timer 2>/dev/null || true
    
    # Remove files
    rm -f "$SCRIPT_PATH"
    rm -f "$SERVICE_PATH"
    rm -f "/etc/systemd/system/update-login-banner.timer"
    
    # Note: We don't remove /etc/issue and /etc/issue.net as they may be used by other systems
    
    # Remove banner from SSH config
    sed -i '/^[[:space:]]*Banner[[:space:]]/d' /etc/ssh/sshd_config
    
    # Reload systemd
    systemctl daemon-reload
    
    # Restart SSH
    systemctl restart sshd || systemctl restart ssh
    
    print_success "Login banner system removed successfully"
}

# Show usage
usage() {
    echo "Usage: $0 [install|uninstall|help]"
    echo
    echo "Commands:"
    echo "  install     Install the login banner update system (with hourly updates)"
    echo "  uninstall   Remove the login banner update system"
    echo "  help        Show this help message"
    echo
    echo "Note: This script must be run as root."
    echo
    echo "The login banner system automatically updates /etc/issue and /etc/issue.net"
    echo "with current hostname and IP address information for console and SSH logins."
    echo "Banner updates run automatically every hour."
}

# Main script logic
case "${1:-install}" in
    install)
        install
        ;;
    uninstall)
        uninstall
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        print_error "Unknown command: $1"
        usage
        exit 1
        ;;
esac