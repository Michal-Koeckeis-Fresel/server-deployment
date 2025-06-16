#!/bin/bash
#
# Redis Password Manager Script
# Handles all password generation, loading, and credential management for Redis
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables for Redis credentials
REDIS_PASSWORD=""
REDIS_SENTINEL_PASSWORD=""
REDIS_CLUSTER_AUTH=""
REDIS_ADMIN_PASSWORD=""
REDIS_REPLICATION_PASSWORD=""

# Password generation functions
generate_redis_password() {
    openssl rand -base64 33
}

generate_secure_password() {
    openssl rand -base64 33
}

generate_cluster_auth() {
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
    
    REDIS_PASSWORD=$(grep "Redis Password:" "$creds_file" | cut -d' ' -f3 2>/dev/null || echo "")
    REDIS_SENTINEL_PASSWORD=$(grep "Sentinel Password:" "$creds_file" | cut -d' ' -f3 2>/dev/null || echo "")
    REDIS_CLUSTER_AUTH=$(grep "Cluster Auth:" "$creds_file" | cut -d' ' -f3 2>/dev/null || echo "")
    REDIS_ADMIN_PASSWORD=$(grep "Admin Password:" "$creds_file" | cut -d' ' -f3 2>/dev/null || echo "")
    REDIS_REPLICATION_PASSWORD=$(grep "Replication Password:" "$creds_file" | cut -d' ' -f3 2>/dev/null || echo "")
    
    local loaded_count=0
    [[ -n "$REDIS_PASSWORD" ]] && ((loaded_count++))
    [[ -n "$REDIS_SENTINEL_PASSWORD" ]] && ((loaded_count++))
    [[ -n "$REDIS_CLUSTER_AUTH" ]] && ((loaded_count++))
    [[ -n "$REDIS_ADMIN_PASSWORD" ]] && ((loaded_count++))
    [[ -n "$REDIS_REPLICATION_PASSWORD" ]] && ((loaded_count++))
    
    if [[ $loaded_count -ge 1 ]]; then
        echo -e "${GREEN}✓ Successfully loaded $loaded_count existing credentials${NC}" >&2
        return 0
    else
        echo -e "${YELLOW}⚠ No valid credentials found${NC}" >&2
        return 1
    fi
}

# Function to generate missing credentials
generate_missing_credentials() {
    local redis_mode="$1"  # standalone, sentinel, cluster
    local generated_count=0
    
    echo -e "${BLUE}Generating missing credentials for Redis mode: $redis_mode${NC}" >&2
    
    # Always generate main Redis password if missing
    if [[ -z "$REDIS_PASSWORD" ]]; then
        REDIS_PASSWORD=$(generate_redis_password)
        echo -e "${GREEN}✓ Generated Redis main password${NC}" >&2
        ((generated_count++))
    fi
    
    # Generate admin password (for management tools)
    if [[ -z "$REDIS_ADMIN_PASSWORD" ]]; then
        REDIS_ADMIN_PASSWORD=$(generate_redis_password)
        echo -e "${GREEN}✓ Generated Redis admin password${NC}" >&2
        ((generated_count++))
    fi
    
    # Generate additional credentials based on mode
    case "$redis_mode" in
        "sentinel")
            if [[ -z "$REDIS_SENTINEL_PASSWORD" ]]; then
                REDIS_SENTINEL_PASSWORD=$(generate_secure_password)
                echo -e "${GREEN}✓ Generated Redis Sentinel password${NC}" >&2
                ((generated_count++))
            fi
            if [[ -z "$REDIS_REPLICATION_PASSWORD" ]]; then
                REDIS_REPLICATION_PASSWORD=$(generate_secure_password)
                echo -e "${GREEN}✓ Generated Redis replication password${NC}" >&2
                ((generated_count++))
            fi
            ;;
        "cluster")
            if [[ -z "$REDIS_CLUSTER_AUTH" ]]; then
                REDIS_CLUSTER_AUTH=$(generate_cluster_auth)
                echo -e "${GREEN}✓ Generated Redis cluster auth token${NC}" >&2
                ((generated_count++))
            fi
            if [[ -z "$REDIS_REPLICATION_PASSWORD" ]]; then
                REDIS_REPLICATION_PASSWORD=$(generate_secure_password)
                echo -e "${GREEN}✓ Generated Redis replication password${NC}" >&2
                ((generated_count++))
            fi
            ;;
        "standalone"|*)
            # Standalone mode - only main and admin passwords needed
            echo -e "${BLUE}ℹ Standalone mode - using basic authentication${NC}" >&2
            ;;
    esac
    
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
    local redis_mode="$2"
    local redis_port="$3"
    local redis_host="$4"
    local max_memory="$5"
    local data_dir="$6"
    local config_file="$7"
    
    echo -e "${BLUE}Saving credentials to: $creds_file${NC}" >&2
    
    # Create backup if file exists
    if [[ -f "$creds_file" ]]; then
        cp "$creds_file" "$creds_file.backup.$(date +%Y%m%d_%H%M%S)"
        echo -e "${GREEN}✓ Existing credentials backed up${NC}" >&2
    fi
    
    cat > "$creds_file" << EOF
# Redis Generated Credentials
# Redis Mode: ${redis_mode:-"standalone"}
# Generated on: $(date)
# Keep this file secure and backed up!

# Main Redis Authentication
Redis Password: $REDIS_PASSWORD
Admin Password: $REDIS_ADMIN_PASSWORD

$(if [[ "$redis_mode" == "sentinel" ]]; then
cat << 'SENTINEL_EOF'
# Redis Sentinel Configuration
Sentinel Password: $REDIS_SENTINEL_PASSWORD
Replication Password: $REDIS_REPLICATION_PASSWORD
SENTINEL_EOF
fi)

$(if [[ "$redis_mode" == "cluster" ]]; then
cat << 'CLUSTER_EOF'
# Redis Cluster Configuration  
Cluster Auth: $REDIS_CLUSTER_AUTH
Replication Password: $REDIS_REPLICATION_PASSWORD
CLUSTER_EOF
fi)

# Connection Details
Redis Host: ${redis_host:-"localhost"}
Redis Port: ${redis_port:-"6379"}
Max Memory: ${max_memory:-"256mb"}

# File Locations
Data Directory: ${data_dir:-"/var/lib/redis"}
Config File: ${config_file:-"/etc/redis/redis.conf"}

# Connection Strings
Redis CLI: redis-cli -h ${redis_host:-"localhost"} -p ${redis_port:-"6379"} -a '$REDIS_PASSWORD'
Redis URL: redis://:$REDIS_PASSWORD@${redis_host:-"localhost"}:${redis_port:-"6379"}/0

$(if [[ "$redis_mode" == "sentinel" ]]; then
cat << 'SENTINEL_CONN_EOF'
# Sentinel Connection
Sentinel CLI: redis-cli -h ${redis_host:-"localhost"} -p 26379 -a '$REDIS_SENTINEL_PASSWORD'
Sentinel URL: redis-sentinel://:$REDIS_SENTINEL_PASSWORD@${redis_host:-"localhost"}:26379
SENTINEL_CONN_EOF
fi)

# Management Commands
Start Service: systemctl start redis-server
Stop Service: systemctl stop redis-server
Restart Service: systemctl restart redis-server
Status: systemctl status redis-server
Monitor: redis-cli -p ${redis_port:-"6379"} -a '$REDIS_PASSWORD' monitor
Info: redis-cli -p ${redis_port:-"6379"} -a '$REDIS_PASSWORD' info

# Security Information:
# All passwords: 264-bit entropy (44 characters, base64 encoded)
# Generated using: openssl rand -base64 33
# Character set: A-Z, a-z, 0-9, +, /, =
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
REDIS_PASSWORD="$REDIS_PASSWORD"
REDIS_SENTINEL_PASSWORD="$REDIS_SENTINEL_PASSWORD"
REDIS_CLUSTER_AUTH="$REDIS_CLUSTER_AUTH"
REDIS_ADMIN_PASSWORD="$REDIS_ADMIN_PASSWORD"
REDIS_REPLICATION_PASSWORD="$REDIS_REPLICATION_PASSWORD"
EOF
}

# Function to validate that all required passwords are set
validate_credentials() {
    local redis_mode="$1"
    local missing=()
    
    [[ -z "$REDIS_PASSWORD" ]] && missing+=("Redis password")
    [[ -z "$REDIS_ADMIN_PASSWORD" ]] && missing+=("Admin password")
    
    case "$redis_mode" in
        "sentinel")
            [[ -z "$REDIS_SENTINEL_PASSWORD" ]] && missing+=("Sentinel password")
            [[ -z "$REDIS_REPLICATION_PASSWORD" ]] && missing+=("Replication password")
            ;;
        "cluster")
            [[ -z "$REDIS_CLUSTER_AUTH" ]] && missing+=("Cluster auth token")
            [[ -z "$REDIS_REPLICATION_PASSWORD" ]] && missing+=("Replication password")
            ;;
        "standalone"|*)
            # Only main and admin passwords required for standalone
            ;;
    esac
    
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
    local redis_mode="$1"
    
    echo -e "${BLUE}Credential Summary:${NC}" >&2
    echo -e "${GREEN}• Redis Password: ${REDIS_PASSWORD:0:8}... (${#REDIS_PASSWORD} chars)${NC}" >&2
    echo -e "${GREEN}• Admin Password: ${REDIS_ADMIN_PASSWORD:0:8}... (${#REDIS_ADMIN_PASSWORD} chars)${NC}" >&2
    
    case "$redis_mode" in
        "sentinel")
            echo -e "${GREEN}• Sentinel Password: ${REDIS_SENTINEL_PASSWORD:0:8}... (${#REDIS_SENTINEL_PASSWORD} chars)${NC}" >&2
            echo -e "${GREEN}• Replication Password: ${REDIS_REPLICATION_PASSWORD:0:8}... (${#REDIS_REPLICATION_PASSWORD} chars)${NC}" >&2
            ;;
        "cluster")
            echo -e "${GREEN}• Cluster Auth: ${REDIS_CLUSTER_AUTH:0:8}... (${#REDIS_CLUSTER_AUTH} chars)${NC}" >&2
            echo -e "${GREEN}• Replication Password: ${REDIS_REPLICATION_PASSWORD:0:8}... (${#REDIS_REPLICATION_PASSWORD} chars)${NC}" >&2
            ;;
        "standalone"|*)
            echo -e "${BLUE}• Mode: Standalone (high-entropy authentication)${NC}" >&2
            ;;
    esac
}

# Function to generate connection test script
generate_connection_test() {
    local test_file="$1"
    local redis_host="${2:-localhost}"
    local redis_port="${3:-6379}"
    
    cat > "$test_file" << EOF
#!/bin/bash
# Redis Connection Test Script
# Generated by Redis Password Manager

echo "Testing Redis connection..."
echo "=========================="

# Test main Redis connection
echo "Testing main Redis server..."
if redis-cli -h $redis_host -p $redis_port -a '$REDIS_PASSWORD' ping | grep -q "PONG"; then
    echo "✓ Main Redis server: Connected"
else
    echo "✗ Main Redis server: Connection failed"
fi

# Test admin connection
echo "Testing admin access..."
if redis-cli -h $redis_host -p $redis_port -a '$REDIS_ADMIN_PASSWORD' ping | grep -q "PONG"; then
    echo "✓ Admin access: Connected"
else
    echo "✗ Admin access: Connection failed"
fi

# Get server info
echo ""
echo "Redis Server Information:"
echo "========================"
redis-cli -h $redis_host -p $redis_port -a '$REDIS_PASSWORD' info server | grep -E "redis_version|process_id|tcp_port|uptime_in_seconds"

echo ""
echo "Memory Usage:"
echo "============="
redis-cli -h $redis_host -p $redis_port -a '$REDIS_PASSWORD' info memory | grep -E "used_memory_human|used_memory_peak_human|maxmemory_human"

echo ""
echo "Connected Clients:"
echo "=================="
redis-cli -h $redis_host -p $redis_port -a '$REDIS_PASSWORD' info clients | grep -E "connected_clients|blocked_clients"
EOF
    
    chmod +x "$test_file"
    echo -e "${GREEN}✓ Connection test script created: $test_file${NC}" >&2
}

# Main function for complete credential management
manage_credentials() {
    local creds_file="$1"
    local redis_mode="${2:-standalone}"
    local redis_port="${3:-6379}"
    local redis_host="${4:-localhost}"
    local max_memory="${5:-256mb}"
    local data_dir="${6:-/var/lib/redis}"
    local config_file="${7:-/etc/redis/redis.conf}"
    
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo -e "${BLUE}                        REDIS CREDENTIAL MANAGEMENT                        ${NC}" >&2
    echo -e "${BLUE}=================================================================================${NC}" >&2
    echo "" >&2
    
    # Try to load existing credentials
    if load_existing_credentials "$creds_file"; then
        echo -e "${GREEN}✓ Existing credentials loaded successfully${NC}" >&2
    else
        echo -e "${BLUE}ℹ No existing credentials found or incomplete${NC}" >&2
    fi
    
    # Generate any missing credentials
    generate_missing_credentials "$redis_mode"
    
    # Validate all credentials are present
    if ! validate_credentials "$redis_mode"; then
        echo -e "${RED}✗ Credential validation failed${NC}" >&2
        return 1
    fi
    
    # Save credentials to file
    if ! save_credentials "$creds_file" "$redis_mode" "$redis_port" "$redis_host" "$max_memory" "$data_dir" "$config_file"; then
        echo -e "${RED}✗ Failed to save credentials${NC}" >&2
        return 1
    fi
    
    # Generate connection test script
    local test_script_dir=$(dirname "$creds_file")
    generate_connection_test "$test_script_dir/redis-connection-test.sh" "$redis_host" "$redis_port"
    
    # Show summary
    show_credential_summary "$redis_mode"
    
    echo "" >&2
    echo -e "${GREEN}✓ Redis credential management completed successfully${NC}" >&2
    echo "" >&2
    
    return 0
}

# Function to update existing password in running Redis instance
update_redis_password() {
    local new_password="$1"
    local redis_host="${2:-localhost}"
    local redis_port="${3:-6379}"
    local current_password="$REDIS_PASSWORD"
    
    echo -e "${BLUE}Updating Redis password in running instance...${NC}" >&2
    
    # Try to connect with current password and set new one
    if redis-cli -h "$redis_host" -p "$redis_port" -a "$current_password" CONFIG SET requirepass "$new_password" >/dev/null 2>&1; then
        REDIS_PASSWORD="$new_password"
        echo -e "${GREEN}✓ Redis password updated successfully${NC}" >&2
        
        # Test new password
        if redis-cli -h "$redis_host" -p "$redis_port" -a "$new_password" ping | grep -q "PONG"; then
            echo -e "${GREEN}✓ New password verified${NC}" >&2
            return 0
        else
            echo -e "${RED}✗ New password verification failed${NC}" >&2
            return 1
        fi
    else
        echo -e "${RED}✗ Failed to update Redis password${NC}" >&2
        return 1
    fi
}

# Function to rotate all passwords
rotate_passwords() {
    local redis_mode="$1"
    local creds_file="$2"
    
    echo -e "${BLUE}Rotating all Redis passwords...${NC}" >&2
    
    # Clear existing passwords to force regeneration
    REDIS_PASSWORD=""
    REDIS_ADMIN_PASSWORD=""
    REDIS_SENTINEL_PASSWORD=""
    REDIS_CLUSTER_AUTH=""
    REDIS_REPLICATION_PASSWORD=""
    
    # Generate new credentials
    generate_missing_credentials "$redis_mode"
    
    # Validate
    if validate_credentials "$redis_mode"; then
        echo -e "${GREEN}✓ All passwords rotated successfully${NC}" >&2
        
        # Save updated credentials if file provided
        if [[ -n "$creds_file" ]]; then
            save_credentials "$creds_file" "$redis_mode"
        fi
        
        return 0
    else
        echo -e "${RED}✗ Password rotation failed${NC}" >&2
        return 1
    fi
}

# If script is run directly, show usage
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Redis Password Manager Script"
    echo ""
    echo "This script is designed to be sourced by other scripts."
    echo ""
    echo "Available functions:"
    echo "  manage_credentials <creds_file> [redis_mode] [port] [host] [max_memory] [data_dir] [config_file]"
    echo "  load_existing_credentials <creds_file>"
    echo "  generate_missing_credentials [redis_mode]"
    echo "  save_credentials <creds_file> [redis_mode] [port] [host] [max_memory] [data_dir] [config_file]"
    echo "  validate_credentials [redis_mode]"
    echo "  get_passwords"
    echo "  show_credential_summary [redis_mode]"
    echo "  update_redis_password <new_password> [host] [port]"
    echo "  rotate_passwords <redis_mode> [creds_file]"
    echo "  generate_connection_test <test_file> [host] [port]"
    echo ""
    echo "Redis modes: standalone, sentinel, cluster"
    echo ""
    echo "Example usage:"
    echo "  source helper_redis_password_manager.sh"
    echo "  manage_credentials \"/root/redis-credentials.txt\" \"standalone\" \"6379\" \"localhost\""
fi