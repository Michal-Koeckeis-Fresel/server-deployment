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

# Enhanced BunkerWeb Uninstall Script with Data Preservation Options

# This script can preserve Redis and other data based on configuration settings

set -e

INSTALL_DIR=”/data/BunkerWeb”
CONFIG_FILE=”$INSTALL_DIR/BunkerWeb.conf”

# Colors for output

RED=’\033[0;31m’
GREEN=’\033[0;32m’
YELLOW=’\033[1;33m’
BLUE=’\033[0;34m’
NC=’\033[0m’ # No Color

# Default values for data preservation

KEEP_REDIS=“no”
KEEP_DATA=“no”
KEEP_SYSLOG=“no”
FORCE_REMOVAL=“no”

# Function to display usage

show_usage() {
echo -e “${BLUE}Usage: $0 [OPTIONS]${NC}”
echo “”
echo -e “${YELLOW}Options:${NC}”
echo -e “  –keep-redis        Preserve Redis container and data”
echo -e “  –keep-data         Preserve all BunkerWeb data”
echo -e “  –keep-syslog       Preserve syslog container and data”
echo -e “  –force             Force removal without confirmation”
echo -e “  –complete          Remove everything including preserved data”
echo -e “  -h, –help          Show this help message”
echo “”
echo -e “${BLUE}Configuration-based preservation:${NC}”
echo -e “  The script reads KEEP_REDIS, KEEP_DATA, and KEEP_SYSLOG from BunkerWeb.conf”
echo -e “  Command line options override configuration file settings”
echo “”
echo -e “${YELLOW}Examples:${NC}”
echo -e “  $0                  # Normal uninstall (respects config file)”
echo -e “  $0 –keep-redis     # Preserve Redis data”
echo -e “  $0 –keep-data      # Preserve all data”
echo -e “  $0 –keep-syslog    # Preserve syslog data”
echo -e “  $0 –complete       # Remove everything (ignore config)”
echo -e “  $0 –force          # Skip confirmation prompts”
}

# Parse command line arguments

while [[ $# -gt 0 ]]; do
case $1 in
–keep-redis)
KEEP_REDIS=“yes”
shift
;;
–keep-data)
KEEP_DATA=“yes”
shift
;;
–keep-syslog)
KEEP_SYSLOG=“yes”
shift
;;
–force)
FORCE_REMOVAL=“yes”
shift
;;
–complete)
KEEP_REDIS=“no”
KEEP_DATA=“no”
KEEP_SYSLOG=“no”
FORCE_REMOVAL=“yes”
shift
;;
-h|–help)
show_usage
exit 0
;;
*)
echo -e “${RED}Error: Unknown option ‘$1’${NC}”
show_usage
exit 1
;;
esac
done

echo -e “${BLUE}================================================${NC}”
echo -e “${BLUE}        BunkerWeb Uninstall Script${NC}”
echo -e “${BLUE}================================================${NC}”
echo “”

# Load configuration from BunkerWeb.conf if it exists and no command line overrides

if [[ -f “$CONFIG_FILE” ]]; then
echo -e “${BLUE}Loading configuration from $CONFIG_FILE…${NC}”

```
# Only load from config if not overridden by command line
if [[ "$KEEP_REDIS" == "no" ]]; then
    CONFIG_KEEP_REDIS=$(grep "^KEEP_REDIS=" "$CONFIG_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "no")
    if [[ -n "$CONFIG_KEEP_REDIS" ]]; then
        KEEP_REDIS="$CONFIG_KEEP_REDIS"
    fi
fi

if [[ "$KEEP_DATA" == "no" ]]; then
    CONFIG_KEEP_DATA=$(grep "^KEEP_DATA=" "$CONFIG_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "no")
    if [[ -n "$CONFIG_KEEP_DATA" ]]; then
        KEEP_DATA="$CONFIG_KEEP_DATA"
    fi
fi

if [[ "$KEEP_SYSLOG" == "no" ]]; then
    CONFIG_KEEP_SYSLOG=$(grep "^KEEP_SYSLOG=" "$CONFIG_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "no")
    if [[ -n "$CONFIG_KEEP_SYSLOG" ]]; then
        KEEP_SYSLOG="$CONFIG_KEEP_SYSLOG"
    fi
fi

echo -e "${GREEN}✓ Configuration loaded${NC}"
```

else
echo -e “${YELLOW}⚠ Configuration file not found at $CONFIG_FILE${NC}”
echo -e “${BLUE}Using default settings${NC}”
fi

# Display current settings

echo “”
echo -e “${GREEN}Uninstall Configuration:${NC}”
echo -e “${GREEN}• Keep Redis Data:${NC} $KEEP_REDIS”
echo -e “${GREEN}• Keep All Data:${NC} $KEEP_DATA”
echo -e “${GREEN}• Keep Syslog Data:${NC} $KEEP_SYSLOG”
echo -e “${GREEN}• Force Removal:${NC} $FORCE_REMOVAL”
echo “”

# If KEEP_DATA is yes, it overrides KEEP_REDIS and KEEP_SYSLOG

if [[ “$KEEP_DATA” == “yes” ]]; then
KEEP_REDIS=“yes”
KEEP_SYSLOG=“yes”
echo -e “${BLUE}ℹ KEEP_DATA=yes implies KEEP_REDIS=yes and KEEP_SYSLOG=yes${NC}”
echo “”
fi

# Warning about data preservation

if [[ “$KEEP_REDIS” == “yes” || “$KEEP_DATA” == “yes” || “$KEEP_SYSLOG” == “yes” ]]; then
echo -e “${YELLOW}⚠ Data Preservation Mode Enabled${NC}”
if [[ “$KEEP_DATA” == “yes” ]]; then
echo -e “${BLUE}• All BunkerWeb data will be preserved${NC}”
echo -e “${BLUE}• Installation directory will remain: $INSTALL_DIR${NC}”
else
if [[ “$KEEP_REDIS” == “yes” ]]; then
echo -e “${BLUE}• Redis container and data will be preserved${NC}”
echo -e “${BLUE}• Redis data directory will remain: $INSTALL_DIR/redis${NC}”
fi
if [[ “$KEEP_SYSLOG” == “yes” ]]; then
echo -e “${BLUE}• Syslog container and data will be preserved${NC}”
echo -e “${BLUE}• Syslog data directory will remain: $INSTALL_DIR/logs${NC}”
fi
fi
echo “”
fi

# Confirmation prompt

if [[ “$FORCE_REMOVAL” != “yes” ]]; then
echo -e “${RED}WARNING: This will remove BunkerWeb components!${NC}”
echo “”
echo -e “${YELLOW}What will be removed:${NC}”
echo -e “${RED}• BunkerWeb Docker containers${NC}”
echo -e “${RED}• BunkerWeb Docker images${NC}”
echo -e “${RED}• BunkerWeb Docker networks${NC}”

```
if [[ "$KEEP_DATA" == "yes" ]]; then
    echo -e "${GREEN}• Installation directory: PRESERVED${NC}"
else
    echo -e "${RED}• Installation directory: $INSTALL_DIR${NC}"
fi

if [[ "$KEEP_REDIS" == "yes" ]]; then
    echo -e "${GREEN}• Redis container: PRESERVED${NC}"
    echo -e "${GREEN}• Redis data: PRESERVED${NC}"
else
    echo -e "${RED}• Redis container and data${NC}"
fi

if [[ "$KEEP_SYSLOG" == "yes" ]]; then
    echo -e "${GREEN}• Syslog container: PRESERVED${NC}"
    echo -e "${GREEN}• Syslog data: PRESERVED${NC}"
else
    echo -e "${RED}• Syslog container and data${NC}"
fi

echo ""
read -p "Are you sure you want to continue? (y/N): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Uninstall cancelled${NC}"
    exit 0
fi
echo ""
```

fi

# Change to BunkerWeb directory if it exists

if [[ -d “$INSTALL_DIR” ]]; then
cd “$INSTALL_DIR”
echo -e “${BLUE}Working in: $INSTALL_DIR${NC}”
else
echo -e “${YELLOW}⚠ BunkerWeb directory not found at $INSTALL_DIR${NC}”
echo -e “${BLUE}Continuing with container and image cleanup…${NC}”
fi

# Stop and remove containers

echo -e “${BLUE}Stopping BunkerWeb containers…${NC}”
if [[ -f “docker-compose.yml” ]]; then
# Stop all containers first
docker compose down 2>/dev/null || echo -e “${YELLOW}⚠ Docker compose down failed (containers may not be running)${NC}”
echo -e “${GREEN}✓ Containers stopped via docker-compose${NC}”
else
echo -e “${YELLOW}⚠ docker-compose.yml not found, stopping containers manually${NC}”
# Stop containers manually
docker stop $(docker ps -q –filter “name=bw-”) 2>/dev/null || echo -e “${YELLOW}⚠ No BunkerWeb containers running${NC}”
fi

# Remove containers (except Redis and/or Syslog if preservation is enabled)

echo -e “${BLUE}Removing BunkerWeb containers…${NC}”

# Build list of containers to preserve

CONTAINERS_TO_PRESERVE=””
if [[ “$KEEP_REDIS” == “yes” ]]; then
CONTAINERS_TO_PRESERVE=”$CONTAINERS_TO_PRESERVE bw-redis”
echo -e “${BLUE}Preserving Redis container as requested${NC}”
fi

if [[ “$KEEP_SYSLOG” == “yes” ]]; then
CONTAINERS_TO_PRESERVE=”$CONTAINERS_TO_PRESERVE bw-syslog”
echo -e “${BLUE}Preserving Syslog container as requested${NC}”
fi

# Get all BunkerWeb containers

ALL_BW_CONTAINERS=$(docker ps -aq –filter “name=bw-” 2>/dev/null || echo “”)

if [[ -n “$ALL_BW_CONTAINERS” ]]; then
if [[ -n “$CONTAINERS_TO_PRESERVE” ]]; then
# Remove containers except preserved ones
CONTAINERS_TO_REMOVE=””
for container in $ALL_BW_CONTAINERS; do
CONTAINER_NAME=$(docker inspect –format=’{{.Name}}’ “$container” 2>/dev/null | sed ‘s/^//’)
PRESERVE_CONTAINER=false

```
        for preserve_name in $CONTAINERS_TO_PRESERVE; do
            if [[ "$CONTAINER_NAME" == "$preserve_name" ]]; then
                PRESERVE_CONTAINER=true
                break
            fi
        done
        
        if [[ "$PRESERVE_CONTAINER" == "false" ]]; then
            CONTAINERS_TO_REMOVE="$CONTAINERS_TO_REMOVE $container"
        fi
    done
    
    if [[ -n "$CONTAINERS_TO_REMOVE" ]]; then
        echo $CONTAINERS_TO_REMOVE | xargs docker rm -f 2>/dev/null || true
        echo -e "${GREEN}✓ BunkerWeb containers removed (preserved: $CONTAINERS_TO_PRESERVE)${NC}"
    else
        echo -e "${YELLOW}⚠ No containers to remove (all are preserved)${NC}"
    fi
    
    # Check preserved containers status
    for preserve_name in $CONTAINERS_TO_PRESERVE; do
        if docker ps --filter "name=$preserve_name" --format "table {{.Names}}" | grep -q "$preserve_name"; then
            echo -e "${GREEN}✓ $preserve_name container preserved and running${NC}"
        else
            echo -e "${YELLOW}⚠ $preserve_name container not found or not running${NC}"
        fi
    done
else
    # Remove all BunkerWeb containers
    echo $ALL_BW_CONTAINERS | xargs docker rm -f 2>/dev/null || true
    echo -e "${GREEN}✓ All BunkerWeb containers removed${NC}"
fi
```

else
echo -e “${YELLOW}⚠ No BunkerWeb containers found${NC}”
fi

# Remove BunkerWeb networks (but not if preserved containers are using them)

echo -e “${BLUE}Removing BunkerWeb networks…${NC}”
if [[ “$KEEP_REDIS” == “yes” || “$KEEP_SYSLOG” == “yes” ]]; then
echo -e “${BLUE}Checking network usage before removal…${NC}”

```
# Remove networks that are not being used by preserved containers
for network in bw-universe bw-services bw-docker bw-db bw-redis bw-syslog; do
    if docker network ls --format "{{.Name}}" | grep -q "^${network}$"; then
        NETWORK_IN_USE=false
        
        # Check if any preserved containers are using this network
        if [[ "$KEEP_REDIS" == "yes" ]] && docker inspect bw-redis 2>/dev/null | grep -q "\"${network}\""; then
            NETWORK_IN_USE=true
        fi
        
        if [[ "$KEEP_SYSLOG" == "yes" ]] && docker inspect bw-syslog 2>/dev/null | grep -q "\"${network}\""; then
            NETWORK_IN_USE=true
        fi
        
        if [[ "$NETWORK_IN_USE" == "true" ]]; then
            echo -e "${YELLOW}⚠ Network ${network} preserved (used by preserved container)${NC}"
        else
            docker network rm "$network" 2>/dev/null || echo -e "${YELLOW}⚠ Could not remove network $network${NC}"
            echo -e "${GREEN}✓ Network ${network} removed${NC}"
        fi
    fi
done
```

else
# Remove all BunkerWeb networks
for network in bw-universe bw-services bw-docker bw-db bw-redis bw-syslog; do
docker network rm “$network” 2>/dev/null || true
done
echo -e “${GREEN}✓ BunkerWeb networks removed${NC}”
fi

# Remove BunkerWeb images (but not preserved service images)

echo -e “${BLUE}Removing BunkerWeb images…${NC}”
if [[ “$KEEP_REDIS” == “yes” || “$KEEP_SYSLOG” == “yes” ]]; then
PRESERVED_SERVICES=””
[[ “$KEEP_REDIS” == “yes” ]] && PRESERVED_SERVICES=”$PRESERVED_SERVICES Redis”
[[ “$KEEP_SYSLOG” == “yes” ]] && PRESERVED_SERVICES=”$PRESERVED_SERVICES Syslog”
echo -e “${BLUE}Preserving images for:$PRESERVED_SERVICES${NC}”

```
# Remove BunkerWeb images but not preserved service images
docker images | grep bunkerity/bunkerweb | awk '{print $1":"$2}' | xargs docker rmi 2>/dev/null || true
docker images | grep bunkerity/bunkerweb-scheduler | awk '{print $1":"$2}' | xargs docker rmi 2>/dev/null || true
docker images | grep bunkerity/bunkerweb-ui | awk '{print $1":"$2}' | xargs docker rmi 2>/dev/null || true
docker images | grep bunkerity/bunkerweb-autoconf | awk '{print $1":"$2}' | xargs docker rmi 2>/dev/null || true
docker images | grep tecnativa/docker-socket-proxy | awk '{print $1":"$2}' | xargs docker rmi 2>/dev/null || true
docker images | grep mariadb | awk '{print $1":"$2}' | xargs docker rmi 2>/dev/null || true

# Remove Redis image only if not preserved
if [[ "$KEEP_REDIS" != "yes" ]]; then
    docker images | grep redis | awk '{print $1":"$2}' | xargs docker rmi 2>/dev/null || true
fi

# Remove Syslog images only if not preserved
if [[ "$KEEP_SYSLOG" != "yes" ]]; then
    docker images | grep balabit/syslog-ng | awk '{print $1":"$2}' | xargs docker rmi 2>/dev/null || true
    docker images | grep "linuxserver/syslog-ng" | awk '{print $1":"$2}' | xargs docker rmi 2>/dev/null || true
fi

echo -e "${GREEN}✓ BunkerWeb images removed ($PRESERVED_SERVICES images preserved)${NC}"
```

else
# Remove all images including Redis and Syslog
docker images | grep bunkerity/bunkerweb | awk ‘{print $1”:”$2}’ | xargs docker rmi 2>/dev/null || true
docker images | grep bunkerity/bunkerweb-scheduler | awk ‘{print $1”:”$2}’ | xargs docker rmi 2>/dev/null || true
docker images | grep bunkerity/bunkerweb-ui | awk ‘{print $1”:”$2}’ | xargs docker rmi 2>/dev/null || true
docker images | grep bunkerity/bunkerweb-autoconf | awk ‘{print $1”:”$2}’ | xargs docker rmi 2>/dev/null || true
docker images | grep tecnativa/docker-socket-proxy | awk ‘{print $1”:”$2}’ | xargs docker rmi 2>/dev/null || true
docker images | grep mariadb | awk ‘{print $1”:”$2}’ | xargs docker rmi 2>/dev/null || true
docker images | grep redis | awk ‘{print $1”:”$2}’ | xargs docker rmi 2>/dev/null || true
docker images | grep balabit/syslog-ng | awk ‘{print $1”:”$2}’ | xargs docker rmi 2>/dev/null || true
docker images | grep “linuxserver/syslog-ng” | awk ‘{print $1”:”$2}’ | xargs docker rmi 2>/dev/null || true

```
echo -e "${GREEN}✓ All BunkerWeb and related images removed${NC}"
```

fi

# Remove installation directory and data

if [[ “$KEEP_DATA” == “yes” ]]; then
echo -e “${BLUE}Preserving BunkerWeb installation directory as requested${NC}”
echo -e “${GREEN}✓ Installation directory preserved: $INSTALL_DIR${NC}”
elif [[ “$KEEP_REDIS” == “yes” || “$KEEP_SYSLOG” == “yes” ]]; then
echo -e “${BLUE}Removing BunkerWeb data (preserving selected services)…${NC}”

```
if [[ -d "$INSTALL_DIR" ]]; then
    cd "$INSTALL_DIR"
    
    # Build exclusion list for preserved services
    PRESERVE_DIRS="."
    [[ "$KEEP_REDIS" == "yes" ]] && PRESERVE_DIRS="$PRESERVE_DIRS redis"
    [[ "$KEEP_SYSLOG" == "yes" ]] && PRESERVE_DIRS="$PRESERVE_DIRS logs syslog"
    PRESERVE_DIRS="$PRESERVE_DIRS BunkerWeb.conf"
    
    # Create find exclusion pattern
    FIND_EXCLUDES=""
    for dir in $PRESERVE_DIRS; do
        FIND_EXCLUDES="$FIND_EXCLUDES -not -name \"$dir\""
    done
    
    # Remove everything except preserved directories
    eval "find . -maxdepth 1 $FIND_EXCLUDES -exec rm -rf {} \;" 2>/dev/null || true
    
    echo -e "${GREEN}✓ BunkerWeb data removed${NC}"
    echo -e "${GREEN}✓ Configuration file preserved: $INSTALL_DIR/BunkerWeb.conf${NC}"
    [[ "$KEEP_REDIS" == "yes" ]] && echo -e "${GREEN}✓ Redis data preserved: $INSTALL_DIR/redis${NC}"
    [[ "$KEEP_SYSLOG" == "yes" ]] && echo -e "${GREEN}✓ Syslog data preserved: $INSTALL_DIR/logs and $INSTALL_DIR/syslog${NC}"
fi
```

else
echo -e “${BLUE}Removing complete BunkerWeb installation directory…${NC}”

```
if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf "$INSTALL_DIR"
    echo -e "${GREEN}✓ Installation directory removed: $INSTALL_DIR${NC}"
else
    echo -e "${YELLOW}⚠ Installation directory not found${NC}"
fi
```

fi

# Summary

echo “”
echo -e “${GREEN}================================================${NC}”
echo -e “${GREEN}        Uninstall Complete!${NC}”
echo -e “${GREEN}================================================${NC}”
echo “”

if [[ “$KEEP_DATA” == “yes” ]]; then
echo -e “${BLUE}📁 Data Preservation Summary:${NC}”
echo -e “${GREEN}✓ All BunkerWeb data preserved in: $INSTALL_DIR${NC}”
echo -e “${GREEN}✓ Configuration preserved: $INSTALL_DIR/BunkerWeb.conf${NC}”
echo -e “${GREEN}✓ Database data preserved: $INSTALL_DIR/database${NC}”
echo -e “${GREEN}✓ Storage data preserved: $INSTALL_DIR/storage${NC}”
if [[ -d “$INSTALL_DIR/redis” ]]; then
echo -e “${GREEN}✓ Redis data preserved: $INSTALL_DIR/redis${NC}”
fi
if [[ -d “$INSTALL_DIR/logs” ]]; then
echo -e “${GREEN}✓ Syslog data preserved: $INSTALL_DIR/logs${NC}”
fi
echo “”
echo -e “${BLUE}🔄 To reinstall BunkerWeb with preserved data:${NC}”
echo -e “${BLUE}1. Run the deploy script again${NC}”
echo -e “${BLUE}2. Your existing configuration and data will be reused${NC}”

elif [[ “$KEEP_REDIS” == “yes” || “$KEEP_SYSLOG” == “yes” ]]; then
PRESERVED_SERVICES=””
[[ “$KEEP_REDIS” == “yes” ]] && PRESERVED_SERVICES=”$PRESERVED_SERVICES Redis”
[[ “$KEEP_SYSLOG” == “yes” ]] && PRESERVED_SERVICES=”$PRESERVED_SERVICES Syslog”

```
echo -e "${BLUE}📁 Service Preservation Summary:${NC}"
echo -e "${GREEN}✓ Configuration preserved: $INSTALL_DIR/BunkerWeb.conf${NC}"

if [[ "$KEEP_REDIS" == "yes" ]]; then
    echo -e "${GREEN}✓ Redis container preserved and running${NC}"
    echo -e "${GREEN}✓ Redis data preserved: $INSTALL_DIR/redis${NC}"
fi

if [[ "$KEEP_SYSLOG" == "yes" ]]; then
    echo -e "${GREEN}✓ Syslog container preserved and running${NC}"
    echo -e "${GREEN}✓ Syslog data preserved: $INSTALL_DIR/logs${NC}"
    echo -e "${GREEN}✓ Syslog config preserved: $INSTALL_DIR/syslog${NC}"
fi

echo ""
echo -e "${BLUE}🔄 To reinstall BunkerWeb with preserved services:${NC}"
echo -e "${BLUE}1. Run the deploy script again${NC}"
echo -e "${BLUE}2.$PRESERVED_SERVICES data and configuration will be reused${NC}"
echo -e "${BLUE}3. Set appropriate USE_* flags in your configuration${NC}"

# Show connection info for preserved services
CREDS_FILE="/root/BunkerWeb-Credentials.txt"
echo ""
echo -e "${BLUE}🔗 Preserved Service Connection Info:${NC}"

if [[ "$KEEP_REDIS" == "yes" ]]; then
    REDIS_PASSWORD=""
    if [[ -f "$CREDS_FILE" ]]; then
        REDIS_PASSWORD=$(grep "Redis Password:" "$CREDS_FILE" 2>/dev/null | cut -d' ' -f3 || echo "")
    fi
    echo -e "${BLUE}• Redis Container: bw-redis${NC}"
    echo -e "${BLUE}• Redis Port: 6379${NC}"
    if [[ -n "$REDIS_PASSWORD" ]]; then
        echo -e "${BLUE}• Test connection: docker exec bw-redis redis-cli -a '$REDIS_PASSWORD' ping${NC}"
    else
        echo -e "${YELLOW}• Password: Check /root/BunkerWeb-Credentials.txt${NC}"
    fi
fi

if [[ "$KEEP_SYSLOG" == "yes" ]]; then
    echo -e "${BLUE}• Syslog Container: bw-syslog${NC}"
    echo -e "${BLUE}• Syslog Port: 514 (UDP)${NC}"
    echo -e "${BLUE}• View logs: docker exec bw-syslog cat /var/log/bunkerweb/all.log${NC}"
    echo -e "${BLUE}• Live logs: docker exec bw-syslog tail -f /var/log/bunkerweb/all.log${NC}"
fi
```

else
echo -e “${BLUE}🧹 Complete Removal Summary:${NC}”
echo -e “${GREEN}✓ All BunkerWeb containers removed${NC}”
echo -e “${GREEN}✓ All BunkerWeb images removed${NC}”
echo -e “${GREEN}✓ All BunkerWeb networks removed${NC}”
echo -e “${GREEN}✓ All BunkerWeb data removed${NC}”
echo “”
echo -e “${BLUE}🔄 To reinstall BunkerWeb:${NC}”
echo -e “${BLUE}curl https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/deploy_scripts/deploy_bunkerweb.sh|bash${NC}”
fi

# Manual cleanup instructions if needed

if [[ “$KEEP_REDIS” == “yes” || “$KEEP_DATA” == “yes” || “$KEEP_SYSLOG” == “yes” ]]; then
echo “”
echo -e “${YELLOW}📋 Manual Cleanup (if needed later):${NC}”

```
if [[ "$KEEP_REDIS" == "yes" ]]; then
    echo -e "${YELLOW}To remove preserved Redis:${NC}"
    echo -e "${BLUE}• Stop container: docker stop bw-redis${NC}"
    echo -e "${BLUE}• Remove container: docker rm bw-redis${NC}"
    echo -e "${BLUE}• Remove image: docker rmi redis:7-alpine${NC}"
    if [[ "$KEEP_DATA" != "yes" ]]; then
        echo -e "${BLUE}• Remove data: rm -rf $INSTALL_DIR/redis${NC}"
    fi
fi

if [[ "$KEEP_SYSLOG" == "yes" ]]; then
    echo -e "${YELLOW}To remove preserved Syslog:${NC}"
    echo -e "${BLUE}• Stop container: docker stop bw-syslog${NC}"
    echo -e "${BLUE}• Remove container: docker rm bw-syslog${NC}"
    echo -e "${BLUE}• Remove image: docker rmi balabit/syslog-ng:4.8.0${NC}"
    if [[ "$KEEP_DATA" != "yes" ]]; then
        echo -e "${BLUE}• Remove data: rm -rf $INSTALL_DIR/logs $INSTALL_DIR/syslog${NC}"
    fi
fi

if [[ "$KEEP_DATA" == "yes" ]]; then
    echo -e "${YELLOW}To remove all preserved data:${NC}"
    echo -e "${BLUE}• Remove directory: rm -rf $INSTALL_DIR${NC}"
    echo -e "${BLUE}• Remove credentials: rm -f /root/BunkerWeb-Credentials.txt${NC}"
elif [[ "$KEEP_REDIS" == "yes" || "$KEEP_SYSLOG" == "yes" ]]; then
    echo -e "${YELLOW}To remove remaining data:${NC}"
    echo -e "${BLUE}• Remove config: rm -f $INSTALL_DIR/BunkerWeb.conf${NC}"
    echo -e "${BLUE}• Remove directory: rm -rf $INSTALL_DIR${NC}"
fi

echo -e "${YELLOW}To remove with --complete flag:${NC}"
echo -e "${BLUE}• Run: $0 --complete${NC}"
```

fi

echo “”
echo -e “${GREEN}Uninstall completed successfully!${NC}”