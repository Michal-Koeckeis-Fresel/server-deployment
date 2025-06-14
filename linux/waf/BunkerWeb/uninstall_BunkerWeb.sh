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

echo "WARNING: YOU DELETE THE COMPLETE INSTALLATION"

cd /data/BunkerWeb
docker compose down

# Remove BunkerWeb networks
docker network rm bw-universe 2>/dev/null || true
docker network rm bw-services 2>/dev/null || true
docker network rm bw-docker 2>/dev/null || true
docker network rm bw-db 2>/dev/null || true


# Remove all BunkerWeb images (any version)
docker images | grep bunkerity/bunkerweb | awk '{print $1":"$2}' | xargs docker rmi 2>/dev/null || true
docker images | grep bunkerity/bunkerweb-scheduler | awk '{print $1":"$2}' | xargs docker rmi 2>/dev/null || true
docker images | grep bunkerity/bunkerweb-ui | awk '{print $1":"$2}' | xargs docker rmi 2>/dev/null || true
docker images | grep bunkerity/bunkerweb-autoconf | awk '{print $1":"$2}' | xargs docker rmi 2>/dev/null || true

# Remove related images
docker images | grep tecnativa/docker-socket-proxy | awk '{print $1":"$2}' | xargs docker rmi 2>/dev/null || true
docker images | grep mariadb | awk '{print $1":"$2}' | xargs docker rmi 2>/dev/null || true


# Remove the entire BunkerWeb installation directory
sudo rm -rf /data/BunkerWeb

echo "to reinstall run:"
echo "curl https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/deploy_scripts/deploy_bunkerweb.sh|bash"