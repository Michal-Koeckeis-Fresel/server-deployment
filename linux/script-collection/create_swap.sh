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

# Auto Swap File Generator
# Creates swap file based on available disk space on root filesystem

set -e  # Exit on any error

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    exit 1
fi

# Check if swap file already exists - exit if it does
if [[ -f /swapfile ]]; then
    exit 0
fi

# Get available space on root filesystem in GB
available_kb=$(df / | awk 'NR==2 {print $4}')
available_gb=$((available_kb / 1024 / 1024))

# Create swap file based on available space
if [[ $available_gb -lt 16 ]]; then
    # No swap file created for less than 16GB
    exit 0
    
elif [[ $available_gb -ge 16 && $available_gb -lt 32 ]]; then
    # Create 2GB swap
    fallocate -l 2G /swapfile
    
elif [[ $available_gb -ge 32 && $available_gb -lt 64 ]]; then
    # Create 4GB swap
    fallocate -l 4G /swapfile
    
elif [[ $available_gb -ge 64 && $available_gb -lt 80 ]]; then
    # Create 8GB swap
    fallocate -l 8G /swapfile
    
elif [[ $available_gb -ge 80 ]]; then
    # Create 16GB swap
    fallocate -l 16G /swapfile
fi

# If swap file was created, set it up
if [[ -f /swapfile ]]; then
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1
    swapon /swapfile
    
    # Add to fstab if not already present
    if ! grep -q "/swapfile" /etc/fstab 2>/dev/null; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi
fi