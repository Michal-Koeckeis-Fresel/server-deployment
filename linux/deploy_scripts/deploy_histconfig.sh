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

# Download bash history configuration
curl -o /etc/profile.d/history-config.sh https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/configs/history-config/history-config.sh
chmod 644 /etc/profile.d/history-config.sh