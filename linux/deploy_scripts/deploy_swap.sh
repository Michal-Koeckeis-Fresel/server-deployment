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

# Download and execute swap creation script
curl -o /tmp/create_swap.sh https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/script-collection/create_swap.sh
chmod +x /tmp/create_swap.sh
/tmp/create_swap.sh