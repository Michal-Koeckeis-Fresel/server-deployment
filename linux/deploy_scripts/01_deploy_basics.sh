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

# Deploy basic system settings

apt-get update 
apt-get install -y fail2ban curl wget rsyslog logrotate sudo

# Download and execute swap creation script
curl -o /tmp/deploy_swap.sh https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/deploy_scripts/deploy_swap.sh
chmod +x /tmp/deploy_swap.sh
/tmp/deploy_swap.sh

# Download and execute fail2ban creation script
curl -o /tmp/deploy_fail2ban.sh https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/deploy_scripts/deploy_fail2ban.sh
chmod +x /tmp/deploy_fail2ban.sh
/tmp/deploy_fail2ban.sh

# Download and execute histconfig creation script
curl -o /tmp/deploy_histconfig.sh https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/deploy_scripts/deploy_histconfig.sh
chmod +x /tmp/deploy_histconfig.sh
/tmp/deploy_histconfig.sh

# Download and execute login-banner creation script
curl -o /tmp/deploy_login-banner.sh https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/deploy_scripts/deploy_login-banner.sh
chmod +x /tmp/deploy_login-banner.sh
/tmp/deploy_login-banner.sh

# Download and execute unbound creation script
curl -o /tmp/deploy_unbound.sh https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/deploy_scripts/deploy_unbound.sh
chmod +x /tmp/deploy_unbound.sh
/tmp/deploy_unbound.sh