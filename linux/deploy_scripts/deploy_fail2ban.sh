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


apt-get install -y rsyslog
apt-get install -y fail2ban

# Enable fail2ban service
systemctl enable fail2ban
  
# Download custom fail2ban jail.local configuration
curl -o /etc/fail2ban/jail.local https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/configs/fail2ban/jail.local
  
# Reload fail2ban to apply new configuration
systemctl restart fail2ban
  