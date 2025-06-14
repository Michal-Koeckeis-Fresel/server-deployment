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


FQDN=$(hostname -f)
IP=$(hostname -I | awk '{print $1}')

echo -e "\nWelcome to $FQDN\nIP Address: $IP\n" > /etc/issue