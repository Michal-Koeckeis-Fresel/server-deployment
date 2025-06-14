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
# Bash history configuration for improved command logging

PROMPT_COMMAND='history -a'
HISTTIMEFORMAT="%F %T "
HISTSIZE=11000
HISTFILESIZE=11000