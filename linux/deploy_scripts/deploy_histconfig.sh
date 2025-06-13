#!/bin/bash

# Author: Michal Koeckeis-Fresel
# License: MIT

# Download bash history configuration
curl -o /etc/profile.d/history-config.sh https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/configs/history-config/history-config.sh
chmod 644 /etc/profile.d/history-config.sh