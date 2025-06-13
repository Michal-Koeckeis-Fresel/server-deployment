#!/bin/bash

# Author: Michal Koeckeis-Fresel
# License: MIT

# Download and execute login banner installation script
curl -o /tmp/install_loginbanner.sh https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/refs/heads/main/linux/script-collection/install_loginbanner.sh
chmod +x /tmp/install_loginbanner.sh
/tmp/install_loginbanner.sh