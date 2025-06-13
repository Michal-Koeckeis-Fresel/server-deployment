#!/bin/bash

# Author: Michal Koeckeis-Fresel
# License: MIT

# Download and execute swap creation script
curl -o /tmp/create_swap.sh https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/main/linux/cloudinit/create_swap.sh
chmod +x /tmp/create_swap.sh
/tmp/create_swap.sh