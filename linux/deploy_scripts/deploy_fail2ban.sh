#!/bin/bash

# Author: Michal Koeckeis-Fresel
# License: MIT

# Enable fail2ban service
systemctl enable fail2ban
  
# Download custom fail2ban jail.local configuration
curl -o /etc/fail2ban/jail.local https://raw.githubusercontent.com/Michal-Koeckeis-Fresel/server-deployment/main/linux/fail2ban/jail.local
  
# Reload fail2ban to apply new configuration
systemctl reload fail2ban
  