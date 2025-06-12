#!/bin/bash

# Author: Michal Koeckeis-Fresel
# License: MIT


FQDN=$(hostname -f)
IP=$(hostname -I | awk '{print $1}')

echo -e "\nWelcome to $FQDN\nIP Address: $IP\n" > /etc/issue