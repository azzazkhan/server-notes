#!/usr/bin/bash

export DEBIAN_FRONTEND=noninteractive

NEW_USER="$1"

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."

   exit 1
fi

if [[ -z $NEW_USER ]]; then
    echo "User name is required!"

    exit 1
fi

# Stop PHP FPM

echo "Stopping PHP FPM ..."

service php8.3-fpm stop

# Remove default user from new user group

deluser ubuntu $NEW_USER

# Delete user and home directory
deluser $NEW_USER
rm -rf /home/$NEW_USER

# Delete PHP FPM user pool

rm -f /etc/php/8.3/fpm/pool.d/www-$NEW_USER.conf

# Restart PHP FPM

echo "Restarting PHP FPM ..."

service php8.3-fpm start
