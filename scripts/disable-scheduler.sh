#!/usr/bin/bash

SITE_NAME="$1"
SITE_DIR="/home/$USER/$SITE_NAME"

if [[ -z $SITE_NAME ]]; then
    echo "Site name is required!"

    exit 1
fi

CRON_EXP="$SITE_DIR/current/artisan schedule:run"

crontab -u $USER -l | grep -v "php $SITE_DIR/current/artisan schedule:run" | crontab -u $USER -
