#!/usr/bin/bash

SITE_NAME="$1"
SITE_DIR="/home/$USER/$SITE_NAME"

if [[ -z $SITE_NAME ]]; then
    echo "Site name is required!"

    exit 1
fi

CRON_EXP="php $SITE_DIR/current/artisan schedule:run >> $SITE_DIR/schedule.log 2>&1"

(crontab -u $USER -l; echo "* * * * * $CRON_EXP") | crontab -u $USER -
