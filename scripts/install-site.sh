#!/usr/bin/bash

SITE_NAME="$1"
REPO_NAME="$2"
RELEASE=$(date "+%Y%m%d%H%M%S")
SITE_DIR="/home/$USER/$SITE_NAME"

if [[ -z $SITE_NAME ]]; then
    echo "Site name is required!"

    exit 1
fi

if [[ -z $REPO_NAME ]]; then
    echo "GitHub repo is required!"

    exit 1
fi


# current                   --> link (releases/20240810211019)
# |- database
#    |- database.sqlite     --> link (database.sqlite)
# |- .env                   --> link (.env)
# |- storage                --> link (storage)
# .env
# database.sqlite
# storage
# releases
# |- 20240810170930
# |- 20240810211019
#
#

if [[ -d $SITE_DIR ]]; then
    read -p "Site directory ${$SITE_NAME} already exists. Overwrite? [y/N] " answer

    if [ "$answer" = "y" -o "$answer" = "Y" ]
    then
        rm -rf $SITE_DIR
    else
        exit 1
    fi
fi

rm -rf $SITE_DIR
mkdir -p $SITE_DIR/releases
touch $SITE_DIR/database.sqlite

git clone git@github.com:$REPO_NAME.git $SITE_DIR/releases/$RELEASE

mv $SITE_DIR/releases/$RELEASE/storage      $SITE_DIR/storage
cp $SITE_DIR/releases/$RELEASE/.env.example $SITE_DIR/.env

ln -s $SITE_DIR/database.sqlite $SITE_DIR/releases/$RELEASE/database/database.sqlite
ln -s $SITE_DIR/.env            $SITE_DIR/releases/$RELEASE/.env
ln -s $SITE_DIR/storage         $SITE_DIR/releases/$RELEASE/storage

cd $SITE_DIR/releases/$RELEASE

composer install --prefer-dist --optimize-autoloader --no-interaction

php $SITE_DIR/releases/$RELEASE/artisan key:generate --ansi

DEPLOY_SCRIPT="$SITE_DIR/releases/$RELEASE/deploy.sh"

php artisan migrate

if [[ -f $DEPLOY_SCRIPT ]]; then
    echo "Deploy script found, executing..."

    bash $DEPLOY_SCRIPT
else
    php artisan optimize
    php artisan storage:link --force
    php artisan migrate --force
fi

ln -s $SITE_DIR/releases/$RELEASE $SITE_DIR/current

sudo service php8.3-fpm reload

# TODO: Add NGINX site configuration
