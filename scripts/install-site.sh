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

yarn install --non-interactive
yarn run build

php $SITE_DIR/releases/$RELEASE/artisan migrate --force

ln -s $SITE_DIR/releases/$RELEASE $SITE_DIR/current

# TODO: Add NGINX site configuration
