#
# REQUIRES:
#       - server (the forge server instance)
#       - event (the forge event instance)
#       - sudo_password (random password for sudo)
#       - db_password (random password for database user)
#       - callback (the callback URL)
#       - recipe_id (recipe id to run at the end)
#

export DEBIAN_FRONTEND=noninteractive

function provisionPing {
  curl --insecure --data "status=$2&server_id=$1" https://forge.laravel.com/provisioning/callback/status
}

function validateServerId {
  if [[ -z "$1" ]]; then
    echo "The server's ID was not accessible to the script."
    exit 1
  fi
}

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."

   exit 1
fi

# Ensure that a function can receive the server's ID as an argument.
validateServerId 830113

UNAME=$(awk -F= '/^NAME/{print $2}' /etc/os-release | sed 's/\"//g')
if [[ "$UNAME" != "Ubuntu" ]]; then
  echo "Forge only supports Ubuntu 20.04, 22.04 and 24.04."

  exit 1
fi

if [[ -f /root/.forge-provisioned ]]; then
  echo "This server has already been provisioned by Laravel Forge."
  echo "If you need to re-provision, you may remove the /root/.forge-provisioned file and try again."

  exit 1
fi

# Create The Root SSH Directory If Necessary

if [ ! -d /root/.ssh ]
then
  mkdir -p /root/.ssh
  touch /root/.ssh/authorized_keys
fi

# Check Permissions Of /root Directory

chown root:root /root
chown -R root:root /root/.ssh

chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

# Setup Forge User

useradd forge
mkdir -p /home/forge/.ssh
mkdir -p /home/forge/.forge
adduser forge sudo

# Setup Bash For Forge User

chsh -s /bin/bash forge
cp /root/.profile /home/forge/.profile
cp /root/.bashrc /home/forge/.bashrc

# Authorize Forge's Unique Server Public Key

cat > /root/.ssh/authorized_keys << EOF
# Laravel Forge
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCd8BkCscwYLUe+LY51OD/lIAVFkBmSBH3aR+eSnIt66QoVLpG8hThBOsE+AQdMpM1OWoJWNSQXN9+9abzn4GRcXnxC8tNllCGPW2bYvC9NpnFwac9wj/rRhRUWQmz3Mxp7MJ/38o44/Jfbzx8HVsi0CGiy+qrTXj1bAZC1KfVvnZaMSYrHFgiUYqmcee7gCRTJXCyWQuiEJnWCwBEUF7PVL26gszVOSyQ31BLU8Cbz6ThlEuVOtg1ay5s3lXX0GtWCwfi2DV8Vd7HXYIFv4Kyr00axw6UEA5hLluYgu96+vbwmT+NVAEWRqNcq994fUrT0ilLTTEdQqBcOxGel9s5SFeswtRv3aEQJWer17T+OmKlMm0dxcahiKJZihpt8XCAp+FZkVONzOGM9AuDbFBCzeslpQITIHxOsLHK0Bdtzn65HsxlNBWPEzIXsJDWXIBqve2e7V8cWimHeTZyyki6ubmKr5hgli67UIq7ylewbITkJQCNIbYoVyXkD8sfxwZ+T8KW7TaEZBEOhCWmpBTysFrG6CHQc0qiYlb4PrsFY+ClpBOz2ZaVniRWCLxRRRAdel7hcZrxu1+522pAYKgRqRMSaDOAle6+fMa14tqjnJhYUj9I4mWPRvTvU4jCRvHgLXPHoFZaQOX68mec/oB1b0ErjnU9N73akF98BHwTGPQ== worker@forge.laravel.com

EOF

cp /root/.ssh/authorized_keys /home/forge/.ssh/authorized_keys

chown -R forge:forge /home/forge
chmod -R 755 /home/forge
chmod 600 /home/forge/.ssh/authorized_keys

apt-get install -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y --force-yes curl

# Check connection with Forge
echo "Checking the Forge connection ..."

response=`curl -s -w "%{http_code}" POST --url https://forge.laravel.com/servers/830113/vps/connection --data-urlencode "forge_token=eyJpdiI6IjFidVpEN1N4dUdiMjFhaWxzTDFiUHc9PSIsInZhbHVlIjoiYzQ3djhEMUZ1ZDhuK3NSNkFKT3JSbGM2b2tkZEk4NEoyZjYrSlZHL3BzclNqWHJVb0RTcG81d2JFNUp4TFUrZzZmYUpCVFZOcXQ0MmVQTGlLRDRZcW12N2ZDSXczZEdQZzIvMkdEUlV5ZEU9IiwibWFjIjoiYzRlMzczNGYxMjg0OGE4MDI4YmRhM2Y2YWM3NjU3Mjc1OTJkZGZmZWFjMTRkZTE5ZjVkNDAzNjlmNzhhYWM1NCIsInRhZyI6IiJ9"`
status=$(printf "%s" "$response" | tail -c 3)
if [ "$status" -ne "200" ]; then
  echo "Error \"$status\" while checking the Forge connection."
  echo "Forge: ${response::-3}"
  exit 1
else
  echo "Forge connection was established."
fi

provisionPing 830113 1

apt_wait () {
    # Run fuser on multiple files once, so that it
    # stops waiting when all files are unlocked

    files="/var/lib/dpkg/lock /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock"
    if [ -f /var/log/unattended-upgrades/unattended-upgrades.log ]; then
        files="$files /var/log/unattended-upgrades/unattended-upgrades.log"
    fi

    while fuser $files >/dev/null 2>&1 ; do
        echo "Waiting for various dpkg or apt locks..."
        sleep 5
    done
}

echo "Checking apt-get availability..."

apt_wait

sed -i "s/#precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/" /etc/gai.conf
if [ -f /etc/needrestart/needrestart.conf ]; then
  # Ubuntu 22 has this set to (i)nteractive, but we want (a)utomatic.
  sed -i "s/^#\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
fi

# Configure Swap Disk

provisionPing 830113 2

if [ -f /swapfile ]; then
    echo "Swap exists."
else
    fallocate -l 1G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo "/swapfile none swap sw 0 0" >> /etc/fstab
    echo "vm.swappiness=30" >> /etc/sysctl.conf
    echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf
fi

provisionPing 830113 3

# Upgrade The Base Packages

export DEBIAN_FRONTEND=noninteractive

apt-get update

apt_wait

apt-get upgrade -y

apt_wait

# Add A Few PPAs To Stay Current

apt-get install -y --force-yes software-properties-common

# apt-add-repository ppa:fkrull/deadsnakes-python2.7 -y
# apt-add-repository ppa:nginx/mainline -y
apt-add-repository ppa:ondrej/nginx -y
# apt-add-repository ppa:chris-lea/redis-server -y

apt-add-repository ppa:ondrej/php -y

apt-add-repository ppa:laravelphp/forge -y


# Update Package Lists

apt_wait

apt-get update
# Base Packages

apt_wait

add-apt-repository universe -y

apt_wait

apt-get install -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y --force-yes \
    acl \
    build-essential \
    bsdmainutils \
    cron \
    curl \
    fail2ban \
    g++ \
    gcc \
    git \
    jq \
    libmagickwand-dev \
    libmcrypt4 \
    libpcre2-dev \
    libpcre3-dev \
    libpng-dev \
    make \
    ncdu \
    net-tools \
    pkg-config \
    python3 \
    python3-pip \
    rsyslog \
    sendmail \
    sqlite3 \
    supervisor \
    ufw \
    unzip \
    uuid-runtime \
    whois \
    zip \
    zsh

MKPASSWD_INSTALLED=$(type mkpasswd &> /dev/null)
if [ $? -ne 0 ]; then
  echo "Failed to install base dependencies."

  exit 1
fi

# Install Python Httpie

pip3 install httpie

# Install AWSCLI

snap install aws-cli --classic

# Disable Password Authentication Over SSH

if [ ! -d /etc/ssh/sshd_config.d ]; then mkdir /etc/ssh/sshd_config.d; fi

cat << EOF > /etc/ssh/sshd_config.d/49-forge.conf
# This file is managed by Laravel Forge.

PasswordAuthentication no

EOF

# Restart SSH

ssh-keygen -A
service ssh restart

# Set The Hostname If Necessary


echo "hollow-reef" > /etc/hostname
sed -i 's/127\.0\.0\.1.*localhost/127.0.0.1	hollow-reef.localdomain hollow-reef localhost/' /etc/hosts
hostname hollow-reef


# Set The Timezone

# ln -sf /usr/share/zoneinfo/UTC /etc/localtime
ln -sf /usr/share/zoneinfo/UTC /etc/localtime

# Set The Sudo Password For Forge

PASSWORD=$(mkpasswd -m sha-512 51aZifUMq03sMfxTGce4)
usermod --password $PASSWORD forge

# Create The Server SSH Key

ssh-keygen -f /home/forge/.ssh/id_rsa -t rsa -N ''

# Copy Source Control Public Keys Into Known Hosts File

ssh-keyscan -H github.com >> /home/forge/.ssh/known_hosts
ssh-keyscan -H bitbucket.org >> /home/forge/.ssh/known_hosts
ssh-keyscan -H gitlab.com >> /home/forge/.ssh/known_hosts

# Configure Git Settings

git config --global user.name "Novels GG"
git config --global user.email "admin@novels.gg"

# Add The Provisioning Cleanup Script Into Root Directory

cat > /root/forge-cleanup.sh << 'EOF'
#!/usr/bin/env bash

# Laravel Forge Provisioning Cleanup Script

UID_MIN=$(awk '/^UID_MIN/ {print $2}' /etc/login.defs)
UID_MAX=$(awk '/^UID_MAX/ {print $2}' /etc/login.defs)
HOME_DIRECTORIES=$(eval getent passwd {0,{${UID_MIN}..${UID_MAX}}} | cut -d: -f6)

for DIRECTORY in $HOME_DIRECTORIES
do
  FORGE_DIRECTORY="$DIRECTORY/.forge"

  if [ ! -d $FORGE_DIRECTORY ]
  then
    continue
  fi

  echo "Cleaning $FORGE_DIRECTORY..."

  find $FORGE_DIRECTORY -type f -mtime +30 -print0 | xargs -r0 rm --
done
EOF

chmod +x /root/forge-cleanup.sh

echo "" | tee -a /etc/crontab
echo "# Laravel Forge Provisioning Cleanup" | tee -a /etc/crontab
tee -a /etc/crontab <<"CRONJOB"
0 0 * * * root bash /root/forge-cleanup.sh 2>&1
CRONJOB

# Add The Reconnect Script Into Forge Directory

cat > /home/forge/.forge/reconnect << EOF
#!/usr/bin/env bash

echo "# Laravel Forge" | tee -a /home/forge/.ssh/authorized_keys > /dev/null
echo \$1 | tee -a /home/forge/.ssh/authorized_keys > /dev/null

echo "# Laravel Forge" | tee -a /root/.ssh/authorized_keys > /dev/null
echo \$1 | tee -a /root/.ssh/authorized_keys > /dev/null

echo "Keys Added!"
EOF

# Setup Forge Home Directory Permissions

chown -R forge:forge /home/forge
chmod -R 755 /home/forge
chmod 700 /home/forge/.ssh/id_rsa
chmod 600 /home/forge/.ssh/authorized_keys

# Setup UFW Firewall

ufw allow 22
ufw deny 80
ufw deny 443


ufw --force enable

# Allow FPM Restart

echo "forge ALL=NOPASSWD: /usr/sbin/service php8.3-fpm reload" > /etc/sudoers.d/php-fpm
echo "forge ALL=NOPASSWD: /usr/sbin/service php8.2-fpm reload" >> /etc/sudoers.d/php-fpm
echo "forge ALL=NOPASSWD: /usr/sbin/service php8.1-fpm reload" >> /etc/sudoers.d/php-fpm
echo "forge ALL=NOPASSWD: /usr/sbin/service php8.0-fpm reload" >> /etc/sudoers.d/php-fpm
echo "forge ALL=NOPASSWD: /usr/sbin/service php7.4-fpm reload" >> /etc/sudoers.d/php-fpm
echo "forge ALL=NOPASSWD: /usr/sbin/service php7.3-fpm reload" >> /etc/sudoers.d/php-fpm
echo "forge ALL=NOPASSWD: /usr/sbin/service php7.2-fpm reload" >> /etc/sudoers.d/php-fpm
echo "forge ALL=NOPASSWD: /usr/sbin/service php7.1-fpm reload" >> /etc/sudoers.d/php-fpm
echo "forge ALL=NOPASSWD: /usr/sbin/service php7.0-fpm reload" >> /etc/sudoers.d/php-fpm
echo "forge ALL=NOPASSWD: /usr/sbin/service php5.6-fpm reload" >> /etc/sudoers.d/php-fpm
echo "forge ALL=NOPASSWD: /usr/sbin/service php5-fpm reload" >> /etc/sudoers.d/php-fpm

# Allow Nginx Reload

echo "forge ALL=NOPASSWD: /usr/sbin/service nginx *" >> /etc/sudoers.d/nginx

# Allow Supervisor Reload


echo "forge ALL=NOPASSWD: /usr/bin/supervisorctl reload" >> /etc/sudoers.d/supervisor
echo "forge ALL=NOPASSWD: /usr/bin/supervisorctl reread" >> /etc/sudoers.d/supervisor
echo "forge ALL=NOPASSWD: /usr/bin/supervisorctl restart *" >> /etc/sudoers.d/supervisor
echo "forge ALL=NOPASSWD: /usr/bin/supervisorctl start *" >> /etc/sudoers.d/supervisor
echo "forge ALL=NOPASSWD: /usr/bin/supervisorctl status *" >> /etc/sudoers.d/supervisor
echo "forge ALL=NOPASSWD: /usr/bin/supervisorctl status" >> /etc/sudoers.d/supervisor
echo "forge ALL=NOPASSWD: /usr/bin/supervisorctl stop *" >> /etc/sudoers.d/supervisor
echo "forge ALL=NOPASSWD: /usr/bin/supervisorctl update *" >> /etc/sudoers.d/supervisor
echo "forge ALL=NOPASSWD: /usr/bin/supervisorctl update" >> /etc/sudoers.d/supervisor

apt_wait

provisionPing 830113 4

    # Install Base PHP Packages

apt-get install -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y --force-yes \
php8.1-cli php8.1-mbstring php8.1-sqlite3 php8.1-xml php8.1-curl php8.1-dom

# Install Composer Package Manager

if [ ! -f /usr/local/bin/composer ]; then
  curl -sS https://getcomposer.org/installer | php
mv composer.phar /usr/local/bin/composer

echo "forge ALL=(root) NOPASSWD: /usr/local/bin/composer self-update*" > /etc/sudoers.d/composer
fi
    update-alternatives --set php /usr/bin/php8.1

provisionPing 830113 5


apt_wait


    provisionPing 830113 6

    #
# REQUIRES:
#		- server (the forge server instance)
#		- db_password (random password for mysql user)
#

export DEBIAN_FRONTEND=noninteractive

# Add MySQL Keys...

sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 467B942D3A79BD29

# Configure MySQL Repositories If Required

# Convert a version string into an integer.

function version { echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'; }

UBUNTU_VERSION=$(lsb_release -rs)
echo "Server on Ubuntu ${UBUNTU_VERSION}"
if [ $(version $UBUNTU_VERSION) -le $(version "20.04") ]; then
    wget -c https://dev.mysql.com/get/mysql-apt-config_0.8.15-1_all.deb
    dpkg --install mysql-apt-config_0.8.15-1_all.deb

    apt-get update
fi

# Set The Automated Root Password

debconf-set-selections <<< "mysql-community-server mysql-community-server/data-dir select ''"
debconf-set-selections <<< "mysql-community-server mysql-community-server/root-pass password 7oR1e4DS30vJwg8weGPV"
debconf-set-selections <<< "mysql-community-server mysql-community-server/re-root-pass password 7oR1e4DS30vJwg8weGPV"

# Install MySQL

apt-get install -y mysql-community-server
apt-get install -y mysql-server

# Configure Password Expiration

echo "default_password_lifetime = 0" >> /etc/mysql/mysql.conf.d/mysqld.cnf

# Set Character Set

echo "" >> /etc/mysql/my.cnf
echo "[mysqld]" >> /etc/mysql/my.cnf
echo "default_authentication_plugin=mysql_native_password" >> /etc/mysql/my.cnf
echo "skip-log-bin" >> /etc/mysql/my.cnf

# Configure Max Connections

RAM=$(awk '/^MemTotal:/{printf "%3.0f", $2 / (1024 * 1024)}' /proc/meminfo)
MAX_CONNECTIONS=$(( 70 * $RAM ))
REAL_MAX_CONNECTIONS=$(( MAX_CONNECTIONS>70 ? MAX_CONNECTIONS : 100 ))
sed -i "s/^max_connections.*=.*/max_connections=${REAL_MAX_CONNECTIONS}/" /etc/mysql/my.cnf

# Configure Access Permissions For Root & Forge Users

if grep -q "bind-address" /etc/mysql/mysql.conf.d/mysqld.cnf; then
  sed -i '/^bind-address/s/bind-address.*=.*/bind-address = */' /etc/mysql/mysql.conf.d/mysqld.cnf
else
  echo "bind-address = *" >> /etc/mysql/mysql.conf.d/mysqld.cnf
fi

mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "CREATE USER 'root'@'1.1.1.1' IDENTIFIED BY '7oR1e4DS30vJwg8weGPV';"
mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "CREATE USER 'root'@'%' IDENTIFIED BY '7oR1e4DS30vJwg8weGPV';"
mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "GRANT ALL PRIVILEGES ON *.* TO root@'1.1.1.1' WITH GRANT OPTION;"
mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "GRANT ALL PRIVILEGES ON *.* TO root@'%' WITH GRANT OPTION;"
service mysql restart

mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "CREATE USER 'forge'@'1.1.1.1' IDENTIFIED BY '7oR1e4DS30vJwg8weGPV';"
mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "CREATE USER 'forge'@'%' IDENTIFIED BY '7oR1e4DS30vJwg8weGPV';"
mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "GRANT ALL PRIVILEGES ON *.* TO 'forge'@'1.1.1.1' WITH GRANT OPTION;"
mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "GRANT ALL PRIVILEGES ON *.* TO 'forge'@'%' WITH GRANT OPTION;"
mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "FLUSH PRIVILEGES;"

# Create The Initial Database If Specified

mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "CREATE DATABASE forge CHARACTER SET utf8 COLLATE utf8_unicode_ci;"

if [[ $(grep --count "maxsize" /etc/logrotate.d/mysql-server) == 0 ]]; then
    sed -i -r "s/^(\s*)(daily|weekly|monthly|yearly)$/\1\2\n\1maxsize 100M/" /etc/logrotate.d/mysql-server
else
    sed -i -r "s/^(\s*)maxsize.*$/\1maxsize 100M/" /etc/logrotate.d/mysql-server
fi

    # If MySQL Fails To Start, Re-Install It

    service mysql restart

    if [[ $? -ne 0 ]]; then
        echo "Purging previous MySQL8 installation..."

        sudo apt-get purge mysql-server mysql-community-server
        sudo apt-get autoclean && sudo apt-get clean

        #
# REQUIRES:
#		- server (the forge server instance)
#		- db_password (random password for mysql user)
#

export DEBIAN_FRONTEND=noninteractive

# Add MySQL Keys...

sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 467B942D3A79BD29

# Configure MySQL Repositories If Required

# Convert a version string into an integer.

function version { echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'; }

UBUNTU_VERSION=$(lsb_release -rs)
echo "Server on Ubuntu ${UBUNTU_VERSION}"
if [ $(version $UBUNTU_VERSION) -le $(version "20.04") ]; then
    wget -c https://dev.mysql.com/get/mysql-apt-config_0.8.15-1_all.deb
    dpkg --install mysql-apt-config_0.8.15-1_all.deb

    apt-get update
fi

# Set The Automated Root Password

debconf-set-selections <<< "mysql-community-server mysql-community-server/data-dir select ''"
debconf-set-selections <<< "mysql-community-server mysql-community-server/root-pass password 7oR1e4DS30vJwg8weGPV"
debconf-set-selections <<< "mysql-community-server mysql-community-server/re-root-pass password 7oR1e4DS30vJwg8weGPV"

# Install MySQL

apt-get install -y mysql-community-server
apt-get install -y mysql-server

# Configure Password Expiration

echo "default_password_lifetime = 0" >> /etc/mysql/mysql.conf.d/mysqld.cnf

# Set Character Set

echo "" >> /etc/mysql/my.cnf
echo "[mysqld]" >> /etc/mysql/my.cnf
echo "default_authentication_plugin=mysql_native_password" >> /etc/mysql/my.cnf
echo "skip-log-bin" >> /etc/mysql/my.cnf

# Configure Max Connections

RAM=$(awk '/^MemTotal:/{printf "%3.0f", $2 / (1024 * 1024)}' /proc/meminfo)
MAX_CONNECTIONS=$(( 70 * $RAM ))
REAL_MAX_CONNECTIONS=$(( MAX_CONNECTIONS>70 ? MAX_CONNECTIONS : 100 ))
sed -i "s/^max_connections.*=.*/max_connections=${REAL_MAX_CONNECTIONS}/" /etc/mysql/my.cnf

# Configure Access Permissions For Root & Forge Users

if grep -q "bind-address" /etc/mysql/mysql.conf.d/mysqld.cnf; then
  sed -i '/^bind-address/s/bind-address.*=.*/bind-address = */' /etc/mysql/mysql.conf.d/mysqld.cnf
else
  echo "bind-address = *" >> /etc/mysql/mysql.conf.d/mysqld.cnf
fi

mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "CREATE USER 'root'@'1.1.1.1' IDENTIFIED BY '7oR1e4DS30vJwg8weGPV';"
mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "CREATE USER 'root'@'%' IDENTIFIED BY '7oR1e4DS30vJwg8weGPV';"
mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "GRANT ALL PRIVILEGES ON *.* TO root@'1.1.1.1' WITH GRANT OPTION;"
mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "GRANT ALL PRIVILEGES ON *.* TO root@'%' WITH GRANT OPTION;"
service mysql restart

mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "CREATE USER 'forge'@'1.1.1.1' IDENTIFIED BY '7oR1e4DS30vJwg8weGPV';"
mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "CREATE USER 'forge'@'%' IDENTIFIED BY '7oR1e4DS30vJwg8weGPV';"
mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "GRANT ALL PRIVILEGES ON *.* TO 'forge'@'1.1.1.1' WITH GRANT OPTION;"
mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "GRANT ALL PRIVILEGES ON *.* TO 'forge'@'%' WITH GRANT OPTION;"
mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "FLUSH PRIVILEGES;"

# Create The Initial Database If Specified

mysql --user="root" --password="7oR1e4DS30vJwg8weGPV" -e "CREATE DATABASE forge CHARACTER SET utf8 COLLATE utf8_unicode_ci;"

if [[ $(grep --count "maxsize" /etc/logrotate.d/mysql-server) == 0 ]]; then
    sed -i -r "s/^(\s*)(daily|weekly|monthly|yearly)$/\1\2\n\1maxsize 100M/" /etc/logrotate.d/mysql-server
else
    sed -i -r "s/^(\s*)maxsize.*$/\1maxsize 100M/" /etc/logrotate.d/mysql-server
fi
    fi

apt_wait



# Configure Supervisor Autostart

systemctl enable supervisor.service
service supervisor start

# Disable protected_regular

sudo sed -i "s/fs.protected_regular = .*/fs.protected_regular = 0/" /usr/lib/sysctl.d/99-protect-links.conf

sysctl --system

# Setup Unattended Security Upgrades

apt_wait

provisionPing 830113 10

apt-get install -y --force-yes unattended-upgrades

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Package-Blacklist {
    //
};
EOF

cat > /etc/apt/apt.conf.d/10periodic << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Configure Additional Log Rotation

if [[ $(grep --count "maxsize" /etc/logrotate.d/fail2ban) == 0 ]]; then
    sed -i -r "s/^(\s*)(daily|weekly|monthly|yearly)$/\1\2\n\1maxsize 100M/" /etc/logrotate.d/fail2ban
else
    sed -i -r "s/^(\s*)maxsize.*$/\1maxsize 100M/" /etc/logrotate.d/fail2ban
fi
if [[ $(grep --count "maxsize" /etc/logrotate.d/rsyslog) == 0 ]]; then
    sed -i -r "s/^(\s*)(daily|weekly|monthly|yearly)$/\1\2\n\1maxsize 100M/" /etc/logrotate.d/rsyslog
else
    sed -i -r "s/^(\s*)maxsize.*$/\1maxsize 100M/" /etc/logrotate.d/rsyslog
fi
if [[ $(grep --count "maxsize" /etc/logrotate.d/ufw) == 0 ]]; then
    sed -i -r "s/^(\s*)(daily|weekly|monthly|yearly)$/\1\2\n\1maxsize 100M/" /etc/logrotate.d/ufw
else
    sed -i -r "s/^(\s*)maxsize.*$/\1maxsize 100M/" /etc/logrotate.d/ufw
fi

cat > /etc/systemd/system/timers.target.wants/logrotate.timer << EOF
[Unit]
Description=Rotation of log files
Documentation=man:logrotate(8) man:logrotate.conf(5)

[Timer]
OnCalendar=*:0/1

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl restart logrotate.timer


curl --insecure --data "event_id=61674868&server_id=830113&recipe_id=" https://forge.laravel.com/provisioning/callback/app

touch /root/.forge-provisioned
