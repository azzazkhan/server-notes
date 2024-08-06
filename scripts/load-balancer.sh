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
validateServerId 830120

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
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCxd4MRtstmxnVWP/ZrjErSK6XTZqiHTnM3LdM/jDDNTEWKPjDv7xPZZEYJ+I9qx+FXzWpQjchPqad4qF8GbUQ9j3L2vTBK2fjD9TXYFSeQnOX/42WSHxuYWd/NRDGh/l7e7OljwaoHnJBnfdKYhgFrFZcsKG632wIwI4y/73brCt+tAL++KT6d301ipdo/2Id2Odrl/6yK44kxoizSfLGTUMAvM3dB6lk3ZrsQ0KugldLoeqm2H2W2xDS0KGqRHuDe6rADn4LEQUSIJR/KQxqqFXXhFHDRFOy+3K7AYmITIbS/rLO89Hd2gt58P0g06JGCiVpHE42G6wYDgpMyi8pj+iBoMmIZD2dSc/kEu+7JBfif5Ove8wVp3PKBehxH8deBWI914syjNI1ZB+yro0yiJpnv3QbMWkn6lRt4eQFRsq8RDVmHKjmDHXO6z/ZZRnYXLQCeMyxhyKDUEpvVpKVbyuXKW2xUuPWBHc/OzI9rSzng5YtltpDPbaOZDxa1x1PouBcU+wowXs82NmNVEq40M6MwdGJHBRm1ZFPO0+uNLdIn00J6DiVg6BJtwUXHqYjJRwpW17C975QlvQV6iEMe7hKJu4od1MsEscl7bQXQ6r+KkqsmU4ysdr2YNwS7hyDx9+joeMNTeUvimsXN/pyaSbsIv4CmJOXRVWzda+uZFQ== worker@forge.laravel.com

EOF

cp /root/.ssh/authorized_keys /home/forge/.ssh/authorized_keys

chown -R forge:forge /home/forge
chmod -R 755 /home/forge
chmod 600 /home/forge/.ssh/authorized_keys

apt-get install -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y --force-yes curl

# Check connection with Forge
echo "Checking the Forge connection ..."

response=`curl -s -w "%{http_code}" POST --url https://forge.laravel.com/servers/830120/vps/connection --data-urlencode "forge_token=eyJpdiI6IlZvWkNJVER5cTlld29NaVFRaWZnSFE9PSIsInZhbHVlIjoiZU5qMUZUOUxoMlVvanRXU1hmZTZ1V0NHeFBaU3BncTY5cnVHNmdJWEhVMlVFVE5JL0F1YlAybTJzM29PNmVVb2VHK0hKcGpYQWlUNGNzS2lucXpIQzBlSmJHZG1HQmM0YzA2QzU2UDdTSmM9IiwibWFjIjoiMmQwNWQ0Mjc2ZmMxNThlNWJmNjU2ZTExODNmMzI0ZjY0Y2JjN2Y5MDJmZWZiYzNmNTIyYTA5NmJiMjY1NDhjNyIsInRhZyI6IiJ9"`
status=$(printf "%s" "$response" | tail -c 3)
if [ "$status" -ne "200" ]; then
  echo "Error \"$status\" while checking the Forge connection."
  echo "Forge: ${response::-3}"
  exit 1
else
  echo "Forge connection was established."
fi

provisionPing 830120 1

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

provisionPing 830120 2

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

provisionPing 830120 3

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


echo "holy-butterfly" > /etc/hostname
sed -i 's/127\.0\.0\.1.*localhost/127.0.0.1	holy-butterfly.localdomain holy-butterfly localhost/' /etc/hosts
hostname holy-butterfly


# Set The Timezone

# ln -sf /usr/share/zoneinfo/UTC /etc/localtime
ln -sf /usr/share/zoneinfo/UTC /etc/localtime

# Set The Sudo Password For Forge

PASSWORD=$(mkpasswd -m sha-512 0KG7D4EhZ13DnWbfd3cx)
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
ufw allow 80
ufw allow 443


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

provisionPing 830120 4

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

provisionPing 830120 5

    #
# REQUIRES:
#       - server (the forge server instance)
#		- site_name (the name of the site folder)
#

# Install Nginx

apt-get install -y --force-yes nginx

systemctl enable nginx.service

# Generate dhparam File

openssl dhparam -out /etc/nginx/dhparams.pem 2048

# Configure Primary Nginx Settings

sed -i "s/user www-data;/user forge;/" /etc/nginx/nginx.conf
sed -i "s/worker_processes.*/worker_processes auto;/" /etc/nginx/nginx.conf
sed -i "s/# multi_accept.*/multi_accept on;/" /etc/nginx/nginx.conf
sed -i "s/# server_names_hash_bucket_size.*/server_names_hash_bucket_size 128;/" /etc/nginx/nginx.conf

# Configure Cloudflare Real IPs

cat > /etc/nginx/conf.d/cloudflare.conf << EOF
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;
real_ip_header X-Forwarded-For;

EOF
# Disable The Default Nginx Site

rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
service nginx restart

# Install A Catch All Server
mkdir -p /etc/nginx/ssl/
cat > /etc/nginx/ssl/catch-all.invalid.crt << EOF
-----BEGIN CERTIFICATE-----
MIIC1TCCAb2gAwIBAgIJAOzFtsytI2mWMA0GCSqGSIb3DQEBBQUAMBoxGDAWBgNV
BAMTD3d3dy5leGFtcGxlLmNvbTAeFw0yMTA1MDMxNTU4MTVaFw0zMTA1MDExNTU4
MTVaMBoxGDAWBgNVBAMTD3d3dy5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBALqkjykou8/yD6rUuz91ZvKC0b7HOZrGmZoenZD1qI85
fHg1v7aavJPaXvhXHstUq6Vu6oTR/XDLhqKAOUfiRMFF7i2al8cB0VOmNtH8IGfh
c5EGZO2uvQRwPUhipdkJWGFDPlME8fNsnCJcUKebaiwYlen00GEgwKUTNrYNLcBN
POTLm9FdiEtTmSIbm7DmVFEVqF1zD/mOzEvU9exeZM8bn0GYAu+/qEUBDYtNWnnr
eQQIhjH1CBagvZn+JRpfNydASIMbu7oMVR7GiooR5KwqJBCqRMSHJEMeMIksP04G
myMQG0lSS3bnXxm2pVnFW8Xstu7q+4RkPyNP8tS77TECAwEAAaMeMBwwGgYDVR0R
BBMwEYIPd3d3LmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBBQUAA4IBAQA8veEEhCEj
evVUpfuh74SgmAWfBQNjSnwqPm20NnRiT3Khp7avvOOgapep31CdGI4cd12PFrqC
wh9ov/Y28Cw191usUbLSoYvIs2VUrv8jNXh/V20s6rKICz292FMmNvKtBVf3dGz6
dYmbW9J9H44AH/q/y3ljQgCmxFJgAAvAAiKgD9Bf5Y8GvFP7EFyqWOwWTwls91QL
lDDbKOegoD1KRRpFZV8qVhMx6lzyAqzK0U9GZGCANv6II5zEgDDXGKt1OVL+90ri
KuGJW+cmqv00F+/bgvNNhIu2tZt/wN3oPEJVjEj0Z5d8+gvo0NHwlwGYrgjHlSpV
2G5KyvZe5dES
-----END CERTIFICATE-----
EOF
cat > /etc/nginx/ssl/catch-all.invalid.key << EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAuqSPKSi7z/IPqtS7P3Vm8oLRvsc5msaZmh6dkPWojzl8eDW/
tpq8k9pe+Fcey1SrpW7qhNH9cMuGooA5R+JEwUXuLZqXxwHRU6Y20fwgZ+FzkQZk
7a69BHA9SGKl2QlYYUM+UwTx82ycIlxQp5tqLBiV6fTQYSDApRM2tg0twE085Mub
0V2IS1OZIhubsOZUURWoXXMP+Y7MS9T17F5kzxufQZgC77+oRQENi01aeet5BAiG
MfUIFqC9mf4lGl83J0BIgxu7ugxVHsaKihHkrCokEKpExIckQx4wiSw/TgabIxAb
SVJLdudfGbalWcVbxey27ur7hGQ/I0/y1LvtMQIDAQABAoIBAQCoJUycRgg9pNOc
kZ5H41rlrBmOCCnLWJRVFrPZPpemwKF0IugeeHTftuHMVaB2ikdA+RXqpsvu7EzU
5TO1oRFUFc4n45hNP0P4WkwVDVGchK36v4n532yGLR/osIa9av/mUBA79r6LERPw
mL5I4WjbZSLZ7SY1+q3TieXGSUUocmHGzgtSQ5lIKGC6ppE/3GBqoSJB24sEhpqp
qnRs3mPe8q6ZhZLAqoEWni/4XrDycVE/BTgVb3qbZe+/4orPvSxLXEQIdvuxI4Mh
MqKZHeS2DSAQd845YgiR2MjlgjPJU7LaIQSjWkfgDIw9iHIbUcaLYEcMtfCu+xPE
d9eZNJQBAoGBAO6RbNavi1w/VjNsmgiFmXIAz5cn1bxkLWpoCq1oXN9uRMKPvBcG
xuKdAVVewvXVD9WEM1CSKeqWSH3mcxxqHaOyqy0aZrk98pphMSvo9QCaoaZP+68H
NQ1g/Ws82HUS7bVPULgMHFkLu1t1DcfYADjvVrgYuTrrL9yBeyj3b1ORAoGBAMhH
1mWaMK3hySMhlfQ7DMfrwsou4tgvALrnkyxyr1FgXCZGJ5ckaVVBmwLns3c5A6+1
MDlMVoXWKI7DSjEh7RPxa02QQTS2FWR0ARvf/Wm8WdGyh7k+0L/y+K+66fZjwLsa
Gjiq7BnvQAt5NgJI9i8wxxWqTVcGKHeM7No7dO+hAoGAalDYphv5CRUYvzYItv+C
0HFYEc6oy5oBO0g+aeT2boPflK0lb0WP4HGDpJ3kWFWpBsgxbhiVIXvztle6uND5
gHghHKqFWMwoj2/8z8qzVJ+Upl9ClE+r7thoVx/4fsP+tywvlrWe9Hfr+OgDSioS
f0z54nTyJzWkUKpLTohmTmECgYASIAY0HbcoFVXpmwGCH9HxSdHQEFwxKlfLkmeM
Tzi0iZ7tS84LbJ0nvQ81PRjNwlgmD6S0msb9x7rV6LCPL73P3zpRw6tTBON8us7a
4fOCHSyXwKttxVSI+oktBiJkTPTFOgCDflxtoGxQXYDYxheZf7WUrVvgc0s4PoW0
3kqf4QKBgQCvFTk0uBaZ9Aqslty0cPA2LoVclmQZenbxPSRosEYVQJ6urEpoolss
W2v3zRTw+Pv3bXxS2F6z6C5whOeaq2V8epF4LyXDBZhiF+ayxUgA/hJAZqoeSrMB
ziOvF1n30W8rVLx3HjfpA5eV2BbT/4NChXwlPTbCd9xy11GimqPsNQ==
-----END RSA PRIVATE KEY-----
EOF

# Convert a version string into an integer.

function version { echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'; }
if [ $(version $(nginx -v 2>&1 | grep -o '[0-9.]\+')) -ge $(version "1.26") ]; then
cat > /etc/nginx/sites-available/000-catch-all << EOF
server {
    http2 on;
    listen 80 default_server;
    listen [::]:80 default_server;
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    server_tokens off;

    ssl_certificate /etc/nginx/ssl/catch-all.invalid.crt;
    ssl_certificate_key /etc/nginx/ssl/catch-all.invalid.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_dhparam /etc/nginx/dhparams.pem;
    ssl_reject_handshake on;

    return 444;
}
EOF
else
cat > /etc/nginx/sites-available/000-catch-all << EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;
    server_tokens off;

    ssl_certificate /etc/nginx/ssl/catch-all.invalid.crt;
    ssl_certificate_key /etc/nginx/ssl/catch-all.invalid.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_dhparam /etc/nginx/dhparams.pem;
    ssl_reject_handshake on;

    return 444;
}
EOF
fi

ln -s /etc/nginx/sites-available/000-catch-all /etc/nginx/sites-enabled/000-catch-all

# Restart Nginx

# Restart Nginx & PHP-FPM Services

#service nginx restart
NGINX=$(ps aux | grep nginx | grep -v grep)
if [[ -z $NGINX ]]; then
    service nginx start
    echo "Started Nginx"
else
    service nginx reload
    echo "Reloaded Nginx"
fi

PHP=$(ps aux | grep php-fpm | grep -v grep)
if [[ ! -z $PHP ]]; then
    service php8.3-fpm restart > /dev/null 2>&1
    service php8.2-fpm restart > /dev/null 2>&1
    service php8.1-fpm restart > /dev/null 2>&1
    service php8.0-fpm restart > /dev/null 2>&1
    service php7.4-fpm restart > /dev/null 2>&1
    service php7.3-fpm restart > /dev/null 2>&1
    service php7.2-fpm restart > /dev/null 2>&1
    service php7.1-fpm restart > /dev/null 2>&1
    service php7.0-fpm restart > /dev/null 2>&1
    service php5.6-fpm restart > /dev/null 2>&1
    service php5-fpm restart > /dev/null 2>&1
fi

# Add Forge User To www-data Group

usermod -a -G www-data forge
id forge
groups forge

if [[ $(grep --count "maxsize" /etc/logrotate.d/nginx) == 0 ]]; then
    sed -i -r "s/^(\s*)(daily|weekly|monthly|yearly)$/\1\2\n\1maxsize 100M/" /etc/logrotate.d/nginx
else
    sed -i -r "s/^(\s*)maxsize.*$/\1maxsize 100M/" /etc/logrotate.d/nginx
fi

apt_wait



apt_wait



# Configure Supervisor Autostart

systemctl enable supervisor.service
service supervisor start

# Disable protected_regular

sudo sed -i "s/fs.protected_regular = .*/fs.protected_regular = 0/" /usr/lib/sysctl.d/99-protect-links.conf

sysctl --system

# Setup Unattended Security Upgrades

apt_wait

provisionPing 830120 10

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

# Fix incorrect logrotate default configuration
sed -i -r "s/^create 0640 www-data adm/create 0640 forge adm/" /etc/logrotate.d/nginx

curl --insecure --data "event_id=61675112&server_id=830120&recipe_id=" https://forge.laravel.com/provisioning/callback/app

touch /root/.forge-provisioned
