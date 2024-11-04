#!/usr/bin/bash

export DEBIAN_FRONTEND=noninteractive

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."

   exit 1
fi


UNAME=$(awk -F= '/^NAME/{print $2}' /etc/os-release | sed 's/\"//g')
if [[ "$UNAME" != "Ubuntu" ]]; then
    echo "This script only supports Ubuntu 20.04, 22.04 and 24.04!"

    exit 1
fi


if [[ -f /root/.provisioned ]]; then
    echo "This server has already been provisioned!"

    exit 1
fi


if [[ ! -f /root/.ssh/authorized_keys ]]; then
    echo "No SSH authorized keys specified for root!"

    exit 1
fi

# Check Permissions Of /root Directory

chown root:root /root
chown -R root:root /root/.ssh

chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys


# Setup custom user

useradd deployer
mkdir -p /home/deployer/.ssh
adduser deployer sudo
passwd -d deployer


# Setup Bash for custom user

chsh -s /bin/bash deployer
cp /root/.profile /home/deployer/.profile
cp /root/.bashrc /home/deployer/.bashrc

# Setup SSH access for custom user

cp /root/.ssh/authorized_keys /home/deployer/.ssh/authorized_keys

chown -R deployer:deployer /home/deployer
chmod -R 755 /home/deployer
chmod 600 /home/deployer/.ssh/authorized_keys

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

apt_wait

# Hot fix for IPv6 host resolution error
# @see https://www.reddit.com/r/linuxquestions/comments/ot40dj/comment/h6sy9za/

sed -i "s/#precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/" /etc/gai.conf

# if [ -f /etc/needrestart/needrestart.conf ]; then
#     # Ubuntu 22 has this set to (i)nteractive, but we want (a)utomatic.
#     sed -i "s/^#\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
# fi

# Configure swap memory limit using `round(sqrt(RAM))` to calculate swap size

if [ -f /swapfile ]; then
    echo "Swap exists."
else
    RAM_SIZE=$(free -g | awk '/^Mem:/{print $2}')
    RAM_SIZE=$((RAM_SIZE + 1))

    SWAP_SIZE=$(echo "sqrt($RAM_SIZE)" | bc)
    SWAP_SIZE=$(printf "%.0f" $SWAP_SIZE)

    # Update swap size accordingly
    fallocate -l ${SWAP_SIZE}G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo "/swapfile none swap sw 0 0" >> /etc/fstab
    echo "vm.swappiness=30" >> /etc/sysctl.conf
    echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf
fi

# Upgrade the base packages

export DEBIAN_FRONTEND=noninteractive

apt_wait

apt-get update
apt_wait

apt-get upgrade -y
apt_wait

# Install required system packages and add PPAs to get latest versions of softwares

apt-get install -y curl apt-transport-https ca-certificates \
    software-properties-common

apt-add-repository ppa:ondrej/nginx -y
apt-add-repository ppa:ondrej/php -y

# @see https://redis.io/docs/getting-started/installation/install-redis-on-linux/
curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list

apt_wait

apt-get update
apt_wait

add-apt-repository universe -y
apt_wait

apt_wait
apt-get install -y acl apache2-utils build-essential bsdmainutils cron curl \
    fail2ban g++ gcc git gnupg jq libffi-dev libmagickwand-dev libmcrypt4 \
    libpcre2-dev libssl-dev libpcre3-dev libpng-dev make ncdu net-tools \
    pkg-config python3 python3-dev python3-venv python3-pip pwgen rsyslog \
    sqlite3 supervisor tar ufw unzip uuid-runtime wget whois zip zsh

MKPASSWD_INSTALLED=$(type mkpasswd &> /dev/null)
if [ $? -ne 0 ]; then
  echo "Failed to install base dependencies."

  exit 1
fi

apt_wait

# Run cron on system boot

systemctl enable cron

# Install Python Httpie

pip3 install httpie

# Install AWS CLI

# snap install aws-cli --classic

# Set the timezon to UTC

ln -sf /usr/share/zoneinfo/UTC /etc/localtime

# Set the hostname if necessary

# CUSTOM_HOSTNAME="my-server"

# echo $CUSTOM_HOSTNAME > /etc/hostname
# sed -i "s/127\.0\.0\.1.*localhost/127.0.0.1	$CUSTOM_HOSTNAME.localdomain $CUSTOM_HOSTNAME localhost/" /etc/hosts
# hostname $CUSTOM_HOSTNAME

# Create SSH key for custom user

ssh-keygen -f /home/deployer/.ssh/id_ed25519 -t ed25519 -N ''

# Replace `root` with proper username in generated SSH key

sed -i "s/root@$HOSTNAME/deployer@$HOSTNAME/" /home/deployer/.ssh/id_ed25519.pub

# Copy source control pulic keys into known hosts file

ssh-keyscan -H github.com >> /home/deployer/.ssh/known_hosts
ssh-keyscan -H bitbucket.org >> /home/deployer/.ssh/known_hosts
ssh-keyscan -H gitlab.com >> /home/deployer/.ssh/known_hosts

# Setup custom user home directory permissions

chown -R deployer:deployer /home/deployer
chmod -R 755 /home/deployer
chmod 400 /home/deployer/.ssh/id_ed25519
chmod 400 /home/deployer/.ssh/id_ed25519.pub
chmod 600 /home/deployer/.ssh/authorized_keys

# Add new group for isolated users

addgroup isolated

# Disable password authentication and root access over SSH

if [ ! -d /etc/ssh/sshd_config.d ]; then mkdir /etc/ssh/sshd_config.d; fi

cat << EOF > /etc/ssh/sshd_config.d/50-custom.conf
# This is a custom file

PubkeyAuthentication yes
PasswordAuthentication no

EOF

# Restart SSH

ssh-keygen -A
service ssh restart

# Configure Git Settings

git config --global user.name "Worker"
git config --global user.email "worker@example.com"

# Setup UFW firewall

ufw allow 22
ufw allow 80
ufw allow 443

ufw --force enable

# Allow FPM restart

echo "deployer ALL=NOPASSWD: /usr/sbin/service php8.3-fpm reload" > /etc/sudoers.d/php-fpm
echo "deployer ALL=NOPASSWD: /usr/sbin/service php8.2-fpm reload" >> /etc/sudoers.d/php-fpm
echo "deployer ALL=NOPASSWD: /usr/sbin/service php8.1-fpm reload" >> /etc/sudoers.d/php-fpm
echo "deployer ALL=NOPASSWD: /usr/sbin/service php8.0-fpm reload" >> /etc/sudoers.d/php-fpm

# Allow NGINX reload

echo "deployer ALL=NOPASSWD: /usr/sbin/service nginx *" >> /etc/sudoers.d/nginx

# Allow supervisor reload

echo "deployer ALL=NOPASSWD: /usr/bin/supervisorctl reload" >> /etc/sudoers.d/supervisor
echo "deployer ALL=NOPASSWD: /usr/bin/supervisorctl reread" >> /etc/sudoers.d/supervisor
echo "deployer ALL=NOPASSWD: /usr/bin/supervisorctl restart *" >> /etc/sudoers.d/supervisor
echo "deployer ALL=NOPASSWD: /usr/bin/supervisorctl start *" >> /etc/sudoers.d/supervisor
echo "deployer ALL=NOPASSWD: /usr/bin/supervisorctl status *" >> /etc/sudoers.d/supervisor
echo "deployer ALL=NOPASSWD: /usr/bin/supervisorctl status" >> /etc/sudoers.d/supervisor
echo "deployer ALL=NOPASSWD: /usr/bin/supervisorctl stop *" >> /etc/sudoers.d/supervisor
echo "deployer ALL=NOPASSWD: /usr/bin/supervisorctl update *" >> /etc/sudoers.d/supervisor
echo "deployer ALL=NOPASSWD: /usr/bin/supervisorctl update" >> /etc/sudoers.d/supervisor

# Install required PHP extensions and packages

apt_wait

apt-get --fix-missing install -y php-phpseclib php8.3-bcmath php8.3-cli \
    php8.3-common php8.3-curl php8.3-dev php8.3-ds php8.3-fpm php8.3-gd \
    php8.3-gmp php8.3-gnupg php8.3-igbinary php8.3-imagick php8.3-imap \
    php8.3-intl php8.3-mbstring php8.3-memcached php8.3-msgpack php8.3-mysql \
    php8.3-opcache php8.3-pgsql php8.3-readline php8.3-redis php8.3-soap \
    php8.3-sqlite3 php8.3-swoole php8.3-uuid php8.3-xml php8.3-xmlrpc \
    php8.3-xsl php8.3-yaml php8.3-zip

apt_wait

# Install composer

curl -sLS https://getcomposer.org/installer | php -- --install-dir=/usr/bin/ --filename=composer

# Allow composer execution

echo "deployer ALL=(root) NOPASSWD: /usr/local/bin/composer self-update*" > /etc/sudoers.d/composer

# PHP CLI configurations (error reporting, memory limit, timezone)

sed -i "s/error_reporting = .*/error_reporting = E_ALL/" /etc/php/8.3/cli/php.ini
sed -i "s/display_errors = .*/display_errors = On/" /etc/php/8.3/cli/php.ini
sed -i "s/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/" /etc/php/8.3/cli/php.ini
sed -i "s/memory_limit = .*/memory_limit = 512M/" /etc/php/8.3/cli/php.ini
sed -i "s/;date.timezone.*/date.timezone = UTC/" /etc/php/8.3/cli/php.ini

# PHP FPM configurations (error reporting, memory limit, timezone)
sed -i "s/error_reporting = .*/error_reporting = E_ALL/" /etc/php/8.3/fpm/php.ini
sed -i "s/display_errors = .*/display_errors = Off/" /etc/php/8.3/fpm/php.ini
sed -i "s/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/" /etc/php/8.3/fpm/php.ini
sed -i "s/memory_limit = .*/memory_limit = 128M/" /etc/php/8.3/fpm/php.ini
sed -i "s/;date.timezone.*/date.timezone = UTC/" /etc/php/8.3/fpm/php.ini

# PHP FPM configurations (max execution time, max post/upload size, **update for PHPMyAdmin**)
sed -i "s/max_execution_time = .*/max_execution_time = 30/" /etc/php/8.3/fpm/php.ini
sed -i "s/post_max_size = .*/post_max_size = 10M/" /etc/php/8.3/fpm/php.ini
sed -i "s/upload_max_filesize = .*/upload_max_filesize = 10M/" /etc/php/8.3/fpm/php.ini
sed -i "s/max_file_uploads = .*/max_file_uploads = 20/" /etc/php/8.3/fpm/php.ini
sed -i "s/opcache.validate_timestamps = .*/opcache.validate_timestamps = 0/" /etc/php/8.3/fpm/php.ini

# PHP FPM configurations (enable OPcache and configure parameters)
sed -i "s/;opcache.enable=1/opcache.enable=1/" /etc/php/8.3/fpm/php.ini
sed -i "s/;opcache.memory_consumption=.*/opcache.memory_consumption=512/" /etc/php/8.3/fpm/php.ini
sed -i "s/;opcache.interned_strings_buffer=.*/opcache.interned_strings_buffer=64/" /etc/php/8.3/fpm/php.ini
sed -i "s/;opcache.max_accelerated_files=.*/opcache.max_accelerated_files=30000/" /etc/php/8.3/fpm/php.ini
sed -i "s/;opcache.validate_timestamps=.*/opcache.validate_timestamps=1/" /etc/php/8.3/fpm/php.ini
sed -i "s/;opcache.save_comments=.*/opcache.save_comments=1/" /etc/php/8.3/fpm/php.ini

# PHP FPM pool configuration (user/group, listen mode, request timeout)

sed -i "s/^user = .*/user = deployer/" /etc/php/8.3/fpm/pool.d/www.conf
sed -i "s/^group = .*/group = deployer/" /etc/php/8.3/fpm/pool.d/www.conf
sed -i "s/;listen\.owner.*/listen.owner = deployer/" /etc/php/8.3/fpm/pool.d/www.conf
sed -i "s/;listen\.group.*/listen.group = deployer/" /etc/php/8.3/fpm/pool.d/www.conf
sed -i "s/listen\.owner.*/listen.owner = deployer/" /etc/php/8.3/fpm/pool.d/www.conf
sed -i "s/listen\.group.*/listen.group = deployer/" /etc/php/8.3/fpm/pool.d/www.conf
sed -i "s/;listen\.mode.*/listen.mode = 0666/" /etc/php/8.3/fpm/pool.d/www.conf
sed -i "s/;request_terminate_timeout .*/request_terminate_timeout = 60/" /etc/php/8.3/fpm/pool.d/www.conf

# PHP FPM child processes configuration

sed -i "s/^pm.max_children.*=.*/pm.max_children = 60/" /etc/php/8.3/fpm/pool.d/www.conf

# Configure sessions directory permissions

chmod 733 /var/lib/php/sessions
chmod +t /var/lib/php/sessions

# Set global alias for PHP 8.3

update-alternatives --set php /usr/bin/php8.3

# Ensure sudoers is up-to-date

LINE="ALL=NOPASSWD: /usr/sbin/service php8.3-fpm reload"
FILE="/etc/sudoers.d/php-fpm"
grep -q -- "^deployer $LINE" "$FILE" || echo "deployer $LINE" >> "$FILE"

# TODO: Configure logrotate for PHP FPM

# Install NGINX and enable on system boot

apt_wait
apt-get install -y nginx
apt_wait

systemctl enable nginx.service

# Generate a secure DH Param for NGINX (will take some time)

openssl dhparam -out /etc/nginx/dhparams.pem 4096

# Add GZIP compression configuration

cat > /etc/nginx/conf.d/gzip.conf << EOF
gzip_comp_level 5;
gzip_min_length 256;
gzip_proxied any;
gzip_vary on;
gzip_http_version 1.1;

gzip_types
application/atom+xml
application/javascript
application/json
application/ld+json
application/manifest+json
application/rss+xml
application/vnd.geo+json
application/vnd.ms-fontobject
application/x-font-ttf
application/x-web-app-manifest+json
application/xhtml+xml
application/xml
font/opentype
image/bmp
image/svg+xml
image/x-icon
text/cache-manifest
text/css
text/plain
text/vcard
text/vnd.rim.location.xloc
text/vtt
text/x-component
text/x-cross-domain-policy;

EOF

# Configure Cloudflare proxy IPs

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

# Configure max execution time

cat > /etc/nginx/conf.d/timeout.conf << EOF
fastcgi_read_timeout 30;

EOF

# Configure max upload limit

cat > /etc/nginx/conf.d/uploads.conf << EOF
client_max_body_size 10M;

EOF

# Common security snippet

cat > /etc/nginx/snippets/security.conf << EOF
server_tokens off;

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_dhparam /etc/nginx/dhparams.pem;

add_header X-Frame-Options "SAMEORIGIN";
add_header X-XSS-Protection "1; mode=block";
add_header X-Content-Type-Options "nosniff";

EOF

# Replace default NGINX base configuration

rm /etc/nginx/nginx.conf
cat > /etc/nginx/nginx.conf << EOF
user deployer;
worker_processes auto;
worker_rlimit_nofile 1000; # Increase for Laravel Reverb
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1000; # Increase for Laravel Reverb
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    server_tokens off;

    server_names_hash_bucket_size 128;
    server_name_in_redirect off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # SSL configuration
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
    ssl_prefer_server_ciphers on;

    # Logging
    access_log /var/log/nginx/access.log;

    # GZIP (remaining in `conf.d/nginx.conf`)
    gzip on;

    # Virtual host config
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}

EOF


# Install a dummy catch-all certificate

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

# Remove default NGINX site

rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default

# Setup custom default site to reject connections for unknown hosts

cat > /etc/nginx/sites-available/000-catch-all << EOF
server {
    http2 on;

    listen 80 default_server;
    listen [::]:80 default_server;

    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;

    server_name _;

    ssl_certificate /etc/nginx/ssl/catch-all.invalid.crt;
    ssl_certificate_key /etc/nginx/ssl/catch-all.invalid.key;

    include snippets/security.conf;
    ssl_reject_handshake on;

    return 444;
}
EOF

# Install new catch-all default site

ln -s /etc/nginx/sites-available/000-catch-all /etc/nginx/sites-enabled/000-catch-all

# Restart NGINX service

NGINX=$(ps aux | grep nginx | grep -v grep)
if [[ -z $NGINX ]]; then
    service nginx start
    echo "Started Nginx"
else
    service nginx reload
    echo "Reloaded Nginx"
fi

# Restart PHP-FPM service

PHP=$(ps aux | grep php-fpm | grep -v grep)
if [[ ! -z $PHP ]]; then
    service php8.3-fpm restart > /dev/null 2>&1
    service php8.2-fpm restart > /dev/null 2>&1
    service php8.1-fpm restart > /dev/null 2>&1
    service php8.0-fpm restart > /dev/null 2>&1
fi

# Add custom user to www-data group

usermod -a -G www-data deployer
id deployer
groups deployer

# Change ownership and permissions for NGINX default web root

chown -R deployer:deployer /var/www
chmod 755 -R /var/www

# TODO: Setup logrotate for NGINX

apt_wait

# Install Node JS

mkdir -p /etc/apt/keyrings
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg

NODE_MAJOR=20
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" > /etc/apt/sources.list.d/nodesource.list

apt_wait

apt-get update
apt_wait

sudo apt-get install -y nodejs
apt_wait

npm install -g pm2
npm install -g gulp
npm install -g yarn
npm install -g bun

# Configure max open file limit for custom user

echo "" >> /etc/security/limits.conf
echo "deployer        soft  nofile  10000" >> /etc/security/limits.conf
echo "deployer        hard  nofile  10000" >> /etc/security/limits.conf
echo "" >> /etc/security/limits.conf


# Add MySQL keys

apt_wait

apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 467B942D3A79BD29

apt-get update

apt_wait


# Generate

mkdir -p /root/.credentials

# Generate a secure random password

MYSQL_PASSWD=$(pwgen -cnsBv 20 1)

# Install MySQL

apt-get install -y mysql-server

apt_wait

# Start the MySQL service

service mysql start

# Start MySQL service on system boot

systemctl enable mysql

# Disable password expiration

echo "default_password_lifetime = 0" >> /etc/mysql/mysql.conf.d/mysqld.cnf

# Set password as default authentication plugin

echo "" >> /etc/mysql/my.cnf
echo "[mysqld]" >> /etc/mysql/my.cnf
echo "default_authentication_plugin=mysql_native_password" >> /etc/mysql/my.cnf
echo "skip-log-bin" >> /etc/mysql/my.cnf

# Configure max connections based on available RAM

RAM=$(awk '/^MemTotal:/{printf "%3.0f", $2 / (1024 * 1024)}' /proc/meminfo)
MAX_CONNECTIONS=$(( 70 * $RAM ))
REAL_MAX_CONNECTIONS=$(( MAX_CONNECTIONS>70 ? MAX_CONNECTIONS : 100 ))
sed -i "s/^max_connections.*=.*/max_connections=${REAL_MAX_CONNECTIONS}/" /etc/mysql/my.cnf
sed -i "s/^max_connections.*=.*/max_connections=${REAL_MAX_CONNECTIONS}/" /etc/mysql/mysql.conf.d/mysqld.cnf

if grep -q "bind-address" /etc/mysql/mysql.conf.d/mysqld.cnf; then
  sed -i '/^bind-address/s/bind-address.*=.*/bind-address = */' /etc/mysql/mysql.conf.d/mysqld.cnf
else
  echo "bind-address = *" >> /etc/mysql/mysql.conf.d/mysqld.cnf
fi

service mysql restart

# Manually apply `mysql_secure_installation`

# Change password of the root user
mysql --user="root" --password="" -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH caching_sha2_password BY '$MYSQL_PASSWD';"

# Remove anonymous user
mysql --user="root" --password="$MYSQL_PASSWD" -e "DELETE FROM mysql.user WHERE User='';"

# Disable remote root user access
mysql --user="root" --password="$MYSQL_PASSWD" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"

# Remove test
mysql --user="root" --password="$MYSQL_PASSWD" -e "DROP DATABASE IF EXISTS test;"
mysql --user="root" --password="$MYSQL_PASSWD" -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"

mysql --user="root" --password="$MYSQL_PASSWD" -e "FLUSH PRIVILEGES;"

# Save MySQL password

echo "$MYSQL_PASSWD" > /root/.credentials/mysql

# Create a local super user

mysql --user="root" --password="$MYSQL_PASSWD" -e "CREATE USER 'admin'@'localhost' IDENTIFIED WITH caching_sha2_password BY '$MYSQL_PASSWD';"
mysql --user="root" --password="$MYSQL_PASSWD" -e "GRANT ALL PRIVILEGES ON *.* TO 'admin'@'localhost' WITH GRANT OPTION;"

# Generate a secure password for phpMyAdmin

PMA_PASSWD=$(pwgen -cnsBv 20 1)

# Create database and user for phpMyAdmin

mysql --user="root" --password="$MYSQL_PASSWD" -e "CREATE DATABASE pma CHARACTER SET utf8 COLLATE utf8_unicode_ci;"
mysql --user="root" --password="$MYSQL_PASSWD" -e "CREATE USER 'pma'@'localhost' IDENTIFIED WITH caching_sha2_password BY '$PMA_PASSWD';"
mysql --user="root" --password="$MYSQL_PASSWD" -e "GRANT ALL PRIVILEGES ON pma.* TO 'pma'@'localhost' WITH GRANT OPTION;"

# Refresh privileges to immediately update permissions

mysql --user="root" --password="$MYSQL_PASSWD" -e "FLUSH PRIVILEGES;"

# Save PhpMyAdmin password

echo "$PMA_PASSWD" > /root/.credentials/phpmyadmin

# Download and install PhpMyAdmin

# rm -rf /var/www/phpmyadmin
# curl -sLO https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.tar.gz
# mkdir -p /var/www/phpmyadmin
# tar xvf phpMyAdmin-latest-all-languages.tar.gz --strip-components=1 -C /var/www/phpmyadmin
# mkdir /var/www/phpmyadmin/tmp
# rm phpMyAdmin-latest-all-languages.tar.gz

# Remove test directories

# rm -rf /var/www/phpmyadmin/setup
# rm -rf /var/www/phpmyadmin/test

# Configure phpMyAdmin

# cp /var/www/phpmyadmin/config.sample.inc.php /var/www/phpmyadmin/config.inc.php

# BLOWFISH_SECRET=$(pwgen -cnsBv 33 1)

# sed -i "s/^\$cfg\['blowfish_secret'\].*=.*/\$cfg\['blowfish_secret'\] = '$BLOWFISH_SECRET';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\$cfg\['Servers'\]\[\$i\]\['host'\] = .*/\$cfg\['Servers'\]\[\$i\]\['host'\] = 'localhost';/" /var/www/phpmyadmin/config.inc.php

# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['controluser'\] = .*/\$cfg\['Servers'\]\[\$i\]\['controluser'\] = 'pma';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['controlpass'\] = .*/\$cfg\['Servers'\]\[\$i\]\['controlpass'\] = '$PMA_PASSWD';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['pmadb'\] = .*/\$cfg\['Servers'\]\[\$i\]\['pmadb'\] = 'pma';/" /var/www/phpmyadmin/config.inc.php

# Uncomment required configuration
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['bookmarktable'\] = .*/\$cfg\['Servers'\]\[\$i\]\['bookmarktable'\] = 'pma__bookmark';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['relation'\] = .*/\$cfg\['Servers'\]\[\$i\]\['relation'\] = 'pma__relation';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['table_info'\] = .*/\$cfg\['Servers'\]\[\$i\]\['table_info'\] = 'pma__table_info';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['table_coords'\] = .*/\$cfg\['Servers'\]\[\$i\]\['table_coords'\] = 'pma__table_coords';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['pdf_pages'\] = .*/\$cfg\['Servers'\]\[\$i\]\['pdf_pages'\] = 'pma__pdf_pages';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['column_info'\] = .*/\$cfg\['Servers'\]\[\$i\]\['column_info'\] = 'pma__column_info';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['history'\] = .*/\$cfg\['Servers'\]\[\$i\]\['history'\] = 'pma__history';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['table_uiprefs'\] = .*/\$cfg\['Servers'\]\[\$i\]\['table_uiprefs'\] = 'pma__table_uiprefs';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['tracking'\] = .*/\$cfg\['Servers'\]\[\$i\]\['tracking'\] = 'pma__tracking';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['userconfig'\] = .*/\$cfg\['Servers'\]\[\$i\]\['userconfig'\] = 'pma__userconfig';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['recent'\] = .*/\$cfg\['Servers'\]\[\$i\]\['recent'\] = 'pma__recent';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['favorite'\] = .*/\$cfg\['Servers'\]\[\$i\]\['favorite'\] = 'pma__favorite';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['users'\] = .*/\$cfg\['Servers'\]\[\$i\]\['users'\] = 'pma__users';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['usergroups'\] = .*/\$cfg\['Servers'\]\[\$i\]\['usergroups'\] = 'pma__usergroups';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['navigationhiding'\] = .*/\$cfg\['Servers'\]\[\$i\]\['navigationhiding'\] = 'pma__navigationhiding';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['savedsearches'\] = .*/\$cfg\['Servers'\]\[\$i\]\['savedsearches'\] = 'pma__savedsearches';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['central_columns'\] = .*/\$cfg\['Servers'\]\[\$i\]\['central_columns'\] = 'pma__central_columns';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['designer_settings'\] = .*/\$cfg\['Servers'\]\[\$i\]\['designer_settings'\] = 'pma__designer_settings';/" /var/www/phpmyadmin/config.inc.php
# sed -i "s/^\/\/ \$cfg\['Servers'\]\[\$i\]\['export_templates'\] = .*/\$cfg\['Servers'\]\[\$i\]\['export_templates'\] = 'pma__export_templates';/" /var/www/phpmyadmin/config.inc.php

# echo "" >> /var/www/phpmyadmin/config.inc.php
# echo "\$cfg['Servers'][\$i]['AllowRoot'] = false;" >> /var/www/phpmyadmin/config.inc.php

# Set default user as owner of the PhpMyAdmin

# chown -R deployer:deployer /var/www/phpmyadmin

# Secure credentials files

chmod 600 -R /root/.credentials

# TODO: Password protected PhpMyAdmin directory

# TODO: Configure logrotate for MySQL

# Install and configure Redis

apt_wait

apt-get install -y redis-server
apt_wait

sed -i 's/bind 127.0.0.1/bind 0.0.0.0/' /etc/redis/redis.conf

service redis-server restart
systemctl enable redis-server

# TODO: Configure logrotate for Redis

# Configure supervisor service to start on system boot

systemctl enable supervisor.service
service supervisor start

# TODO: Configure unattented upgrades

# TODO: Configure logrotate for fail2ban, rsyslog and ufw

systemctl daemon-reload
# systemctl restart logrotate.timer

# Fix incorrect logrotate default configuration

# sed -i -r "s/^create 0640 www-data adm/create 0640 deployer adm/" /etc/logrotate.d/nginx

# Download helper scripts

curl -s https://raw.githubusercontent.com/azzazkhan/server-notes/master/scripts/download | bash

# Final setup

touch /root/.provisioned
