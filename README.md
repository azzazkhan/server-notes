1. Update system dependencies `apt-get update && apt-get upgrade -y`.
2. Create new user, add `sudo` privileges, copy `root`'s SSH access key and set home directory permissions.

    ```bash
    adduser ubuntu \
    && passwd -d ubuntu \
    && usermod -aG sudo ubuntu \
    && mkdir /home/ubuntu/.ssh \
    && cp /root/.ssh/authorized_keys /home/ubuntu/.ssh/authorized_keys \
    && chown -R ubuntu:ubuntu /home/ubuntu \
    && chmod -R 755 /home/ubuntu \
    && chmod 600 /home/ubuntu/.ssh/authorized_keys
    ```

3. Hot fix for preferring IPv4 over IPv6 address ([source](https://www.reddit.com/r/linuxquestions/comments/ot40dj/comment/h6sy9za/)).

    ```bash
    sed -i "s/#precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/" /etc/gai.conf
    ```

4. Setup swap memory limit, update swap size per requirement (current size 10 GB).

    **Only run if file `/swapfile` does not exist!**

    ```bash
    fallocate -l 10G /swapfile \
    && chmod 600 /swapfile \
    && mkswap /swapfile \
    && swapon /swapfile \
    && echo "/swapfile none swap sw 0 0" >> /etc/fstab \
    && echo "vm.swappiness=30" >> /etc/sysctl.conf \
    && echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf
    ```

5. Install required system package and add APT repositories for PHP, NGINX and Ubuntu Universe and keyring for Redis.

    ```bash
    apt-get install -y curl apt-transport-https ca-certificates software-properties-common

    apt-add-repository ppa:ondrej/nginx -y
    apt-add-repository ppa:ondrej/php -y

    curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list

    apt-get update

    add-apt-repository universe -y
    ```

6. Install required system packages.

    ```bash
    apt-get install -y acl build-essential bsdmainutils cron curl fail2ban \
        g++ gcc git gnupg jq libmagickwand-dev libmcrypt4 libpcre2-dev \
        libpcre3-dev libpng-dev make ncdu net-tools pkg-config python3 \
        python3-pip rsyslog sendmail sqlite3 tar supervisor ufw unzip \
        uuid-runtime wget whois zip zsh
    ```

7. Update SSH config to disallow password login and root user remote access and restart SSH.

    ```bash
    mkdir -p /etc/ssh/sshd_config.d \
       && echo "# This is a custom file." > /etc/ssh/sshd_config.d/50-custom.conf \
       && echo "" >> /etc/ssh/sshd_config.d/50-custom.conf \
       && echo "PermitRootLogin no" >> /etc/ssh/sshd_config.d/50-custom.conf \
       && echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config.d/50-custom.conf \
       && echo "PasswordAuthentication no" >> /etc/ssh/sshd_config.d/50-custom.conf \
       && echo "" >> /etc/ssh/sshd_config.d/50-custom.conf

    ssh-keygen -A && service ssh restart
    ```

8. Update hostname (if necessary), replace `%HOSTNAME%` with your own hostname.

    ```bash
    echo "%HOSTNAME%" > /etc/hostname
    sed -i 's/127\.0\.0\.1.*localhost/127.0.0.1    %HOSTNAME%.localdomain %HOSTNAME% localhost/' /etc/hosts
    hostname %HOSTNAME%
    ```

9. Change system's timezone to UTC `ln -sf /usr/share/zoneinfo/UTC /etc/localtime`
10. Generate a new local SSH key and add source control provider's resolved IPs to known hosts.

    ```bash
    ssh-keygen -f /home/ubuntu/.ssh/id_ed25519 -t ed25519 -N '' \
        && ssh-keyscan -H github.com >> /home/ubuntu/.ssh/known_hosts \
        && ssh-keyscan -H bitbucket.org >> /home/ubuntu/.ssh/known_hosts \
        && ssh-keyscan -H gitlab.com >> /home/ubuntu/.ssh/known_hosts
    ```

11. Configure global Git configurations.

    ```bash
    git config --global user.name "Worker" \
        && git config --global user.email "worker@example.com"
    ```

12. Enable firewall and allow traffic on HTTP and SSH ports only.

    ```bash
    ufw allow 22 \
        && ufw allow 80 \
        && ufw allow 443 \
        && ufw --force enable
    ```

13. Install PHP and necessary extensions.

    ```bash
    apt-get --fix-missing install -y php-phpseclib php8.3-bcmath php8.3-cli \
        php8.3-common php8.3-curl php8.3-dev php8.3-ds php8.3-fpm php8.3-gd \
        php8.3-gmp php8.3-gnupg php8.3-igbinary php8.3-imagick php8.3-imap \
        php8.3-intl php8.3-mbstring php8.3-memcached php8.3-msgpack \
        php8.3-mysql php8.3-opcache php8.3-pgsql php8.3-readline php8.3-redis \
        php8.3-soap php8.3-sqlite3 php8.3-swoole php8.3-uuid php8.3-xml \
        php8.3-xmlrpc php8.3-xsl php8.3-yaml php8.3-zip

    # Enable PHP-FPM daemon
    systemctl enable php8.3-fpm
    ```

14. Install composer.

    ```bash
    curl -sLS https://getcomposer.org/installer | php -- --install-dir=/usr/bin/ --filename=composer
    ```

15. Update PHP CLI and FPM configurations.

    ```bash
    # PHP CLI configurations (error reporting, memory limit, timezone)
    sed -i "s/error_reporting = .*/error_reporting = E_ALL/" /etc/php/8.3/cli/php.ini \
        && sed -i "s/display_errors = .*/display_errors = On/" /etc/php/8.3/cli/php.ini \
        && sed -i "s/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/" /etc/php/8.3/cli/php.ini \
        && sed -i "s/memory_limit = .*/memory_limit = 512M/" /etc/php/8.3/cli/php.ini \
        && sed -i "s/;date.timezone.*/date.timezone = UTC/" /etc/php/8.3/cli/php.ini

    # PHP FPM configurations (error reporting)
    sed -i "s/display_errors = .*/display_errors = Off/" /etc/php/8.3/fpm/php.ini \
        && sed -i "s/error_reporting = .*/error_reporting = E_ALL/" /etc/php/8.3/fpm/php.ini \
        && sed -i "s/display_errors = .*/display_errors = Off/" /etc/php/8.3/fpm/php.ini \
        && sed -i "s/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/" /etc/php/8.3/fpm/php.ini \
        && sed -i "s/memory_limit = .*/memory_limit = 128M/" /etc/php/8.3/fpm/php.ini \
        && sed -i "s/;date.timezone.*/date.timezone = UTC/" /etc/php/8.3/fpm/php.ini

    # Set max execution time, max post/upload size (update for PhpMyADmin), upload file count
    sed -i "s/max_execution_time = .*/max_execution_time = 30/" /etc/php/8.3/fpm/php.ini \
        && sed -i "s/post_max_size = .*/post_max_size = 10M/" /etc/php/8.3/fpm/php.ini \
        && sed -i "s/upload_max_filesize = .*/upload_max_filesize = 10M/" /etc/php/8.3/fpm/php.ini \
        && sed -i "s/max_file_uploads = .*/max_file_uploads = 20/" /etc/php/8.3/fpm/php.ini

    # Enable OPcache and configure settings
    sed -i "s/;opcache.enable=1/opcache.enable=1/" /etc/php/8.3/fpm/php.ini \
        && sed -i "s/;opcache.memory_consumption=.*/opcache.memory_consumption=512/" /etc/php/8.3/fpm/php.ini \
        && sed -i "s/;opcache.interned_strings_buffer=.*/opcache.interned_strings_buffer=64/" /etc/php/8.3/fpm/php.ini \
        && sed -i "s/;opcache.max_accelerated_files=.*/opcache.max_accelerated_files=30000/" /etc/php/8.3/fpm/php.ini \
        && sed -i "s/;opcache.validate_timestamps=.*/opcache.validate_timestamps=1/" /etc/php/8.3/fpm/php.ini \
        && sed -i "s/;opcache.save_comments=.*/opcache.save_comments=1/" /etc/php/8.3/fpm/php.ini


    # PHP FPM Pool configuration (user/group, permission, request timeout)
    sed -i "s/^user = www-data/user = ubuntu/" /etc/php/8.3/fpm/pool.d/www.conf \
        && sed -i "s/^group = www-data/group = ubuntu/" /etc/php/8.3/fpm/pool.d/www.conf \
        && sed -i "s/;listen\.owner.*/listen.owner = ubuntu/" /etc/php/8.3/fpm/pool.d/www.conf \
        && sed -i "s/;listen\.group.*/listen.group = ubuntu/" /etc/php/8.3/fpm/pool.d/www.conf \
        && sed -i "s/;listen\.mode.*/listen.mode = 0666/" /etc/php/8.3/fpm/pool.d/www.conf \
        && sed -i "s/;request_terminate_timeout .*/request_terminate_timeout = 60/" /etc/php/8.3/fpm/pool.d/www.conf

    # Optimize PHP FPM processes
    sed -i "s/^pm.max_children.*=.*/pm.max_children = 60/" /etc/php/8.3/fpm/pool.d/www.conf


    # Configure PHP session directory permissions
    chmod 733 /var/lib/php/sessions \
        && chmod +t /var/lib/php/sessions

    # Setup alias of PHP 8.3 to PHP
    update-alternatives --set php /usr/bin/php8.3
    ```

16. TODO: Configure `logrotate` for PHP-FPM.

17. Install NGINX, enable daemon service, generate a strong DH parameters (will take some time) and update configuration.

    ```bash
    apt-get install -y nginx

    systemctl enable nginx.service

    openssl dhparam -out /etc/nginx/dhparams.pem 4096

    # Update NGINX configuration (user, process count, )
    sed -i "s/user www-data;/user ubuntu;/" /etc/nginx/nginx.conf \
        && sed -i "s/worker_processes.*/worker_processes auto;/" /etc/nginx/nginx.conf \
        && sed -i "s/# multi_accept.*/multi_accept on;/" /etc/nginx/nginx.conf \
        && sed -i "s/# server_names_hash_bucket_size.*/server_names_hash_bucket_size 128;/" /etc/nginx/nginx.conf \
        && sed -i "s/# server_tokens off;/server_tokens off;/" /etc/nginx/nginx.conf

    # TODO: Add GZIP configuration file in `conf.d/gzip.conf`
    # TODO: Add Cloudflare allowed proxy IPs file in `conf.d/cloudflare.conf`
    ```

18. Add user to `www-data` group and restart services.

    ```bash
    usermod -aG www-data ubuntu \
        && chown -R ubuntu:ubuntu /var/www

    systemctl restart nginx.service
    systemctl restart php8.3-fpm
    ```

19. TODO: Configure `logrotate` for NGINX.
20. Add keyring and install Node JS (replace `20.x` to install different version).

    ```bash
    mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y nodejs

    # Install necessary NPM packages globally
    npm i -g pm2 yarn bun
    ```

21. Increase open file limit (required for Laravel Reverb).

    ```bash
    # Update the "ubuntu" with username
    echo "" >> /etc/security/limits.conf \
        && echo "ubuntu        soft  nofile  10000" >> /etc/security/limits.conf \
        && echo "ubuntu        hard  nofile  10000" >> /etc/security/limits.conf \
        && echo "" >> /etc/security/limits.conf
    ```

22. Add keys for MySQL.

    ```bash
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 467B942D3A79BD29
    apt-get install -y mysql-community-server
    apt-get install -y mysql-server
    ```

23. Install and configure MySQL.
24. Install and configure MySQL.
25. Install and configure MySQL.
26. Install and configure MySQL.
27. Install and configure MySQL.
28. Install and configure MySQL.
29. Install and configure MySQL.

30. Install Redis server and update listen address.

    ```bash
    apt-get install -y redis-server
    sed -i 's/bind 127.0.0.1/bind 0.0.0.0/' /etc/redis/redis.conf

    service redis-server restart && systemctl enable redis-server
    ```

31. Enable supervisor.

    ```bash
    systemctl enable supervisor.service
    service supervisor start
    ```

32. Disable symlink protection (exposes to symlink attacks).

    ```bash
    sudo sed -i "s/fs.protected_regular = .*/fs.protected_regular = 0/" /usr/lib/sysctl.d/99-protect-links.conf

    sysctl --system
    ```

33. Setup unattended security updates

    ```bash
    apt install -y unattended-upgrades

    TODO: Add configuration to file `/etc/apt/apt.conf.d/50-unattended-upgrades`
    TODO: Add configuration to file `/etc/apt/apt.conf.d/10-periodic`
    ```

34. Restart daemon `systemctl daemon-reload`

35. Setup home directory permissions

    ```bash
    chown -R ubuntu:root /home/ubuntu \
    && chmod -R 755 /home/ubuntu \
    && chmod 600 /home/ubuntu/.ssh/authorized_keys \
    && chmod 400 /home/ubuntu/.ssh/id_ed25519 \
    && chmod 400 /home/ubuntu/.ssh/id_ed25519.pub
    ```

36. Install [oh-my-zsh](https://ohmyz.sh) (run as local user).

    ```bash
        sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
    ```

## NGINX Base Configuration

Following the is the base configuration for NGINX (`/etc/nginx/nginx.conf`).

```nginx
user ubuntu;
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
```

### Additional configuration files

1. Should be placed in `conf.d/cloudflare.conf`

    ```nginx
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
    ```

2. Should be placed in `conf.d/gzip.conf`

    ```nginx
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
    ```

3. Should be placed in `conf.d/timeout.conf`

    ```nginx
    fastcgi_read_timeout 30;
    ```

4. Should be placed in `conf.d/uploads.conf`

    ```nginx
    client_max_body_size 10M;
    ```

5. Should be placed in **`snippets/security.conf`**

    ```nginx
    server_tokens off;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_dhparam /etc/nginx/dhparams.pem;

    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Content-Type-Options "nosniff";
    ```

## NGINX Site configuration

```nginx
# Uncomment when using Laravel Reverb
# map $http_upgrade $connection_upgrade {
#     default upgrade;
#     ''      close;
# }

server {
    # Uncomment when using HTTPS
    # http2 on;
    # listen 443 ssl;
    # listen [::]:443 ssl;

    # Comment out when using HTTPS
    listen 80;
    listen [::]:80;

    server_name example.com api.example.com;
    root /home/ubuntu/example.com/current/public;

    # Uncomment and update paths when using SSL certificates
    # ssl_certificate /etc/nginx/ssl/example.com/server.crt;
    # ssl_certificate_key /etc/nginx/ssl/example.com/server.key;

    include snippets/security.conf;

    index index.html index.htm index.php;

    charset utf-8;

    # Use only with PHP-FPM (comment when using Laravel Octane)
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    # Uncomment when using Laravel Octane
    # location /index.php {
    #     try_files /not_exists @octane;
    # }
    #
    # location / {
    #     try_files $uri $uri/ @octane;
    # }

    location = /favicon.ico { access_log off; log_not_found off; }
    location = /robots.txt  { access_log off; log_not_found off; }

    access_log off;
    error_log  /var/log/nginx/example.com-error.log error;

    error_page 404 /index.php;

    # Use only with PHP-FPM (comment when using Laravel Octane)
    location ~ index\.php$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        # fastcgi_pass unix:/var/run/php/php8.3-fpm-example.com.sock;
        fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
    }

    # Uncomment when using
    # location @octane {
    #     set $suffix "";
    #
    #     if ($uri = /index.php) {
    #         set $suffix ?$query_string;
    #     }
    #
    #     proxy_http_version 1.1;
    #     proxy_set_header Host $http_host;
    #     proxy_set_header Scheme $scheme;
    #     proxy_set_header SERVER_PORT $server_port;
    #     proxy_set_header REMOTE_ADDR $remote_addr;
    #     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    #     proxy_set_header Upgrade $http_upgrade;
    #     proxy_set_header Connection $connection_upgrade;
    #
    #     proxy_pass http://127.0.0.1:8000$suffix;
    # }

    location ~ /\.(?!well-known).* {
        deny all;
    }
}

# Uncomment when using Laravel Reverb
# server {
#     # Uncomment when using HTTPS
#     # http2 on;
#     # listen 443 ssl;
#     # listen [::]:443 ssl;
#
#     # Comment out when using HTTPS
#     listen 80;
#     listen [::]:80;
#
#     server_name socket.example.com;
#
#     # Uncomment and update paths when using SSL certificates
#     # **base certificate should include socket subdomain**
#     # ssl_certificate /etc/nginx/ssl/example.com/server.crt;
#     # ssl_certificate_key /etc/nginx/ssl/example.com/server.key;
#
#     include snippets/security.conf;
#
#     charset utf-8;
#
#     access_log off;
#     error_log  /var/log/nginx/socket.example.com-error.log error;
#
#     location / {
#         proxy_http_version 1.1;
#         proxy_set_header Host $http_host;
#         proxy_set_header Scheme $scheme;
#         proxy_set_header SERVER_PORT $server_port;
#         proxy_set_header REMOTE_ADDR $remote_addr;
#         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#         proxy_set_header Upgrade $http_upgrade;
#         proxy_set_header Connection $connection_upgrade;
#
#         # Update address and port accordingly
#         proxy_pass http://127.0.0.1:9000;
#     }
#
#     location ~ /\.(?!well-known).* {
#         deny all;
#     }
# }
```
