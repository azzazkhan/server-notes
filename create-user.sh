NEW_USER="$1"

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."

   exit 1
fi

if [[ -z $NEW_USER ]]; then
    echo "User name is required!"

    exit 1
fi

# Setup custom user

useradd $NEW_USER
mkdir -p /home/$NEW_USER/.ssh
adduser $NEW_USER sudo
passwd -d $NEW_USER

# Setup Bash shell

chsh -s /bin/bash $NEW_USER
cp /root/.profile /home/$NEW_USER/.profile
cp /root/.bashrc /home/$NEW_USER/.bashrc
touch /home/$NEW_USER/.ssh/authorized_keys

# Create SSH key for custom user

ssh-keygen -f /home/$NEW_USER/.ssh/id_ed25519 -t ed25519 -N ''

# Copy source control pulic keys into known hosts file

ssh-keyscan -H github.com >> /home/$NEW_USER/.ssh/known_hosts
ssh-keyscan -H bitbucket.org >> /home/$NEW_USER/.ssh/known_hosts
ssh-keyscan -H gitlab.com >> /home/$NEW_USER/.ssh/known_hosts

# Setup custom user home directory permissions

chown -R $NEW_USER:$NEW_USER /home/$NEW_USER
chmod -R 755 /home/$NEW_USER
chmod 400 /home/$NEW_USER/.ssh/id_ed25519
chmod 400 /home/$NEW_USER/.ssh/id_ed25519.pub
chmod 600 /home/$NEW_USER/.ssh/authorized_keys

# Allow FPM restart

echo "$NEW_USER ALL=NOPASSWD: /usr/sbin/service php8.3-fpm reload" >> /etc/sudoers.d/php-fpm
echo "$NEW_USER ALL=NOPASSWD: /usr/sbin/service php8.2-fpm reload" >> /etc/sudoers.d/php-fpm
echo "$NEW_USER ALL=NOPASSWD: /usr/sbin/service php8.1-fpm reload" >> /etc/sudoers.d/php-fpm
echo "$NEW_USER ALL=NOPASSWD: /usr/sbin/service php8.0-fpm reload" >> /etc/sudoers.d/php-fpm

# Allow composer execution

echo "$NEW_USER ALL=(root) NOPASSWD: /usr/local/bin/composer self-update*" >> /etc/sudoers.d/composer
