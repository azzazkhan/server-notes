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

# Setup custom user

useradd $NEW_USER
mkdir -p /home/$NEW_USER/.ssh
adduser $NEW_USER www-data
adduser $NEW_USER isolated
passwd -d $NEW_USER

# Setup Bash shell

chsh -s /bin/bash $NEW_USER
touch /home/$NEW_USER/.profile
touch /home/$NEW_USER/.bashrc
touch /home/$NEW_USER/.ssh/authorized_keys

# Generate a new SSH key

ssh-keygen -f /home/$NEW_USER/.ssh/id_ed25519 -t ed25519 -N ''

# Copy source control pulic keys into known hosts file

ssh-keyscan -H github.com >> /home/$NEW_USER/.ssh/known_hosts
ssh-keyscan -H bitbucket.org >> /home/$NEW_USER/.ssh/known_hosts
ssh-keyscan -H gitlab.com >> /home/$NEW_USER/.ssh/known_hosts

# Setup home directory permissions

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

# Set Bash config and profile

cat << EOF > /home/$NEW_USER/.bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case \$- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
#shopt -s globstar

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "\$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "\${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=\$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "\$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
#force_color_prompt=yes

if [ -n "\$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
	# We have color support; assume it's compliant with Ecma-48
	# (ISO/IEC-6429). (Lack of such support is extremely rare, and such
	# a case would tend to support setf rather than setaf.)
	color_prompt=yes
    else
	color_prompt=
    fi
fi

if [ "\$color_prompt" = yes ]; then
    PS1='\${debian_chroot:+(\$debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='\${debian_chroot:+(\$debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "\$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;\${debian_chroot:+(\$debian_chroot)}\u@\h: \w\a\]\$PS1"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "\$(dircolors -b ~/.dircolors)" || eval "\$(dircolors -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# colored GCC warnings and errors
#export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Add an "alert" alias for long running commands.  Use like so:
#   sleep 10; alert
alias alert='notify-send --urgency=low -i "\$([ \$? = 0 ] && echo terminal || echo error)" "\$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi

EOF

cat << EOF > /home/$NEW_USER/.profile
# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.
# see /usr/share/doc/bash/examples/startup-files for examples.
# the files are located in the bash-doc package.

# the default umask is set in /etc/profile; for setting the umask
# for ssh logins, install and configure the libpam-umask package.
#umask 022

# if running bash
if [ -n "\$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "\$HOME/.bashrc" ]; then
	. "\$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin if it exists
if [ -d "\$HOME/bin" ] ; then
    PATH="\$HOME/bin:\$PATH"
fi

# set PATH so it includes user's private bin if it exists
if [ -d "\$HOME/.local/bin" ] ; then
    PATH="\$HOME/.local/bin:\$PATH"
fi


EOF

cat << EOF > /home/$NEW_USER/.bash_logout
# ~/.bash_logout: executed by bash(1) when login shell exits.

# when leaving the console clear the screen to increase privacy

if [ "\$SHLVL" = 1 ]; then
    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q
fi

EOF

# Setup home directory permissions

chown -R $NEW_USER:$NEW_USER /home/$NEW_USER
chmod -R 755 /home/$NEW_USER

# Create new PHP FPM pool

POOL_FILE="/etc/php/8.3/fpm/pool.d/www-$NEW_USER.conf"

cp /etc/php/8.3/fpm/pool.d/www.conf $POOL_FILE

sed -i "s/^\[www\]/\[$NEW_USER\]/" $POOL_FILE
sed -i "s/^user = www-data/user = $NEW_USER/" $POOL_FILE
sed -i "s/^group = www-data/group = $NEW_USER/" $POOL_FILE
sed -i "s/^;listen = .*/listen = \/run\/php\/php8.3-fpm-$NEW_USER.sock/" $POOL_FILE
sed -i "s/^;listen\.owner.*/listen.owner = $NEW_USER/" $POOL_FILE
sed -i "s/^;listen\.group.*/listen.group = $NEW_USER/" $POOL_FILE
sed -i "s/^listen = .*/listen = \/run\/php\/php8.3-fpm-$NEW_USER.sock/" $POOL_FILE
sed -i "s/^listen\.owner.*/listen.owner = $NEW_USER/" $POOL_FILE
sed -i "s/^listen\.group.*/listen.group = $NEW_USER/" $POOL_FILE
sed -i "s/^listen\.mode.*/listen.mode = 0666/" $POOL_FILE
sed -i "s/^request_terminate_timeout .*/request_terminate_timeout = 60/" $POOL_FILE

# Restart PHP FPM to create new listening socket

service php8.3-fpm restart

# Remove user, home and PHP FPM pool
# deluser laravel && rm -rf /home/laravel && rm /etc/php/8.3/fpm/pool.d/www-laravel.conf
