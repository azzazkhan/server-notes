export DEBIAN_FRONTEND=noninteractive

CUSTOM_HOSTNAME="$1"

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."

   exit 1
fi

if [[ -z $CUSTOM_HOSTNAME ]]; then
    echo "Hostname is required!"

    exit 1
fi

echo $CUSTOM_HOSTNAME > /etc/hostname
sed -i "s/127\.0\.0\.1.*localhost/127.0.0.1	$CUSTOM_HOSTNAME.localdomain $CUSTOM_HOSTNAME localhost/" /etc/hosts
hostname $CUSTOM_HOSTNAME
