#!/bin/bash -xe
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
echo '* * * * * ec2-user /usr/bin/pgrep circusd || circusd --daemon -- /srv/app/circus.ini >/tmp/application.log 2>&1' > /etc/cron.d/circusd-up
