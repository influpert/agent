#!/bin/sh
# Never resolve privileged executables through the writable agent home.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
unset PYTHONPATH PYTHONHOME ENV BASH_ENV
set -eu
[ -f /run/hatchward/ready ]
exec /usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs tar --extract --file=- --directory=/workspace --no-same-owner --no-same-permissions
