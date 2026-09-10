#!/bin/sh
# Never resolve privileged executables through the writable agent home.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
unset PYTHONPATH PYTHONHOME ENV BASH_ENV
exec /usr/bin/setpriv --reuid=10002 --regid=10002 --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs /usr/bin/python3 -I /usr/local/lib/hatchward/runtime/channel.py
