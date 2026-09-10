#!/bin/sh
# Never resolve privileged executables through the writable agent home.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
unset PYTHONPATH PYTHONHOME ENV BASH_ENV
exec fuse2fs -f "$@"
