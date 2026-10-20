#!/bin/sh
# Selected-instruction SDK experiment, isolated from network and writable host files.
set -eu
umask 077
if [ "$#" -ne 3 ]; then
    echo 'Usage: sh run_isolated.sh PYTHON_ENV_DIRECTORY SDK_BINARY serializer|quantizer' >&2
    exit 2
fi
venv_dir=$(realpath -- "$1")
sdk=$(realpath -- "$2")
lab_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
test -x "$venv_dir/bin/python"
test -f "$sdk"
case "$3" in
    serializer) script=emulate_serializer.py ;;
    quantizer) script=emulate_quantizer.py ;;
    *) echo 'Choose serializer or quantizer.' >&2; exit 2 ;;
esac
ulimit -c 0
ulimit -t 30
exec timeout 30s bwrap --unshare-all --new-session --die-with-parent --cap-drop ALL \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib /lib64 \
 --ro-bind "$venv_dir" /venv --ro-bind "$lab_dir" /lab --ro-bind "$sdk" /input.so \
 --proc /proc --dev /dev --tmpfs /tmp --clearenv --setenv PATH /usr/bin --chdir /tmp \
 /venv/bin/python -I "/lab/$script" /input.so
