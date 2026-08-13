#!/usr/bin/env bash
set -euo pipefail

binary_source=${1:?binary source is required}
service_source=${2:?service source is required}
binary_target=/opt/sstd/sstd
service_target=/etc/systemd/system/sstd.service

if [ "$(id -u)" -ne 0 ]; then
  echo 'Run this script as root.' >&2
  exit 1
fi

test -f /etc/sstd/sstd.ini
install -d -m 0755 /opt/sstd /etc/sstd /var/log/sstd

if [ -f "$binary_target" ]; then
  cp --preserve=mode,timestamps "$binary_target" "${binary_target}.previous"
fi

install -m 0755 "$binary_source" "${binary_target}.new"
mv -f "${binary_target}.new" "$binary_target"
install -m 0644 "$service_source" "$service_target"

systemctl daemon-reload
systemctl enable sstd.service

rollback() {
  if [ -f "${binary_target}.previous" ]; then
    echo 'Deployment health check failed; restoring previous binary.' >&2
    install -m 0755 "${binary_target}.previous" "$binary_target"
    systemctl restart sstd.service || true
  fi
}

if ! systemctl restart sstd.service; then
  rollback
  exit 1
fi

if ! systemctl is-active --quiet sstd.service; then
  rollback
  exit 1
fi
