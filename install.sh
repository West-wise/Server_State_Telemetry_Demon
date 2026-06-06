#!/bin/bash
set -e

BINARY_SRC="build/SST_Demon"
INSTALL_BIN="/opt/sstd/sstd"
CONFIG_DIR="/etc/sstd"
CONFIG_SRC="config/sstd.ini"
CONFIG_DST="$CONFIG_DIR/sstd.ini"
LOG_DIR="/var/log/sstd"
SERVICE_SRC="sstd.service"
SERVICE_DST="/etc/systemd/system/sstd.service"

if [ "$(id -u)" -ne 0 ]; then
    echo "[Error] root 권한 필요: sudo $0"
    exit 1
fi

echo "=== 빌드 ==="
mkdir -p build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel "$(nproc)"

echo "=== 디렉토리 생성 ==="
install -d /opt/sstd
install -d "$CONFIG_DIR"
install -d "$LOG_DIR"

echo "=== 바이너리 설치 ==="
install -m 755 "$BINARY_SRC" "$INSTALL_BIN"

echo "=== 설정 파일 ==="
if [ ! -f "$CONFIG_DST" ]; then
    install -m 644 "$CONFIG_SRC" "$CONFIG_DST"
    echo "설치됨: $CONFIG_DST"
else
    echo "이미 존재, 건너뜀: $CONFIG_DST"
    echo "(업데이트하려면 수동으로 $CONFIG_DST 편집)"
fi

echo "=== systemd 서비스 등록 ==="
install -m 644 "$SERVICE_SRC" "$SERVICE_DST"
systemctl daemon-reload
systemctl enable sstd
systemctl restart sstd

echo ""
echo "=== 완료 ==="
systemctl status sstd --no-pager -l
