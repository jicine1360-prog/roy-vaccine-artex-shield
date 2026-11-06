#!/usr/bin/env bash
# 다른 서버 이식용 설치 — 대상 서버에서: sudo bash install_guard.sh
# 필요 파일: roy_guard.py, roy_trace.py, guard_config.json (같은 폴더에)
set -euo pipefail

SRC="$(dirname "$(readlink -f "$0")")"
DEST=/opt/roy-guard

apt-get update -qq
apt-get install -y -qq fail2ban curl >/dev/null

# --- fail2ban: sshd ---
cat > /etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
port = 22
maxretry = 4
findtime = 60
bantime = 86400
bantime.increment = true
bantime.factor = 7
bantime.maxtime = 1w
EOF
systemctl enable --now fail2ban

# --- 가드 파일 복사 ---
mkdir -p "$DEST"
cp "$SRC/roy_guard.py" "$SRC/roy_trace.py" "$DEST/"
[ -f "$SRC/guard_config.json" ] && cp "$SRC/guard_config.json" "$DEST/" || true
mkdir -p /var/log/roy-guard

# guard_config.json이 없으면 기본 생성 — 여기 IP 대역/로그 경로를 그 서버에 맞게 고칠 것
if [ ! -f "$DEST/guard_config.json" ]; then
cat > "$DEST/guard_config.json" <<'EOF'
{
  "watch_logs": ["/var/log/nginx/access.log"],
  "whitelist_prefixes": ["127.", "10.", "192.168.", "172.16.", "100.64.", "100.65.", "100.66.", "100.67.", "100.68.", "100.69.", "100.70.", "100.71.", "100.72.", "100.73.", "100.74.", "100.75.", "100.76.", "100.77.", "100.78.", "100.79.", "100.80.", "100.81.", "100.82.", "100.83.", "100.84.", "100.85.", "100.86.", "100.87.", "100.88.", "100.89.", "100.90.", "100.91.", "100.92.", "100.93.", "100.94.", "100.95.", "100.96.", "100.97.", "100.98.", "100.99.", "100.100.", "100.101.", "100.102.", "100.103.", "100.104.", "100.105.", "100.106.", "100.107.", "100.108.", "100.109.", "100.110.", "100.111.", "100.112.", "100.113.", "100.114.", "100.115.", "100.116.", "100.117.", "100.118.", "100.119.", "100.120.", "100.121.", "100.122.", "100.123.", "100.124.", "100.125.", "100.126.", "100.127."],
  "block_log": "/var/log/roy-guard/guard.log"
}
EOF
echo "!! /opt/roy-guard/guard_config.json 의 watch_logs 를 그 서버 접근로그 경로로 수정하세요"
fi

# --- systemd 유닛 (경로 자동) ---
cat > /etc/systemd/system/roy-guard.service <<EOF
[Unit]
Description=Roy instant defense watcher (ARTEX/scanner auto-block + trace)
After=network.target

[Service]
ExecStart=/usr/bin/python3 $DEST/roy_guard.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
# roy_guard.py가 roy_trace를 import 하니 같은 폴더면 OK
sed -i "s|/home/hoony/logs/roy-guard.log|/var/log/roy-guard/guard.log|g" "$DEST/roy_guard.py" "$DEST/roy_trace.py" || true
sed -i "s|/home/hoony/strata/defense|$DEST|g" "$DEST/roy_trace.py" || true

systemctl daemon-reload
systemctl enable --now roy-guard

echo "== 설치 완료 =="
systemctl is-active fail2ban roy-guard
