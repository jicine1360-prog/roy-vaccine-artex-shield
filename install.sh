#!/usr/bin/env bash
# 로이 백신 설치 — 대상 서버에서 root로 실행: sudo bash install.sh
# 구성: roy_guard(실시간 차단+추적) + fail2ban + triage cron(정찰) + 텔레그램 알림
set -euo pipefail

SRC="$(dirname "$(readlink -f "$0")")"
DEST=/opt/roy-guard
[ "$(id -u)" = "0" ] || { echo "root로 실행하세요 (sudo bash install.sh)"; exit 1; }

command -v python3 >/dev/null || { echo "python3 필요"; exit 1; }

apt-get update -qq || true
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

# --- 파일 설치 ---
mkdir -p "$DEST" "$DEST/abuse" /var/log/roy-guard
cp "$SRC/roy_guard.py" "$SRC/roy_trace.py" "$SRC/triage_notify.py" "$SRC/triage_cron.sh" "$DEST/"
mkdir -p "$DEST/detections"
cp "$SRC/detections/artex_host_triage.py" "$DEST/detections/"
cp "$SRC/LICENSE.artex-global-detection.txt" "$DEST/" 2>/dev/null || true
chmod +x "$DEST/triage_cron.sh"

# --- 설정 ---
if [ ! -f "$DEST/guard_config.json" ]; then
  cp "$SRC/guard_config.example.json" "$DEST/guard_config.json"
  echo "!! /opt/roy-guard/guard_config.json 확인: watch_logs(접근로그), telegram_token, telegram_chat_id"
fi

# --- systemd ---
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
# 경로 자동 치환 (woojintower 원본 경로 → 대상 서버 경로)
sed -i "s|/home/hoony/logs/roy-guard.log|/var/log/roy-guard/guard.log|g" "$DEST/roy_guard.py" "$DEST/roy_trace.py" || true
sed -i "s|/home/hoony/strata/defense|$DEST|g" "$DEST/roy_trace.py" || true

systemctl daemon-reload
systemctl enable --now roy-guard

# --- triage cron (6시간 주기, 신규 HIT만 알림) ---
if ! crontab -l 2>/dev/null | grep -q "roy-guard-triage"; then
  (crontab -l 2>/dev/null; echo '0 */6 * * * /opt/roy-guard/triage_cron.sh >> /var/log/roy-guard/triage.log 2>&1 # roy-guard-triage') | crontab -
  echo "cron 등록 완료 (초기 실행은 기준선 심기라 알림 없음)"
fi

echo "== 설치 완료 =="
systemctl is-active fail2ban roy-guard || true
