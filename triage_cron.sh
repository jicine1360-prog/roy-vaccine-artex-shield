#!/bin/bash
# ARTEX 백신 주기 정찰 — 신규 HIT만 텔레그램 알림
TRIAGE=/opt/roy-guard/detections/artex_host_triage.py
DIR=/opt/roy-guard
STATE=$DIR/triage_baseline.json
TMP=$(mktemp)
python3 "$TRIAGE" --json > "$TMP" 2>/dev/null || { rm -f "$TMP"; exit 1; }
python3 "$DIR/triage_notify.py" "$STATE" "$TMP"
mv "$TMP" "$STATE"
