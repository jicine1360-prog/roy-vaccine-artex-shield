#!/usr/bin/env python3
"""ARTEX triage 신규 HIT 감지 → 로이 봇으로 텔레그램 알림. 기준선 파일과 비교."""
import json, sys, subprocess, os

state_path, cur_path = sys.argv[1], sys.argv[2]
try:
    cur = json.load(open(cur_path))
except Exception:
    sys.exit(1)
base = set()
if os.path.exists(state_path):
    try:
        base = {f.get("detail", "") for f in json.load(open(state_path)).get("findings", [])}
    except Exception:
        base = set()
new = [f for f in cur.get("findings", []) if f.get("detail") not in base]
if not new:
    print("quiet")
    sys.exit(0)
cfg = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "guard_config.json")))
token = cfg.get("bot_token") or cfg.get("telegram_token")
chat = str(cfg.get("chat_id") or cfg.get("telegram_chat_id") or "50735853")
msg = "🛡️ ARTEX triage 신규 HIT:\n" + "\n".join(f"[{f['severity'].upper()}] {f['detail']}" for f in new)
if token:
    subprocess.run(["curl", "-s", "--max-time", "10",
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    "-d", f"chat_id={chat}", "--data-urlencode", f"text={msg}"], check=False)
print("ALERT:", len(new))
