#!/usr/bin/env python3
"""roy_trace — 차단한 침입자의 출발지를 파악하고 무력화 단계를 자동 실행한다.

roy_guard.py가 차단(blackhole)한 IP에 대해:
  1. 역방향 추적: RDAP whois(netname/org/country/abuse 이메일), rDNS, 소규모이면 /24 전체 netname
  2. 위협 등급: 오픈리졸버/프록시/클라우드(VPS)면 '가짜 출발지'로 표시 — 실제 발신지는 프록시 뒤
  3. 무력화 3단계:
     L1 자동: 해당 /24 전체 blackhole (같은 단지의 연쇄 스캔 차단)
     L2 자동: abuse@ 메일로 자동 신고 메일 생성(발신 로그 첨부) → /home/hoony/strata/defense/abuse/ 에 저장 후 msmtp로 발송 시도
     L3 보고: 텔레그램으로 추적 결과 + 신고 발송 여부 알림 (네가 판단할 부분)
주의: 남의 서버를 직접 공격하는 '반격'은 불법이라 하지 않는다. 합법 무력화는
      (a) 내 네트워크에서의 완전 차단, (b) 출발지 소유자(abuse) 신고로 회선 끊기, (c) /24 선차단 — 이 셋이다.
"""
import json, os, re, subprocess, sys, time

DEF_DIR = "/home/hoony/strata/defense"
TRACE_LOG = os.path.join(DEF_DIR, "trace_log.jsonl")
ABUSE_DIR = os.path.join(DEF_DIR, "abuse")
STATE_FILE = os.path.join(DEF_DIR, "trace_state.json")

CLOUD_NETS = ("amazon", "aws", "google", "gcp", "azure", "microsoft", "oracle", "hetzner",
              "digitalocean", "vultr", "linode", "ovh", "contabo", "alibaba", "tencent",
              "bytedance", "volcano", "ucloud", "hosting", "vps", "server", "datacenter",
              "cloudflare", "fastly", "cdn77", "akamai")

def rdap_ip(ip):
    """RDAP(whois 현대 API)로 netname/org/country/abuse 추출."""
    try:
        r = subprocess.run(["curl", "-s", "-m", "8", f"https://rdap.org/ip/{ip}"],
                           capture_output=True, text=True, timeout=10)
        d = json.loads(r.stdout)
    except Exception:
        return {}
    out = {}
    out["handle"] = d.get("handle", "")
    for e in d.get("entities", []):
        roles = e.get("roles", [])
        if "abuse" in roles:
            for v in e.get("vcardArray", [None, []])[1]:
                if v[0] == "fn":
                    out["abuse_name"] = v[3]
                if v[0] == "email":
                    out["abuse_email"] = v[3].replace("[", "").replace("]", "").replace('"', "")
    for ev in d.get("events", []):
        if ev.get("eventAction") == "registration":
            out["net_created"] = ev.get("eventDate", "")[:10]
    # links에 name이 있는 경우
    out["name"] = d.get("name", "") or (d.get("port43", ""))
    return out

def whois_org(ip):
    try:
        r = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=10)
        t = r.stdout
    except Exception:
        return {}
    out = {}
    for key, pat in [("netname", r"^NetName:\s*(.+)"), ("org", r"^OrgName:\s*(.+)"),
                     ("country", r"^Country:\s*(.+)"), ("descr", r"^descr:\s*(.+)"),
                     ("route", r"^route:\s*(\S+)"), ("abuse_c", r"^abuse-c:\s*(\S+)")]:
        m = re.search(pat, t, re.M)
        if m:
            out[key] = m.group(1).strip()
    return out

def rdns(ip):
    try:
        r = subprocess.run(["dig", "+short", "-x", ip], capture_output=True, text=True, timeout=6)
        return r.stdout.strip().rstrip(".")
    except Exception:
        return ""

def classify(info):
    text = " ".join(str(v) for v in info.values()).lower()
    if any(k in text for k in CLOUD_NETS):
        return "CLOUD/VPS", "출발지는 빌린 서버일 가능성 높음 — 실제 발신자(조종지)는 프록시/제3자일 수 있음"
    if any(k in text for k in ("residential", "ppp", "dsl", "broadband", "korea", "telecom", "kt ", "sk broadband", "lgpowercomm")):
        return "RESIDENTIAL", "일반 회선 — 좀비PC/공유기 침해 가능성, 회선사 신고로 무력화"
    return "HOSTING/OTHER", "구분 불명"

def notify_telegram(text):
    """로이 봇으로 추적 결과 보고 (telegram-stock-bot 설정 재사용)."""
    chat = "50735853"
    token = None
    try:
        cfg = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "guard_config.json")))
        token = cfg.get("telegram_token")
        chat = str(cfg.get("telegram_chat_id", chat))
    except Exception:
        pass
    if not token:
        try:
            cfg = json.load(open("/home/hoony/trading/config.json"))
            token = cfg.get("telegram_token")
            chat = str(cfg.get("telegram_chat_id", chat))
        except Exception:
            pass
    if not token:
        try:
            tb = json.load(open("/home/hoony/telegram-stock-bot/config.json"))
            token = tb.get("bot_token")
            chat = str(tb.get("chat_id", chat))
        except Exception:
            pass
    if not token:
        print("no telegram token for notify")
        return
    try:
        import urllib.request, urllib.parse
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=urllib.parse.urlencode({"chat_id": chat, "text": text}).encode())
        urllib.request.urlopen(req, timeout=8)
    except Exception as e:
        print("notify fail:", e)

def block24(ip, reason):
    """같은 /24 단지 전체 선차단. root 권한 없으면 roy-guard의 /24 규칙으로 위임."""
    base = ".".join(ip.split(".")[:3]) + ".0/24"
    try:
        r = subprocess.run(["ip", "route", "replace", base, "blackhole"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return base
    except Exception:
        pass
    # root 아님 → guard가 주기적으로 blackhole으로 승격할 수 있게 파일에 기록
    try:
        with open(os.path.join(DEF_DIR, "pending24.txt"), "a") as f:
            f.write(base + "\n")
    except Exception:
        pass
    return "queued:" + base

def write_abuse_mail(ip, info, grade, evidence):
    os.makedirs(ABUSE_DIR, exist_ok=True)
    path = os.path.join(ABUSE_DIR, f"abuse_{ip}_{time.strftime('%Y%m%d_%H%M')}.txt")
    body = f"""To: {info.get('abuse_email','abuse@ (미확인)')}
Subject: [Abuse Report] Automated intrusion attempt against my server from {ip}

Hello,

My server was targeted by an automated intrusion/penetration attempt
originating from your network. Details:

  Source IP : {ip}
  Network   : {info.get('route', info.get('handle',''))} ({info.get('netname','')} / {info.get('org','')})
  Country   : {info.get('country','')}
  rDNS      : {info.get('rdns','(none)')}
  Grade     : {grade}
  Time(KST) : {time.strftime('%Y-%m-%d %H:%M:%S')}

Evidence (server log lines):
{evidence}

Please investigate and terminate the offending host/connection.

Regards,
Automated abuse report (woojintower)
"""
    with open(path, "w") as f:
        f.write(body)
    return path

def send_mail(path):
    """msmtp/ sendmail 있으면 발송, 없으면 파일만 보관."""
    for cmd in (["msmtp", "-t", f"<{path}"], ):
        pass
    try:
        r = subprocess.run(["which", "msmtp"], capture_output=True, text=True, timeout=3)
        if r.stdout.strip():
            with open(path) as f:
                subprocess.run(["msmtp", "-t"], stdin=f, timeout=15)
            return True
    except Exception:
        pass
    return False

def trace(ip, evidence=""):
    info = {}
    info.update(rdap_ip(ip))
    info.update(whois_org(ip))
    info["rdns"] = rdns(ip)
    grade, note = classify(info)
    blocked24 = block24(ip, "retaliation-prevention: same /24")
    mail_path = write_abuse_mail(ip, info, grade, evidence or "(see roy-guard.log)")
    mailed = send_mail(mail_path)

    rec = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"), "ip": ip,
        "netname": info.get("netname", info.get("name", "")),
        "org": info.get("org", ""), "country": info.get("country", ""),
        "route": info.get("route", ""), "rdns": info.get("rdns", ""),
        "abuse_email": info.get("abuse_email", ""), "grade": grade, "note": note,
        "blocked_24": blocked24, "abuse_mail": mail_path, "mailed": mailed,
    }
    with open(TRACE_LOG, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    notify_telegram(
        f"🛡️ 침입자 추적 완료\n"
        f"IP: {ip}  ({info.get('netname','?')} / {info.get('country','?')})\n"
        f"종류: {grade} — {note}\n"
        f"rDNS: {info.get('rdns','(none)')}\n"
        f"조치: /24 전체 차단({blocked24 or '실패'}) + abuse신고 {'발송완료' if mailed else '파일 보관: '+mail_path}\n"
        f"abuse: {info.get('abuse_email','미확인')}"
    )
    return rec

if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    print(json.dumps(trace(ip), ensure_ascii=False, indent=1))
