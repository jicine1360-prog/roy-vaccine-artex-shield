#!/usr/bin/env python3
"""로이 즉시방어 워치 — 침입 트래픽을 감시하고 순식간에 route 차단한다.

감시 대상:
  1. ARTEX 계열 UA: artex-enrich/, norma/ (detections/suricata/artex.rules 근거)
  2. 파괴적 스캐너 UA: sqlmap, nikto, nmap, masscan, zgrab, httpx 스캐너 등
  3. 스캔 속도: 한 IP가 60초에 120+ 요청 (티오리 실험: CyberStrikeAI 스캐너 20분 3.2만건)
  4. SSH 교차 감시: auth.log의 Failed password 3회 → 즉시 route drop (fail2ban과 이중)

차단 방식: ip route add <ip> via blackhole (route add 시 기존 커넥션도 즉시 끊김).
whitelist(내 LAN/tailscale/현재 접속 IP)는 절대 차단하지 않는다.
"""
import os, re, subprocess, sys, time, collections, threading, json

BLOCK_LOG = "/home/hoony/logs/roy-guard.log"
STATE = {}  # ip -> count
BLOCKED = set()
WINDOW = collections.defaultdict(list)  # ip -> [ts]

# 내 네트워크 — 차단 금지
# 내 네트워크 — 차단 금지. guard_config.json의 whitelist_prefixes 로 덮어쓸 수 있음
WHITELIST_NETS = ["127.", "10.", "172.16.", "192.168.", "100.64.", "100.65.", "100.66.",
                  "100.67.", "100.68.", "100.69.", "100.70.", "100.71.", "100.72.", "100.73.",
                  "100.74.", "100.75.", "100.76.", "100.77.", "100.78.", "100.79.", "100.80.",
                  "100.81.", "100.82.", "100.83.", "100.84.", "100.85.", "100.86.", "100.87.",
                  "100.88.", "100.89.", "100.90.", "100.91.", "100.92.", "100.93.", "100.94.",
                  "100.95.", "100.96.", "100.97.", "100.98.", "100.99.", "100.100.", "100.101.",
                  "100.102.", "100.103.", "100.104.", "100.105.", "100.106.", "100.107.",
                  "100.108.", "100.109.", "100.110.", "100.111.", "100.112.", "100.113.",
                  "100.114.", "100.115.", "100.116.", "100.117.", "100.118.", "100.119.",
                  "100.120.", "100.121.", "100.122.", "100.123.", "100.124.", "100.125.",
                  "100.126.", "100.127.", "fd7a:"]
try:
    _cfg = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "guard_config.json")))
    if _cfg.get("whitelist_prefixes"):
        WHITELIST_NETS = _cfg["whitelist_prefixes"]
    if _cfg.get("block_log"):
        BLOCK_LOG = _cfg["block_log"]
except Exception:
    pass
# 현재 SSH 접속 IP도 보호
def current_ssh_ips():
    try:
        out = subprocess.run(["who"], capture_output=True, text=True, timeout=5).stdout
        return {m.group(1) for m in re.finditer(r"\(([\d.]+)\)", out)}
    except Exception:
        return set()

def log(msg):
    line = time.strftime("[%Y-%m-%d %H:%M:%S] ") + msg
    print(line, flush=True)
    try:
        with open(BLOCK_LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass

def ip_ok(ip):
    if not re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", ip):
        return False
    if any(ip.startswith(n) for n in WHITELIST_NETS):
        return False
    if ip in current_ssh_ips():
        return False
    return True

def block(ip, reason):
    if ip in BLOCKED or not ip_ok(ip):
        return
    for cmd in (["ip", "route", "replace", "blackhole", ip],
                ["ip", "route", "add", "blackhole", ip]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                BLOCKED.add(ip)
                log(f"BLOCKED {ip} :: {reason}")
                # 출발지 추적 + 무력화 (trace가 /24 선차단 + abuse 신고 + 텔레그램 보고)
                try:
                    import roy_trace
                    roy_trace.trace(ip, reason)
                except Exception as e:
                    log(f"trace fail {ip}: {e}")
                return
        except Exception:
            continue
    log(f"block fail {ip}: {reason}")

BAD_UA = re.compile(
    r"(artex-enrich/|norma/0\.|sqlmap|nikto|nmap|masscan|zgrab|zmap|dirbuster|gobuster|nessus|openvas|cyberstriker)",
    re.I,
)

def watch_http():
    """앞단 서비스 로그(8080 FlingFile, 8081, 8082 등)를 tail해 UA/속도 감시."""
    import glob
    # 감시할 HTTP 로그 목록: config.json의 watch_logs 로 덮어쓸 수 있음 (다른 서버 이식용)
    files = [
        "/home/hoony/flingfile/flingfile.log",
        "/home/hoony/logs/flingfile.log",
    ]
    try:
        cfg = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "guard_config.json")))
        if cfg.get("watch_logs"):
            files = cfg["watch_logs"]
    except Exception:
        pass
    pos = {}
    while True:
        for path in files:
            if not os.path.exists(path):
                continue
            try:
                size = os.path.getsize(path)
                start = pos.get(path, size)
                if size < start:
                    start = 0
                with open(path, "r", errors="ignore") as f:
                    f.seek(start)
                    while True:
                        line = f.readline()
                        if not line:
                            break
                        pos[path] = f.tell()
                        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                        if not m:
                            continue
                        ip = m.group(1)
                        if BAD_UA.search(line):
                            ua = BAD_UA.search(line).group(1)
                            block(ip, f"bad UA '{ua}' in {os.path.basename(path)}")
                        now = time.time()
                        q = WINDOW[ip]
                        q.append(now)
                        while q and now - q[0] > 60:
                            q.pop(0)
                        if len(q) >= 120:
                            q.clear()
                            block(ip, f"scan velocity {len(q)}req/60s")
                    pos[path] = size
            except Exception as e:
                log(f"http watch {path}: {e}")
        time.sleep(2)

def watch_ssh():
    """auth.log 실시간: 실패 3회 → 즉시 blackhole (fail2ban 전 선제 차단)."""
    path = "/var/log/auth.log"
    pat = re.compile(r"Failed password for (?:invalid user )?(\S+) from ((\d{1,3}\.){3}\d{1,3})")
    while not os.path.exists(path):
        time.sleep(3)
    with open(path, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            m = pat.search(line)
            if not m:
                continue
            ip = m.group(2)
            STATE[ip] = STATE.get(ip, 0) + 1
            if STATE[ip] >= 3:
                block(ip, f"ssh failed-password x{STATE[ip]}")

def main():
    log("roy-guard 시작 (ARTEX UA + 스캐너 + 스캔속도 + ssh 즉시차단)")
    threading.Thread(target=watch_http, daemon=True).start()
    threading.Thread(target=watch_ssh, daemon=True).start()
    while True:
        time.sleep(3600)

if __name__ == "__main__":
    main()
