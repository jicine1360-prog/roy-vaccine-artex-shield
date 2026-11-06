# Roy Vaccine — ARTEX Shield (roy-vaccine-artex-shield) — Installer

> **Beta (v0.2.2-beta)** — passed one live field test (detect → blackhole block → trace → abuse draft, ~30s). Deploy only on systems you own or are authorized to protect.

A three-layer defense package against autonomous AI pentest agents of the ARTEX family.

## What it does
| Layer | Component | Behavior |
|---|---|---|
| 1. Real-time block | roy_guard + roy_trace (systemd service) | Watches HTTP access logs for ARTEX/scanner User-Agents and scan velocity → instant blackhole route block → source trace → abuse-mail draft + Telegram alert |
| 2. fail2ban | sshd jail | SSH brute-force: 4 failures → ban (belt-and-suspenders with the guard) |
| 3. Periodic triage | triage cron (6h) | Read-only check for ARTEX traces on this host (ports/CA/audit markers/PG schema) — alerts **only on NEW hits** |

## Install (target server)
```
tar xzf roy-vaccine-artex-shield-*-beta.tar.gz && cd roy-vaccine-artex-shield
sudo bash install.sh
```
Requirements: Ubuntu/Debian, root, python3 (standard library only). Docker optional (only for servers that will run ARTEX itself).

## After install, review
`/opt/roy-guard/guard_config.json`
- `watch_logs`: the HTTP access-log path on that server (nginx etc.)
- `whitelist_prefixes`: networks that must never be blocked (LAN/tailscale)
- `telegram_token` / `telegram_chat_id`: bot for alerts (leave empty = block silently, no alerts)

## Known limitation (field-tested)
Blackhole blocking works on the main routing table (public-network attackers). Traffic arriving via Tailscale/VPN uses its own routing table and will not be cut by a blackhole route — for VPN peers use ACL/policy-level blocking.

## License / legal
- roy_guard / roy_trace / installer scripts: our own code, **MIT** (LICENSE.roy-vaccine).
- `detections/artex_host_triage.py`: derived from the artex-global repository, **AGPL-3.0** (LICENSE.artex-global-detection.txt included). Read-only triage tool.
- Legal principle: use only on systems **you own or have written authorization to inspect**. Scanning someone else's network without permission is itself unlawful in most jurisdictions.

## Disclaimer
- This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability and fitness for a particular purpose.
- The author and copyright holder shall not be liable for any direct, indirect, or incidental damages arising from the use of this software (service interruption, false positives/negatives in blocking, data loss, loss of business, etc.).
- Real-time blocking (blackhole/fail2ban) can drop live network connections. Review the whitelist for your environment before production use.
- Auto-generated abuse-mail drafts are drafts: a human must review the content before sending, and the sender bears responsibility for anything sent.
- This is a beta release. Behavior outside the author's own operating environment is unverified.

## Reference
The ARTEX framework itself is NOT included — this package ships defense/triage tools only. Servers that need the agent itself should run it from the archived Docker images (AGPL) in isolation.
