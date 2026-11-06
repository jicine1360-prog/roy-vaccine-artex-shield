# 로이 백신 — ARTEX 실드 (roy-vaccine-artex-shield) — 설치 프로그램

> **베타 (v0.2.2-beta)** — 실전 시연 1회 통과(차단→추적→신고 초안, 약 30초). 배포 범위: 본인 소유/승인 시스템 한정.

ARTEX 류 자율 AI 침투 에이전트로부터 본인 서버를 지키는 3중 방어 패키지.

## 구성
| 층 | 구성품 | 동작 |
|---|---|---|
| 1. 실시간 차단 | roy_guard + roy_trace (systemd 상주) | ARTEX/스캐너 UA·스캔 속도 감시 → 즉시 blackhole 차단 → 출발지 추적 → abuse 메일 초안 + 텔레그램 알림 |
| 2. fail2ban | sshd jail | SSH 브루트포스 4회 → 즉시 차단 (가드와 이중) |
| 3. 주기 정찰 | triage cron (6h) | ARTEX 흔적(포트/CA/감사마커/PG 스키마) 점검 — **신규 HIT만** 알림 |

## 설치 (대상 서버)
```
tar xzf roy-vaccine-artex-shield-*-beta.tar.gz && cd roy-vaccine-artex-shield
sudo bash install.sh
```
요구사항: Ubuntu/Debian, root, python3(표준 라이브러리만 사용), docker는 선택(ARTEX 본체 돌릴 서버만).

## 설치 후 반드시 확인할 것
`/opt/roy-guard/guard_config.json`
- `watch_logs`: 그 서버의 HTTP 접근로그 경로 (nginx 등)
- `whitelist_prefixes`: 절대 차단 금지 대역 (LAN/tailscale)
- `telegram_token` / `telegram_chat_id`: 알림 받을 봇 (비우면 차단만, 알림 없음)

## 라이선스/법률
- roy_guard/roy_trace/설치 스크립트: 우리 자체 코드 — **MIT** (LICENSE.roy-vaccine).
- `detections/artex_host_triage.py`: artex-global 저장소-derived (**AGPL-3.0**, LICENSE.artex-global-detection.txt 동봉). 이 스크립트는 읽기전용 정찰용이며, 별도 프로세스로 실행되는 별개 저작물(aggregation)입니다.
- 법적 원칙: **본인 소유 또는 서면 승인 시스템에만** 사용. 남의망 무단 스캔/공격은 그 자체로 위법.
- 영문 메뉴얼: README.en.md

## 알려진 한계 (실측)
blackhole 차단은 메인 라우팅 테이블(공개망 공격)에만 유효합니다. 테일스케일/VPN 경유 트래픽은 자체 라우팅 테이블을 타므로 blackhole으로 끊기지 않으며, ACL/정책 수준 차단이 필요합니다.

## 면책조항
- 본 소프트웨어는 "있는 그대로" 제공되며, 상품성 및 특정 목적 적합성에 대한 묵시적 보증 포함 어떠한 보증도 하지 않습니다.
- 제작자·저작권자는 본 소프트웨어 사용으로 발생한 직접·간접·우발적 손해(서비스 중단, 차단 오탐·미탐, 데이터 손실, 비즈니스 손실 등)에 대해 책임을 지지 않습니다.
- 실시간 차단(blackhole/fail2ban)은 네트워크 연결을 끊을 수 있습니다. 화이트리스트를 반드시 본인 환경에 맞게 점검한 뒤 운영하십시오.
- 자동 생성되는 abuse 신고 초안은 발송 전 사람이 내용을 확인해야 하며, 잘못된 발송의 책임은 발송자에게 있습니다.
- 베타 버전입니다. 본사(JICloud) 운영 환경 외에서의 동작은 검증되지 않았습니다.

## 참고
- ARTEX 본체(공격 프레임워크) 자체는 이 패키지에 포함 안 함 — 학습/방어용 정찰 도구만. 본체가 필요한 서버는 아카이브의 docker 이미지(AGPL)로 격리 구동할 것.
