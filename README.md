# VPN Rate

**A tiny background agent that keeps watching your connection and rates how stable and how "clean" it is.**

[Русская версия](README.ru.md)

Online checkers give you a one-second snapshot. VPN Rate shows what happens **over time**:
how often your VPN drops, whether traffic ever escaped the tunnel, when your exit IP
changed and whether the new IP looks like a datacenter, proxy or abuser, which is the
kind of thing that gets accounts flagged by AI services and Google.

- One ~8 MB `.exe`, no runtime. About 25 MB RAM and practically zero CPU when idle.
- Tray icon (green / yellow / red), a local dashboard and Windows notifications.
- Everything stays on your machine. No accounts, no telemetry.
- **Open scoring.** Every point deducted is listed with its reason. The formula is below and in [`internal/score`](internal/score/score.go).

## What it checks

| Check | How | When |
|---|---|---|
| Connectivity and drops | TCP handshake to 1.1.1.1 / 8.8.8.8 / 9.9.9.9 on :443; offline after 2 misses | every 5 s |
| VPN tunnel up/down | Looks for WireGuard, Wintun, TAP, OpenVPN, AmneziaWG, sing-box, Hiddify, Outline and similar adapters | every 5 s |
| Public IPv4 / IPv6 | ipify, icanhazip, ifconfig.co, with fallback | every 90 s |
| IP reputation | [ipapi.is](https://ipapi.is), falling back to [ip-api.com](https://ip-api.com): datacenter, VPN, proxy, Tor, abuser, ASN, country | only when the IP changes (cached 24 h) |
| DNS leak | Resolves `whoami.akamai.net` to find out which resolver really serves you, then compares its country with your exit | on IP change and every 10 min |
| UDP / WebRTC leak | Built-in STUN client; the UDP exit IP must match the HTTP exit IP | on IP change and every 10 min |
| WebRTC in the browser | The dashboard gathers ICE candidates in your browser | whenever the dashboard is open |
| IPv6 leak | IPv6 exit in another country or ASN than IPv4 | on IP change |
| Timezone | System UTC offset vs. the IP's timezone (more than 1 h apart) | on IP change |

## Scores

**Trust (0–100):** starts at 100, then subtracts:

| Signal | Points |
|---|---|
| Tor exit | −50 |
| Exit country not supported by major AI services (RU, BY, CN, HK, MO, IR, KP, SY, CU) | −40 |
| Abuse / blacklist records | −25 |
| Datacenter / hosting IP | −20 |
| Known VPN | −10 |
| Known proxy | −10 |
| DNS leak | −15 |
| UDP / WebRTC leak | −15 |
| IPv6 leak | −15 |
| Timezone mismatch | −10 |

Grades: 85+ excellent, 70+ good, 50+ suspicious, below 50 high risk.

**Stability (last 24 h):** `100 − 2×downtime% − 3×drops (max 30) − tunnel drops (max 20) − latency (p95 > 300 ms: 5, > 800 ms: 10)`.

> No AI provider publishes how it scores IPs. These scores are an informed heuristic, not a guarantee.

## Install and run

Download `vpnrate.exe` from Releases and run it. A tray icon appears, and clicking it opens
the dashboard at <http://127.0.0.1:8737>. On first launch it adds itself to autostart
(`HKCU\...\Run`, no admin rights needed). You can turn that off from the tray menu.

```
vpnrate.exe [-port 8737] [-data DIR] [-headless] [-no-autostart] [-version]
```

`-headless` runs without the tray and logs events to stdout.

Data lives in `%APPDATA%\vpnrate\`: `events.jsonl`, daily `samples-*.jsonl` (kept for 30 days),
`ipcache.json`, `config.json` and `vpnrate.log`.

## Build from source

```
go install github.com/F7EVENTEEN/Vpn_rate_agent/cmd/vpnrate@latest
```

or

Requires Go 1.26+. No C compiler is needed.

```
go test ./...
go build -ldflags "-s -w -H windowsgui" -o vpnrate.exe ./cmd/vpnrate
```

## Privacy

The dashboard listens on `127.0.0.1` only and rejects foreign `Host` headers (DNS
rebinding) as well as non-JSON POSTs (cross-site requests). The only outbound requests
go to the IP / reputation / STUN services listed above. VPN Rate never contacts
claude.ai, chatgpt.com or other AI sites itself, so it never sends traffic to them from
an exit IP you did not choose (for example, while your VPN is down).

## Roadmap

- macOS / Linux tray, autostart and notifications (the core is already cross-platform)
- More reputation sources (e.g. Spamhaus DNSBL)
- Weekly report export
- Signed release builds via GitHub Actions

## License

MIT
