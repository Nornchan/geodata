# Rebuilt geodata — validation record

Built 2026-09-05 by `geox-hardening/tools/build_geodata.py` from the supplied
files, then verified by simulation. **15/15 checks pass.**

| File | SHA-256 | Size |
|---|---|---|
| `geosite.dat` | `41028c7aeb61e23072d98d7a14ea5b2e4ca25b469ed0dad6a9a152e66eb6aa7c` | 2,775,774 |
| `geoip.dat` | `8189d98a724b4ebef3101a9090204d7e1278bacfeaecb32e172dce27e1d0b32d` | 141,407 |
| `Country.mmdb` | `ec711fa4c4a0f54205cf24a1474f1109256f683eb40f8862284ee76e2ccfdd20` | 223,470 |

## Changes

| Category | Before | After | Change |
|---|---|---|---|
| `cn-carveout` | 391 | **406** | +15 unrescued foreign names |
| `private` | 118 | **117** | −1 (`ts.net`, also asserted foreign) |
| `geoip cn` v4 | 7,456 | **6,828** | −628 foreign-delegated ranges |
| `geoip cn` v6 | 3,394 | **3,315** | −79 foreign-delegated ranges |
| `Country.mmdb` | 10,850 | **10,143** | rebuilt from the corrected `cn` |
| `cn`, `cn-accel`, `not-cn`, `reject` | — | unchanged | — |

### 1. `cn-carveout` regenerated from `cn ∪ cn-accel`

The original was computed against `cn` alone — correct for those 391, blind to
the 360 foreign names `cn-accel` captures. It is now **derived** from the union
rather than maintained by hand, so it cannot drift when either domestic list
grows. All 391 original entries were retained; 15 were added.

### 2. `ts.net` removed from `private`

It was in both `private` (→ DIRECT) and `not-cn` (→ PROXY). A name cannot be
both a LAN name and foreign public infrastructure. Tailscale is unaffected: peer
traffic lives in `100.64.0.0/10` and is still caught by the private IP-CIDR rule
ahead of any domain rule.

### 3. 707 foreign ranges removed from `geoip cn`

Validated against the delegation files of all five RIRs (APNIC, RIPE NCC, ARIN,
LACNIC, AFRINIC — 261,113 IPv4 delegations).

| | Before | After |
|---|---|---|
| IPv4 addresses in `cn` delegated to a non-CN country | **13,387,091** | **0** |
| IPv6 ranges in `cn` delegated to a non-CN country | **79** | **0** |

Removed in two groups:

- **510 ranges / 311,333 addresses** — clear misattribution: Amazon
  (`107.176.0.0/15`), Apple (`17.0.0.0/8`), Microsoft, Cloudflare
  (`104.28.0.0/16`), Cisco, Nokia, Siemens, Fastly.
- **118 ranges / 13,075,758 addresses** — Alibaba and Tencent blocks registered
  to Singapore/Hong Kong entities, including `43.0.0.0/10` and `8.160.0.0/11`.
  Removed deliberately: routing a `/10` direct because its *owner* is Chinese
  exposes the real IP to that owner's overseas infrastructure.
- **79 IPv6 ranges** — HK 28, GB 23, US 14, ZA 9, and one each BR/GR/NL/BE/CH.

`Country.mmdb` is generated from the same corrected set in the same run, so the
two can never disagree and `geodata-mode` cannot change routing.

## Verification

```bash
python3 geox-hardening/tools/simulate_routing.py --dir rebuilt \
  --prune review-2026-09-05/geoip-prune-hard.txt \
  --prune review-2026-09-05/geoip-review-soft.txt \
  --prune review-2026-09-05/geoip-prune-v6.txt
```

The simulator models mihomo's first-match-wins engine and enumerates the paths a
connection can take — TCP and UDP, IPv4 and IPv6, hostname recovered or IP-only,
`geodata-mode` dat or mmdb.

| # | Check | Scale |
|---|---|---|
| T1 | foreign domains never DIRECT on any path | 26,044 × 8 paths |
| T2 | `cn-carveout` domains never DIRECT | 406 |
| T3 | no DIRECT/PROXY divergence across transport and stack | 8,026 |
| T4 | `geodata-mode` dat and mmdb agree | 24 addresses |
| T5 | IP-only to known foreign infrastructure never DIRECT | 20 |
| T6 | foreign domain on a CN address still proxied | 500 |
| T7 | unmatched destinations fall through to PROXY | 5 |
| T8 | every previously-leaking domain contained | 26 |
| T9 | private ranges stay local, never proxied | 6 |
| T10 | domestic domains still route DIRECT (functionality) | 2,000 |
| T11 | **exhaustive** — every pruned range routes PROXY | 707 |
| T12 | **exhaustive** — `geoip.dat cn` ≡ `Country.mmdb` | 10,143 |
| T13 | **exhaustive** — no foreign name captured without carveout | 26,044 |
| T14 | subdomain fuzz under foreign parents | 12,000 |
| T15 | IPv6 CN addresses consistent with IPv4 | 400 |

Before/after on the same suite:

```
supplied files   8/10 passed   (ts.net direct; 5 foreign IPs direct)
rebuilt files   15/15 passed
```

REJECT counts as safe on every path: a rejected connection emits no packet and
exposes no address.

## The rule chain these files assume

The files are only leak-free under an ordering that respects them. This is the
chain the simulation models, and it is a property of your config, not of the
data:

```yaml
rules:
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve        # + the other private ranges
  - AND,((NETWORK,udp),(DST-PORT,443)),REJECT   # closes QUIC divergence
  - GEOSITE,private,DIRECT
  - GEOSITE,reject,REJECT
  - GEOSITE,cn-carveout,PROXY                   # MUST precede cn and cn-accel
  - GEOSITE,not-cn,PROXY                        # MUST precede cn and cn-accel
  - GEOSITE,cn,DIRECT
  - GEOSITE,cn-accel,DIRECT
  - GEOIP,cn,DIRECT,no-resolve
  - MATCH,PROXY                                 # MUST fail closed
```

Reordering `cn-carveout` or `not-cn` below `cn`/`cn-accel`, or ending the chain
`MATCH,DIRECT`, reintroduces the leaks these files were rebuilt to remove.

## What the simulation does not cover

- It models the rule engine, not a client. It cannot detect a leak caused by
  traffic escaping the tunnel entirely — that is `strict-route`, and it is
  tested from the device ([CHECKLIST.md](../geox-hardening/CHECKLIST.md)).
- `cn-accel` still carries 110,079 suffixes inherited from a DNS acceleration
  list. Conflicts *visible* to the audit are now zero, but a domain wrongly
  marked domestic that appears in **no** foreign list is invisible to both the
  audit and the simulation, and would still route direct. Only all-proxy routing
  removes that residue.
- RIR delegation establishes registration, not physical location. It is the best
  available ground truth, and it is not the same thing.
