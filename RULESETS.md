# Rule-provider review, and the replacement set

Audit of the 13 `rule-providers` in `Clash.yaml`, all of which were served from
`Loyalsoldier/clash-rules@release`. Ground truth is your own validated geodata
at `Nornchan/geodata@16ae34a5` — a domain that file classifies as foreign must
never be routed `DIRECT`.

**Result: 827 foreign domains were routed `DIRECT`. With the replacement set, 0.**

The geodata pin was the right fix and it is now live and correct — all three
files served from that commit match the validated build byte for byte. But
pinning the geodata while the rule-providers still track a moving branch does
not halve the exposure. It splits it in two, and leaves the unaudited half
holding the rules that route to `DIRECT`.

---

## Findings

### 1. `direct.txt` reintroduces every bare suffix removed from the geosite — 827 domains

`RULE-SET,direct,DIRECT` carries the same 50 single-label suffixes stripped out
of `geosite.dat`:

```
cn  wang  yun  alibaba  alipay  anquan  baidu  citic  icbc  shouji  sina
sohu  taobao  tmall  unicom  weibo  xihuan  + 33 IDN TLDs (xn--*)
```

| Cause | Domains sent DIRECT |
|---|---|
| captured by the bare `cn` suffix | **519** |
| captured by a specific over-broad entry | 307 |
| **total** | **826** |

Casualties include `aboutamazon.cn`, `aadrm.cn` (Microsoft Rights Management),
`acer.com.cn`, `a2z.org.cn`, and every other `.cn` name your geodata marks
foreign. The remaining 307 come from suffixes such as `qq.com` (49),
`baidu.com` (40), `taobao.com` (20) and `umeng.com` (15) swallowing foreign
subdomains beneath them.

This is the defect the geodata rebuild removed, arriving through a different
door and landing one line earlier in the chain.

### 2. `applications.txt` routes BitTorrent clients DIRECT at chain position 2

`RULE-SET,applications,DIRECT` is second in the entire rule chain, above every
geosite and geoip rule. Of its 98 entries, 13 are torrent and download clients:

```
qBittorrent  Transmission  transmission-daemon  qbittorrent-nox  aria2  aria2c
uTorrent  WebTorrent  BitComet  Thunder  Folx  NeatDM  NetTransport  fdm  xdm
```

Upstream routes these direct to keep torrent traffic off a metered proxy. That
is a bandwidth decision with a security consequence: **a public torrent swarm
publishes the address of every participant**, and this rule wins over
everything below it. Under this standard that trade is not available.

The other 85 entries are legitimate — a tunnel client's own connection cannot
be tunnelled without looping.

### 3. `cncidr.txt` marks 2,648,064 foreign addresses as Chinese

Validated against the RIR delegation files, same method as the geodata:

| | |
|---|---|
| ranges containing non-CN delegated space | **133** |
| non-CN addresses routed to `Domestic` (→ DIRECT) | **2,648,064** |
| by country | SG 2,592,512 · HK 20,480 · US 15,104 · PK 10,752 · GB 6,144 |

Worst offenders are Alibaba Cloud blocks: `8.136.0.0/13`, `8.152.0.0/13`,
`8.132.0.0/14`, `8.144.0.0/14`. Your own `geoip.dat` has these removed;
`cncidr.txt` puts them back.

It also disagrees with your geodata in both directions — 1,075 ranges present
here but not there, 1,674 there but not here. Two IP databases consulted by one
rule chain, disagreeing about which addresses are domestic.

### 4. `private.txt` routes `ts.net` DIRECT

The same conflict removed from `geosite private`. Tailscale peer traffic is
carried on `100.64.0.0/10` and is already matched by address, so the domain
entry buys nothing.

### 5. Every provider tracks a moving branch

All 13 use `@release` with `interval: 86400`. Thirteen files, ~370,000 rules,
refetched daily without review, four of them routing to `DIRECT`. The version
you audit is never the version your clients load — the argument that motivated
pinning the geodata, applied to a larger and less examined surface.

### 6. Two config references now point at categories that no longer exist

Your rebuilt `geosite.dat` contains exactly six categories: `cn`, `cn-accel`,
`cn-carveout`, `not-cn`, `private`, `reject`. The config still references:

- **line 564** — `GEOSITE,category-ads-all,REJECT`
- **line 63–64** — `dns.fallback-filter.geosite: [gfw]`

Neither exists. Depending on build, mihomo either refuses the config or drops
the rule silently. Ad blocking is currently carried by the curated
`DOMAIN-SUFFIX` list beneath it and by `RULE-SET,reject`, so the visible
symptom is mild — but a config that fails to load is not a safe config, and
`fallback-filter` needs removing regardless (see below).

### 7. Config-level issues outside the providers

- **line 949 — `DOMAIN-SUFFIX,cn,Domestic`.** The bare `cn` defect, hardcoded.
  Every `.cn` name goes to `Domestic`, which defaults to `DIRECT`. This alone
  re-creates finding 1 even after the providers are replaced. **Delete it.**
- **line 320–324 — `Final` is a selector containing `DIRECT`**, and
  `store-selected: true` (line 24) makes a stray selection permanent and
  invisible. Same for `Domestic`, `Apple`, `Microsoft`, `Gaming`.
- **line 56–67 — `dns.fallback-filter`** decides "is this domestic" using
  geosite data before any routing rule runs, and references the missing `gfw`.
- **line 6 — `allow-lan: true`** with no `bind-address` restriction exposes the
  proxy to every host on the network.
- **line 8 — `log-level: info`** writes visited domains to disk.
- **No `tun:` section**, so nothing enforces `strict-route`.

---

## The replacement set

Generated by [`tools/build_rulesets.py`](tools/build_rulesets.py) from the
`geosite.dat` and `geoip.dat` in this repository, at this commit.

| File | Source category | Behavior | Routes to | Entries |
|---|---|---|---|---|
| `carveout.yaml` | `cn-carveout` | domain | **PROXY** | 406 |
| `proxy.yaml` | `not-cn` | domain | PROXY | 26,044 |
| `reject.yaml` | `reject` | domain | REJECT | 7,666 |
| `private.yaml` | `private` | domain | DIRECT | 117 |
| `direct.yaml` | `cn` | domain | DIRECT | 7,710 |
| `direct-accel.yaml` | `cn-accel` | domain | DIRECT | 110,079 |
| `cncidr.yaml` | geoip `cn` | ipcidr | DIRECT | 10,143 |
| `lancidr.yaml` | geoip `private` | ipcidr | DIRECT | 14 |
| `applications.yaml` | curated | classical | DIRECT | 42 |

Verified: **0** of the 26,044 foreign domains route `DIRECT`, and **0** bare
suffixes in either DIRECT-routed domain set.

`applications.yaml` keeps the 42 tunnel-client entries that prevent routing
loops and drops the torrent clients. `zerotier-one` and `Tailscale` are dropped
too — their peer traffic is on `100.64.0.0/10` and `fc00::/7`, which
`lancidr.yaml` already routes DIRECT by address, so a process-name match adds
nothing while granting those processes a blanket DIRECT for anything else they
contact.

`google`, `apple`, `icloud` and `telegramcidr` are not reproduced here. They
route to proxy groups rather than `DIRECT`, so they cannot leak an address, and
they exist only to steer traffic into a named group. Keep them if you want the
grouping — but pin them to a commit rather than `@release`.

---

## Configuration

Replace the whole `rule-providers:` block:

```yaml
rule-providers:
  # All eight served from one audited commit. Same repository, same pin, same
  # source of truth as geox-url. Change COMMIT_SHA when you publish a new build.
  carveout:     {type: http, behavior: domain,    interval: 86400, path: ./ruleset/carveout.yaml,     url: "https://cdn.jsdelivr.net/gh/Nornchan/geodata@COMMIT_SHA/ruleset/carveout.yaml"}
  proxy:        {type: http, behavior: domain,    interval: 86400, path: ./ruleset/proxy.yaml,        url: "https://cdn.jsdelivr.net/gh/Nornchan/geodata@COMMIT_SHA/ruleset/proxy.yaml"}
  reject:       {type: http, behavior: domain,    interval: 86400, path: ./ruleset/reject.yaml,       url: "https://cdn.jsdelivr.net/gh/Nornchan/geodata@COMMIT_SHA/ruleset/reject.yaml"}
  private:      {type: http, behavior: domain,    interval: 86400, path: ./ruleset/private.yaml,      url: "https://cdn.jsdelivr.net/gh/Nornchan/geodata@COMMIT_SHA/ruleset/private.yaml"}
  direct:       {type: http, behavior: domain,    interval: 86400, path: ./ruleset/direct.yaml,       url: "https://cdn.jsdelivr.net/gh/Nornchan/geodata@COMMIT_SHA/ruleset/direct.yaml"}
  direct-accel: {type: http, behavior: domain,    interval: 86400, path: ./ruleset/direct-accel.yaml, url: "https://cdn.jsdelivr.net/gh/Nornchan/geodata@COMMIT_SHA/ruleset/direct-accel.yaml"}
  cncidr:       {type: http, behavior: ipcidr,    interval: 86400, path: ./ruleset/cncidr.yaml,       url: "https://cdn.jsdelivr.net/gh/Nornchan/geodata@COMMIT_SHA/ruleset/cncidr.yaml"}
  lancidr:      {type: http, behavior: ipcidr,    interval: 86400, path: ./ruleset/lancidr.yaml,      url: "https://cdn.jsdelivr.net/gh/Nornchan/geodata@COMMIT_SHA/ruleset/lancidr.yaml"}
  applications: {type: http, behavior: classical, interval: 86400, path: ./ruleset/applications.yaml, url: "https://cdn.jsdelivr.net/gh/Nornchan/geodata@COMMIT_SHA/ruleset/applications.yaml"}
```

Replace the provider rules (currently lines 891–903) with this ordering. The
order is the security property:

```yaml
  # -- loop prevention: a tunnel client cannot be tunnelled --------------
  - RULE-SET,applications,DIRECT

  # -- LAN and reserved names -------------------------------------------
  - RULE-SET,private,DIRECT
  - RULE-SET,lancidr,DIRECT,no-resolve

  # -- close the QUIC/TCP divergence ------------------------------------
  - AND,((NETWORK,udp),(DST-PORT,443)),REJECT

  # -- carveout FIRST: foreign names a domestic suffix would swallow -----
  - RULE-SET,carveout,PROXY

  # -- blocking ----------------------------------------------------------
  - RULE-SET,reject,REJECT

  # -- foreign BEFORE domestic ------------------------------------------
  - RULE-SET,proxy,PROXY

  # -- domestic ----------------------------------------------------------
  - RULE-SET,direct,DIRECT
  - RULE-SET,direct-accel,DIRECT
  - RULE-SET,cncidr,DIRECT,no-resolve
```

Then, in the rules that follow:

1. **Delete `DOMAIN-SUFFIX,cn,Domestic`** (line 949). Non-negotiable — it
   re-creates finding 1 on its own.
2. **Delete `GEOSITE,category-ads-all,REJECT`** (line 564) — the category no
   longer exists; `RULE-SET,reject` covers it.
3. **Delete the whole `dns.fallback-filter` block** (lines 56–67). It decides
   "domestic" from geosite data before routing runs, and references the missing
   `gfw` category.
4. **Change `MATCH,Final` to `MATCH,PROXY`**, and remove `DIRECT` from the
   `Final`, `Domestic`, `Apple`, `Microsoft` and `Gaming` selectors — or set
   `store-selected: false` at minimum.
5. **`allow-lan: false`**, or add `bind-address: 127.0.0.1`.
6. **`log-level: warning`**.
7. **Add a `tun:` block with `strict-route: true`** and set `ipv6: false` at top
   level, not only under `dns:`.

Items 1–4 are leak fixes. 5–7 are the surrounding posture.

## Regenerating

```bash
python3 tools/build_rulesets.py --in-dir . --out-dir ruleset
```

Rebuild the geodata first if it has changed; the rule-providers are derived
from it and must not be edited by hand.
