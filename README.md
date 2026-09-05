# geodata

Routing databases for mihomo / Clash.Meta, sing-box and Xray, rebuilt so that
**no rule conflict can expose a user's real IP address**.

Three files, published together and validated together:

| File | Contents |
|---|---|
| `geosite.dat` | domain categories — `cn`, `cn-accel`, `cn-carveout`, `not-cn`, `reject`, `private` |
| `geoip.dat` | IP ranges — `cn`, `private` |
| `Country.mmdb` | the same `cn` ranges in MaxMind form, for `geodata-mode: false` |

Every release passes a 15-check routing simulation before it is published. The
current record is in [VALIDATION.md](VALIDATION.md).

---

## Why this exists

The widely used geodata sets classify a meaningful number of domains as **both**
domestic and foreign. Under first-match-wins routing that means the same site
can be reached over the proxy on one transport and directly on another —
presenting an observer with one identity arriving from a proxy IP and from a
residential IP. That correlation is the leak, and it needs no cipher to be
broken.

This set is built to make that impossible:

- `cn-carveout` is **derived** from `cn ∪ cn-accel`, not hand-maintained, so it
  cannot drift when either domestic list grows.
- `cn` in `geoip.dat` is validated against the delegation files of all five RIRs.
  Foreign-delegated space is removed — currently **0 bytes** of it remain.
- `Country.mmdb` is generated from the same corrected `cn` set in the same run,
  so `geodata-mode` cannot change routing.
- The acceleration list is named `cn-accel` rather than folded into `cn`,
  because "resolves fastest domestically" is not "safe to contact from a
  residential Chinese address".

---

## Usage

### mihomo / Clash.Meta

Pin to a commit, not to a branch. A branch reference means the version you
audited is never the version your clients load.

```yaml
geodata-mode: true
geo-auto-update: false
geox-url:
  geoip:   "https://raw.githubusercontent.com/YOUR-USERNAME/geodata/COMMIT_SHA/geoip.dat"
  geosite: "https://raw.githubusercontent.com/YOUR-USERNAME/geodata/COMMIT_SHA/geosite.dat"
  mmdb:    "https://raw.githubusercontent.com/YOUR-USERNAME/geodata/COMMIT_SHA/Country.mmdb"
  # asn: omitted deliberately — see "ASN" below
```

`raw.githubusercontent.com` serves the file at that exact commit forever and is
never cached stale. It is, however, unreachable from inside mainland China
without a working proxy — fetch these once from a machine that can reach it, or
mirror them through a CDN:

```yaml
  geoip:   "https://cdn.jsdelivr.net/gh/YOUR-USERNAME/geodata@COMMIT_SHA/geoip.dat"
  geosite: "https://cdn.jsdelivr.net/gh/YOUR-USERNAME/geodata@COMMIT_SHA/geosite.dat"
  mmdb:    "https://cdn.jsdelivr.net/gh/YOUR-USERNAME/geodata@COMMIT_SHA/Country.mmdb"
```

Both forms take a full 40-character commit SHA. Neither takes a branch name —
see the warning above.

### The rule chain these files require

**The files are only leak-free under this ordering.** It is a property of your
configuration, not of the data:

```yaml
rules:
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,169.254.0.0/16,DIRECT,no-resolve
  - IP-CIDR6,fe80::/10,DIRECT,no-resolve

  - AND,((NETWORK,udp),(DST-PORT,443)),REJECT   # closes the QUIC/TCP divergence

  - GEOSITE,private,DIRECT
  - GEOSITE,reject,REJECT
  - GEOSITE,cn-carveout,PROXY      # MUST precede cn and cn-accel
  - GEOSITE,not-cn,PROXY           # MUST precede cn and cn-accel
  - GEOSITE,cn,DIRECT
  - GEOSITE,cn-accel,DIRECT
  - GEOIP,cn,DIRECT,no-resolve

  - MATCH,PROXY                    # MUST fail closed. Never MATCH,DIRECT.
```

Moving `cn-carveout` or `not-cn` below the domestic lists, or ending the chain
`MATCH,DIRECT`, reintroduces exactly the leaks this set was built to remove.

Set `ipv6: false` consistently and `udp: true` on every node that carries UDP.
An inconsistent IP stack and an unproxied UDP path are the other two ways the
same site ends up reached from two addresses.

### ASN

No `ASN.mmdb` is published here. mihomo's default points at an individual's
personal repository under a moving `latest` tag, for a ~12 MB database consulted
only by `IP-ASN` rules that most deployments never use. If you need it, pin it
or self-host it like everything else.

---

## Verify before you trust

Nothing here should be taken on faith — that is the whole argument. The
toolchain is stdlib-only Python, no third-party packages, so auditing your
supply chain does not widen it.

```bash
# structural conflict audit
python3 tools/audit_geosite.py geosite.dat \
    --cn-key cn --ncn-key not-cn --carveout-key cn-carveout --domestic cn-accel

# routing simulation — every path a connection can take
python3 tools/simulate_routing.py --dir . \
    --prune prune/geoip-prune-hard.txt \
    --prune prune/geoip-review-soft.txt \
    --prune prune/geoip-prune-v6.txt
```

Expected: **0** conflicts on every structural check, **15/15** simulation checks.

The simulation models mihomo's engine and enumerates TCP and UDP, IPv4 and IPv6,
hostname-recovered and IP-only, `geodata-mode` dat and mmdb. It asserts that no
foreign destination is ever `DIRECT` on any path, that no destination is
`DIRECT` on one path and `PROXY` on another, and that unmatched traffic fails
closed. Four checks are exhaustive rather than sampled.

---

## Rebuilding

```bash
python3 tools/build_geodata.py --in-dir source/ --out-dir . \
    --prune prune/geoip-prune-hard.txt \
    --prune prune/geoip-review-soft.txt \
    --prune prune/geoip-prune-v6.txt
```

The prune lists are generated by validating `geoip.dat`'s `cn` category against
the RIR delegated-statistics files (APNIC, RIPE NCC, ARIN, LACNIC, AFRINIC).
They are checked in so a rebuild is reproducible without re-fetching them.

---

## What this does not fix

`cn-accel` still carries ~110,000 suffixes inherited from a DNS acceleration
list. Every conflict **visible** to the audit is zero, but a domain wrongly
marked domestic that appears in no foreign list is invisible to both the audit
and the simulation, and would still route direct.

Split routing narrows exposure. It does not close it. Users for whom
identification carries real consequences should run all-proxy routing on a
dedicated device and keep domestic services on a separate one — that removes the
geodata supply chain from the trust model rather than managing it.

RIR delegation establishes registration, not physical location. It is the best
available ground truth and it is not the same thing.

---

## Provenance and licence

The tooling in `tools/` is MIT-licensed (see [LICENSE](LICENSE)).

The geodata is derived from upstream community rule sets, which carry their own
terms and remain the work of their maintainers. This repository redistributes
corrected builds; it makes no ownership claim over the underlying data. Check
the upstream licences before redistributing further.
