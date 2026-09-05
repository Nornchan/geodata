#!/usr/bin/env python3
"""
build_geodata.py — rebuild geosite.dat, geoip.dat and Country.mmdb with the
audit findings applied.

Two corrections:

  1. `cn-carveout` is regenerated from `cn UNION cn-accel` rather than from `cn`
     alone. Deriving it from the union is the point: a hand-maintained carveout
     drifts the moment either domestic list grows, and drift here is a leak.

  2. Ranges in `cn` that authoritative RIR delegation data assigns to another
     country are removed, and Country.mmdb is rebuilt from the same corrected
     set so the two can never disagree.

Usage
  python3 tools/build_geodata.py --in-dir . --out-dir rebuilt/ \
      --prune review/geoip-prune-hard.txt --prune review/geoip-review-soft.txt
"""
import argparse
import ipaddress
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from geoparse import parse_geosite, parse_geoip   # noqa: E402
from geowrite import write_geosite, write_geoip   # noqa: E402
from mmdbwrite import write_mmdb                  # noqa: E402


def load_prune(paths):
    out = set()
    for p in paths or []:
        for line in open(p, encoding="utf-8"):
            s = line.split("#", 1)[0].strip()
            if s:
                out.add(ipaddress.ip_network(s))
    return out


def covered_by(domain, suffixes):
    """True if `domain` is matched by an equal-or-broader suffix rule."""
    if domain in suffixes:
        return True
    parts = domain.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in suffixes:
            return True
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in-dir", default=".")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--prune", action="append", default=[],
                    help="file of CIDRs to remove from the cn category (repeatable)")
    ap.add_argument("--cn-key", default="cn")
    ap.add_argument("--accel-key", default="cn-accel")
    ap.add_argument("--carveout-key", default="cn-carveout")
    ap.add_argument("--notcn-key", default="not-cn")
    a = ap.parse_args()
    os.makedirs(a.out_dir, exist_ok=True)

    # ---------------------------------------------------------- geosite ----
    gs = parse_geosite(os.path.join(a.in_dir, "geosite.dat"))
    cats = {k: [(t, v) for t, v, _ in gs[k]] for k in gs}
    cn = {v for t, v, _ in gs[a.cn_key] if t == "suffix"}
    accel = {v for t, v, _ in gs[a.accel_key] if t == "suffix"}
    notcn = {v for t, v, _ in gs[a.notcn_key] if t == "suffix"}
    domestic = cn | accel

    new_carve = sorted(d for d in notcn if covered_by(d, domestic))
    old_carve = {v for t, v, _ in gs[a.carveout_key]}
    added = sorted(set(new_carve) - old_carve)
    removed = sorted(old_carve - set(new_carve))

    cats[a.carveout_key] = [("suffix", d) for d in new_carve]

    # A name cannot be both a LAN/reserved name and foreign public infrastructure.
    # `private` routes DIRECT, so anything the database also asserts is foreign
    # must not sit there. (ts.net is the live case: Tailscale peer traffic is
    # still caught by the 100.64.0.0/10 IP-CIDR rule, so proxying the namespace
    # costs nothing and removes the conflict.)
    priv = {v for t_, v, _ in gs["private"]}
    conflicted = sorted(priv & notcn)
    if conflicted:
        cats["private"] = [(t_, v) for t_, v in cats["private"] if v not in set(conflicted)]
        print(f"  private: removed {len(conflicted)} name(s) also asserted foreign: "
              f"{', '.join(conflicted)}")
    n = write_geosite(cats, os.path.join(a.out_dir, "geosite.dat"))
    print(f"geosite.dat   {n:>10,} bytes")
    print(f"  {a.carveout_key}: {len(old_carve)} -> {len(new_carve)}  (+{len(added)} added, -{len(removed)} removed)")
    if added:
        print(f"    added: {', '.join(added[:6])}{' ...' if len(added) > 6 else ''}")

    # ------------------------------------------------------------ geoip ----
    gi = parse_geoip(os.path.join(a.in_dir, "geoip.dat"))
    prune = load_prune(a.prune)
    out_gi, pruned_total = {}, 0
    for code, (cidrs, inverse) in gi.items():
        nets = [ipaddress.ip_network(c) for c in cidrs]
        if code.lower() == a.cn_key.lower():
            kept = [x for x in nets if x not in prune]
            pruned_total = len(nets) - len(kept)
            nets = kept
        out_gi[code] = ([str(x) for x in nets], inverse)
    n = write_geoip(out_gi, os.path.join(a.out_dir, "geoip.dat"))
    cn_nets = [ipaddress.ip_network(c) for c in out_gi[a.cn_key][0]]
    print(f"geoip.dat     {n:>10,} bytes")
    print(f"  {a.cn_key}: {len(gi[a.cn_key][0]):,} -> {len(cn_nets):,} ranges  ({pruned_total:,} pruned)")

    # ------------------------------------------------------- Country.mmdb --
    # Built from the SAME corrected cn set, so geodata-mode cannot change routing.
    record = {"country": {"iso_code": "CN", "geoname_id": 1814991,
                          "names": {"en": "China"}},
              "registered_country": {"iso_code": "CN", "geoname_id": 1814991,
                                     "names": {"en": "China"}}}
    info = write_mmdb([(x, record) for x in cn_nets],
                      os.path.join(a.out_dir, "Country.mmdb"),
                      database_type="GeoIP2-Country", languages=("en",),
                      description={"en": "self-built CN-only, RIR-validated"},
                      build_epoch=int(time.time()), record_size=24)
    size = os.path.getsize(os.path.join(a.out_dir, "Country.mmdb"))
    print(f"Country.mmdb  {size:>10,} bytes   nodes={info['node_count']:,}  networks={len(cn_nets):,}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
