#!/usr/bin/env python3
"""
audit_geosite.py — find routing conflicts in a geosite database that can leak a
user's real IP under split ("rule mode") routing.

The premise: a domain classified as *both* domestic and foreign is not a
cosmetic inconsistency. Under first-match-wins rule evaluation it means the same
site can be reached over two different paths — proxy on one transport, direct on
another — presenting an observer with the same identity on a proxy IP and on a
residential IP. That correlation is the leak.

Checks performed
  1. Identical suffix present in both the CN and the !CN list.
  2. Foreign (!CN) entries swallowed by a broader CN suffix   <- highest severity
  3. Domestic (CN) entries swallowed by a broader !CN suffix
  4. Bare single-label suffixes in CN (whole-namespace capture, e.g. `cn`, `ms`).
  5. Sensitive-category domains sitting in the direct-connect list.
  6. Rule-type composition, which exposes broken upstream transformations.

Usage
  python3 tools/audit_geosite.py geosite.dat
  python3 tools/audit_geosite.py geosite.dat --emit-overrides overrides/
  python3 tools/audit_geosite.py geosite.dat --max-overlap 0   # CI gate
"""
import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from geoparse import parse_geosite  # noqa: E402

# Categories whose members must never be reached on the user's real IP.
SENSITIVE = ("CATEGORY-PORN", "CATEGORY-CRYPTOCURRENCY", "CATEGORY-ANTICENSORSHIP",
             "CATEGORY-VPNSERVICES", "GFW")


def covered_by(needles, haystack):
    """Entries in `needles` shadowed by a strictly broader suffix in `haystack`."""
    hits = []
    for d in needles:
        parts = d.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in haystack:
                hits.append((d, parent))
                break
    return hits


def audit(path, cn_key="CN", ncn_key="GEOLOCATION-!CN", carveout_key=None,
          extra_domestic=()):
    """
    carveout_key: a category evaluated BEFORE the domestic lists, whose members
    are therefore rescued from being swallowed by a broader domestic suffix.
    extra_domestic: further domestic categories (e.g. an acceleration list) that
    also route DIRECT and so must be checked for capture.
    """
    g = parse_geosite(path)
    if cn_key not in g or ncn_key not in g:
        sys.exit(f"error: {path} lacks {cn_key} / {ncn_key}; is this a geosite database?")

    cn_all, ncn_all = g[cn_key], g[ncn_key]
    cn_s = {v for t, v, _ in cn_all if t == "suffix"}
    ncn_s = {v for t, v, _ in ncn_all if t == "suffix"}
    for k in extra_domestic:
        if k in g:
            cn_s |= {v for t, v, _ in g[k] if t == "suffix"}
    carve = {v for _, v, _ in g.get(carveout_key, [])} if carveout_key else set()

    both = (cn_s & ncn_s) - carve
    ncn_under_cn = [(d, p) for d, p in covered_by(ncn_s, cn_s) if d not in carve]
    cn_under_ncn = covered_by(cn_s, ncn_s)
    bare = sorted(d for d in cn_s if "." not in d)

    sensitive = {}
    for cat in SENSITIVE:
        if cat in g:
            hit = cn_s & {v for _, v, _ in g[cat]}
            if hit:
                sensitive[cat] = sorted(hit)

    return {
        "path": path, "categories": len(g),
        "cn_total": len(cn_all), "ncn_total": len(ncn_all),
        "cn_types": dict(collections.Counter(t for t, _, _ in cn_all)),
        "ncn_types": dict(collections.Counter(t for t, _, _ in ncn_all)),
        "both": sorted(both),
        "ncn_under_cn": sorted(ncn_under_cn),
        "cn_under_ncn": sorted(cn_under_ncn),
        "bare": bare, "sensitive": sensitive,
        "overlap_total": len(both) + len(ncn_under_cn) + len(cn_under_ncn),
    }


def report(r, verbose=False):
    p = print
    p(f"\n{'=' * 72}\n  geosite audit: {r['path']}\n{'=' * 72}")
    p(f"categories: {r['categories']}")
    p(f"  CN               {r['cn_total']:>8,}  {r['cn_types']}")
    p(f"  GEOLOCATION-!CN  {r['ncn_total']:>8,}  {r['ncn_types']}")

    if "full" not in r["cn_types"] and r["cn_total"] > 50000:
        p("\n  ! CN contains ZERO exact-match rules. Upstream lists normally carry")
        p("    hundreds. Their absence is the fingerprint of a broken suffix conversion,")
        p("    which also silently widens exact rules into whole-subtree rules.")

    p(f"\n[1] identical suffix in BOTH CN and !CN ......... {len(r['both']):>6,}")
    p(f"[2] !CN entries swallowed by broader CN suffix .. {len(r['ncn_under_cn']):>6,}  <-- leaks real IP")
    p(f"[3] CN entries swallowed by broader !CN suffix .. {len(r['cn_under_ncn']):>6,}")
    p(f"    bidirectional overlap total ................ {r['overlap_total']:>6,}")
    p(f"[4] bare single-label suffixes in CN ............ {len(r['bare']):>6,}")
    if r["bare"]:
        p("    " + ", ".join(r["bare"][:24]) + (" ..." if len(r["bare"]) > 24 else ""))
        p("    Each captures an entire namespace. `cn` sends google.cn direct;")
        p("    `ms` is Montserrat's ccTLD, not Microsoft, and captures aka.ms / 1drv.ms.")

    p("[5] sensitive-category domains in the direct list:")
    if not r["sensitive"]:
        p("      none")
    for cat, ds in r["sensitive"].items():
        p(f"      {cat:26s} {len(ds):>4}   {', '.join(ds[:6])}")

    if verbose:
        p("\n--- [2] full detail (foreign domains that will route DIRECT) ---")
        for d, parent in r["ncn_under_cn"]:
            p(f"    {d:48s} <- CN suffix '{parent}'")


def emit_overrides(r, outdir):
    os.makedirs(outdir, exist_ok=True)
    forced = set(r["both"]) | {d for d, _ in r["ncn_under_cn"]}
    for ds in r["sensitive"].values():
        forced |= set(ds)
    forced = sorted(forced)

    header = ("# Domains that must never be routed DIRECT.\n"
              "# Generated by tools/audit_geosite.py from a live geosite database.\n"
              "# Cause: present in both the domestic and foreign lists, swallowed by a\n"
              "# broader domestic suffix, or a sensitive category found in the direct list.\n")

    plain = os.path.join(outdir, "force-proxy.txt")
    with open(plain, "w") as f:
        f.write(header + "\n".join(forced) + "\n")

    yamlp = os.path.join(outdir, "force-proxy.yaml")
    with open(yamlp, "w") as f:
        f.write("# mihomo/Clash rule-provider, behavior: domain\n"
                "# Reference it FIRST in your rule chain so it pre-empts every geosite rule.\n"
                "payload:\n")
        for d in forced:
            f.write(f"  - '+.{d}'\n")

    rules = os.path.join(outdir, "force-proxy.rules.yaml")
    with open(rules, "w") as f:
        f.write("# Paste at the very TOP of `rules:` (first match wins).\n"
                "# Bare-namespace guards first, then the individual conflicted domains.\n")
        for d in r["bare"]:
            f.write(f"  - DOMAIN-SUFFIX,{d},PROXY\n")
        for d in forced:
            f.write(f"  - DOMAIN-SUFFIX,{d},PROXY\n")

    print(f"\nwrote {len(forced):,} force-proxy domains + {len(r['bare'])} bare-namespace guards:")
    for x in (plain, yamlp, rules):
        print(f"  {x}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("geosite")
    ap.add_argument("--cn-key", default="CN")
    ap.add_argument("--ncn-key", default="GEOLOCATION-!CN")
    ap.add_argument("--carveout-key", default=None,
                    help="category evaluated before the domestic lists, rescuing its members")
    ap.add_argument("--domestic", action="append", default=[],
                    help="additional category that also routes DIRECT (repeatable)")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--emit-overrides", metavar="DIR")
    ap.add_argument("--max-overlap", type=int, default=None,
                    help="exit 1 if bidirectional overlap exceeds this (CI gate)")
    a = ap.parse_args()

    r = audit(a.geosite, a.cn_key, a.ncn_key, a.carveout_key, a.domestic)
    report(r, a.verbose)
    if a.emit_overrides:
        emit_overrides(r, a.emit_overrides)
    if a.max_overlap is not None and r["overlap_total"] > a.max_overlap:
        print(f"\nFAIL: overlap {r['overlap_total']} > threshold {a.max_overlap}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
