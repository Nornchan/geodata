#!/usr/bin/env python3
"""
audit_ruleset.py — detect rule-priority inversion in a mihomo/Clash rule chain.

geosite conflicts are only half the problem. The other half is ordering. Rules
are evaluated top to bottom and the first match wins, so a broad DIRECT rule
placed above a narrow PROXY rule silently cancels it. The proxy rule is still in
the config, still updating daily, and doing nothing.

This tool takes the DIRECT-routed list and one or more PROXY-routed lists (in the
order they appear in `rules:`) and reports exactly which domains you believe you
are proxying but are in fact sending out on the user's real IP.

Usage
  python3 tools/audit_ruleset.py --direct direct.txt --proxy gfw.txt proxy.txt
  python3 tools/audit_ruleset.py --direct direct.txt --proxy gfw.txt --list
"""
import argparse
import re
import sys


def load(path):
    """Read a Clash rule-provider payload or a plain domain list."""
    out = set()
    for line in open(path, encoding="utf-8", errors="replace"):
        s = line.strip()
        if not s or s.startswith("#") or s == "payload:":
            continue
        s = re.sub(r"^-\s*", "", s).strip().strip("'\"")
        if not s or s.endswith(":"):
            continue
        out.add(s[2:] if s.startswith("+.") else s.lstrip("."))
    return out


def shadowed(lower, upper):
    """Entries in `lower` that a rule in `upper` will match first."""
    exact = lower & upper
    broad = set()
    for d in lower - exact:
        parts = d.split(".")
        for i in range(1, len(parts)):
            if ".".join(parts[i:]) in upper:
                broad.add(d)
                break
    return exact, broad


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--direct", required=True,
                    help="the list routed to DIRECT (the earlier/broader rule)")
    ap.add_argument("--proxy", required=True, nargs="+",
                    help="one or more lists routed to a proxy (the later rules)")
    ap.add_argument("--list", action="store_true", help="print every affected domain")
    ap.add_argument("--max", type=int, default=None, help="exit 1 if total exceeds this")
    a = ap.parse_args()

    direct = load(a.direct)
    print(f"DIRECT list: {a.direct}  ({len(direct):,} entries)\n")

    total = 0
    for p in a.proxy:
        s = load(p)
        e, b = shadowed(s, direct)
        n = len(e) + len(b)
        total += n
        print(f"{p}  ({len(s):,} entries)")
        print(f"    pre-empted by the earlier DIRECT rule: {n}"
              f"   (exact {len(e)}, swallowed by broader suffix {len(b)})")
        show = sorted(e | b)
        if show:
            print("    e.g. " + ", ".join(show[:8]))
            if a.list:
                for d in show:
                    print(f"       {d}")
        print()

    print(f"TOTAL domains intended for PROXY that will route DIRECT: {total}")
    if total:
        print("\nFix: move the PROXY rule-sets ABOVE the DIRECT rule-set in `rules:`,")
        print("or place overrides/force-proxy.yaml first so it pre-empts both.")
    if a.max is not None and total > a.max:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
