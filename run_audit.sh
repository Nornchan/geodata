#!/usr/bin/env bash
# run_audit.sh — fetch geodata from a provider and audit it before you ship it.
#
#   ./tools/run_audit.sh                       # audit the mihomo default provider
#   ./tools/run_audit.sh loyalsoldier          # audit the v2ray-rules-dat provider
#   ./tools/run_audit.sh <geosite_url> <geoip_url>
#
# Exit status is non-zero when the database exceeds the configured conflict
# threshold, so this is usable directly as a release gate.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
WORK="${WORK:-$ROOT/.geodata-cache}"
MAX_OVERLAP="${MAX_OVERLAP:-0}"

case "${1:-metacubex}" in
  metacubex)
    GEOSITE="https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
    GEOIP="https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat" ;;
  loyalsoldier)
    GEOSITE="https://testingcf.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"
    GEOIP="https://testingcf.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat" ;;
  *)
    GEOSITE="$1"; GEOIP="${2:-}" ;;
esac

mkdir -p "$WORK"
echo "==> fetching $GEOSITE"
curl -fsSL --retry 3 --max-time 180 -o "$WORK/geosite.dat" "$GEOSITE"
sha256sum "$WORK/geosite.dat" 2>/dev/null || shasum -a 256 "$WORK/geosite.dat"

if [ -n "${GEOIP:-}" ]; then
  echo "==> fetching $GEOIP"
  curl -fsSL --retry 3 --max-time 180 -o "$WORK/geoip.dat" "$GEOIP"
  sha256sum "$WORK/geoip.dat" 2>/dev/null || shasum -a 256 "$WORK/geoip.dat"
fi

echo
python3 "$HERE/audit_geosite.py" "$WORK/geosite.dat" \
        --emit-overrides "$ROOT/overrides" \
        --max-overlap "$MAX_OVERLAP"
