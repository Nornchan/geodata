"""
Minimal, dependency-free decoder for V2Ray/Xray `geosite.dat` and `geoip.dat`.

These files are protobuf messages. Rather than pull in the protobuf runtime and
the upstream .proto definitions (themselves supply-chain surface), this module
walks the wire format directly. Stdlib only, ~80 lines, auditable in one sitting.

Schemas being decoded:

    message Domain   { Type type = 1; string value = 2; repeated Attribute attribute = 3; }
                       Type: 0=Plain(keyword) 1=Regex 2=Domain(suffix) 3=Full(exact)
    message GeoSite  { string country_code = 1; repeated Domain domain = 2; }
    message CIDR     { bytes ip = 1; uint32 prefix = 2; }
    message GeoIP    { string country_code = 1; repeated CIDR cidr = 2; bool inverse_match = 3; }
"""
import ipaddress

DOMAIN_TYPE = {0: "keyword", 1: "regexp", 2: "suffix", 3: "full"}


def _varint(b, i):
    r = s = 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7F) << s
        if not x & 0x80:
            return r, i
        s += 7


def fields(b, start=0, end=None):
    """Yield (field_number, wire_type, payload) for one protobuf message."""
    i, end = start, len(b) if end is None else end
    while i < end:
        key, i = _varint(b, i)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _varint(b, i)
            yield fn, wt, v
        elif wt == 2:
            ln, i = _varint(b, i)
            yield fn, wt, b[i:i + ln]
            i += ln
        elif wt == 5:
            yield fn, wt, b[i:i + 4]; i += 4
        elif wt == 1:
            yield fn, wt, b[i:i + 8]; i += 8
        else:
            raise ValueError(f"unsupported wire type {wt} at offset {i}")


def parse_geosite(path):
    """-> {CATEGORY: [(rule_type, value, (attributes,)), ...]}"""
    data = open(path, "rb").read()
    out = {}
    for fn, _, payload in fields(data):
        if fn != 1:
            continue
        code, domains = None, []
        for f2, _, p2 in fields(payload):
            if f2 == 1:
                code = p2.decode("utf-8", "replace")
            elif f2 == 2:
                dtype, val, attrs = 0, None, []
                for f3, _, p3 in fields(p2):
                    if f3 == 1:
                        dtype = p3
                    elif f3 == 2:
                        val = p3.decode("utf-8", "replace")
                    elif f3 == 3:
                        for f4, _, p4 in fields(p3):
                            if f4 == 1:
                                attrs.append(p4.decode("utf-8", "replace"))
                domains.append((DOMAIN_TYPE.get(dtype, str(dtype)), val, tuple(attrs)))
        out[code] = domains
    return out


def parse_geoip(path):
    """-> {COUNTRY: ([cidr_str, ...], inverse_match_bool)}"""
    data = open(path, "rb").read()
    out = {}
    for fn, _, payload in fields(data):
        if fn != 1:
            continue
        code, cidrs, inverse = None, [], False
        for f2, _, p2 in fields(payload):
            if f2 == 1:
                code = p2.decode("utf-8", "replace")
            elif f2 == 2:
                ip, pfx = None, 0
                for f3, _, p3 in fields(p2):
                    if f3 == 1:
                        ip = p3
                    elif f3 == 2:
                        pfx = p3
                if ip is not None:
                    a = (ipaddress.IPv4Address(bytes(ip)) if len(ip) == 4
                         else ipaddress.IPv6Address(bytes(ip)))
                    cidrs.append(f"{a}/{pfx}")
            elif f2 == 3:
                inverse = bool(p2)
        out[code] = (cidrs, inverse)
    return out
