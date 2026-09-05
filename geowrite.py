"""
Protobuf writers for V2Ray/Xray `geosite.dat` and `geoip.dat`.

Counterpart to geoparse.py. Stdlib only, same reasoning: a toolchain for
auditing a supply chain should not enlarge it.

Wire format written here matches what geoparse.py reads:

    message Domain   { Type type = 1; string value = 2; }
                       Type: 0=Plain(keyword) 1=Regex 2=Domain(suffix) 3=Full(exact)
    message GeoSite  { string country_code = 1; repeated Domain domain = 2; }
    message GeoSiteList { repeated GeoSite entry = 1; }

    message CIDR     { bytes ip = 1; uint32 prefix = 2; }
    message GeoIP    { string country_code = 1; repeated CIDR cidr = 2; bool inverse_match = 3; }
    message GeoIPList { repeated GeoIP entry = 1; }
"""
import ipaddress

TYPE_ID = {"keyword": 0, "regexp": 1, "suffix": 2, "full": 3}


def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _tag(field, wire):
    return _varint((field << 3) | wire)


def _bytes_field(field, payload):
    return _tag(field, 2) + _varint(len(payload)) + payload


def _varint_field(field, value):
    return _tag(field, 0) + _varint(value)


def write_geosite(categories, path):
    """categories: {NAME: [(rule_type, value), ...]} -> writes geosite.dat"""
    out = bytearray()
    for code, rules in categories.items():
        entry = bytearray()
        entry += _bytes_field(1, code.encode("utf-8"))
        for item in rules:
            rtype, value = item[0], item[1]
            dom = bytearray()
            tid = TYPE_ID[rtype] if isinstance(rtype, str) else rtype
            if tid:                                  # omit field when 0 (proto3 default)
                dom += _varint_field(1, tid)
            dom += _bytes_field(2, value.encode("utf-8"))
            entry += _bytes_field(2, bytes(dom))
        out += _bytes_field(1, bytes(entry))
    with open(path, "wb") as f:
        f.write(bytes(out))
    return len(out)


def write_geoip(categories, path):
    """categories: {NAME: [cidr_str, ...]} or {NAME: ([cidr_str,...], inverse)}"""
    out = bytearray()
    for code, val in categories.items():
        cidrs, inverse = val if isinstance(val, tuple) else (val, False)
        entry = bytearray()
        entry += _bytes_field(1, code.encode("utf-8"))
        for c in cidrs:
            net = ipaddress.ip_network(c) if isinstance(c, str) else c
            cidr = bytearray()
            cidr += _bytes_field(1, net.network_address.packed)
            if net.prefixlen:
                cidr += _varint_field(2, net.prefixlen)
            entry += _bytes_field(2, bytes(cidr))
        if inverse:
            entry += _varint_field(3, 1)
        out += _bytes_field(1, bytes(entry))
    with open(path, "wb") as f:
        f.write(bytes(out))
    return len(out)
