"""
Minimal MaxMind DB (MMDB) writer — stdlib only.

Enough of the format to emit a correct GeoIP2-Country database from a set of
disjoint networks sharing a small number of record values. Written rather than
pulled in as a dependency for the same reason as geoparse.py: the toolchain that
rebuilds your routing data should not itself widen the supply chain.

Layout produced:
    [binary search tree] [16 zero bytes] [data section]
    [\xab\xcd\xefMaxMind.com] [metadata]

Tree: `node_count` nodes, two records each, `record_size` bits per record.
    record <  node_count            -> index of the next node
    record == node_count            -> no data
    record >  node_count            -> (record - node_count - 16) is a data offset

IPv4 networks are stored inside the IPv6 tree under ::/96, which is where
readers of an ip_version 6 database look for them.
"""
import struct

DATA_SEPARATOR = b"\x00" * 16
METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"


class Typed:
    """Force a specific MMDB integer type. The metadata section mandates exact
    types per field (node_count is uint32 even when it fits in uint16), so they
    cannot be inferred from magnitude."""
    __slots__ = ("type_id", "value")

    def __init__(self, type_id, value):
        self.type_id, self.value = type_id, value

    def __repr__(self):
        return f"Typed({self.type_id},{self.value})"


def U16(v): return Typed(5, v)
def U32(v): return Typed(6, v)
def U64(v): return Typed(9, v)


# ---------------------------------------------------------------- encoding ---
def _ctrl(type_id, size):
    out = bytearray()
    if size < 29:
        sz, extra = size, b""
    elif size < 285:
        sz, extra = 29, bytes([size - 29])
    elif size < 65821:
        sz, extra = 30, (size - 285).to_bytes(2, "big")
    else:
        sz, extra = 31, (size - 65821).to_bytes(3, "big")
    if type_id <= 7:
        out.append((type_id << 5) | sz)
    else:
        out.append(sz)                       # type 0 => extended
        out.append(type_id - 7)
    return bytes(out) + extra


def enc(value):
    """Encode a Python value into MMDB data-section bytes."""
    if isinstance(value, Typed):
        v = value.value
        b = v.to_bytes((v.bit_length() + 7) // 8, "big").lstrip(b"\x00") if v else b""
        return _ctrl(value.type_id, len(b)) + b
    if isinstance(value, str):
        b = value.encode("utf-8")
        return _ctrl(2, len(b)) + b
    if isinstance(value, bool):
        return _ctrl(14, 1 if value else 0)
    if isinstance(value, int):
        if value < 0:
            b = value.to_bytes(4, "big", signed=True)
            return _ctrl(8, len(b)) + b
        b = value.to_bytes((value.bit_length() + 7) // 8 or 0, "big")
        b = b.lstrip(b"\x00")
        if value <= 0xFFFF:
            return _ctrl(5, len(b)) + b      # uint16
        if value <= 0xFFFFFFFF:
            return _ctrl(6, len(b)) + b      # uint32
        return _ctrl(9, len(b)) + b          # uint64
    if isinstance(value, float):
        return _ctrl(3, 8) + struct.pack(">d", value)
    if isinstance(value, bytes):
        return _ctrl(4, len(value)) + value
    if isinstance(value, dict):
        out = _ctrl(7, len(value))
        for k, v in value.items():
            out += enc(k) + enc(v)
        return out
    if isinstance(value, (list, tuple)):
        out = _ctrl(11, len(value))
        for v in value:
            out += enc(v)
        return out
    raise TypeError(f"cannot encode {type(value)}")


# -------------------------------------------------------------------- tree ---
class _Tree:
    def __init__(self):
        self.nodes = [[None, None]]

    def insert(self, key_int, depth, data_key):
        """key_int: 128-bit network address. depth: prefix length in the 128-bit tree."""
        idx = 0
        for i in range(depth):
            bit = (key_int >> (127 - i)) & 1
            if i == depth - 1:
                self.nodes[idx][bit] = ("data", data_key)
                return
            cur = self.nodes[idx][bit]
            if cur is None:
                self.nodes.append([None, None])
                self.nodes[idx][bit] = ("node", len(self.nodes) - 1)
                idx = len(self.nodes) - 1
            elif cur[0] == "node":
                idx = cur[1]
            else:
                return                        # already covered by a broader network


def write_mmdb(networks, path, database_type="GeoIP2-Country",
               languages=("en",), description=None, build_epoch=None,
               record_size=24, ip_version=6):
    """
    networks: iterable of (ipaddress network, python value)
    Values are deduplicated, so many networks sharing one record cost one copy.
    """
    import ipaddress, time
    description = description or {"en": database_type}
    build_epoch = int(build_epoch if build_epoch is not None else time.time())

    tree = _Tree()
    data_values, order = {}, []
    for net, value in networks:
        vkey = repr(value)
        if vkey not in data_values:
            data_values[vkey] = value
            order.append(vkey)
        if net.version == 4:
            # MaxMind readers locate the IPv4 subtree by walking 96 ZERO bits,
            # i.e. IPv4 lives under ::/96 (IPv4-compatible), not under
            # ::ffff:0:0/96 (IPv4-mapped). Using the mapped prefix produces a
            # file that opens cleanly but in which no IPv4 lookup ever matches.
            key = int(net.network_address)
            depth = 96 + net.prefixlen
        else:
            key = int(net.network_address)
            depth = net.prefixlen
        tree.insert(key, depth, vkey)

    # data section, with offsets
    data, offsets = bytearray(), {}
    for vkey in order:
        offsets[vkey] = len(data)
        data += enc(data_values[vkey])

    node_count = len(tree.nodes)
    max_record = (1 << record_size) - 1
    rec_bytes = record_size // 8

    def resolve(rec):
        if rec is None:
            return node_count
        if rec[0] == "node":
            return rec[1]
        v = node_count + 16 + offsets[rec[1]]
        if v > max_record:
            raise ValueError("record_size too small for this data section")
        return v

    tree_buf = bytearray()
    if record_size == 24:
        for left, right in tree.nodes:
            tree_buf += resolve(left).to_bytes(3, "big") + resolve(right).to_bytes(3, "big")
    elif record_size == 32:
        for left, right in tree.nodes:
            tree_buf += resolve(left).to_bytes(4, "big") + resolve(right).to_bytes(4, "big")
    elif record_size == 28:
        for left, right in tree.nodes:
            l, r = resolve(left), resolve(right)
            tree_buf += bytes([(l >> 16) & 0xFF, (l >> 8) & 0xFF, l & 0xFF,
                               ((l >> 24) & 0x0F) << 4 | ((r >> 24) & 0x0F),
                               (r >> 16) & 0xFF, (r >> 8) & 0xFF, r & 0xFF])
    else:
        raise ValueError("record_size must be 24, 28 or 32")

    # Field types here are mandated by the MMDB specification.
    meta = enc({
        "node_count": U32(node_count),
        "record_size": U16(record_size),
        "ip_version": U16(ip_version),
        "database_type": database_type,
        "languages": list(languages),
        "binary_format_major_version": U16(2),
        "binary_format_minor_version": U16(0),
        "build_epoch": U64(build_epoch),
        "description": description,
    })

    with open(path, "wb") as f:
        f.write(bytes(tree_buf) + DATA_SEPARATOR + bytes(data) + METADATA_MARKER + meta)
    return {"node_count": node_count, "record_size": record_size,
            "data_bytes": len(data), "tree_bytes": len(tree_buf)}
