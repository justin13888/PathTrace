#!/usr/bin/env python3
"""Independent PTF 1.x reader (1.0 to 1.2), written only from docs/design/ptf-format.md (REQ-FMT-018).

Every 1.1 and 1.2 addition is a non-critical table, column or head key, so the generic reading
below covers them: heads are decoded as whole CBOR maps, tables and columns by name, and
nullability comes from each column.

Pure Python 3.14 standard library (compression.zstd); CRC32C and BLAKE3 are implemented here
from their published specifications, so nothing is shared with the Rust implementation.

Usage:
    python3 -I ptf.py check FILE...          # exit 0 if all valid
    python3 -I ptf.py conformance DIR        # run DIR/expected.json against DIR/*.ptf
    python3 -I ptf.py summary FILE           # sections, tables, rows, digest
"""

import json
import os
import struct
import sys
from compression import zstd

MAGIC = bytes([0x89, 0x50, 0x54, 0x46, 0x0D, 0x0A, 0x1A, 0x0A])
KNOWN = {b"META", b"FLOW", b"CLOK", b"OBSV", b"CTXS", b"EVNT", b"PLCY", b"PATH", b"SERS", b"VALD", b"INDX"}
CRITICAL, ZSTD, DERIVED = 1, 2, 4
MAX_DEPTH = 32
MAX_SECTION = 1 << 30
MAX_TOTAL = 4 << 30


class PtfError(Exception):
    """kind matches the error kinds used by the conformance corpus."""

    def __init__(self, kind, msg):
        super().__init__(f"{kind}: {msg}")
        self.kind = kind


# ---------------------------------------------------------------- CRC32C (Castagnoli)
def _crc_table():
    poly = 0x82F63B78  # reflected 0x1EDC6F41
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ poly if c & 1 else c >> 1
        t.append(c)
    return t


_CRC = _crc_table()


def crc32c(data):
    c = 0xFFFFFFFF
    t = _CRC
    for b in data:
        c = t[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


# ---------------------------------------------------------------- BLAKE3 (hash mode)
_IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
CHUNK_START, CHUNK_END, PARENT, ROOT = 1, 2, 4, 8
M32 = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def _g(s, a, b, c, d, mx, my):
    s[a] = (s[a] + s[b] + mx) & M32
    s[d] = _rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M32
    s[b] = _rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + my) & M32
    s[d] = _rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M32
    s[b] = _rotr(s[b] ^ s[c], 7)


def _compress(cv, block, counter, blen, flags):
    m = list(struct.unpack("<16I", block))
    s = list(cv) + _IV[:4] + [counter & M32, (counter >> 32) & M32, blen, flags]
    for r in range(7):
        _g(s, 0, 4, 8, 12, m[0], m[1])
        _g(s, 1, 5, 9, 13, m[2], m[3])
        _g(s, 2, 6, 10, 14, m[4], m[5])
        _g(s, 3, 7, 11, 15, m[6], m[7])
        _g(s, 0, 5, 10, 15, m[8], m[9])
        _g(s, 1, 6, 11, 12, m[10], m[11])
        _g(s, 2, 7, 8, 13, m[12], m[13])
        _g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[i] for i in _PERM]
    return [s[i] ^ s[i + 8] for i in range(8)] + [s[i + 8] ^ cv[i] for i in range(8)]


def _chunk_output(chunk, counter):
    """Return (cv_in, last_block, counter, blen, flags) for the chunk's final compression."""
    cv = list(_IV)
    blocks = [chunk[i:i + 64] for i in range(0, max(len(chunk), 1), 64)] or [b""]
    for i, blk in enumerate(blocks):
        flags = (CHUNK_START if i == 0 else 0)
        if i == len(blocks) - 1:
            return cv, blk.ljust(64, b"\0"), counter, len(blk), flags | CHUNK_END
        cv = _compress(cv, blk, counter, 64, flags)[:8]
    raise AssertionError("unreachable")


def blake3(data):
    chunks = [data[i:i + 1024] for i in range(0, len(data), 1024)] or [b""]
    stack = []
    for idx, ch in enumerate(chunks):
        out = _chunk_output(ch, idx)
        if idx == len(chunks) - 1:
            break
        cv = _compress(*out)[:8]
        total = idx + 1
        while total & 1 == 0:
            left = stack.pop()
            cv = _compress(_IV, struct.pack("<16I", *(left + cv)), 0, 64, PARENT)[:8]
            total >>= 1
        stack.append(cv)
    # Finalise: merge the last chunk with the stack, root flag on the final compression.
    cv_in, blk, counter, blen, flags = out
    while stack:
        cv = _compress(cv_in, blk, counter, blen, flags)[:8]
        left = stack.pop()
        cv_in, blk, counter, blen, flags = _IV, struct.pack("<16I", *(left + cv)), 0, 64, PARENT
    words = _compress(cv_in, blk, counter, blen, flags | ROOT)
    return struct.pack("<8I", *words[:8]).hex()


# ---------------------------------------------------------------- deterministic CBOR (§4)
class _Cbor:
    def __init__(self, b):
        self.b, self.p = b, 0

    def take(self, n):
        if len(self.b) - self.p < n:
            raise PtfError("cbor", "truncated")
        v = self.b[self.p:self.p + n]
        self.p += n
        return v

    def head(self):
        ib = self.take(1)[0]
        major, ai = ib >> 5, ib & 31
        if ai < 24:
            arg = ai
        elif ai == 24:
            arg = self.take(1)[0]
        elif ai == 25:
            arg = struct.unpack(">H", self.take(2))[0]
        elif ai == 26:
            arg = struct.unpack(">I", self.take(4))[0]
        elif ai == 27:
            arg = struct.unpack(">Q", self.take(8))[0]
        else:
            raise PtfError("cbor", f"additional info {ai} not allowed")
        if major != 7:
            shortest = {True: ai < 24}[True] if arg < 24 else (ai == 24 if arg < 256 else ai == 25 if arg < 65536 else ai == 26 if arg < 2**32 else ai == 27)
            if not shortest:
                raise PtfError("cbor", "non-shortest integer")
        return major, ai, arg

    def value(self, depth=0):
        major, ai, arg = self.head()
        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major == 2:
            return bytes(self.take(arg))
        if major == 3:
            try:
                return self.take(arg).decode("utf-8")
            except UnicodeDecodeError:
                raise PtfError("cbor", "invalid utf-8")
        if major in (4, 5):
            if depth >= MAX_DEPTH:
                raise PtfError("cbor", "too deep")
            if arg > len(self.b) - self.p:
                raise PtfError("cbor", "length exceeds input")
            if major == 4:
                return [self.value(depth + 1) for _ in range(arg)]
            out, prev = {}, None
            for _ in range(arg):
                kstart = self.p
                kmaj, _, klen = self.head()
                if kmaj != 3:
                    raise PtfError("cbor", "map keys must be text")
                key = self.take(klen).decode("utf-8")
                enc = self.b[kstart:self.p]
                if prev is not None and (len(enc), enc) <= (len(prev), prev):
                    raise PtfError("cbor", "map keys not in canonical order")
                prev = bytes(enc)
                out[key] = self.value(depth + 1)
            return out
        if major == 6:
            raise PtfError("cbor", "tags not allowed")
        if ai == 20:
            return False
        if ai == 21:
            return True
        if ai == 22:
            return None
        if ai == 27:
            f = struct.unpack(">d", struct.pack(">Q", arg))[0]
            if f != f and arg != 0x7FF8000000000000:
                raise PtfError("cbor", "non-canonical NaN")
            return f
        raise PtfError("cbor", "simple value not allowed")


def cbor_decode(b):
    d = _Cbor(b)
    v = d.value()
    if d.p != len(b):
        raise PtfError("cbor", "trailing bytes")
    return v


# ---------------------------------------------------------------- columns (§5)
def leb(b, p):
    v, shift = 0, 0
    while True:
        if p >= len(b):
            raise PtfError("column", "truncated LEB128")
        x = b[p]
        p += 1
        v |= (x & 0x7F) << shift
        if x & 0x80 == 0:
            if x == 0 and shift > 0:
                raise PtfError("column", "overlong LEB128")
            if v >= 1 << 64:
                raise PtfError("column", "LEB128 overflow")
            return v, p
        shift += 7
        if shift > 63:
            raise PtfError("column", "LEB128 overflow")


def unzig(u):
    return (u >> 1) ^ -(u & 1)


def s64(x):
    x &= (1 << 64) - 1
    return x - (1 << 64) if x >= 1 << 63 else x


def decode_values(typ, enc, b, n):
    p = 0
    if enc == "plain":
        if len(b) != 8 * n:
            raise PtfError("column", "plain length")
        fmt = {"u64": "<Q", "i64": "<q", "f64": "<d"}.get(typ)
        if fmt is None:
            raise PtfError("column", "plain on bool")
        return [struct.unpack_from(fmt, b, 8 * i)[0] for i in range(n)]
    if enc == "bitmap":
        if typ != "bool" or len(b) != (n + 7) // 8:
            raise PtfError("column", "bitmap length")
        if n % 8 and b[-1] >> (n % 8):
            raise PtfError("column", "bitmap padding")
        return [bool(b[i // 8] >> (i % 8) & 1) for i in range(n)]
    if typ not in ("u64", "i64"):
        raise PtfError("column", f"{enc} on {typ}")
    out = []
    if enc == "varint":
        for _ in range(n):
            u, p = leb(b, p)
            out.append(unzig(u) if typ == "i64" else u)
    elif enc == "delta":
        prev = 0
        for _ in range(n):
            u, p = leb(b, p)
            prev = s64(prev + unzig(u))
            out.append(prev)
    elif enc == "delta2":
        prev = prev_d = 0
        for i in range(n):
            u, p = leb(b, p)
            e = unzig(u)
            if i == 0:
                x = e
            else:
                prev_d = s64(prev_d + e)
                x = s64(prev + prev_d)
            prev = x
            out.append(x)
    elif enc == "rle":
        while len(out) < n:
            u, p = leb(b, p)
            r, p = leb(b, p)
            val = unzig(u)
            if r == 0 or r > n - len(out):
                raise PtfError("column", "bad run")
            if out and out[-1] == s64(val):
                raise PtfError("column", "non-canonical runs")
            out.extend([s64(val)] * r)
    else:
        raise PtfError("column", f"unknown encoding {enc}")
    if p != len(b):
        raise PtfError("column", "trailing bytes in column")
    if typ == "u64":
        out = [x & ((1 << 64) - 1) for x in out]
    return out


def decode_payload(payload):
    if len(payload) < 4:
        raise PtfError("schema", "payload shorter than head length")
    hl = struct.unpack_from("<I", payload)[0]
    if hl > len(payload) - 4:
        raise PtfError("schema", "head length exceeds payload")
    head = cbor_decode(payload[4:4 + hl])
    if not isinstance(head, dict):
        raise PtfError("schema", "head is not a map")
    p = 4 + hl
    tables = []
    for t in head.pop("tables", []) or []:
        rows = t["rows"]
        cols = {}
        for c in t["columns"]:
            blob = payload[p:p + c["len"]]
            if len(blob) != c["len"]:
                raise PtfError("column", "blob exceeds payload")
            p += c["len"]
            typ, enc = c["type"], c["enc"]
            if typ not in ("u64", "i64", "f64", "bool") or enc not in ("plain", "varint", "delta", "delta2", "rle", "bitmap"):
                cols[c["name"]] = None  # unknown: skip (spec P6)
                continue
            valid = None
            q = 0
            if c.get("nullable", False):
                nb = (rows + 7) // 8
                if len(blob) < nb:
                    raise PtfError("column", "validity truncated")
                valid = [bool(blob[i // 8] >> (i % 8) & 1) for i in range(rows)]
                q = nb
            n = rows if valid is None else sum(valid)
            vals = iter(decode_values(typ, enc, blob[q:], n))
            cols[c["name"]] = [next(vals) if (valid is None or valid[i]) else None for i in range(rows)]
        tables.append({"name": t["name"], "rows": rows, "attrs": t.get("attrs"), "columns": cols})
    if p != len(payload):
        raise PtfError("schema", "trailing bytes after column blobs")
    return head, tables


# ---------------------------------------------------------------- container (§1, §2, §8)
def read(data):
    if len(data) < 16:
        raise PtfError("bad_magic" if len(data) >= 8 and data[:8] != MAGIC else "truncated", "short file")
    if data[:8] != MAGIC:
        raise PtfError("bad_magic", "not PTF")
    major, minor, fflags = struct.unpack_from("<HHI", data, 8)
    if major != 1:
        raise PtfError("unsupported_major", f"major {major}")
    if fflags:
        raise PtfError("reserved", "file flags")
    pos, sections, index, total = 16, [], None, 0
    digest = bytearray()
    while pos < len(data):
        start = pos
        if len(data) - pos < 16:
            raise PtfError("truncated", f"at {pos}")
        typ = data[pos:pos + 4]
        sflags, reserved, length = struct.unpack_from("<HHQ", data, pos + 4)
        if length > len(data) - pos - 20:
            raise PtfError("truncated", f"at {pos}")
        end = pos + 16 + length + 4
        if crc32c(data[pos:end - 4]) != struct.unpack_from("<I", data, end - 4)[0]:
            raise PtfError("crc", f"at {pos}")
        if not all(chr(c).isupper() or chr(c).isdigit() for c in typ):
            raise PtfError("schema", "bad type")
        critical = sflags & CRITICAL
        known = typ in KNOWN
        if critical and not known:
            raise PtfError("unknown_critical", typ.decode())
        unknown_bits = (sflags & ~7) != 0 or reserved != 0
        if unknown_bits and critical:
            raise PtfError("reserved", "flag bits on critical section")
        stored = data[pos + 16:pos + 16 + length]
        if index is not None:
            raise PtfError("order", "INDX must be last")
        if unknown_bits:
            payload = stored
        elif sflags & ZSTD:
            declared = struct.unpack_from("<Q", stored)[0]
            if declared > MAX_SECTION:
                raise PtfError("limit", "declared size")
            total += declared
            if total > MAX_TOTAL:
                raise PtfError("limit", "total size")
            try:
                payload = zstd.decompress(stored[8:])
            except zstd.ZstdError as e:
                raise PtfError("compression", str(e))
            if len(payload) != declared:
                raise PtfError("compression", "size mismatch")
        else:
            payload = stored
        if typ == b"INDX":
            index = (start, cbor_decode(payload[4:4 + struct.unpack_from("<I", payload)[0]]))
        else:
            if not sections and typ != b"META":
                raise PtfError("order", "META first")
            if sections and typ == b"META":
                raise PtfError("order", "META once")
            body = None
            if not unknown_bits:
                try:
                    body = decode_payload(payload)
                except PtfError:
                    if known:
                        raise
            sections.append({"type": typ.decode(), "flags": sflags & ~ZSTD, "body": body})
            digest += typ + struct.pack("<HQ", sflags & ~ZSTD, len(payload)) + payload
        pos = end
    if not sections:
        raise PtfError("order", "no META")
    content = blake3(bytes(digest))
    if index is not None:
        off, head = index
        if head.get("file_blake3") != blake3(data[:off]):
            raise PtfError("schema", "INDX file hash")
        if head.get("content_digest") != content:
            raise PtfError("schema", "INDX content digest")
    return {"major": major, "minor": minor, "sections": sections, "content_digest": content, "index": index is not None}


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "check":
        ok = True
        for f in argv[2:]:
            try:
                r = read(open(f, "rb").read())
                print(f"valid {f} sections={len(r['sections'])} digest={r['content_digest']}")
            except PtfError as e:
                ok = False
                print(f"invalid {f} {e}")
        return 0 if ok else 1
    if cmd == "summary":
        r = read(open(argv[2], "rb").read())
        for s in r["sections"]:
            tabs = [(t["name"], t["rows"]) for t in (s["body"][1] if s["body"] else [])]
            print(s["type"], tabs)
        print("content_digest", r["content_digest"])
        return 0
    if cmd == "conformance":
        d = argv[2]
        expected = json.load(open(os.path.join(d, "expected.json")))
        fails = 0
        for name, exp in sorted(expected.items()):
            data = open(os.path.join(d, name), "rb").read()
            try:
                r = read(data)
                got = {"valid": True, "content_digest": r["content_digest"]}
            except PtfError as e:
                got = {"valid": False, "kind": e.kind}
            ok = got["valid"] == exp["valid"] and (got.get("kind") == exp.get("kind") if not exp["valid"] else got["content_digest"] == exp["content_digest"])
            fails += not ok
            print(("PASS" if ok else "FAIL"), name, got)
        print(f"{len(expected) - fails}/{len(expected)} conformance cases pass")
        return 0 if fails == 0 else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
