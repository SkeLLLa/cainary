"""Generates sig-v1.json, the golden vectors for canonical encoding v1 and signing.

Stdlib only; independent of the Rust implementation. Run from anywhere:

    python3 -I crates/cainary-sig/tests/vectors/gen.py

It rewrites sig-v1.json next to this script. The Rust test `vectors_match` (and later the Swift
tests) re-encode every case and compare with `encoding_hex` / `digest_hex`.

Rejection cases carry `expect_error` ("duplicate-key" | "too-deep" | "too-large") instead of
`encoding_hex`. `{"t":"bytes_repeat","byte":"00","count":N}` is N copies of one byte (keeps the
JSON small). A case whose encoding is too big to inline has `encoding_hex` null and
`encoding_len` / `encoding_sha256_hex` instead. Map keys compare as exact UTF-8 bytes, with no
Unicode normalization.

Case: {name, key_hex (null: encode-only), domain (null: encode `fields` as a bare Map item),
fields (typed), encoding_hex, digest_hex}. With a domain, `encoding_hex` is the full message
List["cainary-sig", u64 1, domain, Map fields] and `digest_hex` is HMAC-SHA256(key, message).
"""
import hashlib
import hmac
import json
import os
import struct


def item(tag, payload):
    return bytes([tag]) + struct.pack(">I", len(payload)) + payload


def enc(t):
    k = t["t"]
    if k == "absent":
        return item(0, b"")
    if k == "null":
        return item(1, b"")
    if k == "bool":
        return item(2, b"\x01" if t["v"] else b"\x00")
    if k == "u64":
        return item(3, struct.pack(">Q", int(t["v"])))
    if k == "i64":
        return item(4, struct.pack(">q", int(t["v"])))
    if k == "bytes":
        return item(5, bytes.fromhex(t["v"]))
    if k == "bytes_repeat":
        return item(5, bytes.fromhex(t["byte"]) * t["count"])
    if k == "str":
        return item(6, t["v"].encode("utf-8"))
    if k == "list":
        return item(7, b"".join(enc(x) for x in t["v"]))
    if k == "map":
        pairs = sorted(((key.encode("utf-8"), v) for key, v in t["v"]), key=lambda p: p[0])
        assert len({p[0] for p in pairs}) == len(pairs), "duplicate key"
        return item(8, b"".join(item(6, key) + enc(v) for key, v in pairs))
    raise ValueError(k)


def s(v):
    return {"t": "str", "v": v}


def u(v):
    return {"t": "u64", "v": str(v)}


def m(*pairs):
    return {"t": "map", "v": [[k, v] for k, v in pairs]}


KEY_A = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
KEY_B = "ab" * 32

cases = [
    ("absent", None, None, {"t": "absent"}),
    ("null", None, None, {"t": "null"}),
    ("bool", None, None, {"t": "list", "v": [{"t": "bool", "v": False}, {"t": "bool", "v": True}]}),
    ("u64-max", None, None, u(18446744073709551615)),
    ("i64-negative", None, None, {"t": "list", "v": [
        {"t": "i64", "v": "-5"}, {"t": "i64", "v": "-9223372036854775808"},
        {"t": "i64", "v": "9223372036854775807"}]}),
    ("bytes-and-str", None, None, {"t": "list", "v": [
        {"t": "bytes", "v": "00ff10"}, {"t": "bytes", "v": ""}, s(""), s("héllo ☃")]}),
    ("absent-vs-null-in-list", None, None, {"t": "list", "v": [
        {"t": "absent"}, {"t": "null"}]}),
    ("empty-map", None, None, m()),
    ("map-sorted-non-ascii", None, None, m(
        ("zeta", u(1)), ("é", u(2)), ("alpha", u(3)), ("Z", u(4)), ("中", u(5)),
        ("\U0001f600", u(6)), ("a", u(7)))),
    ("nested-list-map", None, None, m(
        ("items", {"t": "list", "v": [m(("b", u(1)), ("a", {"t": "null"})), {"t": "list", "v": []},
                                      {"t": "absent"}]}),
        ("flag", {"t": "bool", "v": True}))),
    ("sign-empty-fields-key-id", KEY_A, "key-id/v1", m()),
    ("sign-value-at-location", KEY_A, "alert/value-at-location/v1", m(
        ("service", s("claude-code")), ("signal", s("logs")), ("event", s("tool_result")),
        ("attribute", s("tool_parameters")), ("where", s("body")),
        ("pattern", s("p-aws")), ("match", s("AKIAIOSFODNN7EXAMPLE")))),
    ("sign-unsorted-nested", KEY_B, "otel-shape/v1", m(
        ("version", u(2)), ("paths", {"t": "list", "v": [
            m(("path", s("resource/service.name")), ("type", s("str"))),
            m(("path", s("record/é")), ("type", {"t": "absent"}))]}),
        ("count", {"t": "i64", "v": "-1"}))),
]




def nest(depth):
    v = {"t": "null"}
    for _ in range(depth - 1):
        v = {"t": "list", "v": [v]}
    return v


cases += [
    ("map-composed-and-decomposed-keys", None, None, m(
        ("\u0065\u0301", u(2)), ("\u00e9", u(1)), ("e", u(0)))),
    ("depth-32-accepted", None, None, nest(32)),
    ("bytes-at-size-limit-accepted", None, None,
     {"t": "bytes_repeat", "byte": "00", "count": 1048576 - 5}),
]
errors = [
    ("duplicate-key-rejected", m(("a", u(1)), ("b", u(2)), ("a", {"t": "null"})), "duplicate-key"),
    ("duplicate-nested-key-rejected", {"t": "list", "v": [m(("k", u(1)), ("k", u(1)))]},
     "duplicate-key"),
    ("depth-33-rejected", nest(33), "too-deep"),
    ("size-just-over-limit-rejected", {"t": "bytes_repeat", "byte": "00", "count": 1048576 - 4},
     "too-large"),
    ("size-over-1mib-rejected", {"t": "bytes_repeat", "byte": "00", "count": 1048577},
     "too-large"),
]

out = []
for name, key, domain, fields in cases:
    if domain is None:
        encoding = enc(fields)
        digest = None
    else:
        encoding = enc({"t": "list", "v": [s("cainary-sig"), u(1), s(domain), fields]})
        digest = hmac.new(bytes.fromhex(key), encoding, hashlib.sha256).hexdigest()
    case = {"name": name, "key_hex": key, "domain": domain, "fields": fields}
    if len(encoding) > 4096:
        case.update({"encoding_hex": None, "encoding_len": len(encoding),
                     "encoding_sha256_hex": hashlib.sha256(encoding).hexdigest()})
    else:
        case["encoding_hex"] = encoding.hex()
    case["digest_hex"] = digest
    out.append(case)
for name, fields, err in errors:
    out.append({"name": name, "key_hex": None, "domain": None, "fields": fields,
                "expect_error": err})

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sig-v1.json")
with open(path, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=1, ensure_ascii=False)
    f.write("\n")
