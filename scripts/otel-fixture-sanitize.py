#!/usr/bin/env python3
"""Reduce captured OTLP/JSON dumps to structure-only fixtures.

Usage: python3 -I scripts/otel-fixture-sanitize.py OUT_DIR DUMP.json [DUMP.json ...]

Dumps whose file name contains "codex" are grouped as vendor "codex", all others as
"claude-code". Per vendor and signal the dumps are merged into one OTLP/JSON document
(OUT_DIR/<vendor>/logs.json or metrics.json) where each distinct
(scope, event name, attribute key set) or (scope, metric, type, data-point key set)
appears once. Every attribute value becomes a typed placeholder; only a small
allowlist of constants (service.name, service.version, event.name) keeps its value,
and only when it matches a strict pattern.
"""
import json
import os
import re
import sys

KEEP = {
    "service.name": re.compile(r"^[a-z][a-z0-9_.-]{0,40}$"),
    "service.version": re.compile(r"^\d+\.\d+\.\d+$"),
    "event.name": re.compile(r"^[a-z][a-z0-9_.]{0,80}$"),
}
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
EVENT_BODY = KEEP["event.name"]
STR = {"stringValue": "<string>"}


def jd(x):
    return json.dumps(x, sort_keys=True)


def placeholder(v):
    """Typed placeholder with the same OTLP JSON value shape."""
    if "intValue" in v:
        return {"intValue": "0"}
    if "doubleValue" in v:
        return {"doubleValue": 0}
    if "boolValue" in v:
        return {"boolValue": False}
    if "bytesValue" in v:
        return {"bytesValue": ""}
    if "arrayValue" in v:
        items = {jd(placeholder(x)): placeholder(x) for x in v["arrayValue"].get("values", [])}
        return {"arrayValue": {"values": [items[k] for k in sorted(items)]}}
    if "kvlistValue" in v:
        return {"kvlistValue": {"values": attrs_ph(v["kvlistValue"].get("values", []))}}
    return dict(STR)


def attrs_ph(attrs, keep_constants=False):
    out = {}
    for a in attrs or []:
        k, v = a["key"], a.get("value", {})
        pat = KEEP.get(k)
        if keep_constants and pat and isinstance(v.get("stringValue"), str) and pat.match(v["stringValue"]):
            ph = {"stringValue": v["stringValue"]}
        else:
            ph = placeholder(v)
        if k not in out or jd(ph) < jd(out[k]):
            out[k] = ph
    return [{"key": k, "value": out[k]} for k in sorted(out)]


def attr_str(attrs, key):
    for a in attrs or []:
        if a["key"] == key:
            return a.get("value", {}).get("stringValue")
    return None


def scope_ph(scope):
    ver = scope.get("version", "")
    if ver and not VERSION.match(ver):
        ver = "<string>"
    name = scope.get("name", "")
    return {"name": name, "version": ver}


class Merged:
    def __init__(self):
        self.res_attrs = {}  # key -> placeholder
        self.scopes = {}  # (name, version) -> {sig: item}
        self.schema = {}

    def add_resource(self, res):
        for a in attrs_ph(res.get("attributes"), keep_constants=True):
            cur = self.res_attrs.get(a["key"])
            if cur is None or jd(a["value"]) < jd(cur):
                self.res_attrs[a["key"]] = a["value"]

    def scope(self, scope):
        s = scope_ph(scope)
        return self.scopes.setdefault((s["name"], s["version"]), {})

    def doc(self, top, scopes_key, items_key):
        resource = {"attributes": [{"key": k, "value": self.res_attrs[k]} for k in sorted(self.res_attrs)]}
        scopes = []
        for (name, ver) in sorted(self.scopes):
            items = self.scopes[(name, ver)]
            scopes.append({
                "scope": {"name": name, "version": ver},
                items_key: [items[k] for k in sorted(items)],
            })
        return {top: [{"resource": resource, scopes_key: scopes}]}


def log_record(r, event):
    attrs = attrs_ph(r.get("attributes"), keep_constants=True)
    body = r.get("body")
    if body is None:
        b = None
    elif event and body.get("stringValue") in (event, "claude_code." + event):
        b = {"stringValue": body["stringValue"]}
    else:
        b = placeholder(body)
    rec = {"timeUnixNano": "0", "observedTimeUnixNano": "0"}
    if "severityNumber" in r:
        rec["severityNumber"] = r["severityNumber"]
    if "severityText" in r:
        rec["severityText"] = r["severityText"]
    if b is not None:
        rec["body"] = b
    rec["attributes"] = attrs
    rec["traceId"] = ""
    rec["spanId"] = ""
    return rec


def add_logs(m, dump):
    for rl in dump.get("resourceLogs", []):
        m.add_resource(rl.get("resource", {}))
        for sl in rl.get("scopeLogs", []):
            items = m.scope(sl.get("scope", {}))
            for r in sl.get("logRecords", []):
                ev = attr_str(r.get("attributes"), "event.name")
                if ev is None:
                    b = (r.get("body") or {}).get("stringValue")
                    ev = b if b and EVENT_BODY.match(b) else None
                if ev is not None and not EVENT_BODY.match(ev):
                    ev = None
                rec = log_record(r, ev)
                sig = jd([ev, [a["key"] for a in rec["attributes"]]])
                if sig not in items or jd(rec) < jd(items[sig]):
                    items[sig] = rec


def dp_ph(dp, kind):
    out = {"attributes": attrs_ph(dp.get("attributes")), "startTimeUnixNano": "0", "timeUnixNano": "0"}
    if kind == "histogram":
        out.update({"count": "0", "sum": 0, "bucketCounts": [], "explicitBounds": []})
    elif "asDouble" in dp:
        out["asDouble"] = 0
    else:
        out["asInt"] = "0"
    return out


def add_metrics(m, dump):
    for rm in dump.get("resourceMetrics", []):
        m.add_resource(rm.get("resource", {}))
        for sm in rm.get("scopeMetrics", []):
            items = m.scope(sm.get("scope", {}))
            for met in sm.get("metrics", []):
                kind = next((k for k in ("sum", "gauge", "histogram", "exponentialHistogram", "summary") if k in met), None)
                if kind is None:
                    continue
                body = met[kind]
                for dp in body.get("dataPoints", []):
                    p = dp_ph(dp, kind)
                    keys = [a["key"] for a in p["attributes"]]
                    sig = jd([met["name"], kind, keys])
                    inner = {"dataPoints": [p]}
                    if kind in ("sum", "histogram"):
                        inner["aggregationTemporality"] = body.get("aggregationTemporality", 0)
                    if kind == "sum":
                        inner["isMonotonic"] = body.get("isMonotonic", False)
                    item = {"name": met["name"], "description": met.get("description", ""),
                            "unit": met.get("unit", ""), kind: inner}
                    if sig not in items or jd(item) < jd(items[sig]):
                        items[sig] = item


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    out_dir, files = argv[1], argv[2:]
    groups = {}
    for f in sorted(files):
        vendor = "codex" if "codex" in os.path.basename(f) else "claude-code"
        with open(f, encoding="utf-8") as fh:
            dump = json.load(fh)
        if "resourceLogs" in dump:
            g = groups.setdefault((vendor, "logs"), Merged())
            add_logs(g, dump)
        elif "resourceMetrics" in dump:
            g = groups.setdefault((vendor, "metrics"), Merged())
            add_metrics(g, dump)
    for (vendor, sig), m in sorted(groups.items()):
        doc = m.doc("resourceLogs", "scopeLogs", "logRecords") if sig == "logs" else \
            m.doc("resourceMetrics", "scopeMetrics", "metrics")
        d = os.path.join(out_dir, vendor)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, sig + ".json"), "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, sort_keys=False)
            fh.write("\n")


if __name__ == "__main__":
    main(sys.argv)
