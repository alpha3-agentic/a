
import json
import re
from pathlib import Path
from typing import Any, Optional, List, Dict, Union
from datetime import datetime

# ------------------- CONFIG -------------------
INPUT_DIR  = r"Training-DATA"
OUTPUT_DIR = r"Training-DATA-Normal"

# ------------------- HELPERS -------------------
def get_nested(obj: Any, path: str, default=None):
    cur = obj
    for raw in path.split("."):
        if cur is None:
            return default
        if raw.endswith("[]"):
            key = raw[:-2]
            if not isinstance(cur, dict) or key not in cur:
                return default
            lst = cur.get(key)
            if not isinstance(lst, list) or not lst:
                return default
            cur = lst[0]
        else:
            if isinstance(cur, dict) and raw in cur:
                cur = cur[raw]
            else:
                return default
    return cur

def is_empty(v: Any) -> bool:
    if v is None: return True
    if isinstance(v, str) and v.strip() == "": return True
    if isinstance(v, (list, dict)) and len(v) == 0: return True
    return False

def to_int(v: Any) -> Optional[int]:
    try:
        if isinstance(v, (int, float)):
            return int(v)
        if isinstance(v, str) and v.strip().isdigit():
            return int(v.strip())
        if isinstance(v, str):
            return int(v.strip(), 0)
    except Exception:
        return None
    return None

def parse_time(ts: Optional[str]) -> Optional[str]:
    if not ts:
        return None
    try:
        if isinstance(ts, str) and ts.isdigit() and len(ts) <= 10:
            return datetime.utcfromtimestamp(int(ts)).isoformat() + "Z"
        if isinstance(ts, str) and ts.isdigit() and len(ts) > 10:
            return datetime.utcfromtimestamp(int(ts) / 1000.0).isoformat() + "Z"
    except Exception:
        pass
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return dt.isoformat()
    except Exception:
        return ts

def to_confidence_0_100(val):
    if isinstance(val, (int, float)):
        n = int(val)
        return max(0, min(100, n))
    if isinstance(val, str):
        m = val.strip().lower()
        mapping = {
            "critical": 95, "malicious": 90, "high": 85,
            "medium": 60, "suspicious": 50, "low": 30,
            "benign": 10, "informational": 10,
        }
        return mapping.get(m, 70)
    return None

def to_severity_id(val) -> Optional[int]:
    if val is None: return None
    m = str(val).strip().lower()
    table = {"critical": 90, "high": 70, "medium": 50, "low": 30, "informational": 10}
    return table.get(m)

def parse_protocol(proto_str: Optional[str], resolved: Optional[str]) -> Optional[str]:
    if isinstance(resolved, str) and "(" in resolved:
        return resolved.split("(")[0].strip()
    if isinstance(proto_str, str) and proto_str.strip().isdigit():
        return {"6": "TCP", "17": "UDP"}.get(proto_str.strip(), proto_str.strip())
    return resolved or proto_str

def ensure_list(x):
    if x is None: return []
    if isinstance(x, list): return x
    return [x]

def domain_from_url(url: Optional[str]) -> Optional[str]:
    if not isinstance(url, str): return None
    m = re.match(r"^[a-zA-Z]+://([^/]+)", url.strip())
    return m.group(1) if m else None

def boolish(v) -> Optional[bool]:
    if isinstance(v, bool): return v
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true","yes","1"): return True
        if s in ("false","no","0"): return False
    return None

# ------------------- FLATTEN / UNFLATTEN -------------------
_SEG_RE = re.compile(r'([^.[]+)(?:\[(\d*)\])?')

def unflatten_dotmap(flat: Dict[str, Any]) -> Dict[str, Any]:
    root: Dict[str, Any] = {}
    for path, value in flat.items():
        cur = root
        parts = path.split(".")
        for i, part in enumerate(parts):
            m = _SEG_RE.fullmatch(part)
            key, idx = (m.group(1), m.group(2)) if m else (part, None)
            last = (i == len(parts) - 1)
            if idx is None:
                if last:
                    cur[key] = value
                else:
                    if key not in cur or not isinstance(cur[key], dict):
                        cur[key] = {}
                    cur = cur[key]
            else:
                index = 0 if idx == "" else int(idx)
                if key not in cur or not isinstance(cur[key], list):
                    cur[key] = []
                while len(cur[key]) <= index:
                    cur[key].append({})
                if last:
                    cur[key][index] = value
                else:
                    if not isinstance(cur[key][index], dict):
                        cur[key][index] = {}
                    cur = cur[key][index]
    return root

def flatten_json(obj: Any, prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else str(k)
            out.update(flatten_json(v, p))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            p = f"{prefix}[{i}]"
            out.update(flatten_json(v, p))
    else:
        out[prefix] = obj
    return out

def normalize_idx_placeholders(path: str) -> str:
    return re.sub(r"\[\d+\]", "[]", path)

# ------------------- OCSF MAPPINGS (FIREWALL THREAT) -------------------
OCSF_MAPPED: List[tuple[str, str]] = [
    ("time",                               "time"),
    ("id",                                 "id"),
    ("session_id",                         "network.session_id"),
    ("ticket_id",                          "ticket.id"),
    ("policy_date",                        "policy.applied_time"),
    ("policy_time",                        "policy.update_time"),
    ("policy_name",                        "policy.name"),
    ("policy",                             "policy.rule.name"),
    ("policy_mgmt",                        "policy.manager"),
    ("verdict",                            "disposition"),
    ("severity",                           "severity"),
    ("confidence_level",                   "confidence"),
    ("malware_action",                     "title"),
    ("protection_name",                    "rule.name"),
    ("malware_family",                     "malware[0].name"),
    ("calc_desc",                          "description"),
    ("src",                                "src_endpoint.ip"),
    ("dst",                                "dst_endpoint.ip"),
    ("s_port",                             "src_endpoint.port"),
    ("service",                            "dst_endpoint.port"),
    ("src_attr[].resolved",                "src_endpoint.name"),
    ("dst_attr[].resolved",                "dst_endpoint.name"),
    ("proxy_src_ip",                       "proxy.src.ip"),
    ("i_f_dir",                            "network.direction"),
    ("i_f_name",                            "device.interface.name"),
    ("__interface",                        "device.interface.name"),
    ("proto",                              "network.protocol_id"),
    ("proto_attr[].resolved",              "network.protocol"),
    ("received_bytes",                     "network.bytes_in"),
    ("sent_bytes",                         "network.bytes_out"),
    ("rounded_received_bytes",             "network.bytes_in_rounded"),
    ("rounded_sent_bytes",                 "network.bytes_out_rounded"),
    ("content_length",                     "http.response.content_length"),
    ("method",                             "http.request.method"),
    ("resource",                           "url.full"),
    ("http_host",                          "http.host"),
    ("referrer",                           "http.request.referrer"),
    ("user_agent",                         "http.user_agent"),
    ("http_status",                        "http.response.status_code"),
    ("content_type",                       "http.response.content_type"),
    ("http_server",                        "http.server"),
    ("web_client_type",                    "http.client_variant"),
    ("resource_table[].resource",          "url.full"),
    ("file_name",                          "file.name"),
    ("file_type",                          "file.type"),
    ("file_md5",                           "file.hashes.md5"),
    ("file_sha256",                        "file.hashes.sha256"),
    ("product",                            "detector.product_name"),
    ("product_family",                     "detector.product_family"),
    ("vendor_list",                        "detector.vendor_name"),
    ("orig",                               "detector.device_name"),
    ("orig_log_server",                    "detector.log_server"),
    ("orig_log_server_ip",                 "detector.log_server_ip"),
    ("stored",                             "storage.stored"),
    ("packet_capture",                     "evidence.packet_capture.label"),
    ("packet_capture_name",                "evidence.packet_capture.name"),
    ("packet_capture_time",                "evidence.packet_capture.time"),
    ("packet_capture_unique_id",           "evidence.packet_capture.uid"),
]

# Extra top-level fields to surface explicitly with 'unmapped_' prefix
EXTRA_UNMAPPED = [
    ("action", "unmapped_action"),
    ("indicator_name", "unmapped_indicator_name"),
    ("scope", "unmapped_scope"),
    ("dst_country", "unmapped_dst_country"),
    ("suppressed_logs", "unmapped_suppressed_logs"),
    ("times_submitted", "unmapped_times_submitted"),
    ("fservice", "unmapped_fservice"),
]

# ------------------- SPECIAL BUILDERS -------------------
def post_process(flat: Dict[str, Any]) -> Dict[str, Any]:
    conf = flat.get("confidence")
    flat["confidence_id"] = to_confidence_0_100(conf)
    flat["severity_id"] = to_severity_id(flat.get("severity"))
    if "url.full" in flat and (flat.get("http.host") is None or flat.get("http.host") == ""):
        dom = domain_from_url(flat.get("url.full"))
        if dom:
            flat["http.host"] = dom
    proto_resolved = flat.get("network.protocol")
    proto_id = flat.get("network.protocol_id")
    proto_str = parse_protocol(str(proto_id) if proto_id is not None else None, proto_resolved)
    if proto_str:
        flat["network.protocol"] = proto_str
    if "storage.stored" in flat:
        flat["storage.stored"] = boolish(flat["storage.stored"])
    for key in ["src_endpoint.port", "dst_endpoint.port", "http.response.status_code",
                "network.bytes_in", "network.bytes_out", "network.bytes_in_rounded",
                "network.bytes_out_rounded", "http.response.content_length"]:
        if key in flat and flat[key] is not None:
            ival = to_int(flat[key])
            flat[key] = ival if ival is not None else flat[key]
    for k in ["time", "policy.applied_time", "policy.update_time", "evidence.packet_capture.time"]:
        if k in flat and flat[k] is not None:
            flat[k] = parse_time(str(flat[k]))
    if flat.get("network.direction") in ("inbound","outbound"):
        flat["network.direction"] = flat["network.direction"].capitalize()
    return flat

# ------------------- INPUT SHAPE HANDLERS -------------------
def iter_alert_items(payload: dict) -> List[dict]:
    if isinstance(payload, dict) and "data" in payload and isinstance(payload["data"], list):
        return [item for item in payload["data"] if isinstance(item, dict)]
    return [payload]

# ------------------- NORMALIZE ONE ALERT → NESTED -------------------
def normalize_one_to_nested(src: dict) -> dict:
    flat: Dict[str, Any] = {}

    # 1) Direct mappings
    for fw_path, ocsf_path in OCSF_MAPPED:
        val = get_nested(src, fw_path)
        flat[ocsf_path] = None if is_empty(val) else val

    # 1b) Add requested explicit 'unmapped_' fields (top-level source keys)
    for src_key, out_key in EXTRA_UNMAPPED:
        v = get_nested(src, src_key)
        if not is_empty(v):
            flat[out_key] = v

    # 2) Post-process derived fields
    flat = post_process(flat)

    # 3) Also capture UNMAPPED vendor fields (flattened)
    used_src = { normalize_idx_placeholders(s) for (s, _) in OCSF_MAPPED }
    flattened_src = flatten_json(src)
    for spath, sval in flattened_src.items():
        if is_empty(sval):
            continue
        nspath = normalize_idx_placeholders(spath)
        if nspath not in used_src and not any(nspath == k for (k, _) in EXTRA_UNMAPPED):
            flat[f"unmapped.{spath}"] = sval

    # 4) Unflatten to nested JSON
    nested = unflatten_dotmap(flat)

    # 5) Add OCSF "Security Finding" framing
    nested.setdefault("class_name", "Malware Finding")
    nested.setdefault("category_name", "Security Finding")
    nested.setdefault("activity_name", "Detection")

    # Detector defaults
    det = nested.setdefault("detector", {})
    det.setdefault("vendor_name", "Check Point")
    if "product_name" not in det and "product_family" in det:
        det["product_name"] = det["product_family"]

    # HTTP convenience: add url.domain
    url = nested.get("url", {})
    if isinstance(url, dict) and "full" in url and "domain" not in url:
        dom = domain_from_url(url.get("full"))
        if dom:
            url["domain"] = dom
            nested["url"] = url

    return nested

# ------------------- MAIN -------------------
def main():
    in_dir = Path(INPUT_DIR)
    out_dir = Path(OUTPUT_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)

    total_files, total_items, ok = 0, 0, 0

    for p in in_dir.glob("*.json"):
        total_files += 1
        try:
            payload = json.loads(p.read_text(encoding="utf-8"))

            items = iter_alert_items(payload)
            if not items:
                print(f"[WARN] {p.name}: no alert items found")
                continue

            for idx, raw_item in enumerate(items):
                total_items += 1
                nested_obj = normalize_one_to_nested(raw_item)

                alert_id = (raw_item.get("id") or raw_item.get("ticket_id") or f"{p.stem}_{idx}")
                safe_alert_id = str(alert_id).replace(":", "_").replace("\\", "_").replace("/", "_")

                out_path = out_dir / f"{p.stem}__{safe_alert_id}.json"
                out_path.write_text(
                    json.dumps(nested_obj, indent=2, ensure_ascii=False),
                    encoding="utf-8"
                )
                ok += 1

        except Exception as e:
            print(f"[ERROR] {p.name}: {e}")

    print(f"Files processed: {total_files} | Alert items found: {total_items} | Normalized & saved: {ok} | Output: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
