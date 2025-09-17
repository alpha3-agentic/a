
import json
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from datetime import datetime

def safe_get(d: Dict[str, Any], path: List[Union[str, int]], default=None):
    cur = d
    try:
        for p in path:
            if isinstance(cur, dict):
                cur = cur.get(p, default)
            elif isinstance(cur, list) and isinstance(p, int):
                cur = cur[p] if p < len(cur) else default
            else:
                return default
        return cur
    except Exception:
        return default

def parse_time(ts: Optional[str]) -> Optional[str]:
    if not ts:
        return None
    # pass through if already ISO
    try:
        # Handle Zulu or offset formats
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.isoformat()
    except Exception:
        return ts  # fallback

def compute_file_depth(path_str: Optional[str]) -> Optional[int]:
    if not path_str:
        return None
    # Normalize both backslashes and forward slashes
    parts = [p for p in path_str.replace("\\\\", "/").replace("\\", "/").split("/") if p]
    return len(parts) if parts else None

def pick_ip(alert: Dict[str, Any]) -> Optional[str]:
    v4 = safe_get(alert, ["agentDetectionInfo", "agentIpV4"])
    if v4:
        return v4
    # Try real-time interfaces
    inet = safe_get(alert, ["agentRealtimeInfo", "networkInterfaces", 0, "inet"])
    if isinstance(inet, list) and inet:
        return inet[0]
    return None

def pick_mac(alert: Dict[str, Any]) -> Optional[str]:
    return safe_get(alert, ["agentRealtimeInfo", "networkInterfaces", 0, "physical"])

def mitigation_actions(alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    acts = []
    for m in alert.get("mitigationStatus", []) or []:
        acts.append({
            "action": m.get("action"),
            "status": m.get("status"),
            "started_at": parse_time(m.get("mitigationStartedAt")),
            "ended_at": parse_time(m.get("mitigationEndedAt")),
            "report_id": m.get("reportId"),
            "latest_report": m.get("latestReport"),
        })
    return acts

def map_confidence(conf: Optional[str]) -> Dict[str, Optional[Union[str,int]]]:
    # SentinelOne "confidenceLevel" can be "suspicious", "malicious", "unknown", etc.
    # OCSF uses a numeric confidence_id (1 low .. 100 high) and confidence string.
    if not conf:
        return {"confidence": None, "confidence_id": None}
    conf_l = conf.lower()
    if conf_l in ("malicious", "high"):
        return {"confidence": "High", "confidence_id": 80}
    if conf_l in ("suspicious", "medium"):
        return {"confidence": "Medium", "confidence_id": 50}
    if conf_l in ("low",):
        return {"confidence": "Low", "confidence_id": 20}
    return {"confidence": conf, "confidence_id": None}

def status_from_incident(s: Optional[str]) -> Dict[str, Optional[str]]:
    if not s:
        return {"status": None, "status_detail": None}
    s_l = s.lower()
    if s_l in ("resolved", "closed", "mitigated"):
        return {"status": "Closed", "status_detail": s}
    if s_l in ("open", "new", "in_progress"):
        return {"status": "Open", "status_detail": s}
    return {"status": s, "status_detail": None}

def build_ocsf(alert: Dict[str, Any], product_vendor="SentinelOne", product_name="Singularity XDR") -> Dict[str, Any]:
    # Important top-level components from the sample SentinelOne-style alert
    threat = alert.get("threatInfo", {}) or {}
    agent_rt = alert.get("agentRealtimeInfo", {}) or {}
    agent_det = alert.get("agentDetectionInfo", {}) or {}

    # Choose the best timestamps
    event_time = parse_time(threat.get("identifiedAt") or threat.get("createdAt"))
    created_time = parse_time(threat.get("createdAt"))
    updated_time = parse_time(threat.get("updatedAt"))

    conf_map = map_confidence(threat.get("confidenceLevel"))
    status_map = status_from_incident(threat.get("incidentStatus"))

    # Endpoint (source) information
    src_endpoint = {
        "hostname": agent_rt.get("agentComputerName"),
        "ip": pick_ip(alert),
        "mac": pick_mac(alert),
        "os": {
            "name": agent_rt.get("agentOsName") or agent_det.get("agentOsName"),
            "type": agent_rt.get("agentOsType"),
            "version": agent_rt.get("agentOsRevision") or agent_det.get("agentOsRevision"),
        },
        "domain": agent_rt.get("agentDomain") or agent_det.get("agentDomain"),
        "device_type": agent_rt.get("agentMachineType"),
        "uid": agent_rt.get("agentUuid") or agent_det.get("agentUuid"),
        "id": agent_rt.get("agentId"),
        "group": {
            "id": agent_rt.get("groupId") or agent_det.get("groupId"),
            "name": agent_rt.get("groupName") or agent_det.get("groupName"),
            "site_id": agent_rt.get("siteId") or agent_det.get("siteId"),
            "site_name": agent_rt.get("siteName") or agent_det.get("siteName"),
        },
    }

    # File object (primary observable)
    file_path = threat.get("filePath")
    file_obj = {
        "name": threat.get("threatName"),
        "path": file_path,
        "size": threat.get("fileSize"),
        "extension": threat.get("fileExtension"),
        "extension_type": threat.get("fileExtensionType"),
        "hashes": {
            "sha256": threat.get("sha256"),
            "sha1": threat.get("sha1"),
            "md5": threat.get("md5"),
        },
        "is_signed": True if threat.get("isValidCertificate") else False,
        "verification_type": threat.get("fileVerificationType"),
        "depth": compute_file_depth(file_path),
    }

    # Actor/user
    user = {
        "user_id": threat.get("initiatingUserId"),
        "user_name": threat.get("initiatingUsername") or agent_det.get("agentLastLoggedInUserName"),
        "upn": agent_det.get("agentLastLoggedInUpn"),
        "email": agent_det.get("agentLastLoggedInUserMail"),
        "domain": agent_det.get("agentDomain"),
    }

    # Build OCSF-like finding event
    ocsf = {
        # We avoid numeric IDs to keep schema-agnostic; names follow OCSF "Security Finding / Malware" concepts
        "class_name": "Malware Finding",
        "category_name": "Security Finding",
        "activity_name": "Detection",
        "time": event_time,
        "created_time": created_time,
        "updated_time": updated_time,
        "severity": None,  # SentinelOne severity not present in sample
        **conf_map,
        **status_map,

        "title": threat.get("classification") or "Malware detected",
        "description": threat.get("analystVerdictDescription"),
        "disposition": threat.get("analystVerdict"),  # true_positive / false_positive etc.

        "detector": {
            "vendor_name": product_vendor,
            "product_name": product_name,
            "version": agent_det.get("agentVersion") or agent_rt.get("agentVersion"),
            "engine_names": threat.get("engines") or threat.get("detectionEngines"),
            "detection_type": threat.get("detectionType"),
            "initiated_by": threat.get("initiatedByDescription") or threat.get("initiatedBy"),
        },

        "src_endpoint": src_endpoint,
        "file": file_obj,
        "storyline_id": threat.get("storyline"),
        "external": {
            "ticket_exists": threat.get("externalTicketExists"),
            "ticket_id": threat.get("externalTicketId"),
            "cloud_files_hash_verdict": threat.get("cloudFilesHashVerdict"),
        },
        "mitigation": {
            "status": threat.get("mitigationStatus"),
            "status_description": threat.get("mitigationStatusDescription"),
            "actions": mitigation_actions(alert),
            "reboot_required": threat.get("rebootRequired"),
            "automatically_resolved": threat.get("automaticallyResolved"),
        },

        # Keep critical original identifiers under 'raw' for traceability
        "raw": {
            "provider": "SentinelOne",
            "threat_id": threat.get("threatId") or alert.get("id"),
            "collection_id": threat.get("collectionId"),
            "agent_id": agent_rt.get("agentId"),
            "account_id": agent_det.get("accountId") or agent_rt.get("accountId"),
            "site_id": agent_rt.get("siteId") or agent_det.get("siteId"),
        }
    }

    return ocsf

def iter_input_files(input_path: Path) -> List[Path]:
    if input_path.is_dir():
        return sorted([p for p in input_path.rglob("*.json") if p.is_file()])
    if input_path.is_file():
        return [input_path]
    return []

def normalize_pathlike(p: str) -> str:
    return str(Path(p).resolve())

def main():
    ap = argparse.ArgumentParser(description="Normalize SentinelOne-like EDR alerts to OCSF-style JSON")
    ap.add_argument("input", help="Path to a .json file or a directory of .json files")
    ap.add_argument("-o", "--output_dir", default="ocsf_out", help="Where to write normalized outputs")
    ap.add_argument("--vendor", default="SentinelOne", help="Detector vendor name")
    ap.add_argument("--product", default="Singularity XDR", help="Detector product name")
    ap.add_argument("--format", choices=["ndjson", "json_per_file"], default="json_per_file", help="Output format")
    args = ap.parse_args()

    input_path = Path(args.input)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    files = iter_input_files(input_path)
    if not files:
        print("No JSON files found at", input_path)
        return

    events = []
    for src in files:
        try:
            with open(src, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[WARN] Skipping {src}: {e}")
            continue

        # Some logs may be arrays; handle both
        candidates = []
        if isinstance(data, list):
            candidates = data
        elif isinstance(data, dict) and "logs" in data and isinstance(data["logs"], list):
            candidates = data["logs"]
        else:
            candidates = [data]

        for idx, alert in enumerate(candidates):
            try:
                evt = build_ocsf(alert, product_vendor=args.vendor, product_name=args.product)
                events.append((src, idx, evt))
            except Exception as e:
                print(f"[WARN] Failed to normalize record {idx} in {src}: {e}")

    # Write outputs
    if args.format == "ndjson":
        out_path = out_dir / "normalized.ndjson"
        with open(out_path, "w", encoding="utf-8") as w:
            for _, _, evt in events:
                w.write(json.dumps(evt, ensure_ascii=False) + "\n")
        print(f"Wrote NDJSON: {out_path}")
    else:
        # One JSON file per source record
        for src, idx, evt in events:
            base = src.stem if src.is_file() else "record"
            out_path = out_dir / f"{base}_{idx:03d}_ocsf.json"
            with open(out_path, "w", encoding="utf-8") as w:
                json.dump(evt, w, ensure_ascii=False, indent=2)
        print(f"Wrote {len(events)} JSON file(s) to {out_dir}")

if __name__ == "__main__":
    main()
