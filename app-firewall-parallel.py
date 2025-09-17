import os
import json
import pickle
import pandas as pd
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from sklearn.preprocessing import LabelEncoder, StandardScaler
import xgboost as xgb
import uvicorn
import os
import re
import math
from datetime import datetime
from typing import Dict, Any, List

from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, Optional
from datetime import datetime
import traceback
import re
import requests
import time
import math
from fastapi import HTTPException, UploadFile, File, Body, Query
from fastapi.responses import JSONResponse
from datetime import datetime
from typing import Dict, Any, List
from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from dataclasses import dataclass
from typing import Dict, Any, Tuple, Optional
import numpy as np
import torch
import torch.nn as nn
# Neo4j and LangChain imports
from neo4j import GraphDatabase
from langchain_neo4j import GraphCypherQAChain, Neo4jGraph
from langchain_openai import ChatOpenAI
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional
from datetime import datetime

# Load environment variables
load_dotenv()
import re
import math
from datetime import datetime
from typing import Dict, Any, List
from fastapi import UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import Optional, Union, List, Any
import traceback

from pydantic import BaseModel, Field
from typing import Optional, Union, List, Any, Dict
import traceback

from fastapi.middleware.cors import CORSMiddleware
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", module="langchain")
warnings.filterwarnings("ignore", module="fastapi")


    
app = FastAPI(title="Alert Classifier API", version="1.0")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# ----------------- GNN defaults -----------------
DEFAULT_GNN_CKPT = os.getenv("RGCN_CKPT", "models/rgcn_nodgl.pt")
try:
    DEFAULT_GNN_HOPS = int(os.getenv("RGCN_HOPS", "5"))
except Exception:
    DEFAULT_GNN_HOPS = 5
    
class BaseAgent:
    def __init__(self, role: str, tools: List[str]):
        self.role = role
        self.tools = tools
        self.context = {}
        

import json
import subprocess
import tempfile
import os
import re
import math
import time
from datetime import datetime
from typing import Any, Dict, Optional
import traceback
from fastapi import FastAPI, File, UploadFile, Body, HTTPException
from fastapi.responses import JSONResponse

class SimpleMCPClient:
    """Simple MCP client that uses hardcoded prompts to communicate with the MCP server"""
    
    def __init__(self, server_script_path: str = "server.py"):
        self.server_script_path = server_script_path
        
        # Hardcoded prompts for different enrichment tasks
        self.prompts = {
            "enrich_virustotal": "enrich this alert with virustotal threat intelligence",
            "enrich_checkpoint": "enrich this alert with checkpoint reputation data", 
            "enrich_cyberint": "enrich this alert with cyberint threat intelligence",
            "enrich_combined": "enrich this alert with all available threat intelligence sources (virustotal, checkpoint, cyberint)",
            "enrich_combined_edr": "enrich this alert with all available threat intelligence sources (virustotal, checkpoint, cyberint)"
        }
    
    async def enrich_alert(self, sha256_hash: str, prompt_type: str = "enrich_combined") -> Dict[str, Any]:
        """
        Send a hardcoded prompt to enrich an alert using the MCP server
        
        Args:
            sha256_hash: The file hash to enrich
            prompt_type: Type of enrichment prompt to use
        """
        
        print(f"MCP Client: {self.prompts.get(prompt_type, 'enrich this alert')}")
        print(f"Hash to enrich: {sha256_hash}")
        
        try:
            # Create a temporary alert file that the MCP server can process
            temp_dir = tempfile.mkdtemp()
            alert_id = f"triage_{int(time.time())}"
            
            # Create alert in the format expected by MCP server
            alert_data = {
                "id": alert_id,
                "file": {
                    "hashes": {
                        "sha256": sha256_hash,
                        "sha1": "",
                        "md5": ""
                    },
                    "path": f"temp_file_{alert_id}.exe",
                    "size": 1024
                },
                "meta": {
                    "detected_time": datetime.utcnow().isoformat(),
                    "source": "triage_analysis"
                }
            }
            
            alert_file = os.path.join(temp_dir, f"{alert_id}.json")
            with open(alert_file, 'w') as f:
                json.dump(alert_data, f, indent=2)
            
            print(f"Created alert file: {alert_file}")
            
            # Determine which MCP tool to call based on prompt type
            if prompt_type == "enrich_virustotal":
                tool_name = "enrich_virustotal"
            elif prompt_type == "enrich_checkpoint":
                tool_name = "enrich_checkpoint"
            elif prompt_type == "enrich_cyberint":
                tool_name = "enrich_cyberint"
            else:
                tool_name = "enrich_alert_combined"
            
            # Fix Windows path issues by using raw strings and proper escaping
            server_dir = os.path.dirname(os.path.abspath(self.server_script_path)).replace('\\', '\\\\')
            server_module = os.path.splitext(os.path.basename(self.server_script_path))[0]
            temp_dir_escaped = temp_dir.replace('\\', '\\\\')
            
            # Call the MCP server using subprocess
            cmd = [
                "python", "-c", f"""
import sys
import os
import json
import asyncio
sys.path.append(r'{server_dir}')

async def main():
    try:
        # Import MCP server functions
        from {server_module} import call_tool
        
        # Simulate calling the MCP tool
        arguments = {{
            "alert_id": "{alert_id}",
            "folder": r"{temp_dir_escaped}"
        }}
        
        result = await call_tool("{tool_name}", arguments)
        
        # Extract text content from result
        if hasattr(result, '__iter__') and len(result) > 0:
            if hasattr(result[0], 'text'):
                print(result[0].text)
            elif isinstance(result[0], dict) and 'text' in result[0]:
                print(result[0]['text'])
            else:
                print(json.dumps({{"error": "Invalid result format"}}))
        else:
            print(json.dumps({{"error": "No result returned"}}))
            
    except Exception as e:
        print(json.dumps({{"error": f"MCP call failed: {{str(e)}}"}}))

if __name__ == '__main__':
    asyncio.run(main())
"""
            ]
            
            print(f"Calling MCP server with tool: {tool_name}")
            
            # Execute the MCP call
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    response_data = json.loads(result.stdout.strip())
                    print("MCP Server response received successfully")
                    return response_data
                except json.JSONDecodeError:
                    print(f"Failed to parse MCP response: {result.stdout}")
                    return {"error": "Invalid JSON response from MCP server"}
            else:
                print(f"MCP server call failed: {result.stderr}")
                return {"error": f"MCP server error: {result.stderr}"}
                
        except Exception as e:
            print(f"MCP client error: {str(e)}")
            return {"error": f"MCP client failed: {str(e)}"}
        
        finally:
            # Clean up temporary files
            try:
                import shutil
                if 'temp_dir' in locals():
                    shutil.rmtree(temp_dir)
            except Exception as e:
                print(f"Cleanup failed: {e}")
        
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, root_validator

def _expand_dotpaths(d: Dict[str, Any]) -> Dict[str, Any]:
    """
    Turn dotted keys into nested dicts:
      {"file.size": 123, "threat.detection.type": "static"}
    -> {"file": {"size": 123}, "threat": {"detection": {"type": "static"}}}
    """
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if "." in k:
            cur = out
            parts = k.split(".")
            for p in parts[:-1]:
                if p not in cur or not isinstance(cur[p], dict):
                    cur[p] = {}
                cur = cur[p]
            cur[parts[-1]] = v
        else:
            out[k] = v
    return out

def _deep_merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Deep-merge dict b into a (mutates and returns a)."""
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict):
            _deep_merge(a[k], v)
        else:
            a[k] = v
    return a


class FlexibleAlertInput(BaseModel):
    """
    Flexible input model for various EDR formats.

    Features:
      - Accepts normal fields and unmapped_ fields.
      - Accepts nested dicts: file, threat, device, process.
      - Accepts dotted keys in input (e.g., file.size, threat.detection.type).
      - Auto-extracts alert_id from common locations.
      - to_raw_format() returns a normalized dict your scoring system expects.
    """

    # ---- Canonical fields ----
    alert_id: Optional[str] = None
    file_size: Optional[float] = None
    file_extension: Optional[str] = None
    file_extension_type: Optional[str] = None
    verification_type: Optional[str] = None
    is_valid_certificate: Optional[bool] = None
    threat_confidence: Optional[float] = None
    detection_type: Optional[str] = None
    threat_classification: Optional[str] = None
    os_name: Optional[str] = None
    device_type: Optional[str] = None
    is_active: Optional[bool] = None
    is_fileless: Optional[bool] = None
    confidence_level: Optional[str] = None
    severity: Optional[str] = None
    verdict: Optional[str] = None

    # ---- Unmapped variants (if provided, they take precedence) ----
    unmapped_alert_id: Optional[str] = None
    unmapped_file_size: Optional[float] = None
    unmapped_file_extension: Optional[str] = None
    unmapped_file_extension_type: Optional[str] = None
    unmapped_verification_type: Optional[str] = None
    unmapped_is_valid_certificate: Optional[bool] = None
    unmapped_threat_confidence: Optional[float] = None
    unmapped_detection_type: Optional[str] = None
    unmapped_threat_classification: Optional[str] = None
    unmapped_os_name: Optional[str] = None
    unmapped_device_type: Optional[str] = None
    unmapped_is_active: Optional[bool] = None
    unmapped_is_fileless: Optional[bool] = None
    unmapped_confidence_level: Optional[str] = None
    unmapped_severity: Optional[str] = None
    unmapped_verdict: Optional[str] = None

    # ---- Nested raw structures (optional) ----
    file: Optional[Dict[str, Any]] = None
    threat: Optional[Dict[str, Any]] = None
    device: Optional[Dict[str, Any]] = None
    process: Optional[Dict[str, Any]] = None

    # Keep the original, expanded input around if needed
    raw_input: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        extra = "allow"  # keep any extra vendor-specific fields

    # ---- Helpers ----
    def _get_field_value(self, field_name: str) -> Any:
        """Return unmapped_ variant if present, else the mapped value."""
        unmapped = getattr(self, f"unmapped_{field_name}", None)
        regular = getattr(self, field_name, None)
        return unmapped if unmapped is not None else regular

    @staticmethod
    def _extract_alert_id_from(data: Dict[str, Any]) -> Optional[str]:
        # Try common top-level keys
        for k in ["id", "alert_id", "threatId", "threat_id", "incidentId", "incident_id", "alertId"]:
            if k in data and data[k] is not None:
                return str(data[k])

        # Try nested vendors (SentinelOne-style, etc.)
        threat_info = data.get("threatInfo") or data.get("threat") or {}
        for k in ["threatId", "id"]:
            if isinstance(threat_info, dict) and k in threat_info and threat_info[k] is not None:
                return str(threat_info[k])

        return None

    # ---- Input normalization: expand dotted keys & auto alert_id ----
    @root_validator(pre=True)
    def _preprocess_input(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        # 1) Expand dotted keys.
        expanded = _expand_dotpaths(values)

        # 2) If user passed both dotted and nested, deep-merge.
        #    The dotted expansions go into 'expanded'; now merge original to ensure no loss.
        expanded = _deep_merge(expanded, {k: v for k, v in values.items() if "." not in k})

        # 3) Keep a copy for raw_input
        expanded["raw_input"] = dict(expanded)

        # 4) Auto alert_id if missing
        if "alert_id" not in expanded or expanded.get("alert_id") in (None, "", "unknown_alert"):
            auto_id = cls._extract_alert_id_from(expanded)
            if auto_id:
                expanded["alert_id"] = auto_id

        return expanded

    # ---- Outputs ----
    def to_raw_format(self) -> Dict[str, Any]:
        """Return the normalized dict expected by the scoring/feature pipeline."""
        result: Dict[str, Any] = {}

        # Pull from nested first (then let explicit/unmapped fields override)
        if self.file:
            result["file_size"] = (self.file.get("size") or 0)
            result["file_extension"] = str(self.file.get("extension", "unknown")).lower()
            result["file_extension_type"] = str(self.file.get("extension_type", "unknown")).lower()
            cert_status = (self.file.get("signature", {}) or {}).get("certificate", {})
            result["is_valid_certificate"] = cert_status.get("status") == "valid"
            result["verification_type"] = str((self.file.get("verification", {}) or {}).get("type", "unknown")).lower()

        if self.threat:
            result["threat_confidence"] = self.threat.get("confidence", 50) or 50
            result["detection_type"] = str((self.threat.get("detection", {}) or {}).get("type", "unknown")).lower()
            result["threat_classification"] = str(self.threat.get("classification", "unknown")).lower()
            result["verdict"] = str(self.threat.get("verdict", "unknown")).lower()

        if self.device:
            result["os_name"] = str((self.device.get("os", {}) or {}).get("name", "unknown")).lower()
            result["device_type"] = str(self.device.get("type", "unknown")).lower()
            result["is_active"] = bool(self.device.get("is_active", False))

        if self.process:
            result["is_fileless"] = bool(self.process.get("is_fileless", False))

        # Now override with explicit/unmapped values
        def put(name: str, lower: bool = False, default_if_none: Any = None):
            v = self._get_field_value(name)
            if v is None and default_if_none is not None:
                v = default_if_none
            if v is not None:
                result[name] = v.lower() if (lower and isinstance(v, str)) else v

        put("alert_id")
        put("file_size")
        put("file_extension", lower=True)
        put("file_extension_type", lower=True)
        put("verification_type", lower=True)
        put("is_valid_certificate")
        put("threat_confidence")
        put("detection_type", lower=True)
        put("threat_classification", lower=True)
        put("os_name", lower=True)
        put("device_type", lower=True)
        put("is_active")
        put("is_fileless")
        put("confidence_level", lower=True)
        put("severity", lower=True)
        put("verdict", lower=True)

        # Final fallback for alert_id
        if "alert_id" not in result or not result["alert_id"]:
            aid = self._extract_alert_id_from(self.raw_input)
            result["alert_id"] = aid or "unknown_alert"

        return result

    def to_legacy_format(self) -> Dict[str, Any]:
        """
        For backward compatibility with older code expecting the raw/original structure.
        This returns the expanded original (with dotted keys expanded), not the normalized view.
        """
        return dict(self.raw_input)

    # Convenience alternative constructor
    @classmethod
    def create(cls, **data: Any) -> "FlexibleAlertInput":
        """
        Friendly constructor that allows passing dotted keys directly:
            obj = FlexibleAlertInput.create(**{"file.size": 123, "threat.detection.type": "static"})
        """
        return cls(**data)

class ScoringTool:
    """Tool for scoring alerts using heuristic rules and MCP-based threat intelligence"""
    
    # Existing constants remain the same
    EVIL_PATH_REGEX = re.compile(
        r'(\\AppData\\|\\Downloads\\|\\Users\\Public|\\Windows\\[^\\]+\\|\$Recycle\.Bin)',
        re.I
    )
    
    LOLBINS = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wmic.exe", "regsvr32.exe",
        "mshta.exe", "python.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
        "curl.exe", "wget.exe"
    }
    
    SUSP_ARGS_RE = re.compile(r'(-enc\b|FromBase64String|Invoke-Expression|curl\s+http)', re.I)
    
    ENGINE_WEIGHTS = {
        "SentinelOne Cloud": 25,
        "on-write static ai": 15,
        "user": 10,
        "behavioral": 5
    }
    
    ASSET_WEIGHTS = {
        "server": 15,
        "laptop": 5
    }
    
    CONF_WEIGHTS = {
        "malicious": 10,
        "suspicious": 5
    }

    def __init__(self, mcp_client: SimpleMCPClient):
        self.mcp_client = mcp_client

    @classmethod
    def weight_engine(cls, name: str) -> int:
        if not name:
            return 0
        low = name.strip().lower()
        for key, w in cls.ENGINE_WEIGHTS.items():
            if key.lower() == low:
                return w
        return 0
    
    
    
    @classmethod
    def _apply_aliases(cls, flat: Dict[str, Any]) -> Dict[str, Any]:
        def first_present(keys, transform=None, default=None):
            """Return first non-None value from a list of keys (in order)."""
            for k in keys:
                if k in flat and flat[k] is not None:
                    val = flat[k]
                    return transform(val) if transform else val
            return default

        def with_unmapped(*base_keys: str):
            keys = []
            for b in base_keys:
                # snake variant
                keys.append(f"unmapped_{b}")
                keys.append(b)
            return keys

        def put_if_missing(target_key: str, value):
            if value is None:
                return
            if target_key not in flat or flat[target_key] in (None, ""):
                flat[target_key] = value

        lower = lambda s: str(s).lower()

        # ---------------- File ----------------
        put_if_missing("file.size", first_present(
            with_unmapped("file_size", "file.size")
        ))

        put_if_missing("file.extension", first_present(
            with_unmapped("file_extension", "file.extension"),
            transform=lower
        ))

        put_if_missing("file.extension_type", first_present(
            with_unmapped("file_extension_type", "file.extension_type"),
            transform=lower
        ))

        put_if_missing("file.verification.type", first_present(
            # accept unmapped snake, mapped snake, dotted
            with_unmapped("file_verification_type", "verification_type", "file.verification.type"),
            transform=lower
        ))

        # Certificate: prefer dotted if present; else build from boolean 'is_valid_certificate'
        cert_status = first_present(["file.signature.certificate.status"])
        if cert_status is None:
            is_valid = first_present(with_unmapped("is_valid_certificate"))
            if isinstance(is_valid, bool):
                put_if_missing("file.signature.certificate.status", "valid" if is_valid else "invalid")

        put_if_missing("file.path", first_present(
            with_unmapped("file_path", "file.path")
        ))

        # Hashes
        put_if_missing("file.hashes.sha256", first_present(
            # snake, unmapped snake, common alternatives, dotted
            ["unmapped_file_hashes_sha256", "file_hashes_sha256", "hash.sha256", "sha256", "file.hashes.sha256"]
        ))

        # ---------------- Threat ----------------
        put_if_missing("threat.confidence", first_present(
            # prefer explicit threat_confidence / confidence_level (unmapped > mapped)
            with_unmapped("threat_confidence", "confidence_level", "threat.confidence"),
            transform=lower
        ))

        put_if_missing("threat.detection.type", first_present(
            with_unmapped("threat_detection_type", "detection_type", "threat.detection.type"),
            transform=lower
        ))

        put_if_missing("threat.verdict", first_present(
            with_unmapped("verdict", "threat.verdict"),
            transform=lower
        ))

        # ---------------- Device ----------------
        put_if_missing("device.os.name", first_present(
            with_unmapped("os_name", "device_os_name", "device.os.name"),
            transform=lower
        ))

        put_if_missing("device.type", first_present(
            # some payloads use device_os_type to mean asset class; accept it for robustness
            with_unmapped("device_type", "device_os_type", "device.type"),
            transform=lower
        ))

        put_if_missing("device.is_active", first_present(
            with_unmapped("is_active", "device.is_active")
        ))

        # ---------------- Process ----------------
        put_if_missing("process.name", first_present(
            with_unmapped("process_name", "process.name"),
            transform=lower
        ))

        put_if_missing("process.cmd.args", first_present(
            # accept cmdline variants
            with_unmapped("process_cmd_args", "process.cmd.args"),  # prefer these
        ) or first_present(
            with_unmapped("process_cmdline", "process.cmdline", "process.cmdline.args")
        ))

        put_if_missing("process.is_fileless", first_present(
            with_unmapped("is_fileless", "process.is_fileless")
        ))

        put_if_missing("actor.process.user.name", first_present(
            with_unmapped("actor_process_user_name", "actor.process.user.name")
        ))

        # ---------------- Severity ----------------
        # If severity_id missing, derive from severity (string/num), supporting unmapped_*
        if "severity_id" not in flat or flat["severity_id"] in (None, ""):
            sev_raw = first_present(with_unmapped("severity", "severity_id"))
            sev_id = None
            if isinstance(sev_raw, (int, float)) or (isinstance(sev_raw, str) and str(sev_raw).isdigit()):
                sev_id = int(sev_raw)
            elif isinstance(sev_raw, str):
                sev_map = {
                    "informational": 1, "info": 1,
                    "low": 2,
                    "medium": 5, "moderate": 5,
                    "high": 8,
                    "critical": 10
                }
                sev_id = sev_map.get(sev_raw.lower())
            if sev_id is not None:
                flat["severity_id"] = sev_id

        # ---------------- Alert ID ----------------
        put_if_missing("alert_id", first_present(
            with_unmapped("alert_id", "id"),
            # also check common vendor paths if present in flattened keys
        ) or first_present([
            "threatInfo.threatId", "threat.id", "incidentId", "incident_id", "alertId"
        ]))

        return flat


    @classmethod
    def flatten_alert(cls, raw: Any, parent_key: str = "") -> Dict[str, Any]:
        """
        Recursively flattens dicts/lists with better error handling,
        then applies alias normalization to ensure Agent1/2/3/4 can read
        canonical dotted keys (e.g., 'file.verification.type', 'process.name').
        """
        flat: Dict[str, Any] = {}

        def _flatten(node: Any, pk: str = ""):
            try:
                if pk == "" and not isinstance(node, (dict, list)):
                    if hasattr(node, "__dict__"):
                        node = node.__dict__
                    else:
                        flat["raw_data"] = str(node)
                        return

                if isinstance(node, dict):
                    # Avoid flattening internal debug blobs into scoring space
                    if pk == "" and "_input_debug" in node:
                        node = {k: v for k, v in node.items() if k != "_input_debug"}

                    for k, v in node.items():
                        nk = f"{pk}.{k}" if pk else k
                        try:
                            _flatten(v, nk)
                        except Exception as e:
                            print(f"Error flattening key {nk}: {str(e)}")
                            flat[nk] = str(v)

                elif isinstance(node, list):
                    for i, v in enumerate(node):
                        nk = f"{pk}[{i}]"
                        try:
                            _flatten(v, nk)
                        except Exception as e:
                            print(f"Error flattening list item {nk}: {str(e)}")
                            flat[nk] = str(v)

                else:
                    if node is None:
                        flat[pk] = None
                    elif isinstance(node, (str, int, float, bool)):
                        flat[pk] = node
                    else:
                        flat[pk] = str(node)

            except Exception as e:
                print(f"Critical error in flatten_alert: {str(e)}")
                flat["flattening_error"] = str(e)
                flat["original_data_type"] = str(type(node))

        # 1) Flatten
        _flatten(raw, parent_key)

        # 2) Apply aliases so agents can find canonical dotted keys
        flat = cls._apply_aliases(flat)

        # Debug print
        top_keys = [k for k in flat.keys() if not k.startswith("_input_debug")]
        if parent_key == "":
            print(f"DEBUG: flatten_alert - received {len(top_keys)} top-level keys")

        return flat


    @classmethod
    def _extract_sha256_from_alert(cls, flat: Dict[str, Any]) -> str:
        """Extract file hash from flattened alert data with SHA256 -> SHA1 -> MD5 fallback"""
        
        # Priority 1: SHA256 (preferred for threat intelligence lookups)
        sha256_keys = [
            "file.hashes.sha256",
            "threat.sha256", 
            "file.sha256",
            "hash.sha256",
            "sha256",
            "threatInfo.sha256"
        ]
        
        print("Looking for SHA256 hash...")
        for key in sha256_keys:
            if key in flat and flat[key]:
                hash_value = str(flat[key]).lower().strip()
                if len(hash_value) == 64 and all(c in '0123456789abcdef' for c in hash_value):
                    print(f"Found SHA256 hash: {hash_value[:16]}...")
                    return hash_value
        
        # Also check for any key containing 'sha256'
        for key, value in flat.items():
            if 'sha256' in key.lower() and value:
                hash_value = str(value).lower().strip()
                if len(hash_value) == 64 and all(c in '0123456789abcdef' for c in hash_value):
                    print(f"Found SHA256 hash in key '{key}': {hash_value[:16]}...")
                    return hash_value
        
        # Priority 2: SHA1 fallback
        sha1_keys = [
            "file.hashes.sha1",
            "threat.sha1",
            "file.sha1", 
            "hash.sha1",
            "sha1",
            "threatInfo.sha1"
        ]
        
        print("SHA256 not found, looking for SHA1 hash...")
        for key in sha1_keys:
            if key in flat and flat[key]:
                hash_value = str(flat[key]).lower().strip()
                if len(hash_value) == 40 and all(c in '0123456789abcdef' for c in hash_value):
                    print(f"Found SHA1 hash: {hash_value[:16]}...")
                    return hash_value
        
        # Also check for any key containing 'sha1'
        for key, value in flat.items():
            if 'sha1' in key.lower() and value:
                hash_value = str(value).lower().strip()
                if len(hash_value) == 40 and all(c in '0123456789abcdef' for c in hash_value):
                    print(f"Found SHA1 hash in key '{key}': {hash_value[:16]}...")
                    return hash_value
        
        # Priority 3: MD5 fallback (least preferred but still useful)
        md5_keys = [
            "file.hashes.md5",
            "threat.md5",
            "file.md5",
            "hash.md5", 
            "md5",
            "threatInfo.md5"
        ]
        
        print("SHA1 not found, looking for MD5 hash...")
        for key in md5_keys:
            if key in flat and flat[key]:
                hash_value = str(flat[key]).lower().strip()
                if len(hash_value) == 32 and all(c in '0123456789abcdef' for c in hash_value):
                    print(f"Found MD5 hash: {hash_value[:16]}...")
                    return hash_value
        
        # Also check for any key containing 'md5'
        for key, value in flat.items():
            if 'md5' in key.lower() and value:
                hash_value = str(value).lower().strip()
                if len(hash_value) == 32 and all(c in '0123456789abcdef' for c in hash_value):
                    print(f"Found MD5 hash in key '{key}': {hash_value[:16]}...")
                    return hash_value
        
        # Last resort: look for any hash-like string (32, 40, or 64 hex chars)
        print("No standard hash found, scanning for hash-like values...")
        for key, value in flat.items():
            if value and isinstance(value, str):
                clean_value = str(value).lower().strip()
                if (len(clean_value) in [32, 40, 64] and 
                    all(c in '0123456789abcdef' for c in clean_value)):
                    hash_type = "MD5" if len(clean_value) == 32 else "SHA1" if len(clean_value) == 40 else "SHA256"
                    print(f"Found {hash_type}-like hash in key '{key}': {clean_value[:16]}...")
                    return clean_value
        
        print("No file hash found in alert data")
        return ""

    # AGENT 1: Heuristic Analysis
    @classmethod
    def score_agent1(cls, flat: Dict[str, Any]) -> Dict[str, dict]:
        """Agent1: Heuristic-based scoring from alert metadata analysis - All attributes evaluated"""
        scores = {}
        
        print("=== AGENT1 SCORING START (Heuristic Analysis) ===")
        print(f"Available keys ({len(flat)}): {sorted(flat.keys())}")

        # 1. Severity scoring
        sev = 0
        sev_val = flat.get("severity_id", 0)
        try:
            sev = int(sev_val) if sev_val is not None else 0
        except (ValueError, TypeError):
            sev = 0
            
        scores["severity"] = {
            "value": sev,
            "risk_score": sev * 10,
            "description": f"Severity level {sev}"
        }
        print(f"✓ Severity: {sev} -> score: {sev * 10}")

        # 2. File signing verification
        fv = flat.get("file.verification.type", "")
        if isinstance(fv, str):
            fv = fv.lower()
        else:
            fv = str(fv).lower() if fv is not None else ""
            
        if fv == "notsigned":
            scores["file_signing"] = {
                "value": fv,
                "risk_score": 25,
                "description": "File is not signed"
            }
            print(f"✓ File signing: {fv} -> score: 25")
        elif fv == "signed":
            scores["file_signing"] = {
                "value": fv,
                "risk_score": -5,
                "description": "File is signed"
            }
            print(f"✓ File signing: {fv} -> score: -5")
        elif fv == "":
            scores["file_signing"] = {
                "value": "unknown",
                "risk_score": 0,
                "description": "File signing status unknown"
            }
            print(f"✓ File signing: unknown -> score: 0")
        else:
            scores["file_signing"] = {
                "value": fv,
                "risk_score": 0,
                "description": f"File signing status: {fv}"
            }
            print(f"✓ File signing: {fv} -> score: 0")

        # 3. Suspicious file path
        fp = flat.get("file.path", "")
        fp = str(fp) if fp is not None else ""
        if fp and cls.EVIL_PATH_REGEX.search(fp):
            scores["file_path"] = {
                "value": fp,
                "risk_score": 15,
                "description": "File located in suspicious directory"
            }
            print(f"✓ Suspicious file path: {fp} -> score: 15")
        elif fp:
            scores["file_path"] = {
                "value": fp,
                "risk_score": 0,
                "description": "File path appears normal"
            }
            print(f"✓ File path: normal -> score: 0")
        else:
            scores["file_path"] = {
                "value": "unknown",
                "risk_score": 0,
                "description": "File path not available"
            }
            print(f"✓ File path: not available -> score: 0")

        # 4. process (LOLBins)
        parent = flat.get("process.name", "")
        parent = str(parent).lower() if parent is not None else ""
        if parent and any(bin_name in parent for bin_name in cls.LOLBINS):
            scores["parent_process"] = {
                "value": parent,
                "risk_score": 20,
                "description": "Parent process is a known LOLBin"
            }
            print(f"✓ LOLBin parent process: {parent} -> score: 20")
        elif parent:
            scores["parent_process"] = {
                "value": parent,
                "risk_score": 0,
                "description": "Parent process appears normal"
            }
            print(f"✓ Parent process: normal -> score: 0")
        else:
            scores["parent_process"] = {
                "value": "unknown",
                "risk_score": 0,
                "description": "Parent process not available"
            }
            print(f"✓ Parent process: not available -> score: 0")

        # 5. Command line patterns
        cli = flat.get("process.cmd.args")
        cli = str(cli) if cli is not None else ""
        if cli and cli != "None" and cls.SUSP_ARGS_RE.search(cli):
            scores["command_line"] = {
                "value": cli,
                "risk_score": 15,
                "description": "Contains suspicious command line patterns"
            }
            print(f"✓ Suspicious command line -> score: 15")
        elif cli and cli != "None":
            scores["command_line"] = {
                "value": cli,
                "risk_score": 0,
                "description": "Command line appears normal"
            }
            print(f"✓ Command line: normal -> score: 0")
        else:
            scores["command_line"] = {
                "value": "unknown",
                "risk_score": 0,
                "description": "Command line not available"
            }
            print(f"✓ Command line: not available -> score: 0")

        # 6. Threat confidence - Fixed logic
        conf_raw = flat.get("threat.confidence")
        conf = ""
        risk_score = 0
        
        if isinstance(conf_raw, str):
            conf = conf_raw.lower()
            risk_score = cls.CONF_WEIGHTS.get(conf, 0)
        elif isinstance(conf_raw, (int, float)):
            # Convert numeric confidence to string categories
            conf_num = float(conf_raw)
            if conf_num >= 90:
                conf = "malicious"
                risk_score = cls.CONF_WEIGHTS.get("malicious", 10)
            elif conf_num >= 70:
                conf = "suspicious" 
                risk_score = cls.CONF_WEIGHTS.get("suspicious", 5)
            else:
                conf = f"low_confidence_{conf_num}"
                risk_score = 0
        elif conf_raw is not None:
            conf = str(conf_raw).lower()
            risk_score = cls.CONF_WEIGHTS.get(conf, 0)
        else:
            conf = "unknown"
            risk_score = 0
            
        scores["confidence_level"] = {
            "value": conf,
            "risk_score": risk_score,
            "description": f"Vendor confidence: {conf}"
        }
        print(f"✓ Threat confidence: {conf_raw} -> {conf} -> score: {risk_score}")

        # 7. Detection engine
        # Try multiple possible paths for detection engine
        engine_candidates = [
            flat.get("metadata.product.feature.name"),
            flat.get("detection_engine"),
            flat.get("engine.name"),
            flat.get("detection.engine"),
            flat.get("source.engine")
        ]
        
        e_name = "unknown"
        for candidate in engine_candidates:
            if candidate:
                if isinstance(candidate, list) and len(candidate) > 0:
                    if isinstance(candidate[0], dict) and "title" in candidate[0]:
                        e_name = candidate[0]["title"]
                        break
                    elif isinstance(candidate[0], str):
                        e_name = candidate[0]
                        break
                elif isinstance(candidate, str):
                    e_name = candidate
                    break
        
        engine_score = cls.weight_engine(e_name)
        scores["detection_engine"] = {
            "value": e_name,
            "risk_score": engine_score,
            "description": f"Detected by: {e_name}"
        }
        print(f"✓ Detection engine: {e_name} -> score: {engine_score}")

        # 8. Asset type
        asset = flat.get("device.type", "")
        asset = str(asset).lower() if asset is not None else ""
        asset_score = cls.ASSET_WEIGHTS.get(asset, 0)
        if not asset:
            asset = "unknown"
            asset_score = 0
            
        scores["asset_type"] = {
            "value": asset,
            "risk_score": asset_score,
            "description": f"Asset type: {asset}"
        }
        print(f"✓ Asset type: {asset} -> score: {asset_score}")

        # 9. Process user privileges
        user_candidates = [
            flat.get("actor.process.user.name"),
            flat.get("process.user.name"),
            flat.get("user.name"),
            flat.get("process_user")
        ]
        
        process_user = ""
        for candidate in user_candidates:
            if candidate and str(candidate) != "None":
                process_user = str(candidate)
                break
        
        if process_user and process_user.lower() in ["system", "administrator", "root"]:
            scores["process_user"] = {
                "value": process_user,
                "risk_score": 10,
                "description": "Process running with elevated privileges"
            }
            print(f"✓ Elevated process user: {process_user} -> score: 10")
        elif process_user:
            scores["process_user"] = {
                "value": process_user,
                "risk_score": 0,
                "description": "Process running with normal user privileges"
            }
            print(f"✓ Normal process user: {process_user} -> score: 0")
        else:
            scores["process_user"] = {
                "value": "unknown",
                "risk_score": 0,
                "description": "Process user not available"
            }
            print(f"✓ Process user: not available -> score: 0")

        # Calculate total and show summary
        agent1_total = sum(score_data.get("risk_score", 0) for score_data in scores.values())
        
        print("\n--- AGENT1 SCORING SUMMARY ---")
        for attr_name, attr_data in scores.items():
            print(f"  {attr_name}: {attr_data['risk_score']} points - {attr_data['description']}")
        
        print(f"=== AGENT1 TOTAL SCORE: {agent1_total} ===")
        print(f"=== AGENT1 ATTRIBUTES EVALUATED: {len(scores)}/9 ===")
        
        return scores

    # AGENT 2: VirusTotal Analysis
    async def score_agent2_virustotal(self, flat: Dict[str, Any]) -> Dict[str, dict]:
        """Agent2: Enhanced VirusTotal-based scoring with comprehensive analysis"""
        scores = {}
        
        print("=== AGENT2 SCORING START (Enhanced VirusTotal Analysis) ===")
        print(f"Available keys: {list(flat.keys())}")

        # Extract SHA256 hash from alert
        sha256_hash = self._extract_sha256_from_alert(flat)
        
        if not sha256_hash:
            print("No SHA256 hash found in alert data")
            scores["vt_no_hash"] = {
                "value": "No hash available",
                "risk_score": 0,
                "description": "No SHA256 hash found for VirusTotal lookup"
            }
            return scores

        print(f"Found SHA256 hash: {sha256_hash}")

        try:
            enrichment_result = await self.mcp_client.enrich_alert(
                sha256_hash, 
                prompt_type="enrich_virustotal"
            )
            
            if "error" in enrichment_result:
                print(f"VirusTotal enrichment failed: {enrichment_result['error']}")
                scores["vt_error"] = {
                    "value": enrichment_result.get("error", "unknown_error"),
                    "risk_score": 5,
                    "description": f"VirusTotal lookup failed: {enrichment_result.get('error', 'unknown')}"
                }
                return scores

            # Process VirusTotal results with enhanced scoring
            vt_data = enrichment_result.get("virustotal", {})
            if vt_data.get("found"):
                vt_scores = self._process_virustotal_data_enhanced(vt_data)
                scores.update(vt_scores)
                print(f"✓ VirusTotal: Added {len(vt_scores)} enhanced risk indicators")
            else:
                scores["vt_not_found"] = {
                    "value": "File not found in VirusTotal",
                    "risk_score": 8,  # Increased from 2 - unknown files are riskier
                    "description": "File hash not found in VirusTotal database (potentially new/rare malware)"
                }

        except Exception as e:
            print(f"VirusTotal communication error: {str(e)}")
            scores["vt_communication_error"] = {
                "value": str(e),
                "risk_score": 10,  # Increased from 5
                "description": f"Failed to communicate with VirusTotal: {str(e)}"
            }

        agent2_total = sum(score_data.get("risk_score", 0) for score_data in scores.values())
        
        print("\n--- AGENT2 SCORING SUMMARY ---")
        for attr_name, attr_data in scores.items():
            print(f"  {attr_name}: {attr_data['risk_score']} points - {attr_data['description']}")
        
        print(f"=== AGENT2 (Enhanced VirusTotal) TOTAL SCORE: {agent2_total} ===")
        return scores

    def _process_virustotal_data_enhanced(self, vt_data: dict) -> dict:
        """Enhanced VirusTotal data processing with comprehensive scoring (max ~100 points)"""
        scores = {}
        
        if not vt_data.get("found") or "json" not in vt_data:
            return scores
            
        attributes = vt_data.get("json", {}).get("data", {}).get("attributes", {})
        if not attributes:
            return scores

        print("Processing enhanced VirusTotal analysis...")

        # 1. MALICIOUS DETECTIONS (0-40 points) - Primary indicator
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        malicious_count = last_analysis_stats.get("malicious", 0)
        total_engines = sum(last_analysis_stats.values()) if last_analysis_stats else 1
        
        if malicious_count > 0:
            # Enhanced scoring: higher impact for more detections
            base_score = min(malicious_count * 0.6, 35)  # 0.6 per detection, max 35
            detection_ratio = malicious_count / max(total_engines, 1)
            
            # Bonus for high detection ratio
            if detection_ratio > 0.8:  # >80% detection rate
                base_score += 15
            elif detection_ratio > 0.6:  # >60% detection rate  
                base_score += 10
            elif detection_ratio > 0.4:  # >40% detection rate
                base_score += 5
                
            final_score = min(base_score, 40)
            scores["vt_malicious_detections"] = {
                "value": f"{malicious_count}/{total_engines}",
                "risk_score": final_score,
                "description": f"VirusTotal malicious detections: {malicious_count}/{total_engines} engines ({detection_ratio*100:.1f}%)"
            }

        # 2. SUSPICIOUS DETECTIONS (0-15 points)
        suspicious_count = last_analysis_stats.get("suspicious", 0)
        if suspicious_count > 0:
            risk_score = min(suspicious_count * 0.8, 15)
            scores["vt_suspicious_detections"] = {
                "value": suspicious_count,
                "risk_score": risk_score,
                "description": f"VirusTotal suspicious detections: {suspicious_count}"
            }

        # 3. TIMEOUT DETECTIONS (0-12 points) - Evasion indicator
        timeout_count = last_analysis_stats.get("timeout", 0)
        if timeout_count > 0:
            risk_score = min(timeout_count * 1.2, 12)
            scores["vt_timeout_detections"] = {
                "value": timeout_count,
                "risk_score": risk_score,
                "description": f"VirusTotal timeout detections: {timeout_count} (potential evasion)"
            }

        # 4. THREAT SEVERITY (0-25 points)
        threat_severity = attributes.get("threat_severity", {})
        if threat_severity:
            severity_level = threat_severity.get("threat_severity_level", "")
            severity_data = threat_severity.get("threat_severity_data", {})
            
            if "HIGH" in severity_level or "CRITICAL" in severity_level:
                risk_score = 25
                scores["vt_threat_severity_high"] = {
                    "value": severity_level,
                    "risk_score": risk_score,
                    "description": f"VirusTotal critical/high threat severity: {severity_level}"
                }
            elif "MEDIUM" in severity_level:
                risk_score = 15
                scores["vt_threat_severity_medium"] = {
                    "value": severity_level,
                    "risk_score": risk_score,
                    "description": f"VirusTotal medium threat severity: {severity_level}"
                }

        # 5. POPULAR THREAT CLASSIFICATION (0-20 points)
        popular_threat = attributes.get("popular_threat_classification", {})
        if popular_threat:
            suggested_threat_label = popular_threat.get("suggested_threat_label", "")
            popular_categories = popular_threat.get("popular_threat_category", [])
            
            high_risk_categories = ["trojan", "malware", "virus", "backdoor", "ransomware", "rootkit", "worm"]
            medium_risk_categories = ["adware", "pup", "potentially unwanted", "suspicious"]
            
            max_category_score = 0
            detected_category = ""
            
            for category_info in popular_categories:
                if isinstance(category_info, dict):
                    category = category_info.get("value", "").lower()
                    count = category_info.get("count", 0)
                    
                    if any(risk_cat in category for risk_cat in high_risk_categories):
                        category_score = min(15 + (count * 0.5), 20)
                        if category_score > max_category_score:
                            max_category_score = category_score
                            detected_category = f"{category} ({count})"
                    elif any(risk_cat in category for risk_cat in medium_risk_categories):
                        category_score = min(8 + (count * 0.3), 12)
                        if category_score > max_category_score:
                            max_category_score = category_score
                            detected_category = f"{category} ({count})"
            
            if max_category_score > 0:
                scores["vt_threat_classification"] = {
                    "value": detected_category,
                    "risk_score": max_category_score,
                    "description": f"VirusTotal threat classification: {detected_category}"
                }

        # 6. SANDBOX VERDICTS (0-18 points)
        sandbox_verdicts = attributes.get("sandbox_verdicts", {})
        malicious_sandbox_count = 0
        suspicious_sandbox_count = 0
        
        for sandbox_name, verdict in sandbox_verdicts.items():
            if isinstance(verdict, dict):
                category = verdict.get("category", "").lower()
                if category == "malicious":
                    malicious_sandbox_count += 1
                elif category == "suspicious":
                    suspicious_sandbox_count += 1
        
        if malicious_sandbox_count > 0:
            risk_score = min(malicious_sandbox_count * 6, 18)
            scores["vt_malicious_sandbox"] = {
                "value": malicious_sandbox_count,
                "risk_score": risk_score,
                "description": f"Malicious sandbox verdicts: {malicious_sandbox_count}"
            }
        elif suspicious_sandbox_count > 0:
            risk_score = min(suspicious_sandbox_count * 3, 10)
            scores["vt_suspicious_sandbox"] = {
                "value": suspicious_sandbox_count,
                "risk_score": risk_score,
                "description": f"Suspicious sandbox verdicts: {suspicious_sandbox_count}"
            }

        # 7. YARA RULE MATCHES (0-15 points)
        yara_results = attributes.get("crowdsourced_yara_results", [])
        if yara_results:
            exploit_count = 0
            malware_count = 0
            total_yara = len(yara_results)
            
            for yara_rule in yara_results:
                if isinstance(yara_rule, dict):
                    rule_name = yara_rule.get("rule_name", "").lower()
                    description = yara_rule.get("description", "").lower()
                    
                    if any(keyword in rule_name or keyword in description 
                        for keyword in ["exploit", "cve", "apt", "backdoor"]):
                        exploit_count += 1
                    elif any(keyword in rule_name or keyword in description 
                            for keyword in ["malware", "trojan", "virus"]):
                        malware_count += 1
            
            if exploit_count > 0:
                risk_score = min(exploit_count * 8, 15)
                scores["vt_exploit_yara"] = {
                    "value": f"{exploit_count}/{total_yara}",
                    "risk_score": risk_score,
                    "description": f"VirusTotal exploit YARA matches: {exploit_count}/{total_yara}"
                }
            elif malware_count > 0:
                risk_score = min(malware_count * 4, 10)
                scores["vt_malware_yara"] = {
                    "value": f"{malware_count}/{total_yara}",
                    "risk_score": risk_score,
                    "description": f"VirusTotal malware YARA matches: {malware_count}/{total_yara}"
                }
            elif total_yara > 0:
                risk_score = min(total_yara * 1, 5)
                scores["vt_generic_yara"] = {
                    "value": total_yara,
                    "risk_score": risk_score,
                    "description": f"VirusTotal generic YARA matches: {total_yara}"
                }

        # 8. REPUTATION SCORE (0-12 points)
        reputation = attributes.get("reputation", 0)
        if reputation < 0:
            risk_score = min(abs(reputation) * 0.2, 12)
            scores["vt_negative_reputation"] = {
                "value": reputation,
                "risk_score": risk_score,
                "description": f"VirusTotal negative reputation: {reputation}"
            }

        # 9. FILE AGE AND SUBMISSION PATTERNS (0-10 points)
        first_submission_date = attributes.get("first_submission_date")
        times_submitted = attributes.get("times_submitted", 0)
        
        if first_submission_date and times_submitted:
            import time
            current_time = int(time.time())
            file_age_days = (current_time - first_submission_date) / 86400
            
            # Recent files with many submissions = suspicious
            if file_age_days < 30 and times_submitted > 100:
                risk_score = 10
                scores["vt_recent_popular"] = {
                    "value": f"{times_submitted} submissions, {file_age_days:.0f} days old",
                    "risk_score": risk_score,
                    "description": f"Recently discovered file with high submission rate: {times_submitted} submissions in {file_age_days:.0f} days"
                }
            elif file_age_days < 7 and times_submitted > 50:
                risk_score = 8
                scores["vt_very_recent"] = {
                    "value": f"{times_submitted} submissions, {file_age_days:.0f} days old",
                    "risk_score": risk_score,
                    "description": f"Very recent file with notable submission rate: {times_submitted} submissions in {file_age_days:.0f} days"
                }

        # 10. SIGNATURE VERIFICATION ISSUES (0-8 points)
        signature_info = attributes.get("signature_info", {})
        if signature_info:
            # Check for signature issues
            copyright_info = signature_info.get("copyright", "")
            product = signature_info.get("product", "")
            
            # Suspicious copyright or product names
            suspicious_signatures = ["microsoft", "adobe", "google", "apple"]
            if any(susp in copyright_info.lower() for susp in suspicious_signatures) or \
            any(susp in product.lower() for susp in suspicious_signatures):
                # File claims to be from major vendor but is flagged as malicious
                if malicious_count > 0:
                    scores["vt_fake_signature"] = {
                        "value": f"{copyright_info or product}",
                        "risk_score": 8,
                        "description": f"Potentially fake signature from major vendor: {copyright_info or product}"
                    }

        # 11. HARMLESS DETECTIONS (negative score, reduces risk)
        harmless_count = last_analysis_stats.get("harmless", 0)
        if harmless_count > 10:  # Only if significant number of harmless verdicts
            risk_score = -min(harmless_count * 0.1, 5)
            scores["vt_harmless_detections"] = {
                "value": harmless_count,
                "risk_score": risk_score,
                "description": f"VirusTotal harmless detections: {harmless_count} (risk reduction)"
            }

        return scores

    # AGENT 3: Check Point Analysis
    async def score_agent3_checkpoint(self, flat: Dict[str, Any]) -> Dict[str, dict]:
        """Agent3: Check Point-based scoring using MCP integration"""
        scores = {}
        
        print("=== AGENT3 SCORING START (Check Point Analysis) ===")
        
        # Extract SHA256 hash from alert
        sha256_hash = self._extract_sha256_from_alert(flat)
        
        if not sha256_hash:
            print("No SHA256 hash found in alert data")
            scores["cp_no_hash"] = {
                "value": "No hash available",
                "risk_score": 0,
                "description": "No SHA256 hash found for Check Point lookup"
            }
            return scores

        print(f"Found SHA256 hash: {sha256_hash}")

        try:
            enrichment_result = await self.mcp_client.enrich_alert(
                sha256_hash, 
                prompt_type="enrich_checkpoint"
            )
            
            if "error" in enrichment_result:
                print(f"Check Point enrichment failed: {enrichment_result['error']}")
                scores["cp_error"] = {
                    "value": enrichment_result.get("error", "unknown_error"),
                    "risk_score": 5,
                    "description": f"Check Point lookup failed: {enrichment_result.get('error', 'unknown')}"
                }
                return scores

            # Process Check Point results
            cp_data = enrichment_result.get("checkpoint", {})
            if cp_data.get("found"):
                cp_scores = self._process_checkpoint_data(cp_data)
                scores.update(cp_scores)
                print(f"✓ Check Point: Added {len(cp_scores)} risk indicators")
            else:
                scores["cp_not_found"] = {
                    "value": "File not found in Check Point",
                    "risk_score": 2,
                    "description": "File hash not found in Check Point database"
                }

        except Exception as e:
            print(f"Check Point communication error: {str(e)}")
            scores["cp_communication_error"] = {
                "value": str(e),
                "risk_score": 5,
                "description": f"Failed to communicate with Check Point: {str(e)}"
            }

        agent3_total = sum(score_data.get("risk_score", 0) for score_data in scores.values())
        
        print(f"=== AGENT3 (Check Point) TOTAL SCORE: {agent3_total} ===")
        return scores

    # AGENT 4: Cyberint Analysis
    async def score_agent4_cyberint(self, flat: Dict[str, Any]) -> Dict[str, dict]:
        """Agent4: Cyberint-based scoring using MCP integration"""
        scores = {}
        
        print("=== AGENT4 SCORING START (Cyberint Analysis) ===")
        
        # Extract SHA256 hash from alert
        sha256_hash = self._extract_sha256_from_alert(flat)
        
        if not sha256_hash:
            print("No SHA256 hash found in alert data")
            scores["cyb_no_hash"] = {
                "value": "No hash available",
                "risk_score": 0,
                "description": "No SHA256 hash found for Cyberint lookup"
            }
            return scores

        print(f"Found SHA256 hash: {sha256_hash}")

        try:
            enrichment_result = await self.mcp_client.enrich_alert(
                sha256_hash, 
                prompt_type="enrich_cyberint"
            )
            
            if "error" in enrichment_result:
                print(f"Cyberint enrichment failed: {enrichment_result['error']}")
                scores["cyb_error"] = {
                    "value": enrichment_result.get("error", "unknown_error"),
                    "risk_score": 5,
                    "description": f"Cyberint lookup failed: {enrichment_result.get('error', 'unknown')}"
                }
                return scores

            # Process Cyberint results
            cyb_data = enrichment_result.get("cyberint", {})
            if cyb_data.get("found"):
                cyb_scores = self._process_cyberint_data(cyb_data)
                scores.update(cyb_scores)
                print(f"✓ Cyberint: Added {len(cyb_scores)} risk indicators")
            else:
                scores["cyb_not_found"] = {
                    "value": "File not found in Cyberint",
                    "risk_score": 2,
                    "description": "File hash not found in Cyberint database"
                }

        except Exception as e:
            print(f"Cyberint communication error: {str(e)}")
            scores["cyb_communication_error"] = {
                "value": str(e),
                "risk_score": 5,
                "description": f"Failed to communicate with Cyberint: {str(e)}"
            }

        agent4_total = sum(score_data.get("risk_score", 0) for score_data in scores.values())
        print(f"=== AGENT4 (Cyberint) TOTAL SCORE: {agent4_total} ===")
        return scores

    def _process_virustotal_data(self, vt_data: dict) -> dict:
        """Process VirusTotal data from MCP response with enhanced scoring logic"""
        scores = {}
        
        if not vt_data.get("found") or "json" not in vt_data:
            return scores
            
        attributes = vt_data.get("json", {}).get("data", {}).get("attributes", {})
        if not attributes:
            return scores

        # 1. Malicious detections - Primary indicator
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        malicious_count = last_analysis_stats.get("malicious", 0)
        
        if malicious_count > 0:
            # Logarithmic scaling: high impact for first few detections, diminishing returns
            risk_score = min(20 * math.log2(malicious_count + 1), 60)
            scores["vt_malicious_detections"] = {
                "value": malicious_count,
                "risk_score": risk_score,
                "description": f"VirusTotal malicious detections: {malicious_count}"
            }

        # 2. Suspicious detections
        suspicious_count = last_analysis_stats.get("suspicious", 0)
        if suspicious_count > 0:
            risk_score = min(10 * math.log2(suspicious_count + 1), 30)
            scores["vt_suspicious_detections"] = {
                "value": suspicious_count,
                "risk_score": risk_score,
                "description": f"VirusTotal suspicious detections: {suspicious_count}"
            }

        # 3. Reputation score (negative values indicate bad reputation)
        reputation = attributes.get("reputation", 0)
        if reputation < 0:
            risk_score = min(abs(reputation) * 0.1, 25)  # Scale down the impact
            scores["vt_negative_reputation"] = {
                "value": reputation,
                "risk_score": risk_score,
                "description": f"VirusTotal negative reputation: {reputation}"
            }

        # 4. Threat severity (new scoring based on your data)
        threat_severity = attributes.get("threat_severity", {})
        if threat_severity:
            severity_level = threat_severity.get("threat_severity_level", "")
            if "HIGH" in severity_level:
                scores["vt_threat_severity_high"] = {
                    "value": severity_level,
                    "risk_score": 35,
                    "description": f"VirusTotal threat severity: {severity_level}"
                }
            elif "MEDIUM" in severity_level:
                scores["vt_threat_severity_medium"] = {
                    "value": severity_level,
                    "risk_score": 20,
                    "description": f"VirusTotal threat severity: {severity_level}"
                }

        # 5. Sandbox verdicts (malicious category)
        sandbox_verdicts = attributes.get("sandbox_verdicts", {})
        malicious_sandbox_count = 0
        for sandbox_name, verdict in sandbox_verdicts.items():
            if verdict.get("category") == "malicious":
                malicious_sandbox_count += 1
        
        if malicious_sandbox_count > 0:
            risk_score = min(malicious_sandbox_count * 8, 25)
            scores["vt_malicious_sandbox"] = {
                "value": malicious_sandbox_count,
                "risk_score": risk_score,
                "description": f"Malicious sandbox verdicts: {malicious_sandbox_count}"
            }

        # 6. Crowdsourced YARA results indicating exploits
        yara_results = attributes.get("crowdsourced_yara_results", [])
        exploit_yara_count = 0
        for yara_rule in yara_results:
            rule_name = yara_rule.get("rule_name", "").lower()
            description = yara_rule.get("description", "").lower()
            if any(keyword in rule_name or keyword in description 
                   for keyword in ["exploit", "cve", "follina", "ole"]):
                exploit_yara_count += 1
        
        if exploit_yara_count > 0:
            risk_score = min(exploit_yara_count * 12, 30)
            scores["vt_exploit_yara"] = {
                "value": exploit_yara_count,
                "risk_score": risk_score,
                "description": f"Exploit-related YARA rules: {exploit_yara_count}"
            }
        
        return scores

    def _process_checkpoint_data(self, cp_data: dict) -> dict:
        """Process Check Point data from MCP response with enhanced scoring logic"""
        scores = {}
        
        if not cp_data.get("found"):
            return scores

        print("Processing Check Point analysis...")

        # Extract the main response data
        json_data = cp_data.get("json", {})
        
        # 1. RISK SCORE (0-40 points) - Primary indicator
        risk_score = json_data.get("risk", 0)
        if risk_score and isinstance(risk_score, (int, float)):
            # Scale risk score: 0-100 -> 0-40 points (primary weight)
            scaled_risk = min(risk_score * 0.4, 40)
            scores["cp_risk_score"] = {
                "value": risk_score,
                "risk_score": scaled_risk,
                "description": f"Check Point risk score: {risk_score}"
            }
            print(f"✓ Risk score: {risk_score} -> {scaled_risk} points")

        # 2. REPUTATION ANALYSIS (0-35 points)
        reputation = json_data.get("reputation", {})
        if reputation:
            classification = reputation.get("classification", "").lower()
            confidence = reputation.get("confidence", "").lower()
            severity = reputation.get("severity", "").lower()
            
            # Classification scoring
            classification_score = 0
            if classification == "malware":
                classification_score = 25
            elif classification in ["suspicious", "potentially unwanted"]:
                classification_score = 15
            elif classification == "unknown":
                classification_score = 5
            
            # Confidence modifier
            confidence_multiplier = 1.0
            if confidence == "high":
                confidence_multiplier = 1.0
            elif confidence == "medium":
                confidence_multiplier = 0.8
            elif confidence == "low":
                confidence_multiplier = 0.6
            
            # Severity bonus
            severity_bonus = 0
            if severity == "high":
                severity_bonus = 10
            elif severity == "medium":
                severity_bonus = 5
            
            final_reputation_score = min((classification_score * confidence_multiplier) + severity_bonus, 35)
            
            scores["cp_reputation"] = {
                "value": f"{classification} ({confidence} confidence, {severity} severity)",
                "risk_score": final_reputation_score,
                "description": f"Check Point reputation: {classification} with {confidence} confidence and {severity} severity"
            }
            print(f"✓ Reputation: {classification}/{confidence}/{severity} -> {final_reputation_score} points")

        # 3. MALWARE CONTEXT (0-20 points)
        context = json_data.get("context", {})
        if context:
            context_score = 0
            context_indicators = []
            
            # Malware family
            malware_family = context.get("malware_family", "")
            if malware_family and malware_family.lower() != "generic":
                context_score += 8
                context_indicators.append(f"family: {malware_family}")
            elif malware_family and malware_family.lower() == "generic":
                context_score += 4
                context_indicators.append("generic family")
            
            # Protection name (indicates specific detection)
            protection_name = context.get("protection_name", "")
            if protection_name:
                context_score += 6
                context_indicators.append("protection rule")
            
            # Malware types
            malware_types = context.get("malware_types", [])
            if malware_types:
                high_risk_types = ["trojan", "backdoor", "ransomware", "rootkit", "virus", "worm"]
                medium_risk_types = ["adware", "pup", "spyware"]
                
                for malware_type in malware_types:
                    if malware_type.lower() in high_risk_types:
                        context_score += 6
                        context_indicators.append(f"high-risk: {malware_type}")
                    elif malware_type.lower() in medium_risk_types:
                        context_score += 3
                        context_indicators.append(f"medium-risk: {malware_type}")
            
            if context_score > 0:
                final_context_score = min(context_score, 20)
                scores["cp_malware_context"] = {
                    "value": ", ".join(context_indicators),
                    "risk_score": final_context_score,
                    "description": f"Check Point malware context: {', '.join(context_indicators)}"
                }
                print(f"✓ Malware context: {context_indicators} -> {final_context_score} points")

        # 4. DETECTION FINDINGS (0-15 points)
        findings = json_data.get("findings", {})
        if findings:
            total_engines = findings.get("total", 0)
            positive_detections = findings.get("positives", 0)
            
            if total_engines > 0 and positive_detections > 0:
                detection_ratio = positive_detections / total_engines
                
                # Base score from positive detections
                base_score = min(positive_detections * 0.2, 10)
                
                # Bonus for high detection ratio
                ratio_bonus = 0
                if detection_ratio >= 0.8:  # >80% detection rate
                    ratio_bonus = 5
                elif detection_ratio >= 0.6:  # >60% detection rate
                    ratio_bonus = 3
                elif detection_ratio >= 0.4:  # >40% detection rate
                    ratio_bonus = 2
                
                final_findings_score = min(base_score + ratio_bonus, 15)
                
                scores["cp_detection_findings"] = {
                    "value": f"{positive_detections}/{total_engines} ({detection_ratio*100:.1f}%)",
                    "risk_score": final_findings_score,
                    "description": f"Check Point detections: {positive_detections}/{total_engines} engines ({detection_ratio*100:.1f}%)"
                }
                print(f"✓ Detection findings: {positive_detections}/{total_engines} -> {final_findings_score} points")

        # 5. FILE AGE ANALYSIS (0-10 points)
        if findings:
            first_seen = findings.get("first_seen", "")
            file_size = findings.get("file_size", 0)
            file_type = findings.get("file_type", "")
            
            age_score = 0
            age_indicators = []
            
            # Analyze first_seen date
            if first_seen:
                try:
                    from datetime import datetime
                    first_seen_date = datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S")
                    current_date = datetime.now()
                    age_days = (current_date - first_seen_date).days
                    
                    if age_days > 365 * 5:  # Very old malware (>5 years)
                        age_score += 3
                        age_indicators.append(f"old malware ({age_days} days)")
                    elif age_days < 30:  # Very recent discovery
                        age_score += 5
                        age_indicators.append(f"recent discovery ({age_days} days)")
                    elif age_days < 365:  # Recent malware
                        age_score += 2
                        age_indicators.append(f"recent malware ({age_days} days)")
                        
                except Exception as e:
                    print(f"Date parsing error: {e}")
            
            # File type analysis
            if file_type:
                executable_types = ["exe", "dll", "scr", "com", "bat", "cmd", "pif"]
                if any(exe_type in file_type.lower() for exe_type in executable_types):
                    age_score += 3
                    age_indicators.append(f"executable: {file_type}")
            
            # Suspicious file size patterns
            if file_size:
                if file_size < 1024:  # Very small files can be droppers
                    age_score += 2
                    age_indicators.append("very small file")
                elif file_size > 10 * 1024 * 1024:  # Very large files
                    age_score += 1
                    age_indicators.append("large file")
            
            if age_score > 0:
                final_age_score = min(age_score, 10)
                scores["cp_file_analysis"] = {
                    "value": ", ".join(age_indicators),
                    "risk_score": final_age_score,
                    "description": f"Check Point file analysis: {', '.join(age_indicators)}"
                }
                print(f"✓ File analysis: {age_indicators} -> {final_age_score} points")

        # 6. STATUS VALIDATION (negative score for errors)
        status = json_data.get("status", {})
        if status:
            status_code = status.get("code", 0)
            status_label = status.get("label", "")
            
            if status_code != 2001 or status_label != "SUCCESS":
                scores["cp_status_error"] = {
                    "value": f"Code: {status_code}, Label: {status_label}",
                    "risk_score": 5,  # Small penalty for API errors
                    "description": f"Check Point API status issue: {status_code} - {status_label}"
                }

        # Calculate total and apply 100-point cap (though Check Point should stay well under)
        raw_total = sum(score_data.get("risk_score", 0) for score_data in scores.values())
        
        # APPLY 100-POINT CAP: If total exceeds 100, scale down proportionally
        if raw_total > 100:
            scaling_factor = 100 / raw_total
            print(f"Check Point raw score {raw_total} exceeds 100, applying scaling factor: {scaling_factor:.3f}")
            
            for score_key, score_data in scores.items():
                original_score = score_data["risk_score"]
                scaled_score = original_score * scaling_factor
                scores[score_key]["risk_score"] = scaled_score
                scores[score_key]["description"] += f" (scaled from {original_score:.1f})"
                print(f"  {score_key}: {original_score:.1f} -> {scaled_score:.1f}")
        
        final_total = sum(score_data.get("risk_score", 0) for score_data in scores.values())
        print(f"Check Point final score: {final_total:.1f}")
        
        return scores

    def _process_cyberint_data(self, cyb_data: dict) -> dict:
        """Process Cyberint data from MCP response with enhanced scoring logic"""
        scores = {}
        
        if not cyb_data.get("found"):
            return scores

        # Handle both summary and json formats
        summary = cyb_data.get("summary", {})
        json_data = cyb_data.get("json", {}).get("data", {})

        # 1. Malicious score (direct numerical indicator)
        malicious_score = None
        if summary and "risk" in summary:
            risk_data = summary["risk"]
            if isinstance(risk_data, dict):
                malicious_score = risk_data.get("malicious_score")
            elif isinstance(risk_data, (int, float)):
                malicious_score = risk_data

        if malicious_score and isinstance(malicious_score, (int, float)):
            # Scale malicious score: 0-100 -> 0-50 points
            risk_score = min(malicious_score * 0.5, 50)
            scores["cyb_malicious_score"] = {
                "value": malicious_score,
                "risk_score": risk_score,
                "description": f"Cyberint malicious score: {malicious_score}"
            }

        # 2. Risk classification from JSON data
        risk_info = json_data.get("risk", {})
        detected_activities = risk_info.get("detected_activities", [])
        
        malware_activities = 0
        payload_activities = 0
        high_confidence_activities = 0
        
        for activity in detected_activities:
            activity_type = activity.get("type", "")
            confidence = activity.get("confidence", 0)
            occurrences = activity.get("occurrences_count", 0)
            
            if activity_type == "malware":
                malware_activities += 1
                if confidence >= 90:
                    high_confidence_activities += 1
            elif activity_type == "malware_payload":
                payload_activities += 1

        # Score based on detected activities
        if malware_activities > 0:
            base_score = malware_activities * 25
            if high_confidence_activities > 0:
                base_score += 10  # Bonus for high confidence
            scores["cyb_malware_activities"] = {
                "value": malware_activities,
                "risk_score": min(base_score, 45),
                "description": f"Cyberint detected {malware_activities} malware activities"
            }

        if payload_activities > 0:
            scores["cyb_payload_activities"] = {
                "value": payload_activities,
                "risk_score": min(payload_activities * 15, 30),
                "description": f"Cyberint detected {payload_activities} malware payload activities"
            }

        # 3. Overall risk assessment from risk object
        overall_risk = risk_info.get("malicious_score", 0)
        if overall_risk >= 80:
            scores["cyb_high_risk"] = {
                "value": overall_risk,
                "risk_score": 35,
                "description": f"Cyberint very high risk assessment: {overall_risk}"
            }
        elif overall_risk >= 60:
            scores["cyb_medium_risk"] = {
                "value": overall_risk,
                "risk_score": 20,
                "description": f"Cyberint high risk assessment: {overall_risk}"
            }

        # 4. Enrichment data - related entities and filenames
        enrichment = json_data.get("enrichment", {})
        filenames = enrichment.get("filenames", [])
        
        # Look for suspicious filename patterns
        suspicious_filename_count = 0
        if filenames:
            for filename in filenames:
                if isinstance(filename, str):
                    filename_lower = filename.lower()
                    # Check for suspicious patterns
                    if any(pattern in filename_lower for pattern in ["malware", "trojan", "sample", "virus", "exploit"]):
                        suspicious_filename_count += 1

        if suspicious_filename_count > 0:
            risk_score = min(suspicious_filename_count * 5, 15)
            scores["cyb_suspicious_filenames"] = {
                "value": suspicious_filename_count,
                "risk_score": risk_score,
                "description": f"Cyberint found {suspicious_filename_count} suspicious filename patterns"
            }

        # 5. Classification from summary (fallback)
        classification = summary.get("classification")
        if classification and isinstance(classification, str):
            classification_lower = classification.lower()
            if classification_lower in ["malware", "trojan", "virus", "backdoor"]:
                scores["cyb_malware_classification"] = {
                    "value": classification,
                    "risk_score": 40,
                    "description": f"Cyberint classification: {classification}"
                }
            elif classification_lower in ["suspicious", "potentially_unwanted", "adware"]:
                scores["cyb_suspicious_classification"] = {
                    "value": classification,
                    "risk_score": 20,
                    "description": f"Cyberint classification: {classification}"
                }

        return scores


class TriageAgent:
    """Enhanced Agent specialized in alert triage using multi-agent analysis"""
    
    def __init__(self, mcp_server_path: str = "server.py"):
        self.role = "Multi-Agent Alert Triage Specialist - Uses Agent1 (Heuristic), Agent2 (VirusTotal), Agent3 (Check Point), Agent4 (Cyberint)"
        self.tools = ["ScoringTool", "SimpleMCPClient"]
        self.mcp_client = SimpleMCPClient(mcp_server_path)
        self.scoring_tool = ScoringTool(self.mcp_client)

    async def analyze_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze alert using four agents: Heuristic, VirusTotal, Check Point, and Cyberint"""
        
        print("=" * 70)
        print("STARTING ENHANCED MULTI-AGENT TRIAGE ANALYSIS")
        print("=" * 70)
        
        # Flatten and validate data
        flat_data = self.scoring_tool.flatten_alert(alert_data)
        
        if not flat_data:
            print("ERROR: No valid alert data received")
            return {
                "error": "No valid alert data provided",
                "timestamp_triage": datetime.utcnow().isoformat()
            }
        
        print(f"Processing alert with {len(flat_data)} fields")
        
        # Run all four scoring agents
        print("\n" + "="*50 + " AGENT1 (HEURISTIC) " + "="*50)
        agent1_scores = self.scoring_tool.score_agent1(flat_data)
        
        print("\n" + "="*50 + " AGENT2 (VIRUSTOTAL) " + "="*50)
        agent2_scores = await self.scoring_tool.score_agent2_virustotal(flat_data)
        
        print("\n" + "="*50 + " AGENT3 (CHECK POINT) " + "="*50)
        agent3_scores = await self.scoring_tool.score_agent3_checkpoint(flat_data)
        
        print("\n" + "="*50 + " AGENT4 (CYBERINT) " + "="*50)
        agent4_scores = await self.scoring_tool.score_agent4_cyberint(flat_data)
        
        # Calculate individual totals
        agent1_total = sum(attr_data.get("risk_score", 0) for attr_data in agent1_scores.values())
        agent2_total = sum(attr_data.get("risk_score", 0) for attr_data in agent2_scores.values())
        agent3_total = sum(attr_data.get("risk_score", 0) for attr_data in agent3_scores.values())
        agent4_total = sum(attr_data.get("risk_score", 0) for attr_data in agent4_scores.values())
        
        print(f"\n" + "="*50 + " FINAL SCORING CALCULATION " + "="*50)
        print(f"Agent1 (Heuristic) Raw Total: {agent1_total}")
        print(f"Agent2 (VirusTotal) Raw Total: {agent2_total}")
        print(f"Agent3 (Check Point) Raw Total: {agent3_total}")
        print(f"Agent4 (Cyberint) Raw Total: {agent4_total}")
        
        # Apply weightings: 25% Agent1, 35% Agent2, 20% Agent3, 20% Agent4
        weighted_agent1 = agent1_total * 0.25
        weighted_agent2 = agent2_total * 0.35
        weighted_agent3 = agent3_total * 0.20
        weighted_agent4 = agent4_total * 0.20
        total_weighted_score = weighted_agent1 + weighted_agent2 + weighted_agent3 + weighted_agent4
        
        print(f"Agent1 Weighted (25%): {weighted_agent1}")
        print(f"Agent2 Weighted (35%): {weighted_agent2}")
        print(f"Agent3 Weighted (20%): {weighted_agent3}")
        print(f"Agent4 Weighted (20%): {weighted_agent4}")
        print(f"Total Weighted Score: {total_weighted_score}")
        
        # Normalize score to 0-100
        normalized_score = max(0, min(total_weighted_score, 100))
        confidence = normalized_score / 100.0
        
        # Determine verdict based on risk score thresholds
        if normalized_score >= 80:
            verdict = "True Positive"
        elif normalized_score >= 25:
            verdict = "Escalate"
        else:
            verdict = "False Positive"
        
        print(f"Normalized Score: {normalized_score}")
        print(f"Final Verdict: {verdict}")
        
        # Combine all attributes from all agents
        all_attributes = {}
        all_attributes.update({f"agent1_{k}": v for k, v in agent1_scores.items()})
        all_attributes.update({f"agent2_{k}": v for k, v in agent2_scores.items()})
        all_attributes.update({f"agent3_{k}": v for k, v in agent3_scores.items()})
        all_attributes.update({f"agent4_{k}": v for k, v in agent4_scores.items()})
        
        result = {
            "prediction": {
                "predicted_verdict": verdict,
                "risk_score": confidence * 100
            },
            "metadata": {
                "total_risk_score": normalized_score,
                "agent1_heuristic": {
                    "name": "Heuristic Analysis",
                    "raw_score": agent1_total,
                    "weighted_score": weighted_agent1,
                    "weight_percentage": 25,
                    "attributes": agent1_scores,
                    "description": "Alert metadata and behavioral pattern analysis"
                },
                "agent2_virustotal": {
                    "name": "VirusTotal Intelligence",
                    "raw_score": agent2_total,
                    "weighted_score": weighted_agent2,
                    "weight_percentage": 35,
                    "attributes": agent2_scores,
                    "description": "Multi-engine malware detection and threat intelligence"
                },
                "agent3_checkpoint": {
                    "name": "Check Point Reputation",
                    "raw_score": agent3_total,
                    "weighted_score": weighted_agent3,
                    "weight_percentage": 20,
                    "attributes": agent3_scores,
                    "description": "File reputation and risk assessment"
                },
                "agent4_cyberint": {
                    "name": "Cyberint Intelligence",
                    "raw_score": agent4_total,
                    "weighted_score": weighted_agent4,
                    "weight_percentage": 20,
                    "attributes": agent4_scores,
                    "description": "Advanced threat intelligence and malware analysis"
                },
                "combined_attribute_analysis": all_attributes,
                "scoring_breakdown": {
                    "agent1_contribution": f"{weighted_agent1:.2f} points (25% weight)",
                    "agent2_contribution": f"{weighted_agent2:.2f} points (35% weight)",
                    "agent3_contribution": f"{weighted_agent3:.2f} points (20% weight)",
                    "agent4_contribution": f"{weighted_agent4:.2f} points (20% weight)",
                    "total_weighted": f"{total_weighted_score:.2f} points"
                },
                "agent_role": self.role,
                "tools_used": self.tools,
                "mcp_integration": True,
                "hardcoded_prompts": True
            },
            "model_version": "4.0_Multi_Agent_Enhanced"
        }
        
        print("=" * 70)
        print("ENHANCED MULTI-AGENT TRIAGE ANALYSIS COMPLETE")
        print("=" * 70)
        
        return result


def _prepare_alert_for_analysis(raw_data: Dict[str, Any]) -> Dict[str, Any]:
    flex = FlexibleAlertInput.create(**raw_data)
    expanded_original = flex.to_legacy_format()
    normalized = flex.to_raw_format()
    merged = dict(expanded_original)
    merged.update(normalized)
    merged["_input_debug"] = {
        "expanded_original_keys": list(expanded_original.keys()),
        "normalized_keys": list(normalized.keys()),
        "alert_id": flex.alert_id,
    }
    return merged


triage_agent = None

@app.on_event("startup")
async def startup_event():
    """Initialize the triage agent on startup"""
    global triage_agent
    triage_agent = TriageAgent("server.py")
    print("Enhanced Multi-Agent Triage system initialized")

@app.post("/triage")
async def triage_alert(
    file: UploadFile = File(None),
    json_data: dict = Body(None)
):
    """
    Enhanced multi-agent triage analysis endpoint.

    Accepts flexible inputs:
    - snake_case (e.g., file_size, device_type, threat_confidence)
    - dotted keys (e.g., file.size, file.verification.type, threat.detection.type)
    - unmapped_* variants (e.g., unmapped_verdict) which override mapped values

    Pipeline:
      - Expand + normalize via FlexibleAlertInput
      - Merge expanded original with normalized canonical fields
      - Run multi-agent (Heuristic, VirusTotal, Check Point, Cyberint)
    """
    from datetime import datetime
    import pytz
    import time
    
    # Set up Indian Standard Time timezone
    ist = pytz.timezone('UTC')
    
    # Record start time with high precision
    start_timestamp = time.time()
    start_time_ist = datetime.now(ist).isoformat()
    
    global triage_agent

    if triage_agent is None:
        raise HTTPException(status_code=500, detail="Triage agent not initialized")

    try:
        # 1) Ingest request JSON from either file or body
        if file is not None:
            if not file.filename.endswith(".json"):
                raise HTTPException(status_code=400, detail="Only JSON files are supported.")
            content = await file.read()
            
            # Print the raw file content
            print("\n" + "=" * 50)
            print("=" * 50)
            print(f"Filename: {file.filename}")
            print(f"Content type: {file.content_type}")
            print(f"Content length: {len(content)} bytes")
            print("Raw bytes:")
            print(content)
            print("\nDecoded content:")
            print(content.decode("utf-8"))
            print("=" * 50 + "\n")
            
            try:
                raw_data = json.loads(content.decode("utf-8"))
                
                # Print the parsed JSON data
                print("\n" + "=" * 50)
                print("PARSED JSON DATA:")
                print("=" * 50)
                print(json.dumps(raw_data, indent=2, default=str))
                print("=" * 50 + "\n")
                
            except json.JSONDecodeError as e:
                raise HTTPException(status_code=400, detail=f"Invalid JSON format: {str(e)}")
        elif json_data is not None:
            raw_data = json_data
            
            # Print the JSON data from request body
            print("\n" + "=" * 50)
            print("JSON DATA FROM REQUEST BODY:")
            print("=" * 50)
            print(json.dumps(raw_data, indent=2, default=str))
            print("=" * 50 + "\n")
            
        else:
            raise HTTPException(status_code=400, detail="Provide either a JSON file or JSON data in request body.")

        # 2) Normalize/expand using FlexibleAlertInput (handles _, unmapped_, dotted)
        validation_success = True
        try:
            alert_data = _prepare_alert_for_analysis(raw_data)
            
            # Print the processed alert data
            print("\n" + "=" * 50)
            print("PROCESSED ALERT DATA:")
            print("=" * 50)
            print(json.dumps(alert_data, indent=2, default=str))
            print("=" * 50 + "\n")
            
        except Exception as e:
            print(f"Flexible input validation error: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            # Fallback: use raw_data as-is
            validation_success = False
            alert_data = raw_data if isinstance(raw_data, dict) else {"raw": raw_data}
            # Ensure minimal ID presence for downstream code paths
            if not any(k in alert_data for k in ["id", "alert_id", "threatInfo", "threat", "alert"]):
                alert_data["alert"] = {"id": "unknown_alert"}

        # 3) Run enhanced multi-agent triage analysis
        print("\n" + "=" * 60)
        print("STARTING ENHANCED MULTI-AGENT TRIAGE ANALYSIS")
        print("=" * 60)

        results = await triage_agent.analyze_alert(alert_data)

        # Record end time with high precision
        end_timestamp = time.time()
        end_time_ist = datetime.now(ist).isoformat()
        
        # Calculate processing time in seconds (including milliseconds)
        processing_time_seconds = round(end_timestamp - start_timestamp, 3)

        # 4) Enrich response with input-processing metadata
        mapped_alert_id = None
        if isinstance(alert_data, dict):
            mapped_alert_id = (
                alert_data.get("alert_id")
                or alert_data.get("id")
                or (alert_data.get("threat") or {}).get("id")
                or (alert_data.get("threatInfo") or {}).get("threatId")
            )

        if "metadata" not in results:
            results["metadata"] = {}

        results["metadata"]["input_processing"] = {
            "validation_success": validation_success,
            "flexible_parsing_used": validation_success,
            "original_keys_count": len(raw_data.keys()) if isinstance(raw_data, dict) else 0,
            "processed_keys_count": len(alert_data.keys()) if isinstance(alert_data, dict) else 0,
            "mapped_alert_id": mapped_alert_id,
            "multi_agent_analysis": True,
            "agents_used": {
                "agent1_heuristic": "25% weight",
                "agent2_virustotal": "35% weight",
                "agent3_checkpoint": "20% weight",
                "agent4_cyberint": "20% weight"
            }
        }

        # Add timing information
        results["start_time_triage"] = start_time_ist
        results["end_time_triage"] = end_time_ist
        results["timestamp_triage"] = processing_time_seconds

        return JSONResponse(content=results)

    except HTTPException:
        raise
    except Exception as e:
        print(f"Triage endpoint error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        
        # Record end time even for errors and calculate processing time
        end_timestamp = time.time()
        end_time_ist = datetime.now(ist).isoformat()
        processing_time_seconds = round(end_timestamp - start_timestamp, 3)
        
        raise HTTPException(status_code=500, detail=f"Enhanced triage analysis failed: {str(e)} (Processing time: {processing_time_seconds}s)")
    
from typing import Dict, Any, Optional
from datetime import datetime
import json
import traceback
import re
import requests
import time
import math
from fastapi import HTTPException, UploadFile, File, Body, Query
from fastapi.responses import JSONResponse

class FirewallScoringTool:
    """Professional Risk Scoring Engine implementing Top 15 attributes for firewall alert triage"""
    
    def __init__(self):
        # High-risk countries/regions (ISO 2-letter codes)
        self.HIGH_RISK_COUNTRIES = {
            'ru', 'cn', 'kp', 'ir', 'sy', 'pk', 'bd', 'ng', 'ro', 'ua'
        }
        
        # Known malware families with severity levels
        self.MALWARE_FAMILIES = {
            'high_severity': ['lockbit', 'ryuk', 'conti', 'revil', 'wannacry', 'petya', 'notpetya', 'ransomware'],
            'medium_severity': ['emotet', 'trickbot', 'qakbot', 'dridex', 'zeus', 'banking', 'trojan', 'bublik', 'upatre'],
            'low_severity': ['adware', 'pup', 'generic', 'suspicious']
        }
        
        # Protection types with severity weights
        self.PROTECTION_TYPES = {
            'anti_bot': 1.5,
            'threat_emulation': 1.4,
            'ips': 1.2,
            'anti_virus': 1.0,
            'web_protection': 1.1,
            'content_inspection': 1.0,
            'indicators': 1.3,
            'signature': 1.1
        }
        
        # Suspicious ports
        self.SUSPICIOUS_PORTS = {
            4444, 4445, 1337, 31337, 8080, 8443, 3389, 5900, 23, 135, 445, 1433, 3306, 9090
        }
        
        # Known malicious user agents
        self.MALICIOUS_USER_AGENTS = [
            'wget', 'curl', 'python', 'powershell', 'winhttp', 'bot', 'scanner', 'nikto'
        ]

    def flatten_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten nested alert data for easier processing"""
        flat = {}
        
        def flatten_recursive(obj, prefix=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    new_key = f"{prefix}_{k}" if prefix else k
                    if isinstance(v, (dict, list)) and len(str(v)) < 500:
                        flatten_recursive(v, new_key)
                    else:
                        flat[new_key] = v
            elif isinstance(obj, list) and obj:
                if isinstance(obj[0], (dict, str, int, float)):
                    flatten_recursive(obj[0], prefix)
        
        flatten_recursive(alert_data)
        return flat

    def score_agent1_top15(self, flat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Agent1: Professional scoring using Top 15 attributes for firewall alerts"""
        print("Running Agent1 Analysis - Top 15 Attributes for Firewall...")
        
        scores = {}
        
        # 1. VERDICT (High Weight - 20 points)
        verdict = flat_data.get("disposition", "").lower()
        action = flat_data.get("unmapped_action", "").lower()
        
        verdict_score = 0
        if "malicious" in verdict:
            verdict_score = 20
        elif "suspicious" in verdict:
            verdict_score = 15
        elif "prevent" in action or "block" in action:
            verdict_score = 12
        elif "detect" in action:
            verdict_score = 8
        
        scores["verdict"] = {
            "risk_score": verdict_score,
            "weight": "HIGH",
            "reason": f"Verdict: {verdict}, Action: {action}",
            "max_score": 20
        }
        
        # 2. CONFIDENCE LEVEL (High Weight - 15 points)
        confidence = flat_data.get("confidence", "").lower()
        conf_score = 0
        if "high" in confidence:
            conf_score = 15
        elif "medium" in confidence:
            conf_score = 10
        elif "low" in confidence:
            conf_score = 5
        
        scores["confidence_level"] = {
            "risk_score": conf_score,
            "weight": "HIGH",
            "reason": f"Confidence: {confidence}",
            "max_score": 15
        }
        
        # 3. FILE HASH REPUTATION (High Weight - 20 points) - Reserved for Agent2
        scores["hash_reputation"] = {
            "risk_score": 0,
            "weight": "HIGH",
            "reason": "Hash reputation scoring delegated to VirusTotal (Agent2)",
            "max_score": 20
        }
        
        # 4. PROTECTION TYPE (Medium Weight - 10 points)
        protection_type = flat_data.get("unmapped_protection_type", "").lower()
        product = flat_data.get("detector.product_name", "").lower()
        detected_by = flat_data.get("unmapped_detected_by", "").lower()
        
        prot_score = 0
        protection_context = f"{protection_type} {product} {detected_by}"
        
        for prot_type, multiplier in self.PROTECTION_TYPES.items():
            if prot_type.replace('_', '') in protection_context:
                prot_score = int(8 * multiplier)
                break
        else:
            prot_score = 6  # Default protection score
        
        scores["protection_type"] = {
            "risk_score": prot_score,
            "weight": "MEDIUM",
            "reason": f"Protection: {protection_type or product or detected_by}",
            "max_score": 12
        }
        
        # 5. MALWARE FAMILY (High Weight - 15 points)
        protection_name = flat_data.get("rule.name", "").lower()
        malware_action = flat_data.get("title", "").lower()
        indicator_name = flat_data.get("unmapped_indicator_name", "").lower()
        
        family_score = 0
        family_found = "unknown"
        
        malware_context = f"{protection_name} {malware_action} {indicator_name}"
        
        for severity, families in self.MALWARE_FAMILIES.items():
            for family in families:
                if family in malware_context:
                    if severity == 'high_severity':
                        family_score = 15
                    elif severity == 'medium_severity':
                        family_score = 10
                    else:
                        family_score = 6
                    family_found = family
                    break
            if family_score > 0:
                break
        
        scores["malware_family"] = {
            "risk_score": family_score,
            "weight": "HIGH",
            "reason": f"Malware family: {family_found}",
            "max_score": 15
        }
        
        action_score = 0
        if "allowed" in action or "pass" in action:
            action_score = 15  
        elif "prevented" in action or "prevent" in action or "blocked" in action:
            action_score = 8   
        elif "detected" in action or "detect" in action:
            action_score = 10 
        scores["malware_action"] = {
            "risk_score": action_score,
            "weight": "HIGH",
            "reason": f"Action taken: {action}",
            "max_score": 15
        }
        
        # 7. SOURCE ASSET CRITICALITY (High Weight - 10 points)
        src_attr = flat_data.get("src_endpoint.name", [])
        src = flat_data.get("src_endpoint.ip", "")
        scope = flat_data.get("unmapped_scope", "")
        
        asset_score = 0
        asset_type = "unknown"
        
        # Check for critical asset indicators
        critical_indicators = ['ad', 'dc', 'domain', 'sql', 'db', 'finance', 'mgmt', 'server']
        asset_info = ""
        
        if isinstance(src_attr, list) and src_attr:
            if isinstance(src_attr[0], dict):
                asset_info = str(src_attr[0].get("resolved", "")).lower()
            else:
                asset_info = str(src_attr[0]).lower()
        
        for indicator in critical_indicators:
            if indicator in asset_info:
                asset_score = 10
                asset_type = "critical"
                break
        
        if asset_score == 0:
            # Check IP ranges for internal critical systems
            source_ip = src or scope
            if source_ip:
                if source_ip.startswith(('10.10.10.', '192.168.1.', '172.16.')):
                    asset_score = 7
                    asset_type = "internal"
                else:
                    asset_score = 3
                    asset_type = "standard"
        
        scores["source_asset_criticality"] = {
            "risk_score": asset_score,
            "weight": "HIGH",
            "reason": f"Asset type: {asset_type}, Source: {src}",
            "max_score": 10
        }
        
        # 8. DESTINATION COUNTRY/IP REPUTATION (Low Weight - 5 points)
        dst_country = flat_data.get("unmapped_dst_country", "").lower()
        dst = flat_data.get("dst_endpoint.ip", "")
        
        geo_score = 0
        if dst_country:
            country_code = dst_country[:2] if len(dst_country) >= 2 else dst_country
            if country_code in self.HIGH_RISK_COUNTRIES:
                geo_score = 5
        elif dst:
            # Check for private vs public IPs
            if dst.startswith(('10.', '192.168.', '172.')):
                geo_score = 2  # Internal communication
            else:
                geo_score = 3  # External communication
        
        scores["destination_reputation"] = {
            "risk_score": geo_score,
            "weight": "LOW",
            "reason": f"Destination: {dst}, Country: {dst_country}",
            "max_score": 5
        }
        
        # 9. HTTP HOST/DOMAIN REPUTATION (Medium Weight - 8 points)
        http_host = flat_data.get("http.host", "")
        resource = flat_data.get("url.full", "")
        
        domain_score = 0
        # Check for suspicious domains/IPs
        if http_host:
            if any(char in http_host for char in ['bit.ly', 'tinyurl', 'shorturl']):
                domain_score = 8  # URL shorteners
            elif re.match(r'^\d+\.\d+\.\d+\.\d+$', http_host):
                domain_score = 5  # Direct IP access
            elif len(http_host.split('.')) > 4:
                domain_score = 6  # Suspicious subdomain structure
        
        scores["http_host_reputation"] = {
            "risk_score": domain_score,
            "weight": "MEDIUM",
            "reason": f"HTTP Host: {http_host}",
            "max_score": 8
        }
        
        # 10. POLICY NAME/PROTECTION PROFILE (Medium Weight - 6 points)
        policy_name = flat_data.get("policy.name", "").lower()
        policy = flat_data.get("policy.rule.name", "").lower()
        
        policy_score = 0
        policy_context = policy_name or policy
        
        if "weak" in policy_context or "basic" in policy_context:
            policy_score = 6  # Weak policy
        elif "standard" in policy_context:
            policy_score = 3  # Standard policy
        elif "strict" in policy_context or "high" in policy_context:
            policy_score = 1  # Strong policy
        else:
            policy_score = 3  # Default
        
        scores["policy_profile"] = {
            "risk_score": policy_score,
            "weight": "MEDIUM",
            "reason": f"Policy: {policy_context}",
            "max_score": 6
        }
        
        # 11. USER-AGENT STRING (Medium Weight - 8 points)
        user_agent = flat_data.get("http.user_agent", "").lower()
        web_client_type = flat_data.get("http.client_variant", "").lower()
        
        ua_score = 0
        ua_context = f"{user_agent} {web_client_type}"
        
        for malicious_ua in self.MALICIOUS_USER_AGENTS:
            if malicious_ua in ua_context:
                ua_score = 8
                break
        
        if ua_score == 0 and user_agent:
            if len(user_agent) < 10 or not any(browser in ua_context for browser in ['chrome', 'firefox', 'safari', 'edge']):
                ua_score = 5
        
        scores["user_agent"] = {
            "risk_score": ua_score,
            "weight": "MEDIUM",
            "reason": f"User-Agent: {user_agent}",
            "max_score": 8
        }
        
        # 12. DELETED BY/MITIGATION EVIDENCE (Medium Weight - 5 points)
        detected_by = flat_data.get("unmapped_detected_by", "").lower()
        action_taken = action
        
        mitigation_score = 0
        if "prevent" in action_taken or "block" in action_taken:
            mitigation_score = -3  # Good - was blocked
        elif "quarantine" in action_taken:
            mitigation_score = -2  # Good - was quarantined
        elif "detect" in action_taken:
            mitigation_score = 5   # Concerning - only detected
        elif "allow" in action_taken:
            mitigation_score = 8   # Bad - was allowed
        
        scores["mitigation_evidence"] = {
            "risk_score": mitigation_score,
            "weight": "MEDIUM",
            "reason": f"Mitigation: {action_taken}",
            "max_score": 8
        }
        
        suppressed_logs = flat_data.get("unmapped_suppressed_logs", "0")
        times_submitted = flat_data.get("unmapped_times_submitted", "1")
        
        freq_score = 0
        try:
            suppressed_count = int(suppressed_logs)
            submitted_count = int(times_submitted)
            total_frequency = suppressed_count + submitted_count
            
            if total_frequency > 10:
                freq_score = 5
            elif total_frequency > 5:
                freq_score = 3
            elif total_frequency > 1:
                freq_score = 2
        except (ValueError, TypeError):
            freq_score = 1
        
        scores["frequency_volume"] = {
            "risk_score": freq_score,
            "weight": "LOW",
            "reason": f"Frequency indicators: suppressed={suppressed_logs}, submitted={times_submitted}",
            "max_score": 5
        }
        
        # 14. FILE TYPE (Medium Weight - 8 points)
        file_type = flat_data.get("file.type", "").lower()
        content_type = flat_data.get("http.response.content_type", "").lower()
        
        file_score = 0
        file_context = f"{file_type} {content_type}"
        
        if any(dangerous in file_context for dangerous in ['executable', '.exe', 'application/octet-stream']):
            file_score = 8
        elif any(script in file_context for script in ['script', '.js', '.vbs', '.ps1']):
            file_score = 7
        elif any(archive in file_context for archive in ['zip', 'rar', '7z', 'archive']):
            file_score = 6
        elif any(doc in file_context for doc in ['document', '.doc', '.pdf']):
            file_score = 4
        elif any(safe in file_context for safe in ['image', '.jpg', '.png', 'text']):
            file_score = 1
        else:
            file_score = 3
        
        scores["file_type"] = {
            "risk_score": file_score,
            "weight": "MEDIUM",
            "reason": f"File type: {file_type or content_type}",
            "max_score": 8
        }
        
        # 15. SERVICE/PORT USED (Medium Weight - 6 points)
        service = flat_data.get("dst_endpoint.port", "")
        s_port = flat_data.get("src_endpoint.port", "")
        fservice = flat_data.get("unmapped_fservice", "")
        
        port_score = 0
        try:
            port_num = int(service or s_port or "0")
            if port_num in self.SUSPICIOUS_PORTS:
                port_score = 6
            elif port_num > 8000 and port_num not in [8080, 8443]:
                port_score = 4  # High ports can be suspicious
            elif port_num in [80, 443, 21, 22, 53]:
                port_score = 1  # Standard ports
            else:
                port_score = 2
        except (ValueError, TypeError):
            if any(susp_service in str(fservice).lower() for susp_service in ['tcp/', 'unknown']):
                port_score = 3
        
        scores["service_port"] = {
            "risk_score": port_score,
            "weight": "MEDIUM",
            "reason": f"Service/Port: {service or fservice}",
            "max_score": 6
        }
        
        print(f"Agent1 completed with {len(scores)} attributes analyzed")
        return scores

    def _get_virustotal_data(self, file_hash: str, api_key: str = None) -> Dict[str, Any]:
        """Fetch VirusTotal data for given hash"""
        if not api_key:
            # Default API key for testing - replace with your own
            api_key = "35432925a51b06b9607b40865e07b97494770344c82c87821f5ae63261e0444c"
            
        if not api_key or not file_hash:
            return {}
        
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {
                "x-apikey": api_key,
                "accept": "application/json"
            }
            
            print(f"Fetching VirusTotal data for hash: {file_hash}")
            
            # Rate limiting
            time.sleep(0.25)
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                print(f"Hash not found in VirusTotal: {file_hash}")
                return {"error": "hash_not_found"}
            elif response.status_code == 429:
                print("VirusTotal rate limit exceeded")
                return {"error": "rate_limit_exceeded"}
            else:
                print(f"VirusTotal API error: {response.status_code}")
                return {"error": f"api_error_{response.status_code}"}
                
        except Exception as e:
            print(f"VirusTotal API error: {str(e)}")
            return {"error": f"request_error: {str(e)}"}

    def _extract_hash_from_alert(self, flat: Dict[str, Any]) -> str:
        """Extract hash with priority: SHA256 > SHA1 > MD5 - DEBUGGED VERSION"""
        
        # Add debugging
        print(f"DEBUG: Hash extraction - total keys: {len(flat)}")
        
        # Look for any hash-related keys
        hash_keys = [key for key in flat.keys() if 'hash' in key.lower() or 'md5' in key.lower() or 'sha' in key.lower()]
        print(f"DEBUG: Found hash-related keys: {hash_keys}")
        
        # Print their values
        for key in hash_keys:
            print(f"DEBUG: {key} = {flat[key]}")
        
        # Priority order for hash lookup
        hash_fields = [
            "file.hashes.sha256", "sha256", "file_sha256",
            "file.hashes.sha1", "sha1", "file_sha1",
            "file.hashes.md5", "md5", "file_md5"
        ]
        
        print(f"DEBUG: Checking priority fields: {hash_fields}")
        
        for field in hash_fields:
            if field in flat and flat[field]:
                hash_value = str(flat[field]).lower().strip()
                if hash_value and hash_value not in ['null', 'none', '', 'none']:
                    print(f"DEBUG: Found hash using field '{field}': {hash_value}")
                    return hash_value
                else:
                    print(f"DEBUG: Field '{field}' exists but value is empty/null: '{hash_value}'")
            else:
                print(f"DEBUG: Field '{field}' not found in flattened data")
        
        # If no standard fields found, search for any field containing a hash-like pattern
        print("DEBUG: Searching for hash-like patterns in all fields...")
        for key, value in flat.items():
            if value and isinstance(value, str):
                # Check for hash patterns (32 chars = MD5, 40 = SHA1, 64 = SHA256)
                if re.match(r'^[a-fA-F0-9]{32}$', value):  # MD5
                    print(f"DEBUG: Found MD5 pattern in '{key}': {value}")
                    return value.lower()
                elif re.match(r'^[a-fA-F0-9]{40}$', value):  # SHA1
                    print(f"DEBUG: Found SHA1 pattern in '{key}': {value}")
                    return value.lower()
                elif re.match(r'^[a-fA-F0-9]{64}$', value):  # SHA256
                    print(f"DEBUG: Found SHA256 pattern in '{key}': {value}")
                    return value.lower()
        
        print("DEBUG: No hash found anywhere in the data")
        return ""

    # Also debug the flatten function to see if it's working correctly
    def flatten_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten nested alert data for easier processing - DEBUGGED VERSION"""
        flat = {}
        
        def flatten_recursive(obj, prefix=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    new_key = f"{prefix}_{k}" if prefix else k
                    if isinstance(v, (dict, list)) and len(str(v)) < 500:
                        flatten_recursive(v, new_key)
                    else:
                        flat[new_key] = v
            elif isinstance(obj, list) and obj:
                if isinstance(obj[0], (dict, str, int, float)):
                    flatten_recursive(obj[0], prefix)
        
        print(f"DEBUG: flatten_alert - received {len(alert_data)} top-level keys")
        
        # Debug: Print the original file structure before flattening
        if 'file' in alert_data:
            print(f"DEBUG: Original file structure: {alert_data['file']}")
            if 'hashes' in alert_data['file']:
                print(f"DEBUG: Original hashes: {alert_data['file']['hashes']}")
        
        flatten_recursive(alert_data)
        
        # Debug: Check what happened to file.hashes after flattening
        file_hash_keys = [key for key in flat.keys() if 'file' in key and 'hash' in key]
        print(f"DEBUG: After flattening, file hash keys: {file_hash_keys}")
        for key in file_hash_keys:
            print(f"DEBUG: {key} = {flat[key]}")
        
        print(f"DEBUG: flatten_alert - produced {len(flat)} flattened keys")
        return flat

    def score_agent2(self, flat: Dict[str, Any], api_key: str = None) -> Dict[str, Any]:
        """Agent2: VirusTotal-based scoring using live API data"""
        scores = {}
        
        print("=== AGENT2 SCORING START (VirusTotal API) ===")

        # Extract hash from alert
        file_hash = self._extract_hash_from_alert(flat)
        
        if not file_hash:
            print("No hash found in alert data")
            scores["vt_no_hash"] = {
                "risk_score": 0,
                "weight": "HIGH",
                "reason": "No hash available for VirusTotal lookup",
                "max_score": 20
            }
            return scores

        # Fetch VirusTotal data
        vt_data = self._get_virustotal_data(file_hash, api_key)
        
        if not vt_data or "error" in vt_data:
            error_msg = vt_data.get("error", "unknown_error") if vt_data else "no_data"
            print(f"VirusTotal data unavailable: {error_msg}")
            
            # Assign risk score based on error type
            if error_msg == "hash_not_found":
                risk_score = 15  # Unknown files are risky
            else:
                risk_score = 10  # API errors get moderate risk
            
            scores["vt_error"] = {
                "risk_score": risk_score,
                "weight": "HIGH",
                "reason": f"VirusTotal lookup failed: {error_msg}",
                "max_score": 20
            }
            return scores

        # Extract attributes from VirusTotal response
        attributes = vt_data.get("data", {}).get("attributes", {})
        
        if not attributes:
            scores["vt_no_attributes"] = {
                "risk_score": 5,
                "weight": "HIGH", 
                "reason": "VirusTotal response contained no file attributes",
                "max_score": 20
            }
            return scores

        print(f"Processing VirusTotal attributes...")

        # 1. Malicious detections (20 points max)
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        malicious_count = last_analysis_stats.get("malicious", 0)
        
        if malicious_count > 0:
            risk_score = min(15 * math.log2(malicious_count + 1), 50)
            scores["vt_malicious_detections"] = {
                "risk_score": risk_score,
                "weight": "HIGH",
                "reason": f"VirusTotal malicious detections: {malicious_count}",
                "max_score": 50
            }

        # 2. Suspicious detections
        suspicious_count = last_analysis_stats.get("suspicious", 0)
        if suspicious_count > 0:
            risk_score = min(8 * math.log2(suspicious_count + 1), 25)
            scores["vt_suspicious_detections"] = {
                "risk_score": risk_score,
                "weight": "MEDIUM",
                "reason": f"VirusTotal suspicious detections: {suspicious_count}",
                "max_score": 25
            }

        # 3. Threat severity
        threat_severity = attributes.get("threat_severity", {})
        if threat_severity:
            severity_level = threat_severity.get("threat_severity_level", "")
            if "HIGH" in severity_level:
                scores["vt_high_severity"] = {
                    "risk_score": 35,
                    "weight": "HIGH",
                    "reason": f"VirusTotal high threat severity",
                    "max_score": 35
                }
            elif "MEDIUM" in severity_level:
                scores["vt_medium_severity"] = {
                    "risk_score": 20,
                    "weight": "MEDIUM",
                    "reason": f"VirusTotal medium threat severity",
                    "max_score": 20
                }

        # 4. Popular threat classification
        threat_class = attributes.get("popular_threat_classification", {})
        if threat_class:
            suggested_label = threat_class.get("suggested_threat_label", "")
            if any(term in suggested_label.lower() for term in ["trojan", "malware", "ransomware"]):
                scores["vt_threat_classification"] = {
                    "risk_score": 25,
                    "weight": "HIGH",
                    "reason": f"VirusTotal classification: {suggested_label}",
                    "max_score": 25
                }

        # 5. File reputation
        reputation = attributes.get("reputation", 0)
        if reputation < 0:
            risk_score = min(abs(reputation) * 2, 30)
            scores["vt_negative_reputation"] = {
                "risk_score": risk_score,
                "weight": "MEDIUM",
                "reason": f"VirusTotal negative reputation: {reputation}",
                "max_score": 30
            }

        agent2_total = sum(score_data.get("risk_score", 0) for score_data in scores.values())
        print(f"=== AGENT2 TOTAL SCORE (VirusTotal): {agent2_total} ===")
        
        return scores

class FirewallTriageAgent:
    """Agent specialized in firewall alert triage and risk scoring"""
    
    def __init__(self):
        self.role = "Firewall Alert Triage Specialist - Performs comprehensive risk assessment using Top 15 attributes (Agent1) and VirusTotal enrichment (Agent2)"
        self.tools = ["FirewallScoringTool", "VirusTotalAPI"]
        self.scoring_tool = FirewallScoringTool()

    def analyze_firewall_alert(self, alert_data: Dict[str, Any], vt_api_key: str = None) -> Dict[str, Any]:
        """Analyze firewall alert using Agent1 (Top 15 attributes) and Agent2 (VirusTotal) scoring"""
        
        print("=" * 60)
        print("STARTING FIREWALL TRIAGE ANALYSIS")
        print("=" * 60)
        
        # Flatten and validate data
        flat_data = self.scoring_tool.flatten_alert(alert_data)
        
        if not flat_data:
            print("ERROR: No valid firewall alert data received")
            return {
                "error": "No valid firewall alert data provided",
                "source": "firewall",
                "timestamp": datetime.utcnow().isoformat()
            }
        
        print(f"Processing firewall alert with {len(flat_data)} fields")
        
        # Run Agent1 scoring (Top 15 attributes)
        print("\n" + "="*40 + " AGENT1 (TOP 15 ATTRIBUTES) " + "="*40)
        agent1_scores = self.scoring_tool.score_agent1_top15(flat_data)
        
        # Run Agent2 scoring (VirusTotal)
        print("\n" + "="*40 + " AGENT2 (VIRUSTOTAL) " + "="*40)
        agent2_scores = self.scoring_tool.score_agent2(flat_data, vt_api_key)
        
        # Calculate totals
        agent1_total = sum(attr_data.get("risk_score", 0) for attr_data in agent1_scores.values())
        agent2_total = sum(attr_data.get("risk_score", 0) for attr_data in agent2_scores.values())
        
        print(f"\n" + "="*40 + " FINAL CALCULATION " + "="*40)
        print(f"Agent1 Raw Total: {agent1_total}")
        print(f"Agent2 Raw Total: {agent2_total}")
        
        # Apply weightings: 40% Agent1, 60% Agent2
        weighted_agent1 = agent1_total * 0.4
        weighted_agent2 = agent2_total * 0.6
        total_weighted_score = weighted_agent1 + weighted_agent2
        
        print(f"Agent1 Weighted (40%): {weighted_agent1}")
        print(f"Agent2 Weighted (60%): {weighted_agent2}")
        print(f"Total Weighted Score: {total_weighted_score}")
        
        # Normalize score to 0-100
        normalized_score = max(0, min(total_weighted_score, 100))
        confidence = normalized_score / 100.0
        
        # Determine verdict based on risk score thresholds
        if normalized_score >= 80:
            verdict = "True Positive"  # Critical - Escalate immediately
        elif normalized_score >= 50:
            verdict = "Escalate"       # Medium - SOC review
        else:
            verdict = "False Positive" # Low - Auto-close/log
        
        print(f"Normalized Score: {normalized_score}")
        print(f"Final Verdict: {verdict}")
        print(f"Risk Score: {confidence * 100}")
        
        # Combine all attribute analyses
        all_attributes = {}
        all_attributes.update(agent1_scores)
        all_attributes.update(agent2_scores)
        
        result = {
            "prediction": {
                "predicted_verdict": verdict,
                "risk_score": confidence * 100,
                "normalized_score": normalized_score
            },
            "metadata": {
                "source": "firewall",
                "total_risk_score": normalized_score,
                "agent1_score": {
                    "raw_score": agent1_total,
                    "weighted_score": weighted_agent1,
                    "weight_percentage": 40,
                    "attributes": agent1_scores
                },
                "agent2_score": {
                    "raw_score": agent2_total,
                    "weighted_score": weighted_agent2,
                    "weight_percentage": 60,
                    "attributes": agent2_scores
                },
                "combined_attribute_analysis": all_attributes,
                "scoring_breakdown": {
                    "agent1_contribution": f"{weighted_agent1:.2f} points (40% weight)",
                    "agent2_contribution": f"{weighted_agent2:.2f} points (60% weight)",
                    "total_weighted": f"{total_weighted_score:.2f} points"
                },
                "thresholds": {
                    "critical": "≥80 (True Positive)",
                    "medium": "50-79 (Escalate)", 
                    "low": "<50 (False Positive)"
                },
                "agent_role": self.role,
                "tools_used": self.tools
            },
            "timestamp": datetime.utcnow().isoformat(),
            "model_version": "1.0"
        }
        
        print("=" * 60)
        print("FIREWALL TRIAGE ANALYSIS COMPLETE")
        print("=" * 60)
        
        return result

# Initialize the firewall triage agent
firewall_triage_agent = FirewallTriageAgent()

@app.post("/triage-firewall")
async def triage_alert(
    file: UploadFile = File(None),
    json_data: dict = Body(None),
    vt_api_key: str = Query(None, description="VirusTotal API key (optional)")
):
    """
    Universal triage endpoint that routes to appropriate triage agent based on source.
    For firewall alerts, use /triage?source=firewall
    """
    try:
        source = "firewall"
        # Validate source
        if source.lower() != "firewall":
            raise HTTPException(
                status_code=400, 
                detail=f"Source '{source}' not supported. Currently supports: firewall"
            )
        
        # Parse input data
        if file is not None:
            if not file.filename.endswith(".json"):
                raise HTTPException(status_code=400, detail="Only JSON files are supported.")
            
            content = await file.read()
            try:
                alert_data = json.loads(content.decode("utf-8"))
            except json.JSONDecodeError as e:
                raise HTTPException(status_code=400, detail=f"Invalid JSON format: {str(e)}")
        elif json_data is not None:
            alert_data = json_data
        else:
            raise HTTPException(status_code=400, detail="Provide either a JSON file or JSON data in request body.")
        
        print(f"Received firewall alert with keys: {list(alert_data.keys())}")
        print(f"Alert ID: {alert_data.get('id', 'unknown')}")
        
        # CORRECTED: Call the actual firewall triage agent
        results = firewall_triage_agent.analyze_firewall_alert(alert_data, vt_api_key)
        
        # Add input processing metadata
        results['metadata']['input_processing'] = {
            'source_type': source,
            'vt_api_provided': vt_api_key is not None,
            'input_keys': list(alert_data.keys()) if isinstance(alert_data, dict) else [],
            'alert_id': alert_data.get('id', 'unknown'),
            'file_hash_found': bool(
                alert_data.get('file', {}).get('hashes', {}).get('sha256') or
                alert_data.get('file', {}).get('hashes', {}).get('sha1') or  
                alert_data.get('file', {}).get('hashes', {}).get('md5')
            ),
            'disposition': alert_data.get('disposition', 'unknown'),
            'severity': alert_data.get('severity', 'unknown'),
            'confidence': alert_data.get('confidence', 'unknown')
        }

        return JSONResponse(content=results)

    except HTTPException:
        raise
    except Exception as e:
        print(f"Firewall triage endpoint error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Firewall triage analysis failed: {str(e)}")
    
        
from fastapi import FastAPI, File, UploadFile, HTTPException, Body
from fastapi.responses import JSONResponse
import json
import os
import pickle
from pathlib import Path
import pandas as pd
import numpy as np
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
from sklearn.preprocessing import StandardScaler
from fastapi import FastAPI, File, UploadFile, HTTPException, Body
from fastapi.responses import JSONResponse
import json
import os
import pickle
from pathlib import Path
import pandas as pd
import numpy as np
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
from sklearn.preprocessing import StandardScaler

# Install shap if not already installed: pip install shap
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    print("Warning: SHAP not available. Install with: pip install shap")



# Safe unpickling shim
class DynamicBehavioralFeatureEngine:
    def __init__(self, *args, **kwargs):
        self.behavioral_patterns = {}
        self.learned_encodings = {}
        self.statistical_profiles = {}

class _SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if name == "DynamicBehavioralFeatureEngine":
            return DynamicBehavioralFeatureEngine
        return super().find_class(module, name)





class SinglePKLPredictor:
    """Predictor that works with a single PKL file and calculates feature contributions"""
    
    def __init__(self, model_path: str):
        self.model_artifacts = {}
        self.model = None
        self.scaler = None
        self.target_encoder = None
        self.label_encoders = {}
        self.expected_features = []
        self.learned_encodings = {}
        self.frequency_maps = {}
        self.clustering_profile = {}
        self.file_size_log_stats = {}
        
        # For SHAP explanations
        self.explainer = None
        self.background_data = None
        
        self.load_model(model_path)

    def load_model(self, model_path: str):
        """Load model from single pickle file"""
        model_path = Path(model_path).expanduser()
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        with open(model_path, "rb") as f:
            try:
                self.model_artifacts = pickle.load(f)
            except AttributeError:
                f.seek(0)
                self.model_artifacts = _SafeUnpickler(f).load()

        # Extract core components
        self.model = self.model_artifacts.get("model")
        self.scaler = self.model_artifacts.get("scaler")
        self.target_encoder = self.model_artifacts.get("target_encoder")
        self.label_encoders = self.model_artifacts.get("label_encoders", {}) or {}
        self.expected_features = self.model_artifacts.get("feature_columns", [])

        # Extract additional feature info if available
        fi = self.model_artifacts.get("feature_info", {}) or {}
        self.learned_encodings = fi.get("learned_encodings", {}) or {}
        self.frequency_maps = fi.get("category_frequency_maps", {}) or {}
        self.clustering_profile = fi.get("clustering_profile", {}) or {}
        self.file_size_log_stats = fi.get("file_size_log_stats", {}) or {}

        # Initialize SHAP explainer if available
        self._initialize_shap_explainer()

        print(f"✅ Model loaded successfully")
        print(f"Expected features: {len(self.expected_features)}")
        print(f"SHAP explainer initialized: {self.explainer is not None}")

    def _initialize_shap_explainer(self):
        """Initialize SHAP explainer for feature contribution analysis"""
        if not SHAP_AVAILABLE or self.model is None:
            return
            
        try:
            # Create background dataset (representative sample for SHAP)
            # In production, you might want to use actual training data
            n_background = min(100, 50)  # Use small background for speed
            
            # Generate synthetic background data based on feature statistics
            background_data = self._generate_background_data(n_background)
            
            if background_data is not None:
                # Choose appropriate explainer based on model type
                model_name = str(type(self.model).__name__).lower()
                
                if any(name in model_name for name in ['tree', 'forest', 'gradient', 'xgb', 'lgb']):
                    # Tree-based models - use TreeExplainer for speed
                    self.explainer = shap.TreeExplainer(self.model)
                else:
                    # Other models - use more general explainer
                    def model_predict(X):
                        if self.scaler:
                            X_df = pd.DataFrame(X, columns=self.expected_features)
                            X_scaled = self.scaler.transform(X_df)
                        else:
                            X_scaled = X
                        return self.model.predict_proba(X_scaled)
                    
                    self.explainer = shap.Explainer(model_predict, background_data)
                    
                self.background_data = background_data
                print(f"SHAP explainer initialized with {len(background_data)} background samples")
                
        except Exception as e:
            print(f"Failed to initialize SHAP explainer: {e}")
            self.explainer = None

    def _generate_background_data(self, n_samples: int) -> np.ndarray:
        """Generate representative background data for SHAP"""
        try:
            # Create diverse background samples
            background = []
            
            for _ in range(n_samples):
                sample = {}
                
                # Generate realistic feature values
                sample['file_size'] = np.random.lognormal(10, 2)  # Log-normal distribution for file sizes
                sample['threat_confidence'] = np.random.uniform(0, 100)
                sample['is_active'] = np.random.choice([0, 1])
                sample['is_fileless'] = np.random.choice([0, 1])
                sample['is_valid_certificate'] = np.random.choice([0, 1])
                sample['file_extension'] = np.random.choice(['exe', 'dll', 'pdf', 'doc', 'unknown'])
                sample['os_name'] = np.random.choice(['windows', 'linux', 'macos', 'unknown'])
                sample['device_type'] = np.random.choice(['desktop', 'server', 'laptop', 'unknown'])
                sample['detection_type'] = np.random.choice(['heuristic', 'signature', 'behavioral', 'unknown'])
                sample['verification_type'] = np.random.choice(['signed', 'unsigned', 'unknown'])
                sample['confidence_level'] = np.random.choice(['high', 'medium', 'low', 'unknown'])
                
                # Apply the same feature engineering as in prediction
                processed_features = self.apply_preprocessing(sample)
                feature_vector = self.build_feature_vector(processed_features)
                background.append(feature_vector)
            
            return np.array(background)
            
        except Exception as e:
            print(f"Failed to generate background data: {e}")
            return None

    def calculate_feature_contributions(self, feature_vector: np.ndarray) -> Dict[str, float]:
        """Calculate individual feature contributions to the prediction"""
        if self.explainer is None:
            return self._fallback_contribution_calculation(feature_vector)
        
        try:
            # Reshape for SHAP (expects 2D array)
            X_sample = feature_vector.reshape(1, -1)
            
            # Calculate SHAP values
            if hasattr(self.explainer, 'shap_values'):
                # TreeExplainer returns different format
                shap_values = self.explainer.shap_values(X_sample)
                if isinstance(shap_values, list):
                    # Multi-class: use values for predicted class
                    pred_class = int(self.model.predict(
                        self.scaler.transform(pd.DataFrame(X_sample, columns=self.expected_features))
                        if self.scaler else X_sample
                    )[0])
                    shap_values = shap_values[pred_class]
                shap_values = shap_values[0]  # Get first (and only) sample
            else:
                # General explainer
                explanation = self.explainer(X_sample)
                shap_values = explanation.values[0]
                
            # Create contribution dictionary
            contributions = {}
            for i, feature_name in enumerate(self.expected_features):
                if i < len(shap_values):
                    contributions[feature_name] = float(shap_values[i])
                else:
                    contributions[feature_name] = 0.0
                    
            return contributions
            
        except Exception as e:
            print(f"SHAP calculation failed: {e}")
            return self._fallback_contribution_calculation(feature_vector)

    def _fallback_contribution_calculation(self, feature_vector: np.ndarray) -> Dict[str, float]:
        """Fallback method to estimate feature contributions without SHAP"""
        contributions = {}
        
        try:
            # Get base prediction (all features set to mean/mode)
            base_vector = np.zeros_like(feature_vector)
            
            if self.scaler:
                X_base_df = pd.DataFrame([base_vector], columns=self.expected_features)
                X_base_scaled = self.scaler.transform(X_base_df)
                X_sample_df = pd.DataFrame([feature_vector], columns=self.expected_features)
                X_sample_scaled = self.scaler.transform(X_sample_df)
            else:
                X_base_scaled = base_vector.reshape(1, -1)
                X_sample_scaled = feature_vector.reshape(1, -1)
            
            # Get predictions
            if hasattr(self.model, 'predict_proba'):
                base_prob = self.model.predict_proba(X_base_scaled)[0]
                sample_prob = self.model.predict_proba(X_sample_scaled)[0]
                base_pred = np.max(base_prob)
                sample_pred = np.max(sample_prob)
            else:
                base_pred = 0.5  # Neutral baseline
                sample_pred = 1.0  # Assume positive prediction
            
            total_diff = sample_pred - base_pred
            
            # Calculate individual feature contributions (simplified approach)
            for i, feature_name in enumerate(self.expected_features):
                if i < len(feature_vector):
                    # Normalize feature value and multiply by total difference
                    feature_val = feature_vector[i]
                    normalized_val = feature_val / (1.0 + abs(feature_val))  # Normalize to [-1, 1]
                    contribution = normalized_val * total_diff / len(self.expected_features)
                    contributions[feature_name] = float(contribution)
                else:
                    contributions[feature_name] = 0.0
                    
        except Exception as e:
            print(f"Fallback contribution calculation failed: {e}")
            # Return zero contributions as last resort
            for feature_name in self.expected_features:
                contributions[feature_name] = 0.0
        
        return contributions

    def extract_raw_features(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract raw features from JSON data"""
        features = {}
        
        # File information
        file_info = data.get("file", {})
        features["file_size"] = float(file_info.get("size", 0) or 0)
        features["file_extension"] = str(file_info.get("extension", "unknown")).lower()
        features["file_extension_type"] = str(file_info.get("extension_type", "unknown")).lower()
        features["verification_type"] = str(file_info.get("verification", {}).get("type", "unknown")).lower()
        
        # Certificate info
        cert_status = file_info.get("signature", {}).get("certificate", {}).get("status")
        features["is_valid_certificate"] = 1.0 if cert_status == "valid" else 0.0
        
        # Threat information
        threat_info = data.get("threat", {})
        features["threat_confidence"] = float(threat_info.get("confidence", 50) or 50)
        features["detection_type"] = str(threat_info.get("detection", {}).get("type", "unknown")).lower()
        
        # Device information
        device_info = data.get("device", {})
        features["os_name"] = str(device_info.get("os", {}).get("name", "unknown")).lower()
        features["device_type"] = str(device_info.get("type", "unknown")).lower()
        features["is_active"] = 1.0 if device_info.get("is_active", False) else 0.0
        
        # Process information
        process_info = data.get("process", {})
        features["is_fileless"] = 1.0 if process_info.get("is_fileless", False) else 0.0
        
        # Additional fields - also check direct keys
        features["confidence_level"] = str(data.get("confidence_level", "unknown")).lower()
        
        # Override with direct values if present
        for key in ["file_size", "file_extension", "file_extension_type", "verification_type", 
                   "is_valid_certificate", "threat_confidence", "detection_type", 
                   "os_name", "device_type", "is_active", "is_fileless", "confidence_level"]:
            if key in data:
                if key in ["is_valid_certificate", "is_active", "is_fileless"]:
                    features[key] = 1.0 if data[key] else 0.0
                elif key in ["file_size", "threat_confidence"]:
                    features[key] = float(data[key] or 0)
                else:
                    features[key] = str(data[key]).lower()
        
        return features

    def apply_preprocessing(self, raw_features: Dict[str, Any]) -> Dict[str, float]:
        """Apply preprocessing to match expected features"""
        processed = {}
        
        # Copy numeric features directly
        numeric_features = ["file_size", "threat_confidence", "is_active", "is_fileless", "is_valid_certificate"]
        for feat in numeric_features:
            if feat in raw_features:
                processed[feat] = float(raw_features[feat])
        
        # Handle categorical features
        categorical_features = ["file_extension", "file_extension_type", "verification_type", 
                              "detection_type", "os_name", "device_type", "confidence_level"]
        
        for feat in categorical_features:
            if feat in raw_features:
                value = str(raw_features[feat]).lower()
                
                # Try to use saved label encoder
                if feat in self.label_encoders:
                    le = self.label_encoders[feat]
                    try:
                        if hasattr(le, 'classes_') and value in le.classes_:
                            processed[feat] = float(le.transform([value])[0])
                        else:
                            processed[feat] = 0.0
                    except:
                        processed[feat] = 0.0
                else:
                    # Simple hash-based encoding as fallback
                    processed[feat] = float(hash(value) % 100)
        
        # Create derived features if expected
        if "size_confidence_ratio" in self.expected_features:
            file_size = processed.get("file_size", 0.0)
            threat_conf = processed.get("threat_confidence", 50.0)
            processed["size_confidence_ratio"] = (file_size + 1.0) / (threat_conf + 1.0)
        
        if "file_size_x_threat_confidence" in self.expected_features:
            processed["file_size_x_threat_confidence"] = processed.get("file_size", 0.0) * processed.get("threat_confidence", 50.0)
        
        # Apply frequency mappings if available
        for feat in categorical_features:
            freq_key = f"{feat}_frequency"
            if freq_key in self.expected_features and feat in raw_features:
                freq_map = self.frequency_maps.get(feat, {})
                value = str(raw_features[feat]).lower()
                processed[freq_key] = float(freq_map.get(value, 0.0))
                
                # Rarity score
                rarity_key = f"{feat}_rarity_score"
                if rarity_key in self.expected_features:
                    processed[rarity_key] = 1.0 - processed[freq_key]
        
        # Apply target encodings if available
        for feat in categorical_features:
            target_key = f"{feat}_target_encoded"
            if target_key in self.expected_features and feat in raw_features:
                enc = self.learned_encodings.get(feat, {})
                if enc:
                    emap = enc.get("encoding_map", {})
                    global_mean = float(enc.get("global_mean", 0.0))
                    value = str(raw_features[feat]).lower()
                    processed[target_key] = float(emap.get(value, global_mean))
        
        return processed

    def build_feature_vector(self, processed_features: Dict[str, float]) -> np.ndarray:
        """Build feature vector matching expected features"""
        vector = []
        missing_features = []
        
        for feat in self.expected_features:
            if feat in processed_features:
                vector.append(processed_features[feat])
            else:
                vector.append(0.0)
                missing_features.append(feat)
        
        if missing_features:
            print(f"Using defaults for missing features: {missing_features[:5]}...")
        
        return np.array(vector, dtype=float)

    def predict(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Make prediction on input data with feature contributions"""
        try:
            # Extract and preprocess features
            raw_features = self.extract_raw_features(input_data)
            processed_features = self.apply_preprocessing(raw_features)
            feature_vector = self.build_feature_vector(processed_features)
            
            # Scale features
            if self.scaler:
                X_df = pd.DataFrame([feature_vector], columns=self.expected_features)
                X_scaled = self.scaler.transform(X_df)
            else:
                X_scaled = feature_vector.reshape(1, -1)

            # Make prediction
            if hasattr(self.model, "predict_proba"):
                proba = self.model.predict_proba(X_scaled)[0]
                idx = int(np.argmax(proba))
                confidence = float(np.max(proba))
                probabilities = {f"class_{i}": float(p) for i, p in enumerate(proba)}
            else:
                idx = int(self.model.predict(X_scaled)[0])
                confidence = 0.5
                probabilities = {}

            # Decode label
            try:
                if self.target_encoder:
                    label = str(self.target_encoder.inverse_transform([idx])[0])
                    # Update probabilities with actual class names
                    if hasattr(self.target_encoder, 'classes_'):
                        class_names = list(self.target_encoder.classes_)
                        if hasattr(self.model, "predict_proba"):
                            probabilities = {class_names[i]: float(proba[i]) for i in range(len(class_names))}
                else:
                    label = str(idx)
            except Exception:
                label = str(idx)

            # Calculate feature contributions (NEW!)
            feature_contributions = self.calculate_feature_contributions(feature_vector)
            
            # Calculate risk score
            file_risk_score = 0.0
            if raw_features.get("is_valid_certificate", 0) == 0:
                file_risk_score += 1.0
            if float(raw_features.get("threat_confidence", 50)) >= 70:
                file_risk_score += 1.0
            if float(raw_features.get("file_size", 0)) < 10 * 1024:
                file_risk_score += 1.0

            return {
                "prediction": {
                    "predicted_verdict": label,
                    "confidence": confidence,
                    "probabilities": probabilities
                },
                "metadata": {
                    "file_risk_score": file_risk_score,
                    "feature_contributions": feature_contributions,  # NEW: Individual contributions
                    "features_used": self.expected_features,
                    "preprocessing_success": True,
                    "shap_enabled": self.explainer is not None
                }
            }

        except Exception as e:
            print(f"Prediction error: {e}")
            return {
                "prediction": {
                    "predicted_verdict": "Error",
                    "confidence": 0.0,
                    "probabilities": {}
                },
                "metadata": {
                    "error": str(e),
                    "preprocessing_success": False,
                    "feature_contributions": {},
                    "features_used": []
                }
            }

MODEL_PATH = "best_model-edr.pkl"  # Update this path
try:
    predictor = SinglePKLPredictor(MODEL_PATH)
    print("✅ Model loaded successfully")
except Exception as e:
    print(f"❌ Failed to load model: {e}")
    predictor = None

@app.post("/predict")
async def predict_alert(
    file: UploadFile = File(None),
    json_data: dict = Body(None)
):
    """
    Predict malware classification for alert data using single PKL model.
    Now includes individual feature contributions to the prediction.
    
    Accepts either:
    - JSON file upload via multipart/form-data
    - Direct JSON data in request body
    """
    if not predictor:
        raise HTTPException(status_code=503, detail="Model not loaded. Check server logs.")
    
    try:
        # Parse input data
        raw_data = None
        validation_success = False
        
        if file is not None:
            if not file.filename.endswith(".json"):
                raise HTTPException(status_code=400, detail="Only JSON files are supported.")
            
            content = await file.read()
            try:
                raw_data = json.loads(content.decode("utf-8"))
            except json.JSONDecodeError as e:
                raise HTTPException(status_code=400, detail=f"Invalid JSON format: {str(e)}")
                
        elif json_data is not None:
            raw_data = json_data
        else:
            raise HTTPException(status_code=400, detail="Provide either a JSON file or JSON data in request body.")

        # Try flexible input processing
        try:
            flexible_input = FlexibleAlertInput(**raw_data)
            processed_data = flexible_input.to_raw_format()
            validation_success = True
        except Exception as e:
            print(f"Flexible input processing failed: {e}")
            processed_data = raw_data
            validation_success = False

        # Run prediction
        result = predictor.predict(processed_data)
        
        # Add input processing metadata
        result['metadata']['input_processing'] = {
            'flexible_parsing_success': validation_success,
            'input_source': 'file_upload' if file else 'json_body',
            'alert_id': processed_data.get('alert_id', 'unknown')
        }

        return JSONResponse(content=result)

    except HTTPException:
        raise
    except Exception as e:
        print(f"Predict endpoint error: {e}")
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")



MODEL_PATH = "best_model-edr.pkl"  # Update this path
try:
    predictor = SinglePKLPredictor(MODEL_PATH)
    print("✅ Model loaded successfully")
except Exception as e:
    print(f"❌ Failed to load model: {e}")
    predictor = None


@app.post("/predict")
async def predict_alert(
    file: UploadFile = File(None),
    json_data: dict = Body(None)
):
    """
    Predict malware classification for alert data using single PKL model.
    
    Accepts either:
    - JSON file upload via multipart/form-data
    - Direct JSON data in request body
    """
    if not predictor:
        raise HTTPException(status_code=503, detail="Model not loaded. Check server logs.")
    
    try:
        # Parse input data
        raw_data = None
        validation_success = False
        
        if file is not None:
            if not file.filename.endswith(".json"):
                raise HTTPException(status_code=400, detail="Only JSON files are supported.")
            
            content = await file.read()
            try:
                raw_data = json.loads(content.decode("utf-8"))
            except json.JSONDecodeError as e:
                raise HTTPException(status_code=400, detail=f"Invalid JSON format: {str(e)}")
                
        elif json_data is not None:
            raw_data = json_data
        else:
            raise HTTPException(status_code=400, detail="Provide either a JSON file or JSON data in request body.")

        # Try flexible input processing
        try:
            flexible_input = FlexibleAlertInput(**raw_data)
            processed_data = flexible_input.to_raw_format()
            validation_success = True
        except Exception as e:
            print(f"Flexible input processing failed: {e}")
            processed_data = raw_data
            validation_success = False

        # Run prediction
        result = predictor.predict(processed_data)
        
        # Add input processing metadata
        result['metadata']['input_processing'] = {
            'flexible_parsing_success': validation_success,
            'input_source': 'file_upload' if file else 'json_body',
            'alert_id': processed_data.get('alert_id', 'unknown')
        }

        return JSONResponse(content=result)

    except HTTPException:
        raise
    except Exception as e:
        print(f"Predict endpoint error: {e}")
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

import math
from datetime import datetime


def flatten(obj, parent_key: str = "", sep: str = "."):
    items = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
            items.extend(flatten(v, new_key, sep=sep).items())
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            new_key = f"{parent_key}{sep}{i}" if parent_key else str(i)
            items.extend(flatten(v, new_key, sep=sep).items())
    else:
        items.append((parent_key, obj))
    return dict(items)

def coalesce_map(flat, candidates, default=None):
    lowered = {k.lower(): v for k, v in flat.items()}
    variants_all = []
    for name in candidates:
        variants_all.extend([name, name.replace(".", "_"), name.replace("_", ".")])
    for variant in variants_all:
        v = lowered.get(variant.lower())
        if v not in [None, "", "-", "--"]:
            return v
    for variant in variants_all:
        v = next((lowered[k] for k in lowered.keys()
                  if k.endswith("." + variant.lower()) or k == variant.lower()), None)
        if v not in [None, "", "-", "--"]:
            return v
    return default

def to_int(x, default=None):
    try:
        if x is None or (isinstance(x, str) and not str(x).strip()):
            return default
        return int(float(x))
    except Exception:
        return default

def to_float(x, default=None):
    try:
        if x is None or (isinstance(x, str) and not str(x).strip()):
            return default
        return float(x)
    except Exception:
        return default

def to_bool(x, default=None):
    if isinstance(x, bool):
        return x
    if isinstance(x, str):
        xl = x.strip().lower()
        if xl in ["true", "yes", "y", "1"]:
            return True
        if xl in ["false", "no", "n", "0"]:
            return False
    if isinstance(x, (int, float)):
        return bool(x)
    return default

def parse_time(x):
    if x is None:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(x), fmt)
        except Exception:
            continue
    try:
        return pd.to_datetime(x, errors="coerce").to_pydatetime()
    except Exception:
        return None

def log1p_safe(x):
    x = to_float(x, None)
    if x is None or x < 0:
        return None
    return math.log1p(x)

def safe_ratio(n, d):
    n = to_float(n, None)
    d = to_float(d, None)
    if n is None or d is None or d == 0:
        return None
    return n / d

def lower_str(x):
    return str(x).strip().lower() if x is not None else None

def family_from_status(code):
    code = to_int(code, None)
    if code is None:
        return None
    base = (code // 100) * 100
    return f"{base}s"

def ua_family(ua):
    ual = lower_str(ua)
    if not ual:
        return None
    if "curl" in ual:
        return "curl"
    if "python-requests" in ual or "requests" in ual:
        return "requests"
    if any(w in ual for w in ["mozilla", "chrome", "safari", "edge", "firefox"]):
        return "browser"
    if "wget" in ual:
        return "wget"
    return "other"

def port_category(p):
    p = to_int(p, None)
    if p is None:
        return None
    if p in (80, 443):
        return "web"
    if p in (53,):
        return "dns"
    if p in (25, 465, 587, 110, 995, 143, 993):
        return "mail"
    if p <= 1023:
        return "well_known"
    if p >= 49152:
        return "ephemeral"
    return "registered"

def bucketize_ratio(r):
    if r is None:
        return None
    if r < 0.2:
        return "outbound_heavy"
    if r > 0.8:
        return "inbound_heavy"
    return "balanced"

def risk_posture_from_ids(severity_id, confidence_id):
    s = to_int(severity_id, None) or 0
    c = to_int(confidence_id, None) or 0
    if s >= 3 and c >= 3:
        return "high"
    if s >= 3 or c >= 3:
        return "medium"
    return "low"

def is_download_mime(ct):
    ctl = lower_str(ct)
    if ctl is None:
        return None
    if ctl.startswith("application/"):
        return True
    return False

FIREWALL_BASE_FIELDS = [
    "unmapped_indicator_name",
    "src_port",
    "alert_time",
    "unmapped_action",
    "severity",
    "confidence_id",
    "confidence",
    "severity_id",
    "rule_name",
    "http_referrer",
    "http_user_agent",
    "http_content_length",
    "http_content_type",
    "http_status_code",
    "pcap_exists",
    "bytes_in",
    "bytes_total",
    "file_name",
]

OCSF_CANDIDATES = {
    "unmapped_indicator_name": ["unmapped_indicator_name","indicator.name","threat.indicator.name","rule.indicator_name","ioc.name"],
    "src_port": ["src_port","src.port","source.port","network.src_port","network.source.port","src.port_number"],
    "alert_time": ["alert_time","time","event_time","start_time","observed_time","created_time","timestamp"],
    "unmapped_action": ["unmapped_action","action","policy.action","rule.action","disposition","verdict.action"],
    "severity": ["severity","threat.severity","event.severity","severity_label"],
    "confidence_id": ["confidence_id","confidence.id","threat.confidence_id","confidence_score_id"],
    "confidence": ["confidence","threat.confidence","event.confidence","confidence_score"],
    "severity_id": ["severity_id","severity.id","threat.severity_id","severity_score_id"],
    "rule_name": ["rule_name","rule.name","policy.rule","signature","ids.rule.name"],
    "http_referrer": ["http_referrer","http.referrer","http.request.referrer","url.referrer","web.referrer"],
    "http_user_agent": ["http_user_agent","http.user_agent","http.request.user_agent","user_agent","http.request.headers.user_agent"],
    "http_content_length": ["http_content_length","http.content_length","http.response.content_length","response.size","http.request.content_length"],
    "http_content_type": ["http_content_type","http.content_type","http.response.content_type","mime_type","response.content_type"],
    "http_status_code": ["http_status_code","http.status_code","http.response.status_code","status_code"],
    "pcap_exists": ["pcap_exists","pcap.available","network.pcap_exists","attachments.pcap","pcap"],
    "bytes_in": ["bytes_in","network.bytes_in","ingress.bytes","in_bytes"],
    "bytes_total": ["bytes_total","network.bytes_total","bytes","total_bytes","octets"],
    "file_name": ["file_name","file.name","http.request.file_name","http.file_name","url.file_name"],
}

def extract_firewall_base(flat):
    row = {}
    for key in FIREWALL_BASE_FIELDS:
        row[key] = coalesce_map(flat, OCSF_CANDIDATES.get(key, [key]))
    return row

def build_firewall_composites(row):
    bytes_in = to_float(row.get("bytes_in"), None)
    bytes_total = to_float(row.get("bytes_total"), None)
    bytes_out = max(bytes_total - bytes_in, 0.0) if (bytes_in is not None and bytes_total is not None) else None

    in_ratio = safe_ratio(bytes_in, bytes_total)
    out_ratio = safe_ratio(bytes_out, bytes_total) if bytes_out is not None else None
    dir_imbalance = None
    if bytes_in is not None and bytes_out is not None and bytes_total not in [None, 0]:
        dir_imbalance = abs(bytes_in - bytes_out) / bytes_total

    http_len_log = log1p_safe(row.get("http_content_length"))

    ts = parse_time(row.get("alert_time"))
    hour = ts.hour if ts else None
    dow = ts.weekday() if ts else None
    is_weekend = int(dow in [5, 6]) if dow is not None else None
    is_off_hours = int((hour < 8) or (hour > 20)) if hour is not None else None
    is_business_hours = int((hour is not None) and (9 <= hour <= 17))
    is_night_time = int((hour is not None) and (hour < 6 or hour > 22))

    pcat = port_category(row.get("src_port"))
    status_family = family_from_status(row.get("http_status_code"))
    is_error = to_int(row.get("http_status_code"), None)
    is_error = int(is_error >= 400) if is_error is not None else None
    has_ref = int(row.get("http_referrer") not in [None, "", "-", "--"])
    has_ua = int(row.get("http_user_agent") not in [None, "", "-", "--"])
    ua_fam = ua_family(row.get("http_user_agent"))
    is_download = is_download_mime(row.get("http_content_type"))

    rn = lower_str(row.get("rule_name"))
    ind = lower_str(row.get("unmapped_indicator_name"))
    rule_indicator_match = int(rn == ind) if (rn is not None and ind is not None) else None

    risk_posture = risk_posture_from_ids(row.get("severity_id"), row.get("confidence_id"))

    inbound_bucket = bucketize_ratio(in_ratio)
    net_posture = "|".join([x for x in [pcat, inbound_bucket] if x]) if (pcat or inbound_bucket) else None

    http_posture = None
    if status_family or is_error is not None or has_ref is not None or has_ua is not None or is_download is not None:
        http_bits = [
            status_family or "unknown_status",
            "error" if (is_error == 1) else "ok" if (is_error == 0) else "unknown_err",
            "ref" if (has_ref == 1) else "no_ref" if (has_ref == 0) else "ref_unknown",
            "ua" if (has_ua == 1) else "no_ua" if (has_ua == 0) else "ua_unknown",
            "dl" if (is_download is True) else "no_dl" if (is_download is False) else "unknown_dl",
        ]
        http_posture = "|".join(http_bits)

    analyst_posture = None
    if (row.get("pcap_exists") is not None) or (row.get("unmapped_action") is not None):
        pcap = to_bool(row.get("pcap_exists"), None)
        analyst_bits = [
            f"pcap_{'yes' if pcap else 'no'}" if pcap is not None else "pcap_unknown",
            f"action_{lower_str(row.get('unmapped_action'))}" if row.get("unmapped_action") else "action_unknown",
        ]
        analyst_posture = "|".join(analyst_bits)

    return {
        "bytes_out": bytes_out,
        "bytes_in_ratio": in_ratio,
        "bytes_out_ratio": out_ratio,
        "bytes_dir_imbalance": dir_imbalance,
        "http_content_length_log1p": http_len_log,
        "hour_of_day": hour,
        "day_of_week": dow,
        "is_weekend": is_weekend,
        "is_off_hours": is_off_hours,
        "is_business_hours": is_business_hours,
        "is_night_time": is_night_time,
        "src_port_category": pcat,
        "http_status_family": status_family,
        "http_is_error": is_error,
        "http_has_referrer": has_ref,
        "http_has_ua": has_ua,
        "http_ua_family": ua_fam,
        "http_is_download_mime": is_download,
        "rule_indicator_match": rule_indicator_match,
        "risk_posture": risk_posture,
        "net_posture": net_posture,
        "http_posture": http_posture,
        "analyst_posture": analyst_posture,
        "severity_confidence_pair": f"S{to_int(row.get('severity_id'), -1)}_C{to_int(row.get('confidence_id'), -1)}",
    }

LEAK_KEYS = ("agent_verdict", "_source_file", "alert_time")

def apply_frequency_maps(row_df: pd.DataFrame, freq_maps: Dict[str, Dict[str, float]]) -> pd.DataFrame:
    if not freq_maps:
        return row_df
    new_cols = {}
    for col, fmap in freq_maps.items():
        if col in {"agent_verdict", "_source_file", "alert_time"}:
            continue
        if col not in row_df.columns:
            continue
        val = str(row_df.loc[0, col]) if pd.notna(row_df.loc[0, col]) else None
        freq = float(fmap.get(val, 0.0)) if val is not None else 0.0
        new_cols[f"{col}_frequency"] = [freq]
        new_cols[f"{col}_rarity_score"] = [1.0 - freq]
        new_cols[f"{col}_is_rare"] = [1 if freq < 0.05 else 0]
    if new_cols:
        row_df = pd.concat([row_df, pd.DataFrame(new_cols)], axis=1)
    return row_df

def apply_anomaly_zscores(row_df: pd.DataFrame, stats: Dict[str, Dict[str, float]]) -> pd.DataFrame:
    out = row_df.copy()
    if "bytes_total_log_stats" in stats and "bytes_total" in out.columns:
        mean = float(stats["bytes_total_log_stats"].get("mean", 0.0))
        std = float(stats["bytes_total_log_stats"].get("std", 1e-6)) or 1e-6
        total_log = np.log1p(pd.to_numeric(out["bytes_total"], errors="coerce").fillna(0.0))
        out.loc[:, "bytes_total_zscore"] = np.abs((total_log - mean) / std)
        out.loc[:, "is_total_extreme"] = (out["bytes_total_zscore"] > 2.5).astype(int)
    if "http_len_log_stats" in stats and "http_content_length_log1p" in out.columns:
        mean = float(stats["http_len_log_stats"].get("mean", 0.0))
        std = float(stats["http_len_log_stats"].get("std", 1e-6)) or 1e-6
        hcl = pd.to_numeric(out["http_content_length_log1p"], errors="coerce").fillna(0.0)
        out.loc[:, "http_len_zscore"] = np.abs((hcl - mean) / std)
        out.loc[:, "is_http_len_extreme"] = (out["http_len_zscore"] > 2.5).astype(int)
    return out

def apply_clustering_profile(row_df: pd.DataFrame, clustering: Dict[str, Any]) -> pd.DataFrame:
    if not clustering:
        return row_df
    features = clustering.get("features", [])
    centers = np.array(clustering.get("centers", []), dtype=float)
    scaler_mean = np.array(clustering.get("scaler_mean", []), dtype=float)
    scaler_scale = np.array(clustering.get("scaler_scale", []), dtype=float)
    if len(features) == 0 or centers.size == 0 or scaler_mean.size == 0 or scaler_scale.size == 0:
        return row_df

    x = []
    for c in features:
        v = pd.to_numeric(row_df[c], errors="coerce").fillna(0.0).values[0] if c in row_df.columns else 0.0
        x.append(v)
    x = np.array(x, dtype=float)
    scaler_scale_safe = np.where(scaler_scale == 0, 1e-6, scaler_scale)
    xs = (x - scaler_mean) / scaler_scale_safe
    if centers.ndim != 2 or centers.shape[1] != xs.shape[0]:
        return row_df

    dists = np.linalg.norm(centers - xs[None, :], axis=1)
    min_dist = float(np.min(dists))
    idx = int(np.argmin(dists))
    isolation = float(min_dist / (np.mean(dists) + 1e-6))

    updates = {"behavioral_cluster": idx, "min_cluster_distance": min_dist, "cluster_isolation_score": isolation}
    for i in range(centers.shape[0]):
        updates[f"in_cluster_{i}"] = 1 if i == idx else 0
    return pd.concat([row_df, pd.DataFrame([updates])], axis=1)

def encode_with_label_encoders(row_df: pd.DataFrame, label_encoders: Dict[str, Any]) -> pd.DataFrame:
    if not label_encoders:
        return row_df
    new_cols, drop_cols = {}, []
    for col, le in label_encoders.items():
        if col in {"agent_verdict", "_source_file", "alert_time"}:
            continue
        if col in row_df.columns:
            drop_cols.append(col)
            classes = list(getattr(le, "classes_", []))
            mapping = {str(v): i for i, v in enumerate(classes)}
            val = str(row_df.loc[0, col]) if pd.notna(row_df.loc[0, col]) else None
            enc = mapping.get(val, 0) if val is not None else 0
            new_cols[f"{col}_standard_encoded"] = [int(enc)]
    out = row_df.drop(columns=drop_cols, errors="ignore")
    if new_cols:
        out = pd.concat([out, pd.DataFrame(new_cols)], axis=1)
    return out

def align_features(row_df: pd.DataFrame, feature_columns: List[str]) -> pd.DataFrame:
    out = row_df.copy()
    for c in feature_columns:
        if c not in out.columns:
            out[c] = 0
    out = out.loc[:, feature_columns].copy()
    for c in feature_columns:
        out.loc[:, c] = pd.to_numeric(out[c], errors="coerce").fillna(0.0)
    return out

def neutralize_leakage_features(df_model: pd.DataFrame, mask_leak: bool) -> pd.DataFrame:
    if not mask_leak:
        return df_model
    cols = [c for c in df_model.columns if any(key in c for key in LEAK_KEYS)]
    if cols:
        out = df_model.copy()
        out.loc[:, cols] = 0.0
        return out
    return df_model

def build_features_for_firewall(flat_alert: Dict[str, Any]) -> Dict[str, Any]:
    base = extract_firewall_base(flat_alert)
    composites = build_firewall_composites(base)
    return {**base, **composites}

def mean_zero_approx_contributions(model, Xs_arr: np.ndarray, feature_names: List[str], pos_index: int):
    # Simple perturbation-based contributions (no SHAP dependency)
    if hasattr(model, "predict_proba"):
        p_base = float(model.predict_proba(np.zeros_like(Xs_arr))[0, pos_index])
        p_orig = float(model.predict_proba(Xs_arr)[0, pos_index])
    else:
        # Fallback: decision_function or predict
        try:
            p_base = float(model.decision_function(np.zeros_like(Xs_arr))[0])
            p_orig = float(model.decision_function(Xs_arr)[0])
        except Exception:
            p_base = 0.0
            p_orig = float(model.predict(Xs_arr)[0])
    deltas = []
    for j in range(Xs_arr.shape[1]):
        x0 = Xs_arr.copy()
        x0[0, j] = 0.0
        try:
            if hasattr(model, "predict_proba"):
                p0 = float(model.predict_proba(x0)[0, pos_index])
            else:
                try:
                    p0 = float(model.decision_function(x0)[0])
                except Exception:
                    p0 = float(model.predict(x0)[0] == 1)
        except Exception:
            p0 = p_base
        deltas.append(p_orig - p0)
    return p_base, list(zip(feature_names, deltas))

# ==============================
# Firewall predictor (single PKL)
# ==============================

class SinglePKLFirewallPredictor:
    def __init__(self, model_path: str, mask_leak: bool = True):
        self.model = None
        self.scaler = None
        self.target_encoder = None
        self.label_encoders = {}
        self.feature_columns = []
        self.feature_info = {}
        self.mask_leak = mask_leak
        self.load_model(model_path)

    def load_model(self, model_path: str):
        """
        Load a single-PKL firewall model artifact with cross-version compatibility.
        Expected keys in the pickle:
        - model
        - scaler (optional)
        - target_encoder (optional)
        - label_encoders (dict[str, LabelEncoder]) (optional)
        - feature_columns OR features (list[str])
        - feature_info (dict) (optional)
        """
        mp = Path(model_path).expanduser()
        if not mp.exists():
            raise FileNotFoundError(f"Firewall model file not found: {mp}")

        with open(mp, "rb") as f:
            try:
                artifacts = pickle.load(f)
            except Exception:
                # fallback to the safe unpickler defined in your file
                f.seek(0)
                artifacts = _SafeUnpickler(f).load()

        if not isinstance(artifacts, dict):
            raise ValueError("Pickle does not contain a dict of artifacts")

        self.model = artifacts.get("model", artifacts.get("estimator"))
        self.scaler = artifacts.get("scaler")
        self.target_encoder = artifacts.get("target_encoder")

        le = artifacts.get("label_encoders", {}) or {}
        if isinstance(le, list):  # sometimes stored as list of (name, encoder)
            le = dict(le)
        self.label_encoders = le

        self.feature_columns = (
            artifacts.get("feature_columns")
            or artifacts.get("features")
            or artifacts.get("feature_names")
            or []
        )
        self.feature_info = artifacts.get("feature_info", {}) or {}

        # ---- sklearn 1.4+ compatibility: patch missing monotonic_cst on trees ----
        def _patch_monotonic(obj):
            if obj is None:
                return
            try:
                if not hasattr(obj, "monotonic_cst"):
                    setattr(obj, "monotonic_cst", None)
            except Exception:
                pass

        # patch the top-level model
        _patch_monotonic(self.model)

        # patch common containers
        try:
            # RandomForest/ExtraTrees/etc.
            if hasattr(self.model, "estimators_") and self.model.estimators_ is not None:
                for est in self.model.estimators_:
                    _patch_monotonic(est)

            # Bagging / old API
            if hasattr(self.model, "base_estimator_"):
                _patch_monotonic(getattr(self.model, "base_estimator_", None))
            if hasattr(self.model, "base_estimator"):
                _patch_monotonic(getattr(self.model, "base_estimator", None))

            # Pipeline
            if hasattr(self.model, "steps"):
                for _, step in getattr(self.model, "steps", []):
                    _patch_monotonic(step)
                    if hasattr(step, "estimators_"):
                        for est in step.estimators_:
                            _patch_monotonic(est)
        except Exception:
            pass
        # -------------------------------------------------------------------------

        print(f"✅ Firewall model loaded from {mp}")
        print(f"   • features: {len(self.feature_columns)}")
        print(f"   • has scaler: {self.scaler is not None}")
        print(f"   • has target_encoder: {self.target_encoder is not None}")
        print(f"   • label_encoders: {len(self.label_encoders)}")

    
    def predict(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict verdict for a single firewall alert payload.
        - Normalizes model probabilities to [0,1]
        - Returns confidence & per-class probabilities as **percent 0..100**
        - Computes simple perturbation-based feature contributions (top 15)
        """
        PERCENT_PRECISION = 2  # round confidence/probabilities to N decimals

        def _normalize_proba(p):
            p = np.asarray(p, dtype=float).ravel()
            if p.size == 0:
                return np.array([], dtype=float)
            # If looks like percent or unnormalized, fix it
            if np.nanmax(p) > 1.0 or np.nansum(p) > 1.00001:
                if np.nanmax(p) <= 100.0:
                    p = p / 100.0
                else:
                    e = np.exp(p - np.nanmax(p))
                    p = e / (np.nansum(e) + 1e-12)
            s = np.nansum(p)
            if s > 0 and abs(s - 1.0) > 1e-6:
                p = p / s
            return p

        try:
            # --- Flatten + feature engineering ---
            flat = flatten(input_data)
            row = build_features_for_firewall(flat)
            df = pd.DataFrame([row])

            # Training-time enrichments
            df = apply_frequency_maps(df, self.feature_info.get("category_frequency_maps", {}))
            df = apply_anomaly_zscores(df, {
                "bytes_total_log_stats": self.feature_info.get("bytes_total_log_stats", {}),
                "http_len_log_stats": self.feature_info.get("http_len_log_stats", {}),
            })
            df = apply_clustering_profile(df, self.feature_info.get("clustering", self.feature_info.get("clustering_profile", {})))
            df = encode_with_label_encoders(df, self.label_encoders)

            # Align to model columns + optional leakage masking
            df_model = align_features(df, self.feature_columns)
            df_model = neutralize_leakage_features(df_model, self.mask_leak)

            # Keep DataFrame for scaler (avoids sklearn feature-name warnings)
            X_df = df_model
            if self.scaler is not None:
                Xs = self.scaler.transform(X_df)
            else:
                Xs = X_df.values
            Xs_arr = Xs if isinstance(Xs, np.ndarray) else np.asarray(Xs)

            # --- Predict ---
            if hasattr(self.model, "predict_proba"):
                proba_raw = self.model.predict_proba(Xs_arr)[0]
                proba = _normalize_proba(proba_raw)
            else:
                # Fallback: decision_function -> sigmoid/softmax, else hard class
                if hasattr(self.model, "decision_function"):
                    dfc = np.asarray(self.model.decision_function(Xs_arr), dtype=float).ravel()
                    if dfc.ndim == 1 or dfc.size == 1:
                        p1 = 1.0 / (1.0 + np.exp(-(dfc[0] if dfc.size else 0.0)))
                        proba = np.array([1 - p1, p1], dtype=float)
                    else:
                        e = np.exp(dfc - np.max(dfc))
                        proba = (e / (np.sum(e) + 1e-12)).ravel()
                else:
                    pred = int(self.model.predict(Xs_arr)[0])
                    proba = np.array([1.0, 0.0], dtype=float) if pred == 0 else np.array([0.0, 1.0], dtype=float)

            # Argmax + confidence (0..1)
            if proba.size == 0:
                idx = 0
                confidence = 0.0
            else:
                idx = int(np.nanargmax(proba))
                confidence = float(proba[idx])

            # Map class names -> probabilities
            try:
                if self.target_encoder is not None and hasattr(self.target_encoder, "classes_"):
                    class_names = list(self.target_encoder.classes_)
                    k = min(len(class_names), proba.shape[0])
                    probabilities = {class_names[i]: float(proba[i]) for i in range(k)}
                    label = str(self.target_encoder.inverse_transform([idx])[0])
                else:
                    label = str(idx)
                    probabilities = {f"class_{i}": float(proba[i]) for i in range(proba.shape[0])}
            except Exception:
                label = str(idx)
                probabilities = {f"class_{i}": float(proba[i]) for i in range(proba.shape[0])}

            
            pos_index = idx
            try:
                if self.target_encoder is not None and hasattr(self.target_encoder, "classes_"):
                    classes = list(self.target_encoder.classes_)
                    if "true_positive" in classes:
                        pos_index = classes.index("true_positive")
            except Exception:
                pass

            # --- Contributions (difference from zeroed feature) ---
            base_val, contribs = mean_zero_approx_contributions(
                self.model, Xs_arr, df_model.columns.tolist(), pos_index
            )
            contribs = sorted(contribs, key=lambda x: abs(x[1]), reverse=True)[:15]
            feature_importance = {name: float(val) for name, val in contribs}

            # --- Simple firewall risk score (reuse 'file_risk_score' key for FE compatibility) ---
            risk = 0.0
            status = to_int(row.get("http_status_code"), None)
            if status is not None and status >= 400:
                risk += 1.0
            if to_int(row.get("severity_id"), 0) >= 3:
                risk += 1.0
            if to_bool(row.get("pcap_exists"), False):
                risk += 1.0
            if to_float(row.get("bytes_total"), 0.0) > 10_000_000:  # ~10MB
                risk += 1.0

            # --- Scale outputs to 0..100 (percent) ---
            confidence_pct = round(confidence * 100.0, PERCENT_PRECISION)
            probabilities_pct = {k: round(v * 100.0, PERCENT_PRECISION) for k, v in probabilities.items()}

            return {
                "prediction": {
                    "predicted_verdict": label,
                    "confidence": confidence_pct,        # 0..100
                    "probabilities": probabilities_pct   # each 0..100 (≈ sum to 100)
                },
                "metadata": {
                    "file_risk_score": risk,
                    "feature_importance": feature_importance,  # deltas in prob space (0..1 scale)
                    "features_used": self.feature_columns,
                    "preprocessing_success": True
                }
            }

        except Exception as e:
            print(f"Firewall prediction error: {e}")
            return {
                "prediction": {
                    "predicted_verdict": "Error",
                    "confidence": 0.0,
                    "probabilities": {}
                },
                "metadata": {
                    "error": str(e),
                    "preprocessing_success": False,
                    "feature_importance": {},
                    "features_used": []
                }
            }


# ==============================
# Load firewall model (single PKL)
# ==============================

FIREWALL_MODEL_PATH = "best_model.pkl" # set via env or keep default
try:
    firewall_predictor = SinglePKLFirewallPredictor(FIREWALL_MODEL_PATH, mask_leak=True)
    print("✅ Firewall model loaded successfully")
except Exception as e:
    print(f"❌ Failed to load firewall model: {e}")
    firewall_predictor = None

# ==============================
# FastAPI route: /predict-firewall
# Same payload/behavior as /predict (file upload or JSON body)
# ==============================

@app.post("/predict-firewall")
async def predict_firewall(
    file: UploadFile = File(None),
    json_data: dict = Body(None)
):
    """
    Predict verdict for firewall alerts using a single-PKL artifact.
    Accepts either:
    - JSON file upload via multipart/form-data
    - Direct JSON data in request body
    Response shape mirrors the EDR /predict endpoint.
    """
    if not firewall_predictor:
        raise HTTPException(status_code=503, detail="Firewall model not loaded. Check server logs.")

    try:
        # Parse input (same flow as EDR)
        if file is not None:
            if not file.filename.lower().endswith(".json"):
                raise HTTPException(status_code=400, detail="Only JSON files are supported.")
            content = await file.read()
            try:
                raw_data = json.loads(content.decode("utf-8"))
            except json.JSONDecodeError as e:
                raise HTTPException(status_code=400, detail=f"Invalid JSON format: {str(e)}")
            input_source = "file_upload"
        elif json_data is not None:
            raw_data = json_data
            input_source = "json_body"
        else:
            raise HTTPException(status_code=400, detail="Provide either a JSON file or JSON data in request body.")

        # Single alert or container of alerts: if list/logs, pick first; or you can loop externally
        payload = raw_data
        if isinstance(raw_data, dict) and any(k in raw_data for k in ("logs", "events", "data", "records", "items")):
            for k in ("logs", "events", "data", "records", "items"):
                if isinstance(raw_data.get(k), list) and raw_data.get(k):
                    payload = raw_data[k][0]
                    break
        elif isinstance(raw_data, list) and raw_data:
            payload = raw_data[0]

        result = firewall_predictor.predict(payload)

        # Add input processing metadata (same keys as EDR)
        result['metadata']['input_processing'] = {
            'flexible_parsing_success': True,  # format-agnostic coalescing
            'input_source': input_source,
            'alert_id': payload.get('alert_id', 'unknown')
        }

        return JSONResponse(content=result)

    except HTTPException:
        raise
    except Exception as e:
        print(f"/predict-firewall error: {e}")
        raise HTTPException(status_code=500, detail=f"Firewall prediction failed: {str(e)}")



NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME") 
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

neo4j_driver = None
try:
    if all([NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD]):
        neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
        neo4j_driver.verify_connectivity()
        print("Neo4j connection established successfully")
    else:
        print("Missing Neo4j environment variables")
except Exception as e:
    print(f"Failed to connect to Neo4j: {e}")
    neo4j_driver = None

class Neo4jGraphManager:
    """Manages Neo4j graph operations for alert data following OCSF mapping"""
    
    def __init__(self, driver):
        self.driver = driver
        self.database = NEO4J_DATABASE
        
    def create_alert_graph(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create comprehensive alert graph with robust error handling"""
        
        print("Creating alert knowledge graph in Neo4j with robust error handling...")
        
        # Create unique alert ID
        alert_id = alert_data.get('alert', {}).get('id', f"alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        with self.driver.session(database=self.database) as session:
            try:
                # Reset counters
                self.nodes_created = {}
                self.relationships_created = []
                
                # Create constraints and indexes first
                print("Creating constraints and indexes...")
                self.create_constraints_and_indexes()
                
                # CREATE NODES with error handling for each
                node_methods = [
                    ('Alert', self._create_node_1_alert),
                    ('Scores', self._create_node_19_scores),
                    ('File', self._create_node_2_file),
                    ('Hash_SHA256', self._create_node_3_hash_sha256),
                    ('Hash_SHA1', self._create_node_4_hash_sha1),
                    ('Process', self._create_node_5_process),
                    ('User', self._create_node_6_user),
                    ('Host', self._create_node_7_host),
                    ('NetworkInterface', self._create_node_8_network_interface),
                    ('ExternalIP', self._create_node_9_external_ip),
                    ('MitigationAction', self._create_node_12_mitigation_action),
                    ('Engine', self._create_node_13_engine_merged),
                    ('Site', self._create_node_14_site),
                    ('Group', self._create_node_15_group),
                    ('Incident', self._create_node_16_incident),
                    ('OsVersion', self._create_node_17_os_version),
                    ('WhiteningRule', self._create_node_18_whitening_rule)
                ]
                
                for node_name, method in node_methods:
                    try:
                        method(session, alert_data)
                    except Exception as e:
                        print(f"Error creating {node_name} node: {e}")
                        continue

                # NEW: Call MCP server to fetch enrichment and create ThreatIntel nodes
                try:
                    enrichment = self._fetch_enrichment_via_mcp(alert_data)
                    if enrichment:
                        self._create_threatintel_nodes_from_enrichment(session, alert_id, alert_data, enrichment)
                except Exception as e:
                    print(f"Enrichment via MCP failed: {e}")
                
                # CREATE RELATIONSHIPS with error handling
                relationship_methods = [
                    ('ALERT_REFERS_TO_FILE', self._create_rel_1_alert_refers_to_file),
                    ('FILE_HAS_HASH_SHA256', self._create_rel_2_file_has_hash_sha256),
                    ('FILE_HAS_HASH_SHA1', self._create_rel_3_file_has_hash_sha1),
                    ('ALERT_TRIGGERED_BY', self._create_rel_4_alert_triggered_by),
                    ('PROCESS_EXECUTED_BY', self._create_rel_5_process_executed_by),
                    ('PROCESS_ON_HOST', self._create_rel_6_process_on_host),
                    ('FILE_RESIDES_ON', self._create_rel_7_file_resides_on),
                    # Removed legacy TI relationships; replaced by ALERT_ENRICHED_BY
                    ('HOST_CONNECTS_TO', self._create_rel_10_host_connects_to),
                    ('ALERT_MITIGATED_VIA', self._create_rel_11_alert_mitigated_via),
                    ('ACTION_APPLIED_ON', self._create_rel_12_action_applied_on),
                    ('ALERT_DETECTED_BY', self._create_rel_13_alert_detected_by),
                    ('ALERT_BELONGS_TO_SITE', self._create_rel_14_alert_belongs_to_site),
                    ('HOST_IN_GROUP', self._create_rel_15_host_in_group),
                    ('HOST_HAS_INTERFACE', self._create_rel_16_host_has_interface),
                    ('ALERT_IN_INCIDENT', self._create_rel_17_alert_in_incident),
                    ('HOST_HAS_OS', self._create_rel_18_host_has_os),
                    ('ALERT_WHITELISTED_BY', self._create_rel_19_alert_whitelisted_by),
                    ('ALERT_HAS_SCORE', self._create_rel_20_alert_has_score)
                ]
                
                for rel_name, method in relationship_methods:
                    try:
                        method(session, alert_data)
                    except Exception as e:
                        print(f"Error creating {rel_name} relationship: {e}")
                        continue
                
                result = {
                    "success": True,
                    "graph_created": True,
                    "alert_id": alert_id,
                    "nodes_created": sum(self.nodes_created.values()),
                    "relationships_created": len(self.relationships_created),
                    "node_breakdown": self.nodes_created,
                    "timestamp": datetime.now().isoformat(),
                    "errors_handled": True
                }
                
                print(f"Graph created successfully: {sum(self.nodes_created.values())} nodes, {len(self.relationships_created)} relationships")
                return result
                
            except Exception as e:
                print(f"Critical error in graph creation: {e}")
                return {
                    "success": False,
                    "error": str(e),
                    "alert_id": alert_id,
                    "nodes_created": sum(self.nodes_created.values()) if hasattr(self, 'nodes_created') else 0,
                    "relationships_created": len(self.relationships_created) if hasattr(self, 'relationships_created') else 0,
                    "timestamp": datetime.now().isoformat()
                }
        
    
    # ==================== NODE CREATION METHODS (18 nodes) ====================
    
    def _create_node_1_alert(self, session, data):
        """1. Alert — key: threat.id"""
        query = """
        MERGE (a:Alert {threat_id: $threat_id})
        SET a.time = $time,
            a.detected_time = $detected_time,
            a.alert_id = $alert_id,
            a.name = $name,
            a.classification = $classification,
            a.confidence = $confidence,
            a.verdict = $verdict,
            a.incident_status = $incident_status,
            a.remediation_status = $remediation_status
        """
        session.run(query,
            threat_id=data['threat']['id'],
            alert_id=data['alert']['id'],
            time=data['time'],
            detected_time=data['threat']['detected_time'],
            name=data['threat']['name'],
            classification=data['threat']['classification'],
            confidence=data['threat']['confidence'],
            verdict=data['threat']['verdict'],
            incident_status=data['incident']['status'],
            remediation_status=data['remediation']['status']
        )
        self.nodes_created['Alert'] = self.nodes_created.get('Alert', 0) + 1

    def _create_node_19_scores(self, session, data):
        """19. Scores — stores ML/GNN/Rule scores for the alert"""
        query = """
        MERGE (s:Scores {alert_id: $alert_id})
        SET s.ml_score_fp = $ml_score_fp,
            s.gnn_score_fp = $gnn_score_fp,
            s.rule_score_fp = $rule_score_fp
        """
        session.run(query,
            alert_id=data['alert']['id'],
            ml_score_fp=data['ml_score'].get('False Positive'),
            gnn_score_fp=data['gnn_score'].get('False Positive'),
            rule_score_fp=data['rule_base_score'].get('False Positive')
        )
        self.nodes_created['Scores'] = self.nodes_created.get('Scores', 0) + 1

    def _create_node_2_file(self, session, data):
        """2. File — key: file.uid"""
        query = """
        MERGE (f:File {uid: $uid})
        SET f.path = $path,
            f.extension = $extension,
            f.size = $size,
            f.verification_type = $verification_type,
            f.certificate_status = $certificate_status,
            f.certificate_issuer = $certificate_issuer,
            f.reputation_score = $reputation_score
        """
        session.run(query,
            uid=data['file']['uid'],
            path=data['file']['path'],
            extension=data['file']['extension'],
            size=data['file']['size'],
            verification_type=data['file']['verification']['type'],
            certificate_status=data['file']['signature']['certificate']['status'],
            certificate_issuer=data['file']['signature']['certificate']['issuer'],
            reputation_score=data['file']['reputation']['score']
        )
        self.nodes_created['File'] = self.nodes_created.get('File', 0) + 1
    
    def _create_node_3_hash_sha256(self, session, data):
        """3. Hash (sha256) — key: file.hashes.sha256"""
        if data['file']['hashes'].get('sha256'):
            query = """
            MERGE (h:Hash {algorithm: 'sha256', value: $value})
            """
            session.run(query, value=data['file']['hashes']['sha256'])
            self.nodes_created['Hash(SHA256)'] = self.nodes_created.get('Hash(SHA256)', 0) + 1
    
    def _create_node_4_hash_sha1(self, session, data):
        """4. Hash (sha1) — key: file.hashes.sha1"""
        if data['file']['hashes'].get('sha1'):
            query = """
            MERGE (h:Hash {algorithm: 'sha1', value: $value})
            """
            session.run(query, value=data['file']['hashes']['sha1'])
            self.nodes_created['Hash(SHA1)'] = self.nodes_created.get('Hash(SHA1)', 0) + 1
    
    def _create_node_5_process(self, session, data):
        """5. Process — key: (threat.id, process.name)"""
        query = """
        MERGE (p:Process {threat_id: $threat_id, name: $name})
        SET p.cmd_args = $cmd_args,
            p.isFileless = $isFileless,
            p.detection_type = $detection_type
        """
        session.run(query,
            threat_id=data['threat']['id'],
            name=data['process']['name'],
            cmd_args=data['process']['cmd']['args'],
            isFileless=data['process']['isFileless'],
            detection_type=data['threat']['detection']['type']
        )
        self.nodes_created['Process'] = self.nodes_created.get('Process', 0) + 1
    
    def _create_node_6_user(self, session, data):
        """6. User â€" key: actor.process.user.name (optional)"""
        actor = data.get('actor', {})
        process = actor.get('process', {})
        user = process.get('user', {})
        user_name = user.get('name')
        
        if user_name:
            query = """
            MERGE (u:User {name: $name})
            SET u.domain = $domain
            """
            session.run(query,
                name=user_name,
                domain=user.get('domain', 'UNKNOWN')
            )
            self.nodes_created['User'] = self.nodes_created.get('User', 0) + 1
        else:
            print(f"No user name found, skipping user creation")
    
    def _create_node_7_host(self, session, data):
        """7. Host — key: device.uuid"""
        query = """
        MERGE (h:Host {uuid: $uuid})
        SET h.hostname = $hostname,
            h.domain = $domain,
            h.ipv4_addresses = $ipv4_addresses,
            h.network_status = $network_status,
            h.is_active = $is_active
        """
        session.run(query,
            uuid=data['device']['uuid'],
            hostname=data['device']['hostname'],
            domain=data['device']['domain'],
            ipv4_addresses=data['device']['ipv4_addresses'],
            network_status=data['device']['network']['status'],
            is_active=data['device']['is_active']
        )
        self.nodes_created['Host'] = self.nodes_created.get('Host', 0) + 1
    
    def _create_node_8_network_interface(self, session, data):
        """8. NetworkInterface — key: (device.uuid, device.interface.mac)"""
        interface = data['device']['interface']
        query = """
        MERGE (n:NetworkInterface {device_uuid: $device_uuid, mac: $mac})
        SET n.name = $name,
            n.ip = $ip
        """
        session.run(query,
            device_uuid=data['device']['uuid'],
            mac=interface['mac'],
            name=interface['name'],
            ip=interface['ip']
        )
        self.nodes_created['NetworkInterface'] = self.nodes_created.get('NetworkInterface', 0) + 1
    
    def _create_node_9_external_ip(self, session, data):
        """9. ExternalIP — key: device.interface.ip"""
        query = """
        MERGE (e:ExternalIP {ip: $ip})
        """
        session.run(query, ip=data['device']['interface']['ip'])
        self.nodes_created['ExternalIP'] = self.nodes_created.get('ExternalIP', 0) + 1
    
    # ===== New enrichment helpers =====
    def _fetch_enrichment_via_mcp(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Call MCP server's enrich_alert_combined by writing the alert to a temp folder."""
        try:
            import tempfile, subprocess, uuid
            temp_dir = tempfile.mkdtemp()
            # Ensure alert has an id
            alert_id = alert_data.get('alert', {}).get('id') or str(uuid.uuid4())
            # Write alert file for MCP server to read
            alert_path = os.path.join(temp_dir, f"{alert_id}.json")
            with open(alert_path, 'w', encoding='utf-8') as f:
                json.dump(alert_data, f, indent=2)

            # Prepare python inline script to import and call server.call_tool
            server_dir = os.path.dirname(os.path.abspath("server.py")).replace('\\', '\\\\')
            server_module = os.path.splitext(os.path.basename("server.py"))[0]
            temp_dir_escaped = temp_dir.replace('\\', '\\\\')

            cmd = [
                "python", "-c",
                f"""
import sys, os, json, asyncio
sys.path.append(r'{server_dir}')
from {server_module} import call_tool

async def main():
    res = await call_tool('enrich_alert_combined', {{'alert_id': '{alert_id}', 'folder': r'{temp_dir_escaped}'}})
    # res is a sequence of TextContent; print the text
    if hasattr(res, '__iter__') and len(res) > 0:
        item = res[0]
        if hasattr(item, 'text'):
            print(item.text)
        elif isinstance(item, dict) and 'text' in item:
            print(item['text'])
        else:
            print(json.dumps({{'error': 'invalid_result'}}))
    else:
        print(json.dumps({{'error': 'no_result'}}))

asyncio.run(main())
"""
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            stdout = (proc.stdout or '').strip()
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr or 'MCP call failed')
            if not stdout:
                return {}
            try:
                parsed = json.loads(stdout)
            except Exception:
                # Sometimes extra logs might be printed; try to find trailing JSON
                last_brace = stdout.rfind('}')
                first_brace = stdout.find('{')
                parsed = json.loads(stdout[first_brace:last_brace+1])
            return parsed
        except Exception as e:
            print(f"MCP enrichment call failed: {e}")
            return {}

    def _flatten_for_props(self, obj: Any, parent_key: str = "") -> Dict[str, Any]:
        props: Dict[str, Any] = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                nk = f"{parent_key}.{k}" if parent_key else str(k)
                props.update(self._flatten_for_props(v, nk))
        elif isinstance(obj, list):
            # store list as JSON string to keep Neo4j property types valid
            props[parent_key] = json.dumps(obj)
        else:
            props[parent_key] = obj
        return props

    def _create_threatintel_nodes_from_enrichment(self, session, alert_id: str, alert_data: Dict[str, Any], enrichment: Dict[str, Any]):
        provider_keys = {
            'virustotal': 'VirusTotal',
            'checkpoint': 'Check Point',
            'cyberint': 'Cyberint',
            'abuseipdb': 'AbuseIPDB'
        }
        for key, provider_name in provider_keys.items():
            data = enrichment.get(key)
            if data is None:
                continue
            # Accept either dict or primitive; wrap non-dict
            ti_payload = data if isinstance(data, dict) else {"value": data}
            flattened = self._flatten_for_props(ti_payload)
            # Always include provider and alert_id
            flattened.update({
                'provider': provider_name,
                'alert_id': alert_id
            })
            # Link threat intel to hash, not alert
            query = """
            MERGE (t:ThreatIntel {provider: $provider, alert_id: $alert_id})
            SET t += $props
            WITH t
            MATCH (h:Hash {algorithm: 'sha256', value: $sha256})
            MERGE (h)-[:HASH_ENRICHED_BY_TI]->(t)
            """
            try:
                sha256_val = ((alert_data.get('file') or {}).get('hashes') or {}).get('sha256')
                if not sha256_val:
                    print("No sha256 in alert file; skipping HASH_ENRICHED_BY_TI creation for", provider_name)
                    continue
                session.run(query,
                    provider=provider_name,
                    alert_id=alert_id,
                    sha256=sha256_val,
                    props=flattened
                )
                self.nodes_created['ThreatIntel'] = self.nodes_created.get('ThreatIntel', 0) + 1
                self.relationships_created.append('HASH_ENRICHED_BY_TI')
            except Exception as e:
                print(f"Failed creating ThreatIntel node for {provider_name}: {e}")
    
    def _create_node_12_mitigation_action(self, session, data):
        """12. MitigationAction — key: remediation.uid"""
        query = """
        MERGE (m:MitigationAction {uid: $uid})
        SET m.status = $status,
            m.desc = $desc,
            m.start_time = $start_time,
            m.end_time = $end_time,
            m.result = $result
        """
        session.run(query,
            uid=data['remediation']['uid'],
            status=data['remediation']['status'],
            desc=data['remediation']['desc'],
            start_time=data['remediation']['start_time'],
            end_time=data['remediation']['end_time'],
            result=data['remediation']['result']
        )
        self.nodes_created['MitigationAction'] = self.nodes_created.get('MitigationAction', 0) + 1
    
    def _create_node_13_engine_merged(self, session, data):
        """13. Engine (merged) — key (uid): pre_execution|On-Write Static AI|On-Write DFI|agent_policy"""
        metadata = data.get('metadata', {}).get('product', {})
        
        # Handle feature name safely
        feature_name = metadata.get('feature', {}).get('name', [])
        if isinstance(feature_name, list) and len(feature_name) > 0:
            if isinstance(feature_name[0], dict):
                feature_str = feature_name[0].get('title', 'Unknown')
            else:
                feature_str = str(feature_name[0])
        else:
            feature_str = str(feature_name) if feature_name else 'Unknown'
        
        # Handle product names safely
        product_names = metadata.get('name', [])
        if not isinstance(product_names, list):
            product_names = [str(product_names)] if product_names else []
        
        # Convert all items to strings
        product_names_str = [str(name) for name in product_names]
        
        engine_names = [feature_str] + product_names_str
        engine_uid = '|'.join(engine_names)
        
        query = """
        MERGE (e:Engine {uid: $uid})
        SET e.name = $name,
            e.version = $version,
            e.names = $names,
            e.detection_type = $detection_type
        """
        session.run(query,
            uid=engine_uid,
            name=feature_str,
            version=metadata.get('feature', {}).get('version', 'Unknown'),
            names=engine_names,
            detection_type=data.get('threat', {}).get('detection', {}).get('type', 'unknown')
        )
        self.nodes_created['Engine'] = self.nodes_created.get('Engine', 0) + 1
    
    def _create_node_14_site(self, session, data):
        """14. Site — key: device.location.uid"""
        location = data['device']['location']
        query = """
        MERGE (s:Site {uid: $uid})
        SET s.desc = $desc
        """
        session.run(query,
            uid=location['uid'],
            desc=location['desc']
        )
        self.nodes_created['Site'] = self.nodes_created.get('Site', 0) + 1
    
    def _create_node_15_group(self, session, data):
        """15. Group â€" key: device.groups[0].uid (optional)"""
        device = data.get('device', {})
        groups = device.get('groups', [])
        
        if groups and len(groups) > 0 and isinstance(groups[0], dict):
            group = groups[0]
            query = """
            MERGE (g:Group {uid: $uid})
            SET g.name = $name
            """
            session.run(query,
                uid=group.get('uid', 'default_group_uid'),
                name=group.get('name', 'Default Group')
            )
            self.nodes_created['Group'] = self.nodes_created.get('Group', 0) + 1
        else:
            print(f"No groups found in device data, skipping group creation")
    
    def _create_node_16_incident(self, session, data):
        """16. Incident — key: INC-{threat.id} (synthetic)"""
        incident_id = f"INC-{data['threat']['id']}"
        query = """
        MERGE (i:Incident {incident_id: $incident_id})
        SET i.status = $status,
            i.desc = $desc
        """
        session.run(query,
            incident_id=incident_id,
            status=data['incident']['status'],
            desc=data['incident']['desc']
        )
        self.nodes_created['Incident'] = self.nodes_created.get('Incident', 0) + 1
    
    def _create_node_17_os_version(self, session, data):
        """17. OsVersion — key: (device.os.name, device.os.build)"""
        os_info = data['device']['os']
        query = """
        MERGE (o:OsVersion {name: $name, build: $build})
        SET o.type = $type
        """
        session.run(query,
            name=os_info['name'],
            build=os_info['build'],
            type=os_info['type']
        )
        self.nodes_created['OsVersion'] = self.nodes_created.get('OsVersion', 0) + 1
    
    def _create_node_18_whitening_rule(self, session, data):
        """18. WhiteningRule — key: remediation.result"""
        query = """
        MERGE (w:WhiteningRule {rule: $rule})
        """
        session.run(query, rule=data['remediation']['result'])
        self.nodes_created['WhiteningRule'] = self.nodes_created.get('WhiteningRule', 0) + 1
    
    # ==================== RELATIONSHIP CREATION METHODS (20 relationships) ====================
    
    def _create_rel_1_alert_refers_to_file(self, session, data):
        """1. ALERT_REFERS_TO_FILE — Alert → File edge props: created_at = time"""
        query = """
        MATCH (a:Alert {threat_id: $threat_id}), (f:File {uid: $file_uid})
        MERGE (a)-[r:ALERT_REFERS_TO_FILE]->(f)
        SET r.created_at = $created_at
        """
        session.run(query,
            threat_id=data['threat']['id'],
            file_uid=data['file']['uid'],
            created_at=data['time']
        )
        self.relationships_created.append('ALERT_REFERS_TO_FILE')
    
    def _create_rel_2_file_has_hash_sha256(self, session, data):
        """2. FILE_HAS_HASH — File → Hash(sha256)"""
        if data['file']['hashes'].get('sha256'):
            query = """
            MATCH (f:File {uid: $file_uid}), (h:Hash {algorithm: 'sha256', value: $hash_value})
            MERGE (f)-[:FILE_HAS_HASH]->(h)
            """
            session.run(query,
                file_uid=data['file']['uid'],
                hash_value=data['file']['hashes']['sha256']
            )
            self.relationships_created.append('FILE_HAS_HASH(SHA256)')
    
    def _create_rel_3_file_has_hash_sha1(self, session, data):
        """3. FILE_HAS_HASH — File → Hash(sha1)"""
        if data['file']['hashes'].get('sha1'):
            query = """
            MATCH (f:File {uid: $file_uid}), (h:Hash {algorithm: 'sha1', value: $hash_value})
            MERGE (f)-[:FILE_HAS_HASH]->(h)
            """
            session.run(query,
                file_uid=data['file']['uid'],
                hash_value=data['file']['hashes']['sha1']
            )
            self.relationships_created.append('FILE_HAS_HASH(SHA1)')
    
    def _create_rel_4_alert_triggered_by(self, session, data):
        """4. ALERT_TRIGGERED_BY — Alert → Process edge props: detection_type, initiated_by"""
        query = """
        MATCH (a:Alert {threat_id: $threat_id}), (p:Process {threat_id: $threat_id, name: $process_name})
        MERGE (a)-[r:ALERT_TRIGGERED_BY]->(p)
        SET r.detection_type = $detection_type,
            r.initiated_by = 'agent_policy'
        """
        session.run(query,
            threat_id=data['threat']['id'],
            process_name=data['process']['name'],
            detection_type=data['threat']['detection']['type']
        )
        self.relationships_created.append('ALERT_TRIGGERED_BY')
    
    def _create_rel_5_process_executed_by(self, session, data):
        """5. PROCESS_EXECUTED_BY — Process → User (optional)"""
        actor = data.get('actor', {})
        process = actor.get('process', {})
        user = process.get('user', {})
        user_name = user.get('name')
        
        if user_name:
            threat_id = data.get('threat', {}).get('id')
            process_name = data.get('process', {}).get('name')
            
            if threat_id and process_name:
                query = """
                MATCH (p:Process {threat_id: $threat_id, name: $process_name}), (u:User {name: $user_name})
                MERGE (p)-[:PROCESS_EXECUTED_BY]->(u)
                """
                session.run(query,
                    threat_id=threat_id,
                    process_name=process_name,
                    user_name=user_name
                )
                self.relationships_created.append('PROCESS_EXECUTED_BY')
            else:
                print(f"Missing threat_id or process_name for PROCESS_EXECUTED_BY relationship")
        else:
            print(f"No user name found, skipping PROCESS_EXECUTED_BY relationship")
    
    def _create_rel_6_process_on_host(self, session, data):
        """6. PROCESS_ON_HOST — Process → Host"""
        query = """
        MATCH (p:Process {threat_id: $threat_id, name: $process_name}), (h:Host {uuid: $host_uuid})
        MERGE (p)-[:PROCESS_ON_HOST]->(h)
        """
        session.run(query,
            threat_id=data['threat']['id'],
            process_name=data['process']['name'],
            host_uuid=data['device']['uuid']
        )
        self.relationships_created.append('PROCESS_ON_HOST')
    
    def _create_rel_7_file_resides_on(self, session, data):
        """7. FILE_RESIDES_ON — File → Host"""
        query = """
        MATCH (f:File {uid: $file_uid}), (h:Host {uuid: $host_uuid})
        MERGE (f)-[:FILE_RESIDES_ON]->(h)
        """
        session.run(query,
            file_uid=data['file']['uid'],
            host_uuid=data['device']['uuid']
        )
        self.relationships_created.append('FILE_RESIDES_ON')
    
    def _create_rel_10_host_connects_to(self, session, data):
        """10. HOST_CONNECTS_TO — Host → ExternalIP edge props: vantage = "egress" """
        query = """
        MATCH (h:Host {uuid: $host_uuid}), (e:ExternalIP {ip: $external_ip})
        MERGE (h)-[r:HOST_CONNECTS_TO]->(e)
        SET r.vantage = 'egress'
        """
        session.run(query,
            host_uuid=data['device']['uuid'],
            external_ip=data['device']['interface']['ip']
        )
        self.relationships_created.append('HOST_CONNECTS_TO')
    
    def _create_rel_11_alert_mitigated_via(self, session, data):
        """11. ALERT_MITIGATED_VIA — Alert → MitigationAction"""
        query = """
        MATCH (a:Alert {threat_id: $threat_id}), (m:MitigationAction {uid: $mitigation_uid})
        MERGE (a)-[:ALERT_MITIGATED_VIA]->(m)
        """
        session.run(query,
            threat_id=data['threat']['id'],
            mitigation_uid=data['remediation']['uid']
        )
        self.relationships_created.append('ALERT_MITIGATED_VIA')
    
    def _create_rel_12_action_applied_on(self, session, data):
        """12. ACTION_APPLIED_ON — MitigationAction → Host"""
        query = """
        MATCH (m:MitigationAction {uid: $mitigation_uid}), (h:Host {uuid: $host_uuid})
        MERGE (m)-[:ACTION_APPLIED_ON]->(h)
        """
        session.run(query,
            mitigation_uid=data['remediation']['uid'],
            host_uuid=data['device']['uuid']
        )
        self.relationships_created.append('ACTION_APPLIED_ON')
    
    def _create_rel_13_alert_detected_by(self, session, data):
        """13. ALERT_DETECTED_BY — Alert → Engine (merged)"""
        metadata = data.get('metadata', {}).get('product', {})
        
        # Handle feature name safely
        feature_name = metadata.get('feature', {}).get('name', [])
        if isinstance(feature_name, list) and len(feature_name) > 0:
            if isinstance(feature_name[0], dict):
                feature_str = feature_name[0].get('title', 'Unknown')
            else:
                feature_str = str(feature_name[0])
        else:
            feature_str = str(feature_name) if feature_name else 'Unknown'
        
        # Handle product names safely
        product_names = metadata.get('name', [])
        if not isinstance(product_names, list):
            product_names = [str(product_names)] if product_names else []
        
        # Convert all items to strings
        product_names_str = [str(name) for name in product_names]
        
        engine_names = [feature_str] + product_names_str
        engine_uid = '|'.join(engine_names)
        
        query = """
        MATCH (a:Alert {threat_id: $threat_id}), (e:Engine {uid: $engine_uid})
        MERGE (a)-[:ALERT_DETECTED_BY]->(e)
        """
        session.run(query,
            threat_id=data['threat']['id'],
            engine_uid=engine_uid
        )
        self.relationships_created.append('ALERT_DETECTED_BY')
    
    def _create_rel_14_alert_belongs_to_site(self, session, data):
        """14. ALERT_BELONGS_TO_SITE — Alert → Site"""
        query = """
        MATCH (a:Alert {threat_id: $threat_id}), (s:Site {uid: $site_uid})
        MERGE (a)-[:ALERT_BELONGS_TO_SITE]->(s)
        """
        session.run(query,
            threat_id=data['threat']['id'],
            site_uid=data['device']['location']['uid']
        )
        self.relationships_created.append('ALERT_BELONGS_TO_SITE')
    
    def _create_rel_15_host_in_group(self, session, data):
        """15. HOST_IN_GROUP — Host → Group (optional)"""
        device = data.get('device', {})
        groups = device.get('groups', [])
        
        if groups and len(groups) > 0 and isinstance(groups[0], dict):
            group_uid = groups[0].get('uid')
            host_uuid = device.get('uuid')
            
            if group_uid and host_uuid:
                query = """
                MATCH (h:Host {uuid: $host_uuid}), (g:Group {uid: $group_uid})
                MERGE (h)-[:HOST_IN_GROUP]->(g)
                """
                session.run(query,
                    host_uuid=host_uuid,
                    group_uid=group_uid
                )
                self.relationships_created.append('HOST_IN_GROUP')
            else:
                print(f"Missing group_uid or host_uuid, skipping HOST_IN_GROUP relationship")
        else:
            print(f"No groups found, skipping HOST_IN_GROUP relationship")
    
    def _create_rel_16_host_has_interface(self, session, data):
        """16. HOST_HAS_INTERFACE — Host → NetworkInterface"""
        query = """
        MATCH (h:Host {uuid: $host_uuid}), 
              (n:NetworkInterface {device_uuid: $host_uuid, mac: $mac})
        MERGE (h)-[:HOST_HAS_INTERFACE]->(n)
        """
        session.run(query,
            host_uuid=data['device']['uuid'],
            mac=data['device']['interface']['mac']
        )
        self.relationships_created.append('HOST_HAS_INTERFACE')
    
    def _create_rel_17_alert_in_incident(self, session, data):
        """17. ALERT_IN_INCIDENT — Alert → Incident"""
        incident_id = f"INC-{data['threat']['id']}"
        query = """
        MATCH (a:Alert {threat_id: $threat_id}), (i:Incident {incident_id: $incident_id})
        MERGE (a)-[:ALERT_IN_INCIDENT]->(i)
        """
        session.run(query,
            threat_id=data['threat']['id'],
            incident_id=incident_id
        )
        self.relationships_created.append('ALERT_IN_INCIDENT')
    
    def _create_rel_18_host_has_os(self, session, data):
        """18. HOST_HAS_OS — Host → OsVersion"""
        query = """
        MATCH (h:Host {uuid: $host_uuid}), 
              (o:OsVersion {name: $os_name, build: $os_build})
        MERGE (h)-[:HOST_HAS_OS]->(o)
        """
        session.run(query,
            host_uuid=data['device']['uuid'],
            os_name=data['device']['os']['name'],
            os_build=data['device']['os']['build']
        )
        self.relationships_created.append('HOST_HAS_OS')
    
    def _create_rel_19_alert_whitelisted_by(self, session, data):
        """19. ALERT_WHITELISTED_BY — Alert → WhiteningRule"""
        query = """
        MATCH (a:Alert {threat_id: $threat_id}), (w:WhiteningRule {rule: $rule})
        MERGE (a)-[:ALERT_WHITELISTED_BY]->(w)
        """
        session.run(query,
            threat_id=data['threat']['id'],
            rule=data['remediation']['result']
        )
        self.relationships_created.append('ALERT_WHITELISTED_BY')
    
    def _create_rel_20_alert_has_score(self, session, data):
        """20. ALERT_HAS_SCORE — Alert → Scores"""
        query = """
        MATCH (a:Alert {threat_id: $threat_id}), (s:Scores {alert_id: $alert_id})
        MERGE (a)-[:ALERT_HAS_SCORE]->(s)
        """
        session.run(query,
            threat_id=data['threat']['id'],
            alert_id=data['alert']['id']
        )
        self.relationships_created.append('ALERT_HAS_SCORE')
    
    def create_constraints_and_indexes(self):
        """Create constraints exactly as per schema specification"""
        constraints_queries = [
            # Node constraints based on exact keys from specification
            "CREATE CONSTRAINT alert_threat_id IF NOT EXISTS FOR (a:Alert) REQUIRE a.threat_id IS UNIQUE",
            "CREATE CONSTRAINT file_uid IF NOT EXISTS FOR (f:File) REQUIRE f.uid IS UNIQUE", 
            "CREATE CONSTRAINT hash_sha256 IF NOT EXISTS FOR (h:Hash) REQUIRE (h.algorithm, h.value) IS UNIQUE",
            "CREATE CONSTRAINT user_name IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE",
            "CREATE CONSTRAINT host_uuid IF NOT EXISTS FOR (h:Host) REQUIRE h.uuid IS UNIQUE",
            "CREATE CONSTRAINT process_composite IF NOT EXISTS FOR (p:Process) REQUIRE (p.threat_id, p.name) IS UNIQUE",
            "CREATE CONSTRAINT network_interface IF NOT EXISTS FOR (n:NetworkInterface) REQUIRE (n.device_uuid, n.mac) IS UNIQUE",
            "CREATE CONSTRAINT external_ip IF NOT EXISTS FOR (e:ExternalIP) REQUIRE e.ip IS UNIQUE",
            "CREATE CONSTRAINT threat_intel_provider_alert IF NOT EXISTS FOR (t:ThreatIntel) REQUIRE (t.provider, t.alert_id) IS UNIQUE",
            "CREATE CONSTRAINT mitigation_uid IF NOT EXISTS FOR (m:MitigationAction) REQUIRE m.uid IS UNIQUE",
            "CREATE CONSTRAINT engine_uid IF NOT EXISTS FOR (e:Engine) REQUIRE e.uid IS UNIQUE",
            "CREATE CONSTRAINT site_uid IF NOT EXISTS FOR (s:Site) REQUIRE s.uid IS UNIQUE",
            "CREATE CONSTRAINT group_uid IF NOT EXISTS FOR (g:Group) REQUIRE g.uid IS UNIQUE",
            "CREATE CONSTRAINT incident_id IF NOT EXISTS FOR (i:Incident) REQUIRE i.incident_id IS UNIQUE",
            "CREATE CONSTRAINT os_version IF NOT EXISTS FOR (o:OsVersion) REQUIRE (o.name, o.build) IS UNIQUE",
            "CREATE CONSTRAINT whitening_rule IF NOT EXISTS FOR (w:WhiteningRule) REQUIRE w.rule IS UNIQUE",
            "CREATE CONSTRAINT scores_alert IF NOT EXISTS FOR (s:Scores) REQUIRE s.alert_id IS UNIQUE"
        ]
        
        with self.driver.session(database=self.database) as session:
            for query in constraints_queries:
                try:
                    session.run(query)
                    print(f"✅ Created constraint: {query.split('FOR')[1].split('REQUIRE')[0].strip()}")
                except Exception as e:
                    print(f"⚠️ Constraint already exists or failed: {e}")
    
    def verify_ingestion(self):
        """Verify the ingestion by counting nodes and relationships"""
        print("🔍 VERIFICATION - Counting nodes and relationships...")

        verification_queries = {
            "Alerts": "MATCH (a:Alert) RETURN COUNT(a) as count",
            "Files": "MATCH (f:File) RETURN COUNT(f) as count",
            "Hashes": "MATCH (h:Hash) RETURN COUNT(h) as count",
            "Processes": "MATCH (p:Process) RETURN COUNT(p) as count",
            "Users": "MATCH (u:User) RETURN COUNT(u) as count",
            "Hosts": "MATCH (h:Host) RETURN COUNT(h) as count",
            "NetworkInterfaces": "MATCH (n:NetworkInterface) RETURN COUNT(n) as count",
            "ExternalIPs": "MATCH (e:ExternalIP) RETURN COUNT(e) as count",
            "ThreatIntel": "MATCH (t:ThreatIntel) RETURN COUNT(t) as count",
            "MitigationActions": "MATCH (m:MitigationAction) RETURN COUNT(m) as count",
            "Engines": "MATCH (e:Engine) RETURN COUNT(e) as count",
            "Sites": "MATCH (s:Site) RETURN COUNT(s) as count",
            "Groups": "MATCH (g:Group) RETURN COUNT(g) as count",
            "Incidents": "MATCH (i:Incident) RETURN COUNT(i) as count",
            "OsVersions": "MATCH (o:OsVersion) RETURN COUNT(o) as count",
            "WhiteningRules": "MATCH (w:WhiteningRule) RETURN COUNT(w) as count",
            "Scores": "MATCH (s:Scores) RETURN COUNT(s) as count",
            "Total Relationships": "MATCH ()-[r]->() RETURN COUNT(r) as count"
        }

        with self.driver.session(database=self.database) as session:
            for entity, query in verification_queries.items():
                try:
                    result = session.run(query)
                    count = result.single()["count"]
                    print(f"   📋 {entity}: {count}")
                except Exception as e:
                    print(f"   ❌ Failed to count {entity}: {e}")



class DynamicThreatAnalyzer:
    """Dynamic analyzer using LangChain Neo4j for question generation and analysis"""

    def __init__(self):
        # Initialize LangChain components
        self.llm = ChatOpenAI(
            temperature=0,
            api_key=OPENAI_API_KEY
        )
        self.graph = Neo4jGraph(
            url=NEO4J_URI,
            username=NEO4J_USERNAME,
            password=NEO4J_PASSWORD
        )
        self.chain = GraphCypherQAChain.from_llm(
            llm=self.llm,
            graph=self.graph,
            allow_dangerous_requests=True
        )
        
        # Analyst-focused question templates
        self.analyst_questions = [
            "What is the complete attack chain visible in this alert?",
            "What are the key threat indicators that suggest malicious activity?",
            "What process execution patterns indicate suspicious behavior?", 
            "How many security vendors flagged this file and what were their detections?",
            "What file reputation and signing information is available?",
            "What network connections or communications were observed?",
            "What system privileges and user context was this executed under?",
            "What behavioral patterns match known attack techniques?",
            "How does this alert relate to known threat intelligence indicators?",
            "What is the timeline and sequence of events in this incident?",
            "What host characteristics make this target valuable to attackers?",
            "What detection engine capabilities identified this threat?"
        ]

    def analyze_alert_from_graph(self, alert_id: str) -> Dict[str, Any]:
        """Dynamically analyze alert using LangChain Neo4j chain"""
        
        print(f"Starting dynamic analysis for alert: {alert_id}")
        
        # First, get basic alert context
        context_query = f"What alert information exists for alert_id '{alert_id}'?"
        
        try:
            context_response = self.chain.run(context_query)
            print(f"Alert context: {context_response}")
        except Exception as e:
            print(f"Error getting context: {e}")
            context_response = "Alert context unavailable"
        
        # Generate dynamic questions and get answers
        qa_analysis = []
        
        for question in self.analyst_questions:
            try:
                # Modify question to be specific to this alert
                specific_question = f"For alert_id '{alert_id}': {question}"
                
                # Get answer from graph
                answer = self.chain.run(specific_question)
                
                # Analyze this Q&A pair for threat assessment
                verdict, confidence, reasoning = self._analyze_qa_for_threat(question, answer)
                
                qa_analysis.append({
                    "question": question,
                    "answer": answer,
                    "individual_verdict": verdict,
                    "individual_confidence": confidence,
                    "reasoning": reasoning
                })
                
                print(f"Q: {question[:60]}...")
                print(f"A: {answer[:100]}...")
                print(f"Verdict: {verdict} ({confidence}%)")
                print("-" * 50)
                
            except Exception as e:
                print(f"Error processing question: {question[:30]}... - {e}")
                continue
        
        # Generate final verdict from all individual assessments
        final_verdict, final_confidence, summary = self._generate_final_verdict(qa_analysis)
        
        result = {
            "success": True,
            "alert_id": alert_id,
            "analysis_method": "Dynamic LangChain Neo4j Analysis",
            "questions_analyzed": len(qa_analysis),
            "qa_analysis": qa_analysis,
            "final_verdict": final_verdict,
            "final_confidence": final_confidence,
            "summary": summary,
            "timestamp": datetime.now().isoformat()
        }
        
        return result

    def _analyze_qa_for_threat(self, question: str, answer: str) -> tuple:
        """Analyze individual Q&A pair for threat indicators"""
        
        threat_analysis_prompt = f"""
You are a cybersecurity analyst. Analyze this specific question and answer for threat indicators:

QUESTION: {question}
ANSWER: {answer}

Based on this information, determine:
1. VERDICT: TRUE_POSITIVE (malicious), FALSE_POSITIVE (benign), or ESCALATE (unclear/mixed)
2. CONFIDENCE: 0-100 confidence in your assessment
3. REASONING: Brief explanation of your assessment

Focus on:
- File reputation and signing status
- Process execution patterns
- Network connections and communications
- Detection by security vendors
- Behavioral indicators
- System context and privileges

Respond with only: VERDICT|CONFIDENCE|REASONING
Example: TRUE_POSITIVE|85|Multiple AV detections with unsigned executable
"""
        
        try:
            response = self.llm.invoke(threat_analysis_prompt)
            analysis = response.content.strip()
            
            # Parse the response
            parts = analysis.split('|')
            if len(parts) >= 3:
                verdict = parts[0].strip()
                confidence = int(parts[1].strip())
                reasoning = '|'.join(parts[2:]).strip()
            else:
                # Fallback parsing
                verdict, confidence, reasoning = self._fallback_threat_analysis(answer)
                
        except Exception as e:
            print(f"Error in threat analysis: {e}")
            verdict, confidence, reasoning = self._fallback_threat_analysis(answer)
        
        return verdict, confidence, reasoning

    def _fallback_threat_analysis(self, answer: str) -> tuple:
        """Fallback threat analysis if LLM analysis fails"""
        answer_lower = answer.lower()
        
        # Count threat indicators
        threat_indicators = [
            "malicious", "suspicious", "trojan", "backdoor", "unsigned", 
            "invalid certificate", "multiple detections", "powershell -enc",
            "base64", "network communication", "drops file", "registry modification"
        ]
        
        benign_indicators = [
            "signed", "valid certificate", "microsoft", "legitimate", 
            "no detections", "clean", "harmless"
        ]
        
        threat_count = sum(1 for indicator in threat_indicators if indicator in answer_lower)
        benign_count = sum(1 for indicator in benign_indicators if indicator in answer_lower)
        
        if threat_count > benign_count and threat_count >= 2:
            return "TRUE_POSITIVE", min(70 + (threat_count * 5), 95), f"Multiple threat indicators detected ({threat_count})"
        elif benign_count > threat_count and benign_count >= 1:
            return "FALSE_POSITIVE", min(60 + (benign_count * 8), 90), f"Benign indicators found ({benign_count})"
        else:
            return "ESCALATE", 50, "Mixed or insufficient indicators for clear determination"

    def _generate_final_verdict(self, qa_analysis: List[Dict]) -> tuple:
        """Generate final verdict from all individual assessments"""
        
        if not qa_analysis:
            return "ESCALATE", 50, "No analysis data available"
        
        # Count verdicts
        tp_count = sum(1 for qa in qa_analysis if qa["individual_verdict"] == "TRUE_POSITIVE")
        fp_count = sum(1 for qa in qa_analysis if qa["individual_verdict"] == "FALSE_POSITIVE")
        escalate_count = sum(1 for qa in qa_analysis if qa["individual_verdict"] == "ESCALATE")
        
        total_questions = len(qa_analysis)
        
        # Calculate weighted confidence
        tp_confidence = sum(qa["individual_confidence"] for qa in qa_analysis if qa["individual_verdict"] == "TRUE_POSITIVE")
        fp_confidence = sum(qa["individual_confidence"] for qa in qa_analysis if qa["individual_verdict"] == "FALSE_POSITIVE")
        
        print(f"Verdict counts - TP: {tp_count}, FP: {fp_count}, ESCALATE: {escalate_count}")
        
        # Determine final verdict
        if tp_count >= 3 and tp_count > fp_count:
            final_verdict = "TRUE_POSITIVE"
            avg_confidence = tp_confidence / tp_count if tp_count > 0 else 70
            final_confidence = min(avg_confidence + (tp_count * 3), 95)
            summary = f"Strong malicious indicators: {tp_count}/{total_questions} questions show threat activity"
            
        elif fp_count >= 3 and fp_count > tp_count:
            final_verdict = "FALSE_POSITIVE"
            avg_confidence = fp_confidence / fp_count if fp_count > 0 else 65
            final_confidence = min(avg_confidence + (fp_count * 2), 90)
            summary = f"Likely benign: {fp_count}/{total_questions} questions indicate legitimate activity"
            
        elif tp_count >= 2 and tp_count >= fp_count:
            final_verdict = "TRUE_POSITIVE"
            final_confidence = 75 + (tp_count * 2)
            summary = f"Probable threat: {tp_count} malicious indicators vs {fp_count} benign"
            
        else:
            final_verdict = "ESCALATE"
            final_confidence = 50 + (total_questions * 2)
            summary = f"Requires human analysis: {tp_count} threat, {fp_count} benign, {escalate_count} unclear indicators"
        
        return final_verdict, final_confidence, summary

# Initialize graph manager
graph_manager = Neo4jGraphManager(neo4j_driver) if neo4j_driver else None

# Initialize threat analyzer only if we have the required components
threat_analyzer = None

if neo4j_driver and OPENAI_API_KEY:
    try:
        threat_analyzer = DynamicThreatAnalyzer()
    except Exception as e:
        print(f"Failed to initialize threat analyzer: {e}")
        threat_analyzer = None

@app.post("/create-graph")
async def create_alert_graph(
    file: UploadFile = File(None),
    json_data: dict = Body(None)
):
    """
    Create Neo4j knowledge graph from alert JSON with flexible input support.
    Accepts either JSON file or JSON body with automatic field mapping.
    """
    try:
        if not graph_manager:
            raise HTTPException(status_code=500, detail="Neo4j connection not available.")

        # Parse input data
        raw_data = None
        
        if file is not None:
            if not file.filename.endswith(".json"):
                raise HTTPException(status_code=400, detail="Only JSON files are supported.")
            
            content = await file.read()
            try:
                raw_data = json.loads(content.decode("utf-8"))
            except json.JSONDecodeError as e:
                raise HTTPException(status_code=400, detail=f"Invalid JSON format: {str(e)}")
        elif json_data is not None:
            raw_data = json_data
        else:
            raise HTTPException(status_code=400, detail="Provide either a JSON file or JSON data in request body.")

        # Flexible input processing
        alert_data = None
        processing_info = {"flexible_parsing_used": False, "fallback_used": False}
        
        try:
            flexible_input = FlexibleAlertInput(**raw_data)
            alert_data = flexible_input.to_legacy_format()
            processing_info["flexible_parsing_used"] = True
            
            print("=== GRAPH CREATION INPUT PROCESSING ===")
            print(f"Original keys: {list(raw_data.keys())}")
            print(f"Mapped alert_id: {flexible_input.alert_id}")
            print(f"Legacy format keys: {list(alert_data.keys())}")
            
        except Exception as e:
            print(f"Flexible input processing failed for graph creation: {str(e)}")
            processing_info["fallback_used"] = True
            
            # Enhanced fallback processing for graph creation
            alert_data = raw_data.copy()
            
            # Ensure required fields for graph creation exist
            if not alert_data.get('alert', {}).get('id') and not alert_data.get('threat', {}).get('id'):
                # Try to find any ID field
                possible_ids = [
                    raw_data.get('id'),
                    raw_data.get('alert_id'), 
                    raw_data.get('alertId'),
                    raw_data.get('threat_id'),
                    raw_data.get('uid')
                ]
                
                found_id = next((pid for pid in possible_ids if pid), None)
                if found_id:
                    alert_data['alert'] = {'id': str(found_id)}
                    alert_data['threat'] = {'id': str(found_id)}
                else:
                    # Generate synthetic ID
                    synthetic_id = f"graph_alert_{hash(str(raw_data))}"
                    alert_data['alert'] = {'id': synthetic_id}
                    alert_data['threat'] = {'id': synthetic_id}
                    print(f"Generated synthetic ID for graph: {synthetic_id}")
            
            # Ensure basic structure for graph creation
            if 'file' not in alert_data:
                alert_data['file'] = {}
            if 'process' not in alert_data:
                alert_data['process'] = {}
            if 'device' not in alert_data:
                alert_data['device'] = {}
            if 'actor' not in alert_data:
                alert_data['actor'] = {'process': {'user': {}}}
            if 'remediation' not in alert_data:
                alert_data['remediation'] = {}
            if 'incident' not in alert_data:
                alert_data['incident'] = {}

        # Create graph
        result = graph_manager.create_alert_graph(alert_data)
        
        # Add processing metadata
        result['input_processing'] = processing_info
        result['processed_alert_id'] = alert_data.get('alert', {}).get('id') or alert_data.get('threat', {}).get('id')

        return JSONResponse(content=result)

    except HTTPException:
        raise
    except Exception as e:
        print(f"Graph creation error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Graph creation failed: {str(e)}")


import os
import json
import traceback
from datetime import datetime
from typing import Dict, Any, List
from neo4j import GraphDatabase
from langchain_openai import ChatOpenAI
from langchain_community.graphs import Neo4jGraph
from langchain.chains import GraphCypherQAChain

# Environment variables (same as EDR)
NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME") 
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Initialize Neo4j connection
neo4j_driver = None
try:
    if all([NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD]):
        neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
        neo4j_driver.verify_connectivity()
        print("Neo4j connection established successfully")
    else:
        print("Missing Neo4j environment variables")
except Exception as e:
    print(f"Failed to connect to Neo4j: {e}")
    neo4j_driver = None

class FirewallGraphManager:
    """Manages Neo4j graph operations for firewall alert data"""
    
    def __init__(self, driver):
        self.driver = driver
        self.database = NEO4J_DATABASE
        
    def create_firewall_graph(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create comprehensive firewall alert graph with robust error handling"""
        
        print("Creating firewall knowledge graph in Neo4j...")
        
        # Create unique alert ID
        alert_id = alert_data.get('id', f"fw_alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        with self.driver.session(database=self.database) as session:
            try:
                # Reset counters
                self.nodes_created = {}
                self.relationships_created = []
                
                # Create constraints and indexes first
                print("Creating firewall constraints and indexes...")
                self.create_firewall_constraints_and_indexes()
                
                # CREATE NODES - Firewall specific entities
                node_methods = [
                    ('FirewallAlert', self._create_node_1_firewall_alert),
                    ('SourceEndpoint', self._create_node_2_source_endpoint),
                    ('DestinationEndpoint', self._create_node_3_destination_endpoint),
                    ('NetworkSession', self._create_node_4_network_session),
                    ('File', self._create_node_5_file),
                    ('Hash', self._create_node_6_hash),
                    ('URL', self._create_node_7_url),
                    ('HTTPTransaction', self._create_node_8_http_transaction),
                    ('Policy', self._create_node_9_policy),
                    ('Detector', self._create_node_10_detector),
                    ('ThreatIntelligence', self._create_node_11_threat_intelligence),
                    ('Evidence', self._create_node_12_evidence),
                    ('NetworkInterface', self._create_node_13_network_interface),
                    ('Ticket', self._create_node_14_ticket),
                    ('Malware', self._create_node_15_malware)
                ]
                
                for node_name, method in node_methods:
                    try:
                        method(session, alert_data)
                    except Exception as e:
                        print(f"Error creating {node_name} node: {e}")
                        continue
                
                # CREATE RELATIONSHIPS - Firewall specific relationships
                relationship_methods = [
                    ('ALERT_ORIGINATED_FROM', self._create_rel_1_alert_originated_from),
                    ('ALERT_TARGETED', self._create_rel_2_alert_targeted),
                    ('ALERT_INVOLVES_SESSION', self._create_rel_3_alert_involves_session),
                    ('SESSION_BETWEEN_ENDPOINTS', self._create_rel_4_session_between_endpoints),
                    ('ALERT_INVOLVES_FILE', self._create_rel_5_alert_involves_file),
                    ('FILE_HAS_HASH', self._create_rel_6_file_has_hash),
                    ('ALERT_ACCESSES_URL', self._create_rel_7_alert_accesses_url),
                    ('ALERT_HTTP_TRANSACTION', self._create_rel_8_alert_http_transaction),
                    ('ALERT_BLOCKED_BY_POLICY', self._create_rel_9_alert_blocked_by_policy),
                    ('ALERT_DETECTED_BY', self._create_rel_10_alert_detected_by),
                    ('ALERT_ENRICHED_BY_TI', self._create_rel_11_alert_enriched_by_ti),
                    ('ALERT_HAS_EVIDENCE', self._create_rel_12_alert_has_evidence),
                    ('ENDPOINT_USES_INTERFACE', self._create_rel_13_endpoint_uses_interface),
                    ('ALERT_GENERATES_TICKET', self._create_rel_14_alert_generates_ticket),
                    ('ALERT_CONTAINS_MALWARE', self._create_rel_15_alert_contains_malware),
                    ('URL_SERVES_FILE', self._create_rel_16_url_serves_file),
                    ('HTTP_DOWNLOADS_FILE', self._create_rel_17_http_downloads_file)
                ]
                
                for rel_name, method in relationship_methods:
                    try:
                        method(session, alert_data)
                    except Exception as e:
                        print(f"Error creating {rel_name} relationship: {e}")
                        continue
                
                result = {
                    "success": True,
                    "graph_created": True,
                    "alert_id": alert_id,
                    "alert_type": "firewall",
                    "nodes_created": sum(self.nodes_created.values()),
                    "relationships_created": len(self.relationships_created),
                    "node_breakdown": self.nodes_created,
                    "timestamp": datetime.now().isoformat(),
                    "disposition": alert_data.get('disposition', 'Unknown'),
                    "severity": alert_data.get('severity', 'Unknown')
                }
                
                print(f"Firewall graph created successfully: {sum(self.nodes_created.values())} nodes, {len(self.relationships_created)} relationships")
                return result
                
            except Exception as e:
                print(f"Critical error in firewall graph creation: {e}")
                return {
                    "success": False,
                    "error": str(e),
                    "alert_id": alert_id,
                    "alert_type": "firewall",
                    "nodes_created": sum(self.nodes_created.values()) if hasattr(self, 'nodes_created') else 0,
                    "relationships_created": len(self.relationships_created) if hasattr(self, 'relationships_created') else 0,
                    "timestamp": datetime.now().isoformat()
                }

    # ==================== FIREWALL NODE CREATION METHODS ====================
    
    def _create_node_1_firewall_alert(self, session, data):
        """1. FirewallAlert — key: id"""
        query = """
        MERGE (a:FirewallAlert {alert_id: $alert_id})
        SET a.time = $time,
            a.disposition = $disposition,
            a.severity = $severity,
            a.confidence = $confidence,
            a.title = $title,
            a.description = $description,
            a.class_name = $class_name,
            a.category_name = $category_name,
            a.activity_name = $activity_name,
            a.action = $action
        """
        session.run(query,
            alert_id=data.get('id'),
            time=data.get('time'),
            disposition=data.get('disposition'),
            severity=data.get('severity'),
            confidence=data.get('confidence'),
            title=data.get('title'),
            description=data.get('description'),
            class_name=data.get('class_name'),
            category_name=data.get('category_name'),
            activity_name=data.get('activity_name'),
            action=data.get('unmapped_action')
        )
        self.nodes_created['FirewallAlert'] = self.nodes_created.get('FirewallAlert', 0) + 1

    def _create_node_2_source_endpoint(self, session, data):
        """2. SourceEndpoint — key: src_endpoint.ip"""
        src_endpoint = data.get('src_endpoint', {})
        query = """
        MERGE (s:SourceEndpoint {ip: $ip})
        SET s.port = $port,
            s.name = $name,
            s.endpoint_type = 'source'
        """
        session.run(query,
            ip=src_endpoint.get('ip'),
            port=src_endpoint.get('port'),
            name=src_endpoint.get('name')
        )
        self.nodes_created['SourceEndpoint'] = self.nodes_created.get('SourceEndpoint', 0) + 1

    def _create_node_3_destination_endpoint(self, session, data):
        """3. DestinationEndpoint — key: dst_endpoint.ip"""
        dst_endpoint = data.get('dst_endpoint', {})
        query = """
        MERGE (d:DestinationEndpoint {ip: $ip})
        SET d.port = $port,
            d.name = $name,
            d.endpoint_type = 'destination'
        """
        session.run(query,
            ip=dst_endpoint.get('ip'),
            port=dst_endpoint.get('port'),
            name=dst_endpoint.get('name')
        )
        self.nodes_created['DestinationEndpoint'] = self.nodes_created.get('DestinationEndpoint', 0) + 1

    def _create_node_4_network_session(self, session, data):
        """4. NetworkSession — key: network.session_id"""
        network = data.get('network', {})
        query = """
        MERGE (n:NetworkSession {session_id: $session_id})
        SET n.direction = $direction,
            n.protocol_id = $protocol_id,
            n.protocol = $protocol,
            n.bytes_in = $bytes_in,
            n.bytes_out = $bytes_out,
            n.bytes_in_rounded = $bytes_in_rounded,
            n.bytes_out_rounded = $bytes_out_rounded
        """
        session.run(query,
            session_id=network.get('session_id'),
            direction=network.get('direction'),
            protocol_id=network.get('protocol_id'),
            protocol=network.get('protocol'),
            bytes_in=network.get('bytes_in'),
            bytes_out=network.get('bytes_out'),
            bytes_in_rounded=network.get('bytes_in_rounded'),
            bytes_out_rounded=network.get('bytes_out_rounded')
        )
        self.nodes_created['NetworkSession'] = self.nodes_created.get('NetworkSession', 0) + 1

    def _create_node_5_file(self, session, data):
        """5. File — key: file.name"""
        file_info = data.get('file', {})
        if file_info.get('name'):
            query = """
            MERGE (f:File {name: $name})
            SET f.type = $type,
                f.size = $size
            """
            session.run(query,
                name=file_info.get('name'),
                type=file_info.get('type'),
                size=data.get('http', {}).get('response', {}).get('content_length')
            )
            self.nodes_created['File'] = self.nodes_created.get('File', 0) + 1

    def _create_node_6_hash(self, session, data):
        """6. Hash — key: (algorithm, value)"""
        file_info = data.get('file', {})
        hashes = file_info.get('hashes', {})
        
        for algorithm, hash_value in hashes.items():
            if hash_value:
                query = """
                MERGE (h:Hash {algorithm: $algorithm, value: $value})
                """
                session.run(query,
                    algorithm=algorithm,
                    value=hash_value
                )
                self.nodes_created[f'Hash({algorithm.upper()})'] = self.nodes_created.get(f'Hash({algorithm.upper()})', 0) + 1

    def _create_node_7_url(self, session, data):
        """7. URL — key: url.full"""
        url_info = data.get('url', {})
        if url_info.get('full'):
            query = """
            MERGE (u:URL {full: $full})
            SET u.domain = $domain
            """
            session.run(query,
                full=url_info.get('full'),
                domain=url_info.get('domain')
            )
            self.nodes_created['URL'] = self.nodes_created.get('URL', 0) + 1

    def _create_node_8_http_transaction(self, session, data):
        """8. HTTPTransaction — key: (alert_id, http details)"""
        http_info = data.get('http', {})
        if http_info:
            transaction_id = f"{data.get('id')}_{http_info.get('request', {}).get('method', 'UNKNOWN')}"
            query = """
            MERGE (h:HTTPTransaction {transaction_id: $transaction_id})
            SET h.method = $method,
                h.user_agent = $user_agent,
                h.server = $server,
                h.client_variant = $client_variant,
                h.status_code = $status_code,
                h.content_type = $content_type,
                h.content_length = $content_length,
                h.host = $host,
                h.referrer = $referrer
            """
            session.run(query,
                transaction_id=transaction_id,
                method=http_info.get('request', {}).get('method'),
                user_agent=http_info.get('user_agent'),
                server=http_info.get('server'),
                client_variant=http_info.get('client_variant'),
                status_code=http_info.get('response', {}).get('status_code'),
                content_type=http_info.get('response', {}).get('content_type'),
                content_length=http_info.get('response', {}).get('content_length'),
                host=http_info.get('host'),
                referrer=http_info.get('request', {}).get('referrer')
            )
            self.nodes_created['HTTPTransaction'] = self.nodes_created.get('HTTPTransaction', 0) + 1

    def _create_node_9_policy(self, session, data):
        """9. Policy — key: policy.name"""
        policy_info = data.get('policy', {})
        if policy_info.get('name'):
            query = """
            MERGE (p:Policy {name: $name})
            SET p.applied_time = $applied_time,
                p.update_time = $update_time,
                p.rule_name = $rule_name,
                p.manager = $manager
            """
            session.run(query,
                name=policy_info.get('name'),
                applied_time=policy_info.get('applied_time'),
                update_time=policy_info.get('update_time'),
                rule_name=policy_info.get('rule', {}).get('name'),
                manager=policy_info.get('manager')
            )
            self.nodes_created['Policy'] = self.nodes_created.get('Policy', 0) + 1

    def _create_node_10_detector(self, session, data):
        """10. Detector — key: detector.device_name"""
        detector_info = data.get('detector', {})
        if detector_info.get('device_name'):
            query = """
            MERGE (d:Detector {device_name: $device_name})
            SET d.product_name = $product_name,
                d.product_family = $product_family,
                d.vendor_name = $vendor_name,
                d.log_server = $log_server,
                d.log_server_ip = $log_server_ip
            """
            session.run(query,
                device_name=detector_info.get('device_name'),
                product_name=detector_info.get('product_name'),
                product_family=detector_info.get('product_family'),
                vendor_name=detector_info.get('vendor_name'),
                log_server=detector_info.get('log_server'),
                log_server_ip=detector_info.get('log_server_ip')
            )
            self.nodes_created['Detector'] = self.nodes_created.get('Detector', 0) + 1

    def _create_node_11_threat_intelligence(self, session, data):
        """11. ThreatIntelligence — key: (rule.name, unmapped_indicator_name)"""
        rule_name = data.get('rule', {}).get('name')
        indicator_name = data.get('unmapped_indicator_name')
        
        if rule_name and indicator_name:
            ti_id = f"{rule_name}_{indicator_name}"
            query = """
            MERGE (t:ThreatIntelligence {ti_id: $ti_id})
            SET t.rule_name = $rule_name,
                t.indicator_name = $indicator_name,
                t.detected_by = $detected_by,
                t.protection_type = $protection_type,
                t.agent_verdict = $agent_verdict
            """
            session.run(query,
                ti_id=ti_id,
                rule_name=rule_name,
                indicator_name=indicator_name,
                detected_by=data.get('unmapped', {}).get('detected_by'),
                protection_type=data.get('unmapped', {}).get('protection_type'),
                agent_verdict=data.get('unmapped', {}).get('agent_verdict')
            )
            self.nodes_created['ThreatIntelligence'] = self.nodes_created.get('ThreatIntelligence', 0) + 1

    def _create_node_12_evidence(self, session, data):
        """12. Evidence — key: evidence.packet_capture.uid"""
        evidence_info = data.get('evidence', {})
        packet_capture = evidence_info.get('packet_capture', {})
        
        if packet_capture.get('uid'):
            query = """
            MERGE (e:Evidence {uid: $uid})
            SET e.label = $label,
                e.name = $name,
                e.time = $time,
                e.evidence_type = 'packet_capture'
            """
            session.run(query,
                uid=packet_capture.get('uid'),
                label=packet_capture.get('label'),
                name=packet_capture.get('name'),
                time=packet_capture.get('time')
            )
            self.nodes_created['Evidence'] = self.nodes_created.get('Evidence', 0) + 1

    def _create_node_13_network_interface(self, session, data):
        """13. NetworkInterface — key: device.interface.name"""
        interface_info = data.get('device', {}).get('interface', {})
        if interface_info.get('name'):
            query = """
            MERGE (n:NetworkInterface {name: $name})
            """
            session.run(query, name=interface_info.get('name'))
            self.nodes_created['NetworkInterface'] = self.nodes_created.get('NetworkInterface', 0) + 1

    def _create_node_14_ticket(self, session, data):
        """14. Ticket — key: ticket.id"""
        ticket_info = data.get('ticket', {})
        if ticket_info.get('id'):
            query = """
            MERGE (t:Ticket {ticket_id: $ticket_id})
            """
            session.run(query, ticket_id=ticket_info.get('id'))
            self.nodes_created['Ticket'] = self.nodes_created.get('Ticket', 0) + 1

    def _create_node_15_malware(self, session, data):
        """15. Malware — key: malware[0].name (if exists)"""
        malware_list = data.get('malware', [])
        if malware_list and malware_list[0].get('name'):
            query = """
            MERGE (m:Malware {name: $name})
            """
            session.run(query, name=malware_list[0].get('name'))
            self.nodes_created['Malware'] = self.nodes_created.get('Malware', 0) + 1

    # ==================== FIREWALL RELATIONSHIP CREATION METHODS ====================

    def _create_rel_1_alert_originated_from(self, session, data):
        """1. ALERT_ORIGINATED_FROM — FirewallAlert → SourceEndpoint"""
        query = """
        MATCH (a:FirewallAlert {alert_id: $alert_id}), 
              (s:SourceEndpoint {ip: $src_ip})
        MERGE (a)-[:ALERT_ORIGINATED_FROM]->(s)
        """
        session.run(query,
            alert_id=data.get('id'),
            src_ip=data.get('src_endpoint', {}).get('ip')
        )
        self.relationships_created.append('ALERT_ORIGINATED_FROM')

    def _create_rel_2_alert_targeted(self, session, data):
        """2. ALERT_TARGETED — FirewallAlert → DestinationEndpoint"""
        query = """
        MATCH (a:FirewallAlert {alert_id: $alert_id}), 
              (d:DestinationEndpoint {ip: $dst_ip})
        MERGE (a)-[:ALERT_TARGETED]->(d)
        """
        session.run(query,
            alert_id=data.get('id'),
            dst_ip=data.get('dst_endpoint', {}).get('ip')
        )
        self.relationships_created.append('ALERT_TARGETED')

    def _create_rel_3_alert_involves_session(self, session, data):
        """3. ALERT_INVOLVES_SESSION — FirewallAlert → NetworkSession"""
        query = """
        MATCH (a:FirewallAlert {alert_id: $alert_id}), 
              (n:NetworkSession {session_id: $session_id})
        MERGE (a)-[:ALERT_INVOLVES_SESSION]->(n)
        """
        session.run(query,
            alert_id=data.get('id'),
            session_id=data.get('network', {}).get('session_id')
        )
        self.relationships_created.append('ALERT_INVOLVES_SESSION')

    def _create_rel_4_session_between_endpoints(self, session, data):
        """4. SESSION_BETWEEN_ENDPOINTS — NetworkSession connects SourceEndpoint and DestinationEndpoint"""
        query = """
        MATCH (n:NetworkSession {session_id: $session_id}), 
              (s:SourceEndpoint {ip: $src_ip}), 
              (d:DestinationEndpoint {ip: $dst_ip})
        MERGE (s)-[:SESSION_TO]->(n)-[:SESSION_FROM]->(d)
        """
        session.run(query,
            session_id=data.get('network', {}).get('session_id'),
            src_ip=data.get('src_endpoint', {}).get('ip'),
            dst_ip=data.get('dst_endpoint', {}).get('ip')
        )
        self.relationships_created.append('SESSION_BETWEEN_ENDPOINTS')

    def _create_rel_5_alert_involves_file(self, session, data):
        """5. ALERT_INVOLVES_FILE — FirewallAlert → File"""
        file_info = data.get('file', {})
        if file_info.get('name'):
            query = """
            MATCH (a:FirewallAlert {alert_id: $alert_id}), 
                  (f:File {name: $file_name})
            MERGE (a)-[:ALERT_INVOLVES_FILE]->(f)
            """
            session.run(query,
                alert_id=data.get('id'),
                file_name=file_info.get('name')
            )
            self.relationships_created.append('ALERT_INVOLVES_FILE')

    def _create_rel_6_file_has_hash(self, session, data):
        """6. FILE_HAS_HASH — File → Hash"""
        file_info = data.get('file', {})
        hashes = file_info.get('hashes', {})
        
        for algorithm, hash_value in hashes.items():
            if hash_value and file_info.get('name'):
                query = """
                MATCH (f:File {name: $file_name}), 
                      (h:Hash {algorithm: $algorithm, value: $hash_value})
                MERGE (f)-[:FILE_HAS_HASH]->(h)
                """
                session.run(query,
                    file_name=file_info.get('name'),
                    algorithm=algorithm,
                    hash_value=hash_value
                )
                self.relationships_created.append(f'FILE_HAS_HASH_{algorithm.upper()}')

    def _create_rel_7_alert_accesses_url(self, session, data):
        """7. ALERT_ACCESSES_URL — FirewallAlert → URL"""
        url_info = data.get('url', {})
        if url_info.get('full'):
            query = """
            MATCH (a:FirewallAlert {alert_id: $alert_id}), 
                  (u:URL {full: $url_full})
            MERGE (a)-[:ALERT_ACCESSES_URL]->(u)
            """
            session.run(query,
                alert_id=data.get('id'),
                url_full=url_info.get('full')
            )
            self.relationships_created.append('ALERT_ACCESSES_URL')

    def _create_rel_8_alert_http_transaction(self, session, data):
        """8. ALERT_HTTP_TRANSACTION — FirewallAlert → HTTPTransaction"""
        http_info = data.get('http', {})
        if http_info:
            transaction_id = f"{data.get('id')}_{http_info.get('request', {}).get('method', 'UNKNOWN')}"
            query = """
            MATCH (a:FirewallAlert {alert_id: $alert_id}), 
                  (h:HTTPTransaction {transaction_id: $transaction_id})
            MERGE (a)-[:ALERT_HTTP_TRANSACTION]->(h)
            """
            session.run(query,
                alert_id=data.get('id'),
                transaction_id=transaction_id
            )
            self.relationships_created.append('ALERT_HTTP_TRANSACTION')

    def _create_rel_9_alert_blocked_by_policy(self, session, data):
        """9. ALERT_BLOCKED_BY_POLICY — FirewallAlert → Policy"""
        policy_info = data.get('policy', {})
        if policy_info.get('name'):
            query = """
            MATCH (a:FirewallAlert {alert_id: $alert_id}), 
                  (p:Policy {name: $policy_name})
            MERGE (a)-[:ALERT_BLOCKED_BY_POLICY]->(p)
            """
            session.run(query,
                alert_id=data.get('id'),
                policy_name=policy_info.get('name')
            )
            self.relationships_created.append('ALERT_BLOCKED_BY_POLICY')

    def _create_rel_10_alert_detected_by(self, session, data):
        """10. ALERT_DETECTED_BY — FirewallAlert → Detector"""
        detector_info = data.get('detector', {})
        if detector_info.get('device_name'):
            query = """
            MATCH (a:FirewallAlert {alert_id: $alert_id}), 
                  (d:Detector {device_name: $device_name})
            MERGE (a)-[:ALERT_DETECTED_BY]->(d)
            """
            session.run(query,
                alert_id=data.get('id'),
                device_name=detector_info.get('device_name')
            )
            self.relationships_created.append('ALERT_DETECTED_BY')

    def _create_rel_11_alert_enriched_by_ti(self, session, data):
        """11. ALERT_ENRICHED_BY_TI — FirewallAlert → ThreatIntelligence"""
        rule_name = data.get('rule', {}).get('name')
        indicator_name = data.get('unmapped_indicator_name')
        
        if rule_name and indicator_name:
            ti_id = f"{rule_name}_{indicator_name}"
            query = """
            MATCH (a:FirewallAlert {alert_id: $alert_id}), 
                  (t:ThreatIntelligence {ti_id: $ti_id})
            MERGE (a)-[:ALERT_ENRICHED_BY_TI]->(t)
            """
            session.run(query,
                alert_id=data.get('id'),
                ti_id=ti_id
            )
            self.relationships_created.append('ALERT_ENRICHED_BY_TI')

    def _create_rel_12_alert_has_evidence(self, session, data):
        """12. ALERT_HAS_EVIDENCE — FirewallAlert → Evidence"""
        evidence_info = data.get('evidence', {})
        packet_capture = evidence_info.get('packet_capture', {})
        
        if packet_capture.get('uid'):
            query = """
            MATCH (a:FirewallAlert {alert_id: $alert_id}), 
                  (e:Evidence {uid: $uid})
            MERGE (a)-[:ALERT_HAS_EVIDENCE]->(e)
            """
            session.run(query,
                alert_id=data.get('id'),
                uid=packet_capture.get('uid')
            )
            self.relationships_created.append('ALERT_HAS_EVIDENCE')

    def _create_rel_13_endpoint_uses_interface(self, session, data):
        """13. ENDPOINT_USES_INTERFACE — SourceEndpoint/DestinationEndpoint → NetworkInterface"""
        interface_info = data.get('device', {}).get('interface', {})
        if interface_info.get('name'):
            # Both source and destination endpoints can use the same interface
            for endpoint_type, ip_key in [('SourceEndpoint', 'src_endpoint'), ('DestinationEndpoint', 'dst_endpoint')]:
                endpoint_ip = data.get(ip_key, {}).get('ip')
                if endpoint_ip:
                    query = f"""
                    MATCH (e:{endpoint_type} {{ip: $endpoint_ip}}), 
                          (n:NetworkInterface {{name: $interface_name}})
                    MERGE (e)-[:ENDPOINT_USES_INTERFACE]->(n)
                    """
                    session.run(query,
                        endpoint_ip=endpoint_ip,
                        interface_name=interface_info.get('name')
                    )
            self.relationships_created.append('ENDPOINT_USES_INTERFACE')

    def _create_rel_14_alert_generates_ticket(self, session, data):
        """14. ALERT_GENERATES_TICKET — FirewallAlert → Ticket"""
        ticket_info = data.get('ticket', {})
        if ticket_info.get('id'):
            query = """
            MATCH (a:FirewallAlert {alert_id: $alert_id}), 
                  (t:Ticket {ticket_id: $ticket_id})
            MERGE (a)-[:ALERT_GENERATES_TICKET]->(t)
            """
            session.run(query,
                alert_id=data.get('id'),
                ticket_id=ticket_info.get('id')
            )
            self.relationships_created.append('ALERT_GENERATES_TICKET')

    def _create_rel_15_alert_contains_malware(self, session, data):
        """15. ALERT_CONTAINS_MALWARE — FirewallAlert → Malware"""
        malware_list = data.get('malware', [])
        if malware_list and malware_list[0].get('name'):
            query = """
            MATCH (a:FirewallAlert {alert_id: $alert_id}), 
                  (m:Malware {name: $malware_name})
            MERGE (a)-[:ALERT_CONTAINS_MALWARE]->(m)
            """
            session.run(query,
                alert_id=data.get('id'),
                malware_name=malware_list[0].get('name')
            )
            self.relationships_created.append('ALERT_CONTAINS_MALWARE')

    def _create_rel_16_url_serves_file(self, session, data):
        """16. URL_SERVES_FILE — URL → File"""
        url_info = data.get('url', {})
        file_info = data.get('file', {})
        
        if url_info.get('full') and file_info.get('name'):
            query = """
            MATCH (u:URL {full: $url_full}), 
                  (f:File {name: $file_name})
            MERGE (u)-[:URL_SERVES_FILE]->(f)
            """
            session.run(query,
                url_full=url_info.get('full'),
                file_name=file_info.get('name')
            )
            self.relationships_created.append('URL_SERVES_FILE')

    def _create_rel_17_http_downloads_file(self, session, data):
        """17. HTTP_DOWNLOADS_FILE — HTTPTransaction → File"""
        http_info = data.get('http', {})
        file_info = data.get('file', {})
        
        if http_info and file_info.get('name'):
            transaction_id = f"{data.get('id')}_{http_info.get('request', {}).get('method', 'UNKNOWN')}"
            query = """
            MATCH (h:HTTPTransaction {transaction_id: $transaction_id}), 
                  (f:File {name: $file_name})
            MERGE (h)-[:HTTP_DOWNLOADS_FILE]->(f)
            """
            session.run(query,
                transaction_id=transaction_id,
                file_name=file_info.get('name')
            )
            self.relationships_created.append('HTTP_DOWNLOADS_FILE')

    def create_firewall_constraints_and_indexes(self):
        """Create constraints and indexes for firewall entities"""
        constraints_queries = [
            # Node constraints based on firewall entities
            "CREATE CONSTRAINT fw_alert_id IF NOT EXISTS FOR (a:FirewallAlert) REQUIRE a.alert_id IS UNIQUE",
            "CREATE CONSTRAINT src_endpoint_ip IF NOT EXISTS FOR (s:SourceEndpoint) REQUIRE s.ip IS UNIQUE",
            "CREATE CONSTRAINT dst_endpoint_ip IF NOT EXISTS FOR (d:DestinationEndpoint) REQUIRE d.ip IS UNIQUE",
            "CREATE CONSTRAINT network_session_id IF NOT EXISTS FOR (n:NetworkSession) REQUIRE n.session_id IS UNIQUE",
            "CREATE CONSTRAINT file_name IF NOT EXISTS FOR (f:File) REQUIRE f.name IS UNIQUE",
            "CREATE CONSTRAINT hash_composite IF NOT EXISTS FOR (h:Hash) REQUIRE (h.algorithm, h.value) IS UNIQUE",
            "CREATE CONSTRAINT url_full IF NOT EXISTS FOR (u:URL) REQUIRE u.full IS UNIQUE",
            "CREATE CONSTRAINT http_transaction_id IF NOT EXISTS FOR (h:HTTPTransaction) REQUIRE h.transaction_id IS UNIQUE",
            "CREATE CONSTRAINT policy_name IF NOT EXISTS FOR (p:Policy) REQUIRE p.name IS UNIQUE",
            "CREATE CONSTRAINT detector_device IF NOT EXISTS FOR (d:Detector) REQUIRE d.device_name IS UNIQUE",
            "CREATE CONSTRAINT ti_id IF NOT EXISTS FOR (t:ThreatIntelligence) REQUIRE t.ti_id IS UNIQUE",
            "CREATE CONSTRAINT evidence_uid IF NOT EXISTS FOR (e:Evidence) REQUIRE e.uid IS UNIQUE",
            "CREATE CONSTRAINT interface_name IF NOT EXISTS FOR (n:NetworkInterface) REQUIRE n.name IS UNIQUE",
            "CREATE CONSTRAINT ticket_id IF NOT EXISTS FOR (t:Ticket) REQUIRE t.ticket_id IS UNIQUE",
            "CREATE CONSTRAINT malware_name IF NOT EXISTS FOR (m:Malware) REQUIRE m.name IS UNIQUE"
        ]
        
        with self.driver.session(database=self.database) as session:
            for query in constraints_queries:
                try:
                    session.run(query)
                    print(f"✅ Created firewall constraint: {query.split('FOR')[1].split('REQUIRE')[0].strip()}")
                except Exception as e:
                    print(f"⚠️ Firewall constraint already exists or failed: {e}")

    def verify_firewall_ingestion(self):
        """Verify the firewall ingestion by counting nodes and relationships"""
        print("🔍 FIREWALL VERIFICATION - Counting nodes and relationships...")

        verification_queries = {
            "FirewallAlerts": "MATCH (a:FirewallAlert) RETURN COUNT(a) as count",
            "SourceEndpoints": "MATCH (s:SourceEndpoint) RETURN COUNT(s) as count",
            "DestinationEndpoints": "MATCH (d:DestinationEndpoint) RETURN COUNT(d) as count",
            "NetworkSessions": "MATCH (n:NetworkSession) RETURN COUNT(n) as count",
            "Files": "MATCH (f:File) RETURN COUNT(f) as count",
            "Hashes": "MATCH (h:Hash) RETURN COUNT(h) as count",
            "URLs": "MATCH (u:URL) RETURN COUNT(u) as count",
            "HTTPTransactions": "MATCH (h:HTTPTransaction) RETURN COUNT(h) as count",
            "Policies": "MATCH (p:Policy) RETURN COUNT(p) as count",
            "Detectors": "MATCH (d:Detector) RETURN COUNT(d) as count",
            "ThreatIntelligence": "MATCH (t:ThreatIntelligence) RETURN COUNT(t) as count",
            "Evidence": "MATCH (e:Evidence) RETURN COUNT(e) as count",
            "NetworkInterfaces": "MATCH (n:NetworkInterface) RETURN COUNT(n) as count",
            "Tickets": "MATCH (t:Ticket) RETURN COUNT(t) as count",
            "Malware": "MATCH (m:Malware) RETURN COUNT(m) as count",
            "Total Relationships": "MATCH ()-[r]->() RETURN COUNT(r) as count"
        }

        with self.driver.session(database=self.database) as session:
            for entity, query in verification_queries.items():
                try:
                    result = session.run(query)
                    count = result.single()["count"]
                    print(f"   📋 {entity}: {count}")
                except Exception as e:
                    print(f"   ❌ Failed to count {entity}: {e}")


class FirewallThreatAnalyzer:
    """Dynamic analyzer for firewall alerts using LangChain Neo4j"""

    def __init__(self):
        # Initialize LangChain components
        self.llm = ChatOpenAI(
            temperature=0,
            api_key=OPENAI_API_KEY
        )
        self.graph = Neo4jGraph(
            url=NEO4J_URI,
            username=NEO4J_USERNAME,
            password=NEO4J_PASSWORD
        )
        self.chain = GraphCypherQAChain.from_llm(
            llm=self.llm,
            graph=self.graph,
            allow_dangerous_requests=True
        )
        
        # Firewall-focused SOC analyst questions
        self.firewall_analyst_questions = [
            "What network communication pattern was observed in this alert?",
            "What are the source and destination endpoints involved?",
            "What file was downloaded and what are its characteristics?",
            "What HTTP transaction details reveal about the attack?",
            "What threat intelligence triggered this detection?",
            "What policy or rule was violated?",
            "What is the file hash reputation and detection status?",
            "What network protocols and data volumes were involved?",
            "What URL and domain reputation indicates malicious intent?",
            "What evidence was captured for forensic analysis?",
            "How does the user agent and client behavior suggest automation?",
            "What firewall detection engine identified this threat?"
        ]

    def analyze_firewall_alert_from_graph(self, alert_id: str) -> Dict[str, Any]:
        """Dynamically analyze firewall alert using LangChain Neo4j chain"""
        
        print(f"Starting firewall dynamic analysis for alert: {alert_id}")
        
        # First, get basic firewall alert context
        context_query = f"What firewall alert information exists for alert_id '{alert_id}'?"
        
        try:
            context_response = self.chain.run(context_query)
            print(f"Firewall alert context: {context_response}")
        except Exception as e:
            print(f"Error getting firewall context: {e}")
            context_response = "Firewall alert context unavailable"
        
        # Generate dynamic questions and get answers
        qa_analysis = []
        
        for question in self.firewall_analyst_questions:
            try:
                # Modify question to be specific to this firewall alert
                specific_question = f"For firewall alert_id '{alert_id}': {question}"
                
                # Get answer from graph
                answer = self.chain.run(specific_question)
                
                # Analyze this Q&A pair for threat assessment
                verdict, confidence, reasoning = self._analyze_firewall_qa_for_threat(question, answer)
                
                qa_analysis.append({
                    "question": question,
                    "answer": answer,
                    "individual_verdict": verdict,
                    "individual_confidence": confidence,
                    "reasoning": reasoning
                })
                
                print(f"Q: {question[:60]}...")
                print(f"A: {answer[:100]}...")
                print(f"Verdict: {verdict} ({confidence}%)")
                print("-" * 50)
                
            except Exception as e:
                print(f"Error processing firewall question: {question[:30]}... - {e}")
                continue
        
        # Generate final verdict from all individual assessments
        final_verdict, final_confidence, summary = self._generate_firewall_final_verdict(qa_analysis)
        
        result = {
            "success": True,
            "alert_id": alert_id,
            "alert_type": "firewall",
            "analysis_method": "Dynamic LangChain Neo4j Firewall Analysis",
            "questions_analyzed": len(qa_analysis),
            "qa_analysis": qa_analysis,
            "final_verdict": final_verdict,
            "final_confidence": final_confidence,
            "summary": summary,
            "timestamp": datetime.now().isoformat()
        }
        
        return result

    def _analyze_firewall_qa_for_threat(self, question: str, answer: str) -> tuple:
        """Analyze individual firewall Q&A pair for threat indicators"""
        
        firewall_threat_analysis_prompt = f"""
You are a SOC analyst specializing in firewall and network security. Analyze this firewall-specific question and answer for threat indicators:

QUESTION: {question}
ANSWER: {answer}

Based on this firewall/network information, determine:
1. VERDICT: TRUE_POSITIVE (malicious), FALSE_POSITIVE (benign), or ESCALATE (unclear/mixed)
2. CONFIDENCE: 0-100 confidence in your assessment
3. REASONING: Brief explanation of your assessment

Focus on firewall-specific threat indicators:
- Malicious file downloads and hash reputation
- Suspicious network communication patterns
- Policy violations and blocked connections
- Threat intelligence feed matches
- HTTP transaction anomalies (user agents, unusual patterns)
- Network protocol abuse
- Command and control communication patterns
- Data exfiltration indicators

Respond with only: VERDICT|CONFIDENCE|REASONING
Example: TRUE_POSITIVE|90|Malicious file download with known bad hash from threat intelligence feed
"""
        
        try:
            response = self.llm.invoke(firewall_threat_analysis_prompt)
            analysis = response.content.strip()
            
            # Parse the response
            parts = analysis.split('|')
            if len(parts) >= 3:
                verdict = parts[0].strip()
                confidence = int(parts[1].strip())
                reasoning = '|'.join(parts[2:]).strip()
            else:
                # Fallback parsing
                verdict, confidence, reasoning = self._fallback_firewall_threat_analysis(answer)
                
        except Exception as e:
            print(f"Error in firewall threat analysis: {e}")
            verdict, confidence, reasoning = self._fallback_firewall_threat_analysis(answer)
        
        return verdict, confidence, reasoning

    def _fallback_firewall_threat_analysis(self, answer: str) -> tuple:
        """Fallback firewall threat analysis if LLM analysis fails"""
        answer_lower = answer.lower()
        
        # Firewall-specific threat indicators
        threat_indicators = [
            "malicious", "blocked", "prevented", "threat intelligence", "ioc", 
            "exploit", "download", "suspicious", "c2", "command and control",
            "bad hash", "known malware", "policy violation", "unauthorized",
            "data exfiltration", "unusual traffic", "automated", "bot"
        ]
        
        benign_indicators = [
            "legitimate", "authorized", "business", "normal", "expected",
            "clean", "allowed", "policy compliant", "safe"
        ]
        
        threat_count = sum(1 for indicator in threat_indicators if indicator in answer_lower)
        benign_count = sum(1 for indicator in benign_indicators if indicator in answer_lower)
        
        if threat_count > benign_count and threat_count >= 2:
            return "TRUE_POSITIVE", min(75 + (threat_count * 5), 95), f"Multiple firewall threat indicators detected ({threat_count})"
        elif benign_count > threat_count and benign_count >= 1:
            return "FALSE_POSITIVE", min(65 + (benign_count * 8), 90), f"Benign network activity indicators found ({benign_count})"
        else:
            return "ESCALATE", 55, "Mixed or insufficient firewall indicators for clear determination"

    def _generate_firewall_final_verdict(self, qa_analysis: List[Dict]) -> tuple:
        """Generate final verdict from all firewall individual assessments"""
        
        if not qa_analysis:
            return "ESCALATE", 50, "No firewall analysis data available"
        
        # Count verdicts
        tp_count = sum(1 for qa in qa_analysis if qa["individual_verdict"] == "TRUE_POSITIVE")
        fp_count = sum(1 for qa in qa_analysis if qa["individual_verdict"] == "FALSE_POSITIVE")
        escalate_count = sum(1 for qa in qa_analysis if qa["individual_verdict"] == "ESCALATE")
        
        total_questions = len(qa_analysis)
        
        # Calculate weighted confidence
        tp_confidence = sum(qa["individual_confidence"] for qa in qa_analysis if qa["individual_verdict"] == "TRUE_POSITIVE")
        fp_confidence = sum(qa["individual_confidence"] for qa in qa_analysis if qa["individual_verdict"] == "FALSE_POSITIVE")
        
        print(f"Firewall verdict counts - TP: {tp_count}, FP: {fp_count}, ESCALATE: {escalate_count}")
        
        # Firewall-specific verdict logic
        if tp_count >= 3 and tp_count > fp_count:
            final_verdict = "TRUE_POSITIVE"
            avg_confidence = tp_confidence / tp_count if tp_count > 0 else 75
            final_confidence = min(avg_confidence + (tp_count * 3), 95)
            summary = f"Strong malicious network activity: {tp_count}/{total_questions} questions show threat indicators"
            
        elif fp_count >= 3 and fp_count > tp_count:
            final_verdict = "FALSE_POSITIVE"
            avg_confidence = fp_confidence / fp_count if fp_count > 0 else 70
            final_confidence = min(avg_confidence + (fp_count * 2), 90)
            summary = f"Likely legitimate network activity: {fp_count}/{total_questions} questions indicate benign traffic"
            
        elif tp_count >= 2 and tp_count >= fp_count:
            final_verdict = "TRUE_POSITIVE"
            final_confidence = 80 + (tp_count * 2)
            summary = f"Probable network threat: {tp_count} malicious vs {fp_count} benign indicators"
            
        else:
            final_verdict = "ESCALATE"
            final_confidence = 55 + (total_questions * 2)
            summary = f"Requires analyst review: {tp_count} threat, {fp_count} benign, {escalate_count} unclear network indicators"
        
        return final_verdict, final_confidence, summary


# Initialize firewall graph manager
firewall_graph_manager = FirewallGraphManager(neo4j_driver) if neo4j_driver else None

# Initialize firewall threat analyzer
firewall_threat_analyzer = None

if neo4j_driver and OPENAI_API_KEY:
    try:
        firewall_threat_analyzer = FirewallThreatAnalyzer()
    except Exception as e:
        print(f"Failed to initialize firewall threat analyzer: {e}")
        firewall_threat_analyzer = None


# FastAPI endpoint for firewall graph creation
@app.post("/create-firewall-graph")
async def create_firewall_alert_graph(
    file: UploadFile = File(None),
    json_data: dict = Body(None)
):
    """
    Create Neo4j knowledge graph from firewall alert JSON.
    Accepts either JSON file or JSON body for firewall alerts.
    """
    try:
        if not firewall_graph_manager:
            raise HTTPException(status_code=500, detail="Neo4j connection not available for firewall.")

        # Parse input data
        raw_data = None
        
        if file is not None:
            if not file.filename.endswith(".json"):
                raise HTTPException(status_code=400, detail="Only JSON files are supported.")
            
            content = await file.read()
            try:
                raw_data = json.loads(content.decode("utf-8"))
            except json.JSONDecodeError as e:
                raise HTTPException(status_code=400, detail=f"Invalid JSON format: {str(e)}")
        elif json_data is not None:
            raw_data = json_data
        else:
            raise HTTPException(status_code=400, detail="Provide either a JSON file or JSON data in request body.")

        # For firewall alerts, we expect the data to already be in the correct format
        # based on the samples provided
        alert_data = raw_data

        # Ensure required fields exist
        if not alert_data.get('id'):
            # Generate synthetic ID if missing
            synthetic_id = f"fw_alert_{hash(str(raw_data))}"
            alert_data['id'] = synthetic_id
            print(f"Generated synthetic ID for firewall alert: {synthetic_id}")

        # Create firewall graph
        result = firewall_graph_manager.create_firewall_graph(alert_data)
        
        # Add processing metadata
        result['processed_alert_id'] = alert_data.get('id')
        result['firewall_alert_type'] = alert_data.get('class_name', 'Unknown')

        return JSONResponse(content=result)

    except HTTPException:
        raise
    except Exception as e:
        print(f"Firewall graph creation error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Firewall graph creation failed: {str(e)}")


    
@app.post("/analyze-from-graph/{alert_id}")
async def analyze_alert_from_graph(
    alert_id: str,
    fallback_data: dict = Body(None)
):
    """
    Analyze alert using dynamic LangChain Neo4j querying with fallback data support.
    If alert_id is not found in graph, can use fallback_data for analysis.
    """
    try:
        if not threat_analyzer:
            raise HTTPException(
                status_code=503, 
                detail="Threat analyzer not available. Check Neo4j and OpenAI configuration."
            )
        
        # Run dynamic analysis
        result = threat_analyzer.analyze_alert_from_graph(alert_id)
        
        # If analysis failed and fallback data provided, try with fallback
        if (not result.get('qa_history') or 
            result.get('agent_verdict') == 'ESCALATE' and 
            fallback_data):
            
            print(f"Using fallback data for analysis of {alert_id}")
            
            # Process fallback data through flexible input
            try:
                flexible_input = FlexibleAlertInput(**fallback_data)
                processed_fallback = flexible_input.to_legacy_format()
                
                # Add fallback analysis info
                result['fallback_analysis'] = {
                    'used': True,
                    'fallback_alert_id': flexible_input.alert_id,
                    'processed_keys': list(processed_fallback.keys())
                }
                
            except Exception as e:
                print(f"Fallback data processing failed: {str(e)}")
                result['fallback_analysis'] = {
                    'used': False,
                    'error': str(e)
                }
        
        return JSONResponse(content=result)

    except Exception as e:
        print(f"Graph analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

from datetime import datetime
from typing import Dict, Any, List, Tuple
from langchain_openai import ChatOpenAI
from langchain_neo4j import GraphCypherQAChain, Neo4jGraph
from langchain.tools import Tool
from langchain.agents import initialize_agent, AgentType
from langchain.schema import AgentAction, AgentFinish
from langchain.memory import ConversationBufferMemory
import concurrent.futures
from typing import Dict, Any, List, Tuple, Optional
import time
import random

import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import hashlib

@dataclass
class InvestigationTask:
    """Task wrapper for parallel investigation steps"""
    task_id: str
    task_type: str
    description: str
    priority: int
    dependencies: List[str]
    completed: bool = False
    result: Optional[str] = None
    error: Optional[str] = None

class AgenticGraphRAG:
    """Dynamic Agentic Graph RAG system with parallel processing and automatic Cypher generation"""
    
    def __init__(self, neo4j_url: str, neo4j_username: str, neo4j_password: str, openai_api_key: str):
        # Initialize core components
        self.llm = ChatOpenAI(
            temperature=0,
            api_key=openai_api_key,
            model="gpt-4o-mini"
        )
        
        self.graph = Neo4jGraph(
            url=neo4j_url,
            username=neo4j_username,
            password=neo4j_password
        )
        
        self.chain = GraphCypherQAChain.from_llm(
            llm=self.llm,
            graph=self.graph,
            allow_dangerous_requests=True,
            verbose=True
        )
        
        # Initialize memory for conversation context
        self.memory = ConversationBufferMemory(
            memory_key="chat_history",
            return_messages=True
        )
        
        # Dynamic schema discovery
        self.graph_schema = None
        self.node_types = []
        self.relationship_types = []
        self.property_patterns = {}
        
        # Define agent tools with dynamic capabilities
        self.tools = self._create_dynamic_agent_tools()
        
        # Initialize the agent
        self.agent = initialize_agent(
            tools=self.tools,
            llm=self.llm,
            agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
            memory=self.memory,
            verbose=True,
            max_iterations=20,
            early_stopping_method="generate"
        )
        
        self.investigation_context = {}
        self.qa_history = []
        
        # Retry and parallel execution settings
        self.max_retries = 2
        self.retry_delay = 1  # seconds
        self.max_parallel_requests = 3
        
        # Parallel processing components
        self.executor = ThreadPoolExecutor(max_workers=self.max_parallel_requests)
        self.task_queue = []
        self.completed_tasks = {}
        self.task_lock = threading.Lock()
        self.question_cache = set()  # Track asked questions to avoid repetition
        
        # Initialize schema discovery
        self._discover_graph_schema()

    def interactive_investigation(self, alert_id: str, question: str) -> str:
        self.investigation_context = {"alert_id": alert_id}
        return self._dynamic_graph_query_tool(question)

    def _discover_graph_schema(self):
        """Dynamically discover the current graph schema"""
        try:
            print("Discovering graph schema...")
            
            # Get node labels
            node_query = "CALL db.labels() YIELD label RETURN label"
            node_result = self.graph.query(node_query)
            self.node_types = [row['label'] for row in node_result]
            
            # Get relationship types
            rel_query = "CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType"
            rel_result = self.graph.query(rel_query)
            self.relationship_types = [row['relationshipType'] for row in rel_result]
            
            # Discover property patterns for each node type
            for node_type in self.node_types:
                prop_query = f"""
                MATCH (n:{node_type})
                WITH keys(n) AS props
                UNWIND props AS prop
                RETURN DISTINCT prop
                LIMIT 20
                """
                try:
                    prop_result = self.graph.query(prop_query)
                    self.property_patterns[node_type] = [row['prop'] for row in prop_result]
                except:
                    self.property_patterns[node_type] = []
            
            # Get schema info from Neo4j
            self.graph_schema = self.graph.get_schema
            
            print(f"Schema discovered: {len(self.node_types)} node types, {len(self.relationship_types)} relationship types")
            
        except Exception as e:
            print(f"Error discovering schema: {e}")
            # Fallback defaults
            self.node_types = ["Alert", "File", "Process", "Host", "User"]
            self.relationship_types = ["INVOLVES_FILE", "DETECTED_ON", "EXECUTED"]
            self.property_patterns = {}
    
    def _generate_question_hash(self, question: str, alert_id: str) -> str:
        """Generate unique hash for questions to avoid repetition"""
        normalized_question = question.lower().strip().replace(" ", "")
        content = f"{normalized_question}_{alert_id}"
        return hashlib.md5(content.encode()).hexdigest()[:8]
    
    def _is_question_duplicate(self, question: str, alert_id: str) -> bool:
        """Check if this question has already been asked"""
        question_hash = self._generate_question_hash(question, alert_id)
        return question_hash in self.question_cache
    
    def _mark_question_asked(self, question: str, alert_id: str):
        """Mark question as asked to avoid repetition"""
        question_hash = self._generate_question_hash(question, alert_id)
        self.question_cache.add(question_hash)
    
    def _generate_parallel_investigation_tasks(self, alert_id: str) -> List[InvestigationTask]:
        """Generate non-repetitive parallel investigation tasks based on discovered schema"""
        
        base_questions = [
            "What are the core ML/GNN scoring results and confidence levels?",
            "What file characteristics and security properties are available?",
            "What detection and analysis information exists from other threat intelligence systems?",
            "What host, network, and system context is present?",
            "What process execution and user activity data exists?",
            "What threat indicators and malicious patterns are evident?"
        ]
        
        tasks = []
        
        # Priority 1: Scoring analysis (highest priority, no dependencies)
        tasks.append(InvestigationTask(
            task_id="scoring_analysis",
            task_type="scoring",
            description="Dynamic scoring and ML results analysis",
            priority=1,
            dependencies=[]
        ))
        
        # Priority 2: Core data gathering (parallel, no dependencies)
        core_tasks = [
            ("file_analysis", "file", "File and security characteristics analysis"),
            ("detection_analysis", "detection", "Detection and security tool results analysis"),
            ("threat_intelligence", "Enrichments analysis", "Reviewing the Virus Total , Checkpoint and other technologies Threat Intelligence"),
            ("context_analysis", "context", "Host, network, and system context analysis")
        ]
        
        for task_id, task_type, description in core_tasks:
            tasks.append(InvestigationTask(
                task_id=task_id,
                task_type=task_type,
                description=description,
                priority=2,
                dependencies=[]
            ))
        
        # Priority 3: Advanced analysis (depends on core data)
        advanced_tasks = [
            ("process_analysis", "process", "Process and user activity analysis", ["file_analysis"]),
            ("threat_analysis", "threat", "Threat pattern and indicator analysis", ["detection_analysis"]),
            
            ("entity_exploration", "entity", "Entity relationship mapping", ["context_analysis"])
        ]
        
        for task_id, task_type, description, deps in advanced_tasks:
            tasks.append(InvestigationTask(
                task_id=task_id,
                task_type=task_type,
                description=description,
                priority=3,
                dependencies=deps
            ))
        
        # Priority 4: Synthesis (depends on all analysis)
        tasks.append(InvestigationTask(
            task_id="evidence_synthesis",
            task_type="synthesis",
            description="Evidence synthesis and verdict determination",
            priority=4,
            dependencies=["scoring_analysis", "file_analysis", "detection_analysis", "context_analysis", "threat_analysis"]
        ))
        
        return tasks
    
    def _execute_task_parallel(self, task: InvestigationTask, alert_id: str) -> InvestigationTask:
        """Execute a single investigation task"""
        
        try:
            print(f"Executing parallel task: {task.task_id}")
            
            # Map task types to specific analysis methods
            if task.task_type == "scoring":
                result = self._dynamic_scoring_analysis_tool(alert_id, attempt=0)
            elif task.task_type == "file":
                question = "What file characteristics and security properties are available for this alert?"
                if not self._is_question_duplicate(question, alert_id):
                    self._mark_question_asked(question, alert_id)
                    result = self._dynamic_graph_query_tool(question, attempt=0)
                else:
                    result = "File analysis completed in previous parallel task."
            elif task.task_type == "detection":
                question = "What detection and analysis information exists for this alert?"
                if not self._is_question_duplicate(question, alert_id):
                    self._mark_question_asked(question, alert_id)
                    result = self._dynamic_graph_query_tool(question, attempt=0)
                else:
                    result = "Detection analysis completed in previous parallel task."
            elif task.task_type == "context":
                question = "What host, network, and system context is available for this alert?"
                if not self._is_question_duplicate(question, alert_id):
                    self._mark_question_asked(question, alert_id)
                    result = self._dynamic_graph_query_tool(question, attempt=0)
                else:
                    result = "Context analysis completed in previous parallel task."
            elif task.task_type == "process":
                question = "What process execution and user activity data exists for this alert?"
                if not self._is_question_duplicate(question, alert_id):
                    self._mark_question_asked(question, alert_id)
                    result = self._dynamic_graph_query_tool(question, attempt=0)
                else:
                    result = "Process analysis completed in previous parallel task."
            elif task.task_type == "threat":
                result = self._dynamic_threat_analysis_tool(alert_id, attempt=0)
            elif task.task_type == "entity":
                entity_desc = f"all entities connected to alert {alert_id}"
                result = self._dynamic_entity_exploration_tool(entity_desc, attempt=0)
            elif task.task_type == "synthesis":
                result = self._dynamic_evidence_synthesis_tool("", attempt=0)
            else:
                result = f"Unknown task type: {task.task_type}"
            
            task.result = result
            task.completed = True
            print(f"Completed parallel task: {task.task_id}")
            
        except Exception as e:
            task.error = str(e)
            task.result = f"Error in {task.task_id}: {str(e)}"
            print(f"Error in parallel task {task.task_id}: {e}")
        
        return task
    
    def _wait_for_dependencies(self, task: InvestigationTask, completed_tasks: Dict[str, InvestigationTask]) -> bool:
        """Check if task dependencies are satisfied"""
        for dep in task.dependencies:
            if dep not in completed_tasks or not completed_tasks[dep].completed:
                return False
        return True
    
    def _execute_parallel_investigation(self, alert_id: str) -> List[InvestigationTask]:
        """Execute investigation tasks in parallel with dependency management"""
        
        tasks = self._generate_parallel_investigation_tasks(alert_id)
        completed_tasks = {}
        futures = {}
        
        print(f"Starting parallel investigation with {len(tasks)} tasks...")
        
        # Process tasks by priority levels
        priority_levels = sorted(set(task.priority for task in tasks))
        
        for priority in priority_levels:
            priority_tasks = [task for task in tasks if task.priority == priority]
            
            # Submit tasks that have their dependencies satisfied
            current_futures = {}
            for task in priority_tasks:
                if self._wait_for_dependencies(task, completed_tasks):
                    future = self.executor.submit(self._execute_task_parallel, task, alert_id)
                    current_futures[future] = task
                    futures[future] = task
                    print(f"Submitted parallel task: {task.task_id} (Priority {priority})")
            
            # Wait for current priority level to complete
            if current_futures:
                for future in as_completed(current_futures):
                    task = current_futures[future]
                    try:
                        completed_task = future.result(timeout=30)  # 30 second timeout per task
                        completed_tasks[task.task_id] = completed_task
                        
                        with self.task_lock:
                            self.completed_tasks[task.task_id] = completed_task
                        
                        print(f"Parallel task completed: {task.task_id}")
                        
                    except concurrent.futures.TimeoutError:
                        print(f"Task {task.task_id} timed out")
                        task.error = "Task timeout"
                        task.result = f"Task {task.task_id} timed out during parallel execution"
                        completed_tasks[task.task_id] = task
                        
                    except Exception as e:
                        print(f"Task {task.task_id} failed: {e}")
                        task.error = str(e)
                        task.result = f"Task {task.task_id} failed: {str(e)}"
                        completed_tasks[task.task_id] = task
        
        return list(completed_tasks.values())
    
    def _create_dynamic_agent_tools(self) -> List[Tool]:
        """Create dynamic tools that adapt to graph schema with parallel processing support"""
        
        return [
            Tool(
                name="parallel_scoring_analysis",
                description="Execute parallel scoring analysis with dynamic schema discovery",
                func=self._parallel_dynamic_scoring_analysis_tool
            ),
            Tool(
                name="parallel_graph_query",
                description="Execute parallel graph queries with automatic Cypher generation",
                func=self._parallel_dynamic_graph_query_tool
            ),
            Tool(
                name="schema_discovery",
                description="Discover and analyze the current graph structure and available data",
                func=self._dynamic_schema_discovery_tool
            ),
            Tool(
                name="parallel_threat_analysis",
                description="Execute parallel threat pattern analysis with dynamic discovery",
                func=self._parallel_dynamic_threat_analysis_tool
            ),
            Tool(
                name="parallel_evidence_synthesis",
                description="Synthesize evidence using parallel processing of all discovered data",
                func=self._parallel_dynamic_evidence_synthesis_tool
            ),
            Tool(
                name="parallel_entity_exploration",
                description="Execute parallel entity exploration across multiple relationship paths",
                func=self._parallel_dynamic_entity_exploration_tool
            ),
            Tool(
                name="dynamic_investigation_summary",
                description="Generate comprehensive summary using all parallel processing results",
                func=self._dynamic_investigation_summary_tool
            )
        ]
    
    def _parallel_dynamic_scoring_analysis_tool(self, alert_context: str, attempt: int = 0) -> str:
        """Parallel scoring analysis with multiple query approaches"""
        
        alert_id = self.investigation_context.get("alert_id", alert_context)
        
        # Generate multiple non-repetitive scoring queries
        scoring_queries = [
            f"Find ML and GNN prediction scores for alert {alert_id}",
            f"Locate confidence levels and verdict information for alert {alert_id}",
            f"Discover rule-based and heuristic analysis results for alert {alert_id}"
        ]
        
        # Remove duplicates based on question cache
        unique_queries = []
        for query in scoring_queries:
            if not self._is_question_duplicate(query, alert_id):
                unique_queries.append(query)
                self._mark_question_asked(query, alert_id)
        
        if not unique_queries:
            return "Scoring analysis already completed in parallel processing."
        
        # Execute queries in parallel
        results = self._execute_queries_parallel(unique_queries, alert_id)
        
        # Combine and synthesize results
        combined_result = "\n".join([r for r in results if r and not self._is_empty_result(r)])
        
        if not combined_result:
            # Fallback to single dynamic execution
            return self._dynamic_scoring_analysis_tool(alert_context, attempt)
        
        # Make response concise
        concise_result = self._make_concise_response(
            question="What are the parallel scoring analysis results?",
            result=combined_result,
            focus="ML/GNN scores, confidence levels, and verdict agreements from parallel analysis"
        )
        
        return concise_result
    
    def _parallel_dynamic_graph_query_tool(self, query: str, attempt: int = 0) -> str:
        """Execute graph queries with parallel processing for faster results"""
        
        alert_id = self.investigation_context.get("alert_id", "")
        
        # Check for duplicate
        if self._is_question_duplicate(query, alert_id):
            return "This question was already processed in parallel execution."
        
        self._mark_question_asked(query, alert_id)
        
        # Generate multiple query variations for parallel execution
        query_variations = [
            f"Primary: {query} for alert {alert_id}",
            f"Alternative: Find related information about '{query}' for alert {alert_id}",
            f"Comprehensive: Explore all aspects of '{query}' connected to alert {alert_id}"
        ]
        
        # Execute variations in parallel
        results = self._execute_queries_parallel(query_variations, alert_id)
        
        # Select best non-empty result
        best_result = None
        for result in results:
            if result and not self._is_empty_result(result) and len(result) > 50:
                best_result = result
                break
        
        if not best_result:
            # Fallback to original single execution
            return self._dynamic_graph_query_tool(query, attempt)
        
        # Make response concise
        concise_result = self._make_concise_response(
            question=query,
            result=best_result,
            focus="key findings from parallel query execution"
        )
        
        return concise_result
    
    def _parallel_dynamic_threat_analysis_tool(self, context: str, attempt: int = 0) -> str:
        """Parallel threat analysis with multiple analytical approaches"""
        
        alert_id = self.investigation_context.get("alert_id", "")
        
        # Generate multiple threat analysis approaches
        threat_approaches = [
            f"Analyze malicious indicators and attack patterns for alert {alert_id}",
            f"Discover security violations and threat evidence for alert {alert_id}",
            f"Threat Intelligence by various technologies like Checkpoint , Virus Total alert {alert_id}",
            f"Identify suspicious activities and behavioral anomalies for alert {alert_id}"
        ]
        
        # Filter out duplicates
        unique_approaches = []
        for approach in threat_approaches:
            if not self._is_question_duplicate(approach, alert_id):
                unique_approaches.append(approach)
                self._mark_question_asked(approach, alert_id)
        
        if not unique_approaches:
            return "Threat analysis already completed in parallel processing."
        
        # Execute parallel threat analysis
        results = self._execute_queries_parallel(unique_approaches, alert_id)
        
        # Get current investigation summary for context
        investigation_summary = "\n".join([
            f"Q: {qa['question']}\nA: {qa['answer']}" 
            for qa in self.qa_history[-3:]  # Last 3 Q&As only for parallel efficiency
        ])
        
        # Synthesize parallel results
        best_result = max(results, key=lambda x: len(x) if x else 0, default="")
        
        if not best_result or self._is_empty_result(best_result):
            # Fallback to original method
            return self._dynamic_threat_analysis_tool(context, attempt)
        
        # Enhance with LLM analysis using parallel data
        analysis_prompt = f"""
        Analyze threat patterns from parallel processing results:
        
        Parallel Analysis Results: {best_result}
        Investigation Context: {investigation_summary}
        Available Schema: Nodes: {self.node_types}, Relationships: {self.relationship_types}
        
        Identify critical threat indicators from parallel analysis.
        Don't need to provide all set of information just important that also in 3-4 lines maximum.
        Provide information in 2-3 lines only, highlighting important threat perspectives.
        """
        
        try:
            analysis = self.llm.invoke(analysis_prompt)
            result = analysis.content.strip()
        except Exception as e:
            result = best_result
        
        # Store in Q&A history
        self.qa_history.append({
            "question": "What threat patterns are present from parallel analysis?",
            "answer": result,
            "timestamp": datetime.now().isoformat(),
            "method": "parallel_processing"
        })
        
        return result
    
    def _execute_queries_parallel(self, queries: List[str], alert_id: str) -> List[str]:
        """Execute multiple queries in parallel"""
        
        if len(queries) <= 1:
            # Single query, execute normally
            if queries:
                return [self._execute_dynamic_cypher(queries[0], alert_id, 0)]
            return []
        
        # Submit all queries in parallel
        query_futures = {}
        with ThreadPoolExecutor(max_workers=min(len(queries), self.max_parallel_requests)) as executor:
            for i, query in enumerate(queries):
                future = executor.submit(self._execute_dynamic_cypher, query, alert_id, i)
                query_futures[future] = query
            
            # Collect results as they complete
            results = []
            for future in as_completed(query_futures, timeout=35):  # 45 second total timeout
                try:
                    result = future.result(timeout=20)  # 15 second per query timeout
                    results.append(result)
                except Exception as e:
                    print(f"Parallel query failed: {e}")
                    results.append(f"Parallel execution error: {str(e)}")
        
        return results
    
    def _parallel_dynamic_evidence_synthesis_tool(self, investigation_summary: str, attempt: int = 0) -> str:
        """Parallel evidence synthesis using all discovered data"""
        
        try:
            # Prepare parallel synthesis approaches
            synthesis_approaches = [
                "primary_classification",
                "confidence_assessment", 
                "evidence_correlation"
            ]
            
            # Execute synthesis components in parallel
            synthesis_futures = {}
            with ThreadPoolExecutor(max_workers=3) as executor:
                
                # Primary classification
                primary_future = executor.submit(
                    self._execute_classification_analysis,
                    "primary", attempt
                )
                synthesis_futures[primary_future] = "primary"
                
                # Confidence assessment
                confidence_future = executor.submit(
                    self._execute_confidence_analysis,
                    "confidence", attempt
                )
                synthesis_futures[confidence_future] = "confidence"
                
                # Evidence correlation
                correlation_future = executor.submit(
                    self._execute_evidence_correlation,
                    "correlation", attempt
                )
                synthesis_futures[correlation_future] = "correlation"
                
                # Collect parallel synthesis results
                synthesis_components = {}
                for future in as_completed(synthesis_futures, timeout=30):
                    approach = synthesis_futures[future]
                    try:
                        result = future.result(timeout=30)
                        synthesis_components[approach] = result
                    except Exception as e:
                        synthesis_components[approach] = f"Error in {approach}: {str(e)}"
            
            # Combine parallel synthesis results
            final_synthesis_prompt = f"""
            Based on parallel evidence synthesis components, make definitive classification:
            
            Primary Classification: {synthesis_components.get('primary', 'N/A')}
            Confidence Assessment: {synthesis_components.get('confidence', 'N/A')}
            Evidence Correlation: {synthesis_components.get('correlation', 'N/A')}
            
            All Investigation Data: {self.qa_history}
            Schema Used: {self.node_types} nodes, {self.relationship_types} relationships
            
            Final Decision: TRUE_POSITIVE, FALSE_POSITIVE, or ESCALATE
            Provide: CLASSIFICATION, CONFIDENCE (0-100), KEY_EVIDENCE, REASONING
            """
            
            synthesis = self.llm.invoke(final_synthesis_prompt)
            
            # Extract classification and confidence
            classification_prompt = f"""
            Extract exact classification and confidence from parallel synthesis:
            
            {synthesis.content}
            
            Format:
            CLASSIFICATION: [TRUE_POSITIVE|FALSE_POSITIVE|ESCALATE]
            CONFIDENCE: [0-100]
            """
            
            verdict_result = self.llm.invoke(classification_prompt)
            
            # Store assessment with parallel processing info
            self.investigation_context['agent_assessment'] = {
                'full_synthesis': synthesis.content,
                'verdict_extraction': verdict_result.content,
                'timestamp': datetime.now().isoformat(),
                'attempt': attempt,
                'schema_used': {'nodes': self.node_types, 'relationships': self.relationship_types},
                'method': 'parallel_processing',
                'synthesis_components': synthesis_components
            }
            
            return synthesis.content
            
        except Exception as e:
            return f"Error in parallel evidence synthesis: {str(e)}"
    
    def _execute_classification_analysis(self, component_type: str, attempt: int) -> str:
        """Execute classification component analysis"""
        try:
            classification_prompt = f"""
            Analyze for PRIMARY CLASSIFICATION based on investigation data:
            Investigation Results: {self.qa_history[-5:]}
            Focus: Determine if evidence points to TRUE_POSITIVE, FALSE_POSITIVE, or ESCALATE
            Provide clear classification reasoning in 3-4 lines.
            """
            
            result = self.llm.invoke(classification_prompt)
            return result.content.strip()
        except Exception as e:
            return f"Classification analysis error: {str(e)}"
    
    def _execute_confidence_analysis(self, component_type: str, attempt: int) -> str:
        """Execute confidence assessment component"""
        try:
            confidence_prompt = f"""
            Assess CONFIDENCE LEVEL for classification based on:
            Investigation Data: {self.qa_history[-5:]}
            Available Evidence Quality: {len([qa for qa in self.qa_history if qa.get('answer') and len(qa['answer']) > 20])} substantial findings
            
            Provide confidence score (0-100) with justification in 3-4 lines.
            """
            
            result = self.llm.invoke(confidence_prompt)
            return result.content.strip()
        except Exception as e:
            return f"Confidence analysis error: {str(e)}"
    
    def _execute_evidence_correlation(self, component_type: str, attempt: int) -> str:
        """Execute evidence correlation component"""
        try:
            correlation_prompt = f"""
            Perform EVIDENCE CORRELATION across all findings:
            All Investigation Results: {self.qa_history}
            Schema Context: {self.node_types} node types, {self.relationship_types} relationships
            
            Identify correlating evidence patterns and conflicts in 3-4 lines.
            """
            
            result = self.llm.invoke(correlation_prompt)
            return result.content.strip()
        except Exception as e:
            return f"Evidence correlation error: {str(e)}"
    
    def _parallel_dynamic_entity_exploration_tool(self, entity_description: str, attempt: int = 0) -> str:
        """Parallel entity exploration with multiple relationship paths"""
        
        alert_id = self.investigation_context.get("alert_id", "")
        
        # Generate multiple exploration approaches in parallel
        exploration_approaches = [
            f"Map direct relationships for entities related to '{entity_description}' and alert {alert_id}",
            f"Discover indirect connections through intermediate nodes for '{entity_description}' and alert {alert_id}",
            f"Explore multi-hop relationships and entity networks for '{entity_description}' and alert {alert_id}"
        ]
        
        # Execute explorations in parallel
        results = self._execute_queries_parallel(exploration_approaches, alert_id)
        
        # Select most comprehensive result
        best_result = max(results, key=lambda x: len(x.split('\n')) if x else 0, default="")
        
        if self._is_empty_result(best_result):
            # Fallback to original method
            return self._dynamic_entity_exploration_tool(entity_description, attempt)
        
        # Make concise
        concise_result = self._make_concise_response(
            question=f"What entities are related to {entity_description} from parallel exploration?",
            result=best_result,
            focus="relationship mappings and connected entities from parallel analysis"
        )
        
        return concise_result
    
    def _generate_dynamic_cypher(self, intent: str, alert_id: str, attempt: int = 0) -> str:
        """Generate Cypher queries dynamically based on intent and discovered schema"""
        
        schema_info = f"""
        Node Types: {self.node_types}
        Relationships: {self.relationship_types}
        """
        
        # Generate intent-specific queries without hardcoded assumptions
        cypher_prompt = f"""
        Generate a Cypher query for: {intent}
        Alert ID: {alert_id}
        Attempt: {attempt + 1}
        
        Current graph schema:
        {schema_info}
        
        Query Generation Rules:
        1. Find node with alert_id property matching '{alert_id}'
        2. Explore relationships discovered in current schema only
        3. Use OPTIONAL MATCH for all relationships
        4. Return properties that exist in current graph
        5. Adapt to whatever schema is actually present
        6. For attempt > 0, use different approach/perspective
        
        Return only executable Cypher code, no explanations.
        """
        
        try:
            response = self.llm.invoke(cypher_prompt)
            cypher_query = response.content.strip()
            
            # Clean response
            if "```" in cypher_query:
                parts = cypher_query.split("```")
                for part in parts:
                    if "MATCH" in part or "OPTIONAL" in part:
                        cypher_query = part
                        break
            
            # Remove code block markers
            cypher_query = cypher_query.replace("cypher", "").strip()
            
            return cypher_query
            
        except Exception as e:
            # Pure fallback without assumptions
            return f"""
            MATCH (n) WHERE n.alert_id = '{alert_id}'
            OPTIONAL MATCH (n)-[r]-(m)
            RETURN n, r, m
            LIMIT 30
            """
    
    def _execute_dynamic_cypher(self, intent: str, alert_id: str, attempt: int = 0) -> str:
        """Execute dynamically generated Cypher with retry logic"""
        
        try:
            # Generate Cypher query
            cypher_query = self._generate_dynamic_cypher(intent, alert_id, attempt)
            
            print(f"Generated Cypher (attempt {attempt + 1}): {cypher_query}")
            
            # Execute the query
            result = self.graph.query(cypher_query)
            
            if result and not self._is_cypher_result_empty(result):
                return self._format_cypher_result(result, intent)
            else:
                return "No data found with generated query"
                
        except Exception as e:
            error_msg = str(e)
            print(f"Cypher execution error: {error_msg}")
            
            # If it's a syntax error, try to fix it
            if "syntax" in error_msg.lower() or "invalid" in error_msg.lower():
                try:
                    # Try a simpler fallback query
                    fallback_query = f"""
                    MATCH (n) 
                    WHERE n.alert_id = '{alert_id}' OR id(n) = '{alert_id}'
                    OPTIONAL MATCH (n)-[r]-(m)
                    RETURN n, type(r) as rel_type, m
                    LIMIT 20
                    """
                    result = self.graph.query(fallback_query)
                    return self._format_cypher_result(result, intent) if result else f"Cypher error: {error_msg}"
                except:
                    return f"Cypher execution failed: {error_msg}"
            
            return f"Query execution error: {error_msg}"
    
    def _format_cypher_result(self, result, intent: str) -> str:
        """Format Cypher query results in a readable way"""
        
        if not result:
            return "No results returned"
        
        formatted_output = []
        
        try:
            for i, row in enumerate(result[:10]):  # Limit to first 10 results
                row_data = []
                
                for key, value in row.items():
                    if value is not None:
                        if isinstance(value, dict):
                            # Node or relationship properties
                            props = ", ".join([f"{k}: {v}" for k, v in value.items() if v])
                            row_data.append(f"{key}: {{{props}}}")
                        elif isinstance(value, list):
                            # Multiple values
                            row_data.append(f"{key}: {value}")
                        else:
                            row_data.append(f"{key}: {value}")
                
                if row_data:
                    formatted_output.append(f"Result {i+1}: {'; '.join(row_data)}")
            
            return "\n".join(formatted_output) if formatted_output else "Results found but no readable data"
            
        except Exception as e:
            return f"Error formatting results: {str(e)}\nRaw result count: {len(result)}"
    
    def _retry_with_dynamic_enhancement(self, func, *args, **kwargs) -> str:
        """Enhanced retry mechanism with dynamic query improvement"""
        
        for attempt in range(self.max_retries + 1):
            try:
                result = func(*args, **kwargs, attempt=attempt)
                
                # Check if result is empty or indicates no data found
                if self._is_empty_result(result):
                    if attempt < self.max_retries:
                        print(f"Attempt {attempt + 1} returned empty result, retrying with enhanced approach...")
                        time.sleep(self.retry_delay * (attempt + 1))
                        continue
                    else:
                        return "No relevant data found after multiple dynamic attempts."
                
                return result
                
            except Exception as e:
                if attempt < self.max_retries:
                    print(f"Attempt {attempt + 1} failed: {str(e)}, retrying with different approach...")
                    time.sleep(self.retry_delay * (attempt + 1))
                    continue
                else:
                    return f"Error after {self.max_retries + 1} dynamic attempts: {str(e)}"
        
        return "Maximum retries exceeded with dynamic queries."
    
    def _dynamic_scoring_analysis_tool(self, alert_context: str, attempt: int = 0) -> str:
        """Dynamic scoring analysis that discovers score-related nodes"""
        
        alert_id = self.investigation_context.get("alert_id", alert_context)
        
        # Dynamic intent generation based on discovered schema
        scoring_intents = [
            f"Find all scoring, prediction, and confidence data for alert {alert_id}",
            f"Discover any machine learning, GNN, or rule-based analysis results for alert {alert_id}",
            f"Locate any nodes with properties containing 'score', 'confidence', 'verdict', or 'prediction' related to alert {alert_id}"
        ]
        
        intent = scoring_intents[min(attempt, len(scoring_intents) - 1)]
        
        try:
            # Use dynamic Cypher generation
            result = self._execute_dynamic_cypher(intent, alert_id, attempt)
            
            if self._is_empty_result(result):
                # Try natural language fallback
                fallback_query = f"Find any scoring or prediction information for alert with ID '{alert_id}'"
                result = self.chain.run(fallback_query)
            
        except Exception as e:
            result = f"Error in dynamic scoring analysis: {str(e)}"
        
        # Make response concise
        concise_result = self._make_concise_response(
            question="What are the scoring analysis results for this alert?",
            result=result,
            focus="scoring verdicts, confidence levels, and model agreements/disagreements"
        )
        
        return concise_result
    
    def _dynamic_graph_query_tool(self, query: str, attempt: int = 0) -> str:
        """Dynamic graph query with automatic Cypher generation"""
        
        alert_id = self.investigation_context.get("alert_id", "")
        
        # Convert natural language query to intent
        intent = f"Answer this question about alert {alert_id}: {query}"
        
        try:
            # First try dynamic Cypher generation
            result = self._execute_dynamic_cypher(intent, alert_id, attempt)
            
            if self._is_empty_result(result):
                # Fallback to LangChain natural language processing
                enhanced_query = f"For alert with alert_id '{alert_id}': {query}"
                result = self.chain.run(enhanced_query)
            
        except Exception as e:
            # Final fallback
            try:
                result = self.chain.run(query)
            except:
                result = f"Error executing dynamic query: {str(e)}"
        
        # Make response concise
        concise_result = self._make_concise_response(
            question=query,
            result=result,
            focus="key findings and critical details"
        )
        
        return concise_result
    
    def _dynamic_schema_discovery_tool(self, _: str = "") -> str:
        """Dynamic schema discovery and analysis"""
        
        # Refresh schema if needed
        self._discover_graph_schema()
        
        schema_summary = f"""
        Current Graph Schema:
        - Node Types ({len(self.node_types)}): {', '.join(self.node_types)}
        - Relationship Types ({len(self.relationship_types)}): {', '.join(self.relationship_types)}
        - Property Patterns: {len(self.property_patterns)} node types with discovered properties
        
        This schema is discovered dynamically and adapts to the current graph structure.
        """
        
        return schema_summary
    
    def _dynamic_threat_analysis_tool(self, context: str, attempt: int = 0) -> str:
        """Dynamic threat pattern analysis using discovered schema"""
        
        alert_id = self.investigation_context.get("alert_id", "")
        
        # Generate threat analysis intent based on available schema
        threat_intents = [
            f"Analyze threat indicators and malicious patterns for alert {alert_id} using all available node types and relationships",
            f"Discover security-related information and threat indicators connected to alert {alert_id}",
            f"Threat Intelligence by various technologies like Checkpoint , Virus Total alert {alert_id}",
            f"Find any nodes or properties indicating malicious activity, threats, or security concerns for alert {alert_id}"
        ]
        
        intent = threat_intents[min(attempt, len(threat_intents) - 1)]
        
        try:
            # Get current investigation data
            investigation_summary = "\n".join([
                f"Q: {qa['question']}\nA: {qa['answer']}" 
                for qa in self.qa_history[-5:]  # Last 5 Q&As
            ])
            
            # Use dynamic Cypher generation for threat analysis
            cypher_result = self._execute_dynamic_cypher(intent, alert_id, attempt)
            
            # Enhance with LLM analysis
            analysis_prompt = f"""
            Based on investigation data and graph discovery, analyze threat patterns:
            
            Graph Data Found: {cypher_result}
            Recent Investigation Findings: {investigation_summary}
            Available Schema: Node types: {self.node_types}, Relationships: {self.relationship_types}
            
            Identify critical threat indicators and attack patterns from the available data.
            Focus on concrete evidence of malicious activity discovered in the graph.
            Provide information in 4-5 lines . Highlighting important perspectives
            """
            
            analysis = self.llm.invoke(analysis_prompt)
            result = analysis.content.strip()
            
        except Exception as e:
            result = f"Error in dynamic threat analysis: {str(e)}"
        
        # Store in Q&A history
        self.qa_history.append({
            "question": "What threat patterns are present in this alert?",
            "answer": result,
            "timestamp": datetime.now().isoformat()
        })
        
        return result
    
    def _dynamic_evidence_synthesis_tool(self, investigation_summary: str, attempt: int = 0) -> str:
        """Dynamic evidence synthesis using all discovered data"""
        
        try:
            synthesis_prompt = f"""
            Based on the complete dynamic investigation, make a definitive classification.
            
            All Investigation Results: {self.qa_history}
            Graph Schema Used: {self.node_types} nodes, {self.relationship_types}
            
            Classification Criteria (adapt based on available data):
            TRUE_POSITIVE: Clear malicious indicators discovered
            FALSE_POSITIVE: Strong benign indicators found
            ESCALATE: Mixed, insufficient, or unclear evidence
            
            Consider all dynamically discovered data including:
            - Any scoring or prediction nodes found
            - Security-related properties and relationships
            - File, process, network, or other threat indicators
            - Detection results from any security tools
            
            Provide: CLASSIFICATION, CONFIDENCE (0-100), KEY_EVIDENCE, REASONING
            Be decisive based on the evidence discovered through dynamic analysis.
            """
            
            synthesis = self.llm.invoke(synthesis_prompt)
            
            # Extract classification and confidence
            classification_prompt = f"""
            From this dynamic analysis, extract the exact classification and confidence:
            
            {synthesis.content}
            
            Respond with EXACTLY this format:
            CLASSIFICATION: [TRUE_POSITIVE|FALSE_POSITIVE|ESCALATE]
            CONFIDENCE: [0-100]
            """
            
            verdict_result = self.llm.invoke(classification_prompt)
            
            # Store assessment
            self.investigation_context['agent_assessment'] = {
                'full_synthesis': synthesis.content,
                'verdict_extraction': verdict_result.content,
                'timestamp': datetime.now().isoformat(),
                'attempt': attempt,
                'schema_used': {'nodes': self.node_types, 'relationships': self.relationship_types}
            }
            
            return synthesis.content
            
        except Exception as e:
            return f"Error in dynamic evidence synthesis: {str(e)}"
    
    def _dynamic_entity_exploration_tool(self, entity_description: str, attempt: int = 0) -> str:
        """Dynamic entity exploration using discovered relationships"""
        
        alert_id = self.investigation_context.get("alert_id", "")
        
        # Generate exploration intent based on available schema
        exploration_intent = f"Explore and map all entities and relationships connected to '{entity_description}' for alert {alert_id}, using available relationship types: {self.relationship_types}"
        
        try:
            result = self._execute_dynamic_cypher(exploration_intent, alert_id, attempt)
            
            if self._is_empty_result(result):
                # Fallback to natural language
                fallback_query = f"For alert_id '{alert_id}', find entities and relationships related to: {entity_description}"
                result = self.chain.run(fallback_query)
            
        except Exception as e:
            result = f"Error in dynamic entity exploration: {str(e)}"
        
        # Make concise
        concise_result = self._make_concise_response(
            question=f"What entities are related to {entity_description}?",
            result=result,
            focus="relationship mappings and connected entities"
        )
        
        return concise_result
    
    def _dynamic_investigation_summary_tool(self, context: str, attempt: int = 0) -> str:
        """Dynamic investigation summary in strict 5-6 lines"""
        
        try:
            summary_prompt = f"""
            Create investigation summary in EXACTLY 5-6 lines only:
            
            Q&A History: {self.qa_history}
            Alert ID: {self.investigation_context.get('alert_id', 'Unknown')}
            Processing Method: {'Parallel Processing' if len(self.completed_tasks) > 0 else 'Sequential Processing'}
            
            STRICT FORMAT:
            - Line 1: Alert ID and basic file/threat info
            - Line 2: ML/GNN/Rule scoring results
            - Line 3: Key threat indicators found
            - Line 4: Detection status and confidence
            - Line 5: Final verdict and reasoning
            - Line 6: Add threat intelligence for this alert
            - Line 7: Critical action needed (optional)
            
            Maximum 4-5 lines total, no formatting, direct statements only.
            """
            
            summary = self.llm.invoke(summary_prompt)
            response = summary.content.strip()
            
            # Enforce strict line limit
            lines = response.split('\n')
            if len(lines) > 6:
                response = '\n'.join(lines[:6])
            
            return response
            
        except Exception as e:
            # Fallback summary from Q&A
            key_points = []
            for qa in self.qa_history[-3:]:  # Last 3 Q&As only
                if qa['answer'] and len(qa['answer']) > 20:
                    key_points.append(qa['answer'].split('.')[0] + '.')
            
            fallback = f"Alert {self.investigation_context.get('alert_id', 'Unknown')} investigation completed using parallel processing. "
            fallback += ' '.join(key_points[:2])  # Only first 2 key points
            return fallback[:400]  # Limit length
    
    def _make_concise_response(self, question: str, result: str, focus: str) -> str:
        """Make responses concise while preserving key information"""
        
        concise_prompt = f"""
        Summarize this in EXACTLY 4-5 lines only, no more:
        
        Question: {question}
        Result: {result}
        Focus on: {focus}
        
        STRICT REQUIREMENTS:
        - Maximum 4-5 lines total
        - Extract only the most critical information
        - No bullet points, headers, or formatting
        - Direct, factual statements only
        - Insert the threat Intelligence information
        """
        
        try:
            concise_result = self.llm.invoke(concise_prompt)
            response = concise_result.content.strip()
            
            # Enforce line limit by truncating if needed
            lines = response.split('\n')
            if len(lines) > 6:
                response = '\n'.join(lines[:6])
            
            # Store in Q&A history with parallel processing info
            self.qa_history.append({
                "question": question,
                "answer": response,
                "timestamp": datetime.now().isoformat(),
                
            })
            
            return response
            
        except Exception as e:
            lines = result.split('\n')[:6]
            fallback_response = '\n'.join(lines) if lines else result[:200] + "..."
            
            self.qa_history.append({
                "question": question,
                "answer": fallback_response,
                "timestamp": datetime.now().isoformat(),
                "method": "fallback"
            })
            
            return fallback_response
    
    def _is_empty_result(self, result: str) -> bool:
        """Check if result indicates no data found"""
        empty_indicators = [
            "no data", "not found", "no results", "no information",
            "empty", "none found", "no records", "[]", "{}"
        ]
        
        result_lower = result.lower().strip()
        return any(indicator in result_lower for indicator in empty_indicators) or len(result_lower) < 10
    
    def _is_cypher_result_empty(self, result) -> bool:
        """Check if Cypher query result is empty or meaningless"""
        if not result:
            return True
        
        if isinstance(result, list):
            if len(result) == 0:
                return True
            
            # Check if all values are None or empty
            for row in result:
                if isinstance(row, dict):
                    non_null_values = [v for v in row.values() if v is not None and v != ""]
                    if non_null_values:
                        return False
            return True
        
        return False
    
    def investigate_alert_parallel(self, alert_id: str) -> Dict[str, Any]:
        """Enhanced investigation with full parallel processing pipeline"""
        
        print(f"Starting parallel investigation for alert: {alert_id}")
        start_time = time.time()
        
        # Reset investigation context
        self.qa_history = []
        self.investigation_context = {"alert_id": alert_id}
        self.completed_tasks = {}
        self.question_cache = set()  # Reset question cache
        
        # Refresh schema discovery for this investigation
        self._discover_graph_schema()
        
        try:
            # Execute parallel investigation pipeline
            completed_tasks = self._execute_parallel_investigation(alert_id)
            
            # Generate summary using parallel results
            summary = self._dynamic_investigation_summary_tool("")
            
            # Extract verdict from synthesis task
            agent_verdict = "ESCALATE"
            agent_confidence = 50
            
            synthesis_task = next((task for task in completed_tasks if task.task_id == "evidence_synthesis"), None)
            if synthesis_task and 'agent_assessment' in self.investigation_context:
                verdict_text = self.investigation_context['agent_assessment'].get('verdict_extraction', '')
                
                if 'CLASSIFICATION:' in verdict_text:
                    classification_lines = [line for line in verdict_text.split('\n') if 'CLASSIFICATION:' in line]
                    if classification_lines:
                        extracted_verdict = classification_lines[0].split('CLASSIFICATION:')[1].strip()
                        if extracted_verdict in ['TRUE_POSITIVE', 'FALSE_POSITIVE', 'ESCALATE']:
                            agent_verdict = extracted_verdict
                
                if 'CONFIDENCE:' in verdict_text:
                    confidence_lines = [line for line in verdict_text.split('\n') if 'CONFIDENCE:' in line]
                    if confidence_lines:
                        try:
                            confidence_str = confidence_lines[0].split('CONFIDENCE:')[1].strip()
                            agent_confidence = int(''.join(filter(str.isdigit, confidence_str)))
                            agent_confidence = min(max(agent_confidence, 0), 100)
                        except:
                            agent_confidence = 50
            
            execution_time = time.time() - start_time
            
            return {
                "alert_id": alert_id,
                "qa_history": self.qa_history,
                "summary": summary,
                "agent_verdict": agent_verdict,
                "agent_confidence": agent_confidence,
                "schema_discovered": {
                    "node_types": self.node_types,
                    "relationship_types": self.relationship_types,
                    "property_patterns_count": len(self.property_patterns)
                }
                }
            
        except Exception as e:
            execution_time = time.time() - start_time
            return {
                "alert_id": alert_id,
                "qa_history": self.qa_history,
                "summary": f"Parallel investigation error: {str(e)}",
                "agent_verdict": "ESCALATE",
                "agent_confidence": 0,
                "schema_discovered": {
                    "node_types": self.node_types,
                    "relationship_types": self.relationship_types,
                    "property_patterns_count": len(self.property_patterns)
                },
                "investigation_method": "Dynamic Parallel Processing (Error Recovery)",
                "parallel_metrics": {
                    "total_tasks": 0,
                    "successful_tasks": 0,
                    "execution_time_seconds": round(execution_time, 2),
                    "error": str(e)
                }
            }
    
    def investigate_alert(self, alert_id: str) -> Dict[str, Any]:
        """Main investigation method - now uses parallel processing by default"""
        return self.investigate_alert_parallel(alert_id)
    
    def _batch_process_alerts_parallel(self, alert_ids: List[str], batch_size: int = 5) -> Dict[str, Dict[str, Any]]:
        """Process multiple alerts in parallel batches"""
        
        print(f"Starting batch parallel processing for {len(alert_ids)} alerts...")
        
        results = {}
        
        # Process alerts in batches to manage resource usage
        for i in range(0, len(alert_ids), batch_size):
            batch = alert_ids[i:i + batch_size]
            print(f"Processing batch {i//batch_size + 1}: {len(batch)} alerts")
            
            # Submit batch for parallel processing
            batch_futures = {}
            with ThreadPoolExecutor(max_workers=min(batch_size, self.max_parallel_requests)) as batch_executor:
                for alert_id in batch:
                    future = batch_executor.submit(self.investigate_alert_parallel, alert_id)
                    batch_futures[future] = alert_id
                
                # Collect batch results
                for future in as_completed(batch_futures, timeout=120):  # 2 minute timeout per alert
                    alert_id = batch_futures[future]
                    try:
                        result = future.result(timeout=60)  # 1 minute per individual alert
                        results[alert_id] = result
                        print(f"Completed parallel investigation for alert: {alert_id}")
                    except Exception as e:
                        print(f"Error in parallel investigation for alert {alert_id}: {e}")
                        results[alert_id] = {
                            "alert_id": alert_id,
                            "error": str(e),
                            "agent_verdict": "ESCALATE",
                            "agent_confidence": 0,
                            "investigation_method": "Parallel Processing (Error)"
                        }
        
        return results
    
    def cleanup(self):
        """Cleanup parallel processing resources"""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=True)
        print("Parallel processing resources cleaned up.")
    
    def __del__(self):
        """Ensure cleanup on deletion"""
        try:
            self.cleanup()
        except:
            pass        
            
def create_agentic_investigator():
    """Create and configure the agentic investigator"""
    
    investigator = AgenticGraphRAG(
        neo4j_url="bolt://localhost:7687",
        neo4j_username="neo4j", 
        neo4j_password="password",
        openai_api_key="sk-..."  # Your API key
    )
    
    return investigator



from fastapi import HTTPException
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import JSONResponse
import time
from typing import Dict, Any, Optional
import threading

# Global investigator pool for resource efficiency
_investigator_pool = {}
_pool_lock = threading.Lock()

def get_investigator() -> AgenticGraphRAG:
    """Get or create investigator instance with proper resource management"""
    thread_id = threading.current_thread().ident
    
    with _pool_lock:
        if thread_id not in _investigator_pool:
            _investigator_pool[thread_id] = AgenticGraphRAG(
                neo4j_url=NEO4J_URI,
                neo4j_username=NEO4J_USERNAME,
                neo4j_password=NEO4J_PASSWORD,
                openai_api_key=OPENAI_API_KEY
            )
    
    return _investigator_pool[thread_id]

from fastapi import HTTPException
@app.post("/investigate-agentic/{alert_id}")
async def investigate_alert_agentic(
    alert_id: str,
    context_data: dict = Body(None),
    timeout: Optional[int] = Body(120)  
):
    """
    Conduct autonomous agentic investigation with parallel processing.
    Enhanced with proper async handling and resource management.
    """
    from datetime import datetime
    import pytz
    
    try:
        if not OPENAI_API_KEY:
            raise HTTPException(
                status_code=503,
                detail="OpenAI API key not configured"
            )
        
        # Validate alert_id
        if not alert_id or len(alert_id.strip()) == 0:
            raise HTTPException(
                status_code=400,
                detail="Invalid alert_id provided"
            )
        
        # Setup IST timezone
        ist = pytz.timezone("UTC")
        start_time_epoch = time.time()
        start_time_investigation = datetime.now(ist).isoformat()
        
        print(f"Starting parallel agentic investigation for alert: {alert_id}")
        
        # Create investigator with proper resource management
        investigator = get_investigator()
        
        try:
            # Run parallel investigation in thread pool to avoid blocking async event loop
            result = await asyncio.get_event_loop().run_in_executor(
                None,  # Use default executor
                lambda: investigator.investigate_alert_parallel(alert_id)
            )
            
            # Enhanced result validation
            if not isinstance(result, dict):
                raise HTTPException(
                    status_code=500,
                    detail="Investigation returned invalid result format"
                )
            
            execution_time = time.time() - start_time_epoch
            end_time_investigation = datetime.now(ist).isoformat()
            
            # Add API-specific metrics
            result.update({
                "api_metrics": {
                    "total_execution_time": round(execution_time, 2),
                    "parallel_processing_used": True,
                    "endpoint": "investigate-agentic",
                    "timestamp_investigation": round(execution_time, 2)
                },
                "start_time_investigation": start_time_investigation,
                "end_time_investigation": end_time_investigation
            })
            
            # Enhanced context data integration if needed
            if (len(result.get('qa_history', [])) < 3 and 
                context_data and 
                result.get('agent_confidence', 0) < 70):
                
                print(f"Enhancing investigation with context data for {alert_id}")
                
                try:
                    flexible_input = FlexibleAlertInput(**context_data)
                    
                    context_enhancement = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: investigator._enhance_with_context_parallel(
                            alert_id, 
                            flexible_input.to_legacy_format()
                        )
                    )
                    
                except Exception as e:
                    print(f"Context data processing failed: {str(e)}")
                    
            else:
                print(f"Context data processing failed: Not full context provided")
            
            # Ensure proper cleanup of parallel resources for this request
            if hasattr(investigator, 'question_cache'):
                investigator.question_cache.clear()
            
            print(f"Parallel investigation completed for {alert_id} in {execution_time:.2f}s")
            
            return JSONResponse(content=result)
        
        finally:
            # Cleanup investigation-specific resources
            try:
                investigator.investigation_context.clear()
                investigator.completed_tasks.clear()
            except:
                pass
    
    except HTTPException:
        raise
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=408,
            detail=f"Investigation timeout for alert {alert_id}"
        )
    except Exception as e:
        print(f"Agentic investigation error for {alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

from fastapi import Body

@app.post("/investigate-interactive/{alert_id}")
async def investigate_alert_interactive(
    alert_id: str,
    question: str = Body(..., embed=True)
):
    """
    Interactive investigation - ask specific questions about an alert
    """
    try:
        investigator = AgenticGraphRAG(
            neo4j_url=NEO4J_URI,
            neo4j_username=NEO4J_USERNAME,
            neo4j_password=NEO4J_PASSWORD,
            openai_api_key=OPENAI_API_KEY
        )

        response = investigator.interactive_investigation(alert_id, question)

        return JSONResponse(content={
            "alert_id": alert_id,
            "question": question,
            "response": response,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _process_firewall_fallback_data(fallback_data: dict, alert_id: str) -> dict:
    """Process firewall fallback data to enhance analysis"""
    
    try:
        # Extract key firewall indicators from fallback data
        disposition = fallback_data.get('disposition', '').lower()
        severity = fallback_data.get('severity', '').lower()
        confidence = fallback_data.get('confidence', '').lower()
        action = fallback_data.get('unmapped_action', '').lower()
        
        # File and hash analysis
        file_info = fallback_data.get('file', {})
        file_type = file_info.get('type', '').lower()
        hashes = file_info.get('hashes', {})
        
        # Network indicators
        src_endpoint = fallback_data.get('src_endpoint', {})
        dst_endpoint = fallback_data.get('dst_endpoint', {})
        network_info = fallback_data.get('network', {})
        
        # HTTP transaction details
        http_info = fallback_data.get('http', {})
        user_agent = http_info.get('user_agent', '').lower()
        
        # Threat intelligence
        rule_name = fallback_data.get('rule', {}).get('name', '').lower()
        indicator_name = fallback_data.get('unmapped_indicator_name', '').lower()
        
        # Agent verdict from original system
        agent_verdict = fallback_data.get('unmapped', {}).get('agent_verdict', '').lower()
        
        # Calculate enhanced verdict based on firewall-specific indicators
        threat_score = 0
        context_factors = []
        
        # Disposition analysis
        if disposition == 'malicious':
            threat_score += 30
            context_factors.append("Marked as malicious by firewall")
        
        # Action analysis
        if action in ['prevent', 'block', 'deny']:
            threat_score += 25
            context_factors.append(f"Traffic was {action}ed by firewall")
        
        # File type analysis
        if any(suspicious_type in file_type for suspicious_type in ['executable', 'script', 'archive']):
            threat_score += 15
            context_factors.append(f"Suspicious file type: {file_type}")
        
        # Hash analysis
        if hashes:
            threat_score += 10
            context_factors.append("File hashes available for reputation check")
        
        # Threat intelligence match
        if 'ioc' in indicator_name or 'threat' in rule_name:
            threat_score += 20
            context_factors.append("Matched threat intelligence indicators")
        
        # User agent analysis
        if 'curl' in user_agent or 'wget' in user_agent or 'bot' in user_agent:
            threat_score += 15
            context_factors.append("Automated tool detected in user agent")
        
        # Network pattern analysis
        bytes_in = network_info.get('bytes_in', 0)
        if bytes_in > 10000:  # Large file download
            threat_score += 10
            context_factors.append("Large data transfer detected")
        
        # Agent verdict consideration
        if agent_verdict == 'false_positive':
            threat_score -= 20
            context_factors.append("Original system marked as false positive")
        
        # Determine enhanced verdict
        if threat_score >= 60:
            enhanced_verdict = "TRUE_POSITIVE"
            confidence = min(85 + (threat_score - 60), 95)
        elif threat_score <= 20:
            enhanced_verdict = "FALSE_POSITIVE"
            confidence = min(70 + (20 - threat_score), 85)
        else:
            enhanced_verdict = "ESCALATE"
            confidence = 50 + threat_score
        
        return {
            'enhanced_verdict': enhanced_verdict,
            'confidence': confidence,
            'context': '; '.join(context_factors),
            'threat_score': threat_score
        }
        
    except Exception as e:
        print(f"Error processing firewall fallback data: {e}")
        return {
            'enhanced_verdict': "ESCALATE",
            'confidence': 50,
            'context': f"Fallback processing error: {str(e)}",
            'threat_score': 0
        }

class FirewallThreatAnalyzer:
    """Dynamic analyzer for firewall alerts using LangChain Neo4j"""

    def __init__(self):
        # Initialize LangChain components
        self.llm = ChatOpenAI(
            temperature=0,
            api_key=OPENAI_API_KEY
        )
        self.graph = Neo4jGraph(
            url=NEO4J_URI,
            username=NEO4J_USERNAME,
            password=NEO4J_PASSWORD
        )
        self.chain = GraphCypherQAChain.from_llm(
            llm=self.llm,
            graph=self.graph,
            allow_dangerous_requests=True
        )
        
        # Firewall-focused SOC analyst questions
        self.firewall_analyst_questions = [
            "What network communication pattern was observed in this alert?",
            "What are the source and destination endpoints involved?",
            "What file was downloaded and what are its characteristics?",
            "What HTTP transaction details reveal about the attack?",
            "What threat intelligence triggered this detection?",
            "What policy or rule was violated?",
            "What is the file hash reputation and detection status?",
            "What network protocols and data volumes were involved?",
            "What URL and domain reputation indicates malicious intent?",
            "What evidence was captured for forensic analysis?",
            "How does the user agent and client behavior suggest automation?",
            "What firewall detection engine identified this threat?"
        ]

    def analyze_firewall_alert_from_graph(self, alert_id: str) -> Dict[str, Any]:
        """Dynamically analyze firewall alert using LangChain Neo4j chain"""
        
        print(f"Starting firewall dynamic analysis for alert: {alert_id}")
        
        # First, get basic firewall alert context
        context_query = f"What firewall alert information exists for alert_id '{alert_id}'?"
        
        try:
            context_response = self.chain.run(context_query)
            print(f"Firewall alert context: {context_response}")
        except Exception as e:
            print(f"Error getting firewall context: {e}")
            context_response = "Firewall alert context unavailable"
        
        # Generate dynamic questions and get answers
        qa_analysis = []
        
        for question in self.firewall_analyst_questions:
            try:
                # Modify question to be specific to this firewall alert
                specific_question = f"For firewall alert_id '{alert_id}': {question}"
                
                # Get answer from graph
                answer = self.chain.run(specific_question)
                
                # Analyze this Q&A pair for threat assessment
                verdict, confidence, reasoning = self._analyze_firewall_qa_for_threat(question, answer)
                
                qa_analysis.append({
                    "question": question,
                    "answer": answer,
                    "individual_verdict": verdict,
                    "individual_confidence": confidence,
                    "reasoning": reasoning
                })
                
                print(f"Q: {question[:60]}...")
                print(f"A: {answer[:100]}...")
                print(f"Verdict: {verdict} ({confidence}%)")
                print("-" * 50)
                
            except Exception as e:
                print(f"Error processing firewall question: {question[:30]}... - {e}")
                continue
        
        # Generate final verdict from all individual assessments
        final_verdict, final_confidence, summary = self._generate_firewall_final_verdict(qa_analysis)
        
        result = {
            "success": True,
            "alert_id": alert_id,
            "alert_type": "firewall",
            "analysis_method": "Dynamic LangChain Neo4j Firewall Analysis",
            "questions_analyzed": len(qa_analysis),
            "qa_analysis": qa_analysis,
            "final_verdict": final_verdict,
            "final_confidence": final_confidence,
            "summary": summary,
            "timestamp": datetime.now().isoformat()
        }
        
        return result

    def _analyze_firewall_qa_for_threat(self, question: str, answer: str) -> tuple:
        """Analyze individual firewall Q&A pair for threat indicators"""
        
        firewall_threat_analysis_prompt = f"""
You are a SOC analyst specializing in firewall and network security. Analyze this firewall-specific question and answer for threat indicators:

QUESTION: {question}
ANSWER: {answer}

Based on this firewall/network information, determine:
1. VERDICT: TRUE_POSITIVE (malicious), FALSE_POSITIVE (benign), or ESCALATE (unclear/mixed)
2. CONFIDENCE: 0-100 confidence in your assessment
3. REASONING: Brief explanation of your assessment

Focus on firewall-specific threat indicators:
- Malicious file downloads and hash reputation
- Suspicious network communication patterns
- Policy violations and blocked connections
- Threat intelligence feed matches
- HTTP transaction anomalies (user agents, unusual patterns)
- Network protocol abuse
- Command and control communication patterns
- Data exfiltration indicators

Respond with only: VERDICT|CONFIDENCE|REASONING
Example: TRUE_POSITIVE|90|Malicious file download with known bad hash from threat intelligence feed
"""
        
        try:
            response = self.llm.invoke(firewall_threat_analysis_prompt)
            analysis = response.content.strip()
            
            # Parse the response
            parts = analysis.split('|')
            if len(parts) >= 3:
                verdict = parts[0].strip()
                confidence = int(parts[1].strip())
                reasoning = '|'.join(parts[2:]).strip()
            else:
                # Fallback parsing
                verdict, confidence, reasoning = self._fallback_firewall_threat_analysis(answer)
                
        except Exception as e:
            print(f"Error in firewall threat analysis: {e}")
            verdict, confidence, reasoning = self._fallback_firewall_threat_analysis(answer)
        
        return verdict, confidence, reasoning

    def _fallback_firewall_threat_analysis(self, answer: str) -> tuple:
        """Fallback firewall threat analysis if LLM analysis fails"""
        answer_lower = answer.lower()
        
        # Firewall-specific threat indicators
        threat_indicators = [
            "malicious", "blocked", "prevented", "threat intelligence", "ioc", 
            "exploit", "download", "suspicious", "c2", "command and control",
            "bad hash", "known malware", "policy violation", "unauthorized",
            "data exfiltration", "unusual traffic", "automated", "bot"
        ]
        
        benign_indicators = [
            "legitimate", "authorized", "business", "normal", "expected",
            "clean", "allowed", "policy compliant", "safe"
        ]
        
        threat_count = sum(1 for indicator in threat_indicators if indicator in answer_lower)
        benign_count = sum(1 for indicator in benign_indicators if indicator in answer_lower)
        
        if threat_count > benign_count and threat_count >= 2:
            return "TRUE_POSITIVE", min(75 + (threat_count * 5), 95), f"Multiple firewall threat indicators detected ({threat_count})"
        elif benign_count > threat_count and benign_count >= 1:
            return "FALSE_POSITIVE", min(65 + (benign_count * 8), 90), f"Benign network activity indicators found ({benign_count})"
        else:
            return "ESCALATE", 55, "Mixed or insufficient firewall indicators for clear determination"

    def _generate_firewall_final_verdict(self, qa_analysis: List[Dict]) -> tuple:
        """Generate final verdict from all firewall individual assessments"""
        
        if not qa_analysis:
            return "ESCALATE", 50, "No firewall analysis data available"
        
        # Count verdicts
        tp_count = sum(1 for qa in qa_analysis if qa["individual_verdict"] == "TRUE_POSITIVE")
        fp_count = sum(1 for qa in qa_analysis if qa["individual_verdict"] == "FALSE_POSITIVE")
        escalate_count = sum(1 for qa in qa_analysis if qa["individual_verdict"] == "ESCALATE")
        
        total_questions = len(qa_analysis)
        
        # Calculate weighted confidence
        tp_confidence = sum(qa["individual_confidence"] for qa in qa_analysis if qa["individual_verdict"] == "TRUE_POSITIVE")
        fp_confidence = sum(qa["individual_confidence"] for qa in qa_analysis if qa["individual_verdict"] == "FALSE_POSITIVE")
        
        print(f"Firewall verdict counts - TP: {tp_count}, FP: {fp_count}, ESCALATE: {escalate_count}")
        
        # Firewall-specific verdict logic
        if tp_count >= 3 and tp_count > fp_count:
            final_verdict = "TRUE_POSITIVE"
            avg_confidence = tp_confidence / tp_count if tp_count > 0 else 75
            final_confidence = min(avg_confidence + (tp_count * 3), 95)
            summary = f"Strong malicious network activity: {tp_count}/{total_questions} questions show threat indicators"
            
        elif fp_count >= 3 and fp_count > tp_count:
            final_verdict = "FALSE_POSITIVE"
            avg_confidence = fp_confidence / fp_count if fp_count > 0 else 70
            final_confidence = min(avg_confidence + (fp_count * 2), 90)
            summary = f"Likely legitimate network activity: {fp_count}/{total_questions} questions indicate benign traffic"
            
        elif tp_count >= 2 and tp_count >= fp_count:
            final_verdict = "TRUE_POSITIVE"
            final_confidence = 80 + (tp_count * 2)
            summary = f"Probable network threat: {tp_count} malicious vs {fp_count} benign indicators"
            
        else:
            final_verdict = "ESCALATE"
            final_confidence = 55 + (total_questions * 2)
            summary = f"Requires analyst review: {tp_count} threat, {fp_count} benign, {escalate_count} unclear network indicators"
        
        return final_verdict, final_confidence, summary


# Initialize firewall graph manager
firewall_graph_manager = FirewallGraphManager(neo4j_driver) if neo4j_driver else None

# Initialize firewall threat analyzer
firewall_threat_analyzer = None

if neo4j_driver and OPENAI_API_KEY:
    try:
        firewall_threat_analyzer = FirewallThreatAnalyzer()
    except Exception as e:
        print(f"Failed to initialize firewall threat analyzer: {e}")
        firewall_threat_analyzer = None



@app.post("/analyze-firewall-from-graph/{alert_id}")
async def analyze_firewall_alert_from_graph(
    alert_id: str,
    fallback_data: dict = Body(None)
):
    """
    Analyze firewall alert using dynamic LangChain Neo4j querying with fallback data support.
    If alert_id is not found in graph, can use fallback_data for enhanced analysis.
    Returns SOC analyst verdict based on firewall-specific graph relationships.
    """
    try:
        if not firewall_threat_analyzer:
            raise HTTPException(
                status_code=503, 
                detail="Firewall threat analyzer not available. Check Neo4j and OpenAI configuration."
            )
        
        print(f"Starting firewall analysis for alert: {alert_id}")
        
        # Run dynamic firewall analysis
        result = firewall_threat_analyzer.analyze_firewall_alert_from_graph(alert_id)
        
        # Check if analysis needs enhancement with fallback data
        needs_fallback = (
            not result.get('qa_analysis') or 
            len(result.get('qa_analysis', [])) < 3 or
            result.get('final_verdict') == 'ESCALATE' and
            fallback_data
        )
        
        if needs_fallback:
            print(f"Using fallback data for enhanced firewall analysis of {alert_id}")
            
            try:
                # Process fallback data for firewall context
                fallback_analysis = _process_firewall_fallback_data(fallback_data, alert_id)
                
                # Enhance result with fallback analysis
                result['fallback_analysis'] = {
                    'used': True,
                    'fallback_alert_id': fallback_data.get('id', alert_id),
                    'processed_keys': list(fallback_data.keys()),
                    'enhanced_verdict': fallback_analysis.get('enhanced_verdict'),
                    'fallback_confidence': fallback_analysis.get('confidence'),
                    'additional_context': fallback_analysis.get('context')
                }
                
                # Update final verdict if fallback provides stronger evidence
                if (fallback_analysis.get('enhanced_verdict') == 'TRUE_POSITIVE' and 
                    fallback_analysis.get('confidence', 0) > result.get('final_confidence', 0)):
                    result['final_verdict'] = fallback_analysis['enhanced_verdict']
                    result['final_confidence'] = fallback_analysis['confidence']
                    result['summary'] += f" Enhanced by fallback analysis: {fallback_analysis.get('context')}"
                
            except Exception as e:
                print(f"Firewall fallback data processing failed: {str(e)}")
                result['fallback_analysis'] = {
                    'used': False,
                    'error': str(e)
                }
        
        return JSONResponse(content=result)
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"Firewall graph analysis error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Firewall analysis failed: {str(e)}")


def _process_firewall_fallback_data(fallback_data: dict, alert_id: str) -> dict:
    """Process firewall fallback data to enhance analysis"""
    
    try:
        # Extract key firewall indicators from fallback data
        disposition = fallback_data.get('disposition', '').lower()
        severity = fallback_data.get('severity', '').lower()
        confidence = fallback_data.get('confidence', '').lower()
        action = fallback_data.get('unmapped_action', '').lower()
        
        # File and hash analysis
        file_info = fallback_data.get('file', {})
        file_type = file_info.get('type', '').lower()
        hashes = file_info.get('hashes', {})
        
        # Network indicators
        src_endpoint = fallback_data.get('src_endpoint', {})
        dst_endpoint = fallback_data.get('dst_endpoint', {})
        network_info = fallback_data.get('network', {})
        
        # HTTP transaction details
        http_info = fallback_data.get('http', {})
        user_agent = http_info.get('user_agent', '').lower()
        
        # Threat intelligence
        rule_name = fallback_data.get('rule', {}).get('name', '').lower()
        indicator_name = fallback_data.get('unmapped_indicator_name', '').lower()
        
        # Agent verdict from original system
        agent_verdict = fallback_data.get('unmapped', {}).get('agent_verdict', '').lower()
        
        # Calculate enhanced verdict based on firewall-specific indicators
        threat_score = 0
        context_factors = []
        
        # Disposition analysis
        if disposition == 'malicious':
            threat_score += 30
            context_factors.append("Marked as malicious by firewall")
        
        # Action analysis
        if action in ['prevent', 'block', 'deny']:
            threat_score += 25
            context_factors.append(f"Traffic was {action}ed by firewall")
        
        # File type analysis
        if any(suspicious_type in file_type for suspicious_type in ['executable', 'script', 'archive']):
            threat_score += 15
            context_factors.append(f"Suspicious file type: {file_type}")
        
        # Hash analysis
        if hashes:
            threat_score += 10
            context_factors.append("File hashes available for reputation check")
        
        # Threat intelligence match
        if 'ioc' in indicator_name or 'threat' in rule_name:
            threat_score += 20
            context_factors.append("Matched threat intelligence indicators")
        
        # User agent analysis
        if 'curl' in user_agent or 'wget' in user_agent or 'bot' in user_agent:
            threat_score += 15
            context_factors.append("Automated tool detected in user agent")
        
        # Network pattern analysis
        bytes_in = network_info.get('bytes_in', 0)
        if bytes_in > 10000:  # Large file download
            threat_score += 10
            context_factors.append("Large data transfer detected")
        
        # Agent verdict consideration
        if agent_verdict == 'false_positive':
            threat_score -= 20
            context_factors.append("Original system marked as false positive")
        
        # Determine enhanced verdict
        if threat_score >= 60:
            enhanced_verdict = "TRUE_POSITIVE"
            confidence = min(85 + (threat_score - 60), 95)
        elif threat_score <= 20:
            enhanced_verdict = "FALSE_POSITIVE"
            confidence = min(70 + (20 - threat_score), 85)
        else:
            enhanced_verdict = "ESCALATE"
            confidence = 50 + threat_score
        
        return {
            'enhanced_verdict': enhanced_verdict,
            'confidence': confidence,
            'context': '; '.join(context_factors),
            'threat_score': threat_score
        }
        
    except Exception as e:
        print(f"Error processing firewall fallback data: {e}")
        return {
            'enhanced_verdict': "ESCALATE",
            'confidence': 50,
            'context': f"Fallback processing error: {str(e)}",
            'threat_score': 0
        }

LABELS = ["False Positive", "Escalate", "True Positive"]
_GNN_CACHE: Dict[str, Tuple[nn.Module, dict, list]] = {}

def stable_hash(s: str, mod: int = 512) -> int:
    import hashlib as _h
    return int(_h.sha256(s.encode("utf-8")).hexdigest(), 16) % mod



@dataclass
class Subgraph:
    N: int
    F: int
    features: torch.Tensor
    edges_by_rel: Dict[str, Tuple[torch.Tensor, torch.Tensor]]
    target_idx: int




# ==== /GNN core ===============================================================

def _flatten_json(obj, parent_key=""):
    flat = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            nk = f"{parent_key}.{k}" if parent_key else k
            flat.update(_flatten_json(v, nk))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:50]):
            nk = f"{parent_key}[{i}]"
            flat.update(_flatten_json(v, nk))
    else:
        flat[parent_key] = obj
    return flat

def _extract_uid_from_json(payload: dict) -> str:
    candidates = ["uid", "alert_id", "alertId", "threatId", "threat_id", "id"]
    for k in candidates:
        if k in payload and payload[k]:
            return str(payload[k])
    flat = _flatten_json(payload)
    for k, v in flat.items():
        last = k.split(".")[-1]
        if last in candidates and v not in (None, ""):
            return str(v)
    return ""

import torch
import torch.nn as nn
import numpy as np
import traceback
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, Body, HTTPException
from fastapi.responses import JSONResponse
import hashlib

# =============================================================================
# CORE DATA STRUCTURES
# =============================================================================

@dataclass
class DynamicSubgraph:
    """Subgraph with dynamically discovered relationships"""
    N: int  # Number of nodes
    F: int  # Feature dimension
    features: torch.Tensor  # Node features [N, F]
    edges_by_rel: Dict[str, Tuple[torch.Tensor, torch.Tensor]]  # Discovered relationships
    discovered_rel_types: List[str]  # All relationship types found
    target_idx: int  # Index of target alert node
    alert_id: str
    metadata: Dict[str, Any]

@dataclass
class RelationshipMapping:
    """Mapping between discovered and model relationships"""
    discovered_to_model: Dict[str, str]
    model_to_discovered: Dict[str, List[str]]
    unmapped_discovered: List[str]
    coverage_score: float

# =============================================================================
# FEATURE ENCODING
# =============================================================================

class DynamicFeatureEncoder:
    """Enhanced feature encoder with better property handling"""
    
    def __init__(self, dim: int = 512):
        self.dim = dim
        self.property_cache = {}
    
    def stable_hash(self, text: str) -> int:
        """Stable hash function for consistent feature positions"""
        return int(hashlib.sha256(text.encode('utf-8')).hexdigest(), 16) % self.dim
    
    def encode_node(self, labels: List[str], properties: Dict[str, Any]) -> List[float]:
        """Encode a node's labels and properties into feature vector"""
        vector = np.zeros(self.dim, dtype=np.float32)
        
        # Encode primary label
        primary_label = labels[0] if labels else "Unknown"
        vector[self.stable_hash(f"label:{primary_label}")] = 1.0
        
        # Encode all labels
        for label in labels:
            vector[self.stable_hash(f"has_label:{label}")] = 1.0
        
        # Encode properties with type awareness
        if properties:
            for key, value in properties.items():
                self._encode_property(vector, primary_label, key, value)
        
        # Optional normalization - preserve feature magnitudes but prevent explosion
        norm = np.linalg.norm(vector)
        if norm > 10.0:  # Only normalize if vector is too large
            vector = vector * (10.0 / norm)
        
        return vector.tolist()
    
    def _encode_property(self, vector: np.ndarray, label: str, key: str, value: Any):
        """Encode individual property with type-specific handling"""
        if value is None:
            return
        
        try:
            if isinstance(value, bool):
                vector[self.stable_hash(f"{label}.{key}:bool:{value}")] += 0.5
            elif isinstance(value, (int, float)):
                # Normalize numeric values
                normalized_val = max(-10, min(10, float(value)))  # Clamp to reasonable range
                vector[self.stable_hash(f"{label}.{key}:num")] += normalized_val / 10.0
            elif isinstance(value, str):
                # Hash string values but limit impact
                if len(value) > 0:
                    vector[self.stable_hash(f"{label}.{key}:str:{value[:100]}")] += 0.8
            elif isinstance(value, (list, tuple)):
                # Handle lists/arrays
                for i, item in enumerate(value[:5]):  # Limit to first 5 items
                    vector[self.stable_hash(f"{label}.{key}[{i}]:{str(item)[:50]}")] += 0.3
            else:
                # Fallback for other types
                vector[self.stable_hash(f"{label}.{key}:other:{str(value)[:100]}")] += 0.4
        except Exception as e:
            # Silently handle encoding errors
            vector[self.stable_hash(f"{label}.{key}:error")] += 0.1

# =============================================================================
# RELATIONSHIP DISCOVERY AND MAPPING
# =============================================================================

class RelationshipDiscovery:
    """Discovers and maps relationships dynamically"""
    
    def __init__(self, neo4j_driver, database: str = "neo4j"):
        self.neo4j_driver = neo4j_driver
        self.database = database
        self.relationship_cache = {}
    
    def discover_alert_subgraph(self, alert_id: str, max_hops: int = 3) -> Optional[DynamicSubgraph]:
        """Discover subgraph around alert with all relationships"""
        
        if not self.neo4j_driver:
            return None
        
        try:
            with self.neo4j_driver.session(database=self.database) as session:
                # Multi-strategy alert discovery - FIXED the query bug
                discovery_query = """
                // Try multiple alert identification strategies
                OPTIONAL MATCH (a1:Alert {alert_id: $id})
                OPTIONAL MATCH (a2:Alert {threat_id: $id})
                OPTIONAL MATCH (a3:Alert) WHERE toString(a3.alert_id) = toString($id)
                OPTIONAL MATCH (a4:Alert) WHERE toString(a4.threat_id) = toString($id)
                
                WITH COALESCE(a1, a2, a3, a4) as alert
                WHERE alert IS NOT NULL
                
                // Get k-hop neighborhood with all relationship types
                OPTIONAL MATCH path = (alert)-[*1..$hops]-(connected)
                
                WITH alert, 
                     CASE WHEN path IS NULL THEN [] ELSE collect(DISTINCT path) END as paths
                
                // Extract all nodes and relationships
                WITH alert, paths,
                     reduce(nodes = [alert], path IN paths | 
                         nodes + [n IN nodes(path) WHERE n <> alert]) as all_nodes,
                     reduce(rels = [], path IN paths | 
                         rels + relationships(path)) as all_rels
                
                // Build node list with metadata
                UNWIND all_nodes as n
                WITH alert, all_rels, 
                     collect(DISTINCT {
                         id: elementId(n),
                         labels: labels(n),
                         properties: properties(n)
                     }) as nodes_data
                
                // Build relationship list with metadata
                UNWIND all_rels as r
                WITH alert, nodes_data,
                     collect(DISTINCT {
                         type: type(r),
                         start_id: elementId(startNode(r)),
                         end_id: elementId(endNode(r)),
                         properties: properties(r)
                     }) as rels_data,
                     collect(DISTINCT type(r)) as discovered_rel_types
                
                RETURN elementId(alert) as alert_element_id,
                       nodes_data, rels_data, discovered_rel_types
                """
                
                result = session.run(discovery_query, 
                                   id=str(alert_id), 
                                   hops=max_hops).single()
                
                if not result or not result.get("nodes_data"):
                    return None
                
                return self._build_subgraph(
                    result["alert_element_id"],
                    result["nodes_data"],
                    result["rels_data"] or [], 
                    result["discovered_rel_types"] or [],
                    alert_id
                )
                
        except Exception as e:
            print(f"Subgraph discovery error: {e}")
            return None
    
    def _build_subgraph(self, alert_element_id: str, nodes_data: List[Dict], 
                       rels_data: List[Dict], discovered_rel_types: List[str],
                       alert_id: str) -> Optional[DynamicSubgraph]:
        """Build subgraph from Neo4j results"""
        
        if not nodes_data:
            return None
        
        try:
            # Create node ID mapping
            id_to_idx = {node["id"]: idx for idx, node in enumerate(nodes_data)}
            
            # Find target alert index
            target_idx = id_to_idx.get(alert_element_id, 0)
            
            # Encode node features
            encoder = DynamicFeatureEncoder()
            features = []
            
            for node in nodes_data:
                labels = node.get("labels", [])
                props = node.get("properties", {})
                feature_vec = encoder.encode_node(labels, props)
                features.append(feature_vec)
            
            features_tensor = torch.tensor(features, dtype=torch.float32)
            
            # Build edge dictionaries by relationship type
            edges_by_rel = {}
            
            # Initialize empty edge lists for all discovered relationship types
            for rel_type in discovered_rel_types:
                edges_by_rel[rel_type] = ([], [])
                edges_by_rel[f"{rel_type}_rev"] = ([], [])  # Reverse direction
            
            # Populate edges
            for rel in rels_data:
                rel_type = rel["type"]
                start_id = rel["start_id"]
                end_id = rel["end_id"]
                
                if start_id in id_to_idx and end_id in id_to_idx:
                    start_idx = id_to_idx[start_id]
                    end_idx = id_to_idx[end_id]
                    
                    # Forward direction
                    if rel_type in edges_by_rel:
                        edges_by_rel[rel_type][0].append(start_idx)
                        edges_by_rel[rel_type][1].append(end_idx)
                    
                    # Reverse direction
                    rev_rel_type = f"{rel_type}_rev"
                    if rev_rel_type in edges_by_rel:
                        edges_by_rel[rev_rel_type][0].append(end_idx)
                        edges_by_rel[rev_rel_type][1].append(start_idx)
            
            # Convert to tensors
            edges_tensor_dict = {}
            for rel_type, (src_list, dst_list) in edges_by_rel.items():
                if src_list:
                    edges_tensor_dict[rel_type] = (
                        torch.tensor(src_list, dtype=torch.long),
                        torch.tensor(dst_list, dtype=torch.long)
                    )
                else:
                    edges_tensor_dict[rel_type] = (
                        torch.empty(0, dtype=torch.long),
                        torch.empty(0, dtype=torch.long)
                    )
            
            return DynamicSubgraph(
                N=len(nodes_data),
                F=features_tensor.size(1),
                features=features_tensor,
                edges_by_rel=edges_tensor_dict,
                discovered_rel_types=discovered_rel_types,
                target_idx=target_idx,
                alert_id=alert_id,
                metadata={
                    "discovery_time": datetime.now().isoformat(),
                    "num_relationships": len(rels_data),
                    "num_rel_types": len(discovered_rel_types)
                }
            )
            
        except Exception as e:
            print(f"Subgraph building error: {e}")
            return None

class RelationshipMapper:
    """Maps discovered relationships to model's expected relationships"""
    
    def __init__(self):
        # Relationship mapping rules based on semantic similarity
        self.mapping_rules = {
            # File-related mappings
            "ALERT_REFERS_TO_FILE": "involves_file",
            "FILE_HAS_HASH": "has_hash",
            "HASH_ENRICHED_BY_TI": "enriched_by_threat_intel",
            
            # Process-related mappings
            "ALERT_TRIGGERED_BY": "triggered_by_process",
            "PROCESS_EXECUTED_BY": "executed_by_user",
            "PROCESS_ON_HOST": "runs_on_host",
            
            # Host-related mappings
            "HOST_CONNECTS_TO": "connects_to_external",
            "HOST_HAS_INTERFACE": "has_network_interface",
            "HOST_HAS_OS": "runs_operating_system",
            "HOST_IN_GROUP": "member_of_group",
            
            # Detection/Response mappings
            "ALERT_DETECTED_BY": "detected_by_engine",
            "ALERT_MITIGATED_VIA": "mitigated_by_action",
            "ACTION_APPLIED_ON": "applied_on_host",
            
            # Context mappings
            "ALERT_BELONGS_TO_SITE": "belongs_to_site",
            "ALERT_IN_INCIDENT": "part_of_incident",
            "ALERT_WHITELISTED_BY": "whitelisted_by_rule",
            "FILE_RESIDES_ON": "resides_on_host",
            
            # Reverse mappings for bidirectional relationships
            "ALERT_REFERS_TO_FILE_rev": "file_involved_in",
            "ALERT_TRIGGERED_BY_rev": "process_triggers",
            "PROCESS_ON_HOST_rev": "host_runs_process"
        }
        
        # Fallback semantic keywords
        self.semantic_keywords = {
            "file": "involves_file",
            "process": "triggered_by_process", 
            "host": "runs_on_host",
            "user": "executed_by_user",
            "hash": "has_hash",
            "threat": "enriched_by_threat_intel",
            "detect": "detected_by_engine",
            "mitigation": "mitigated_by_action",
            "action": "mitigated_by_action",
            "incident": "part_of_incident",
            "site": "belongs_to_site"
        }
    
    def create_mapping(self, discovered_rels: List[str], 
                      model_rels: List[str]) -> RelationshipMapping:
        """Create mapping between discovered and model relationships"""
        
        discovered_to_model = {}
        model_to_discovered = {rel: [] for rel in model_rels}
        unmapped_discovered = []
        
        for disc_rel in discovered_rels:
            mapped_rel = self._map_single_relationship(disc_rel, model_rels)
            
            if mapped_rel:
                discovered_to_model[disc_rel] = mapped_rel
                model_to_discovered[mapped_rel].append(disc_rel)
            else:
                unmapped_discovered.append(disc_rel)
        
        # Calculate coverage score
        mapped_count = len(discovered_to_model)
        total_count = len(discovered_rels)
        coverage_score = mapped_count / total_count if total_count > 0 else 0.0
        
        return RelationshipMapping(
            discovered_to_model=discovered_to_model,
            model_to_discovered=model_to_discovered,
            unmapped_discovered=unmapped_discovered,
            coverage_score=coverage_score
        )
    
    def _map_single_relationship(self, discovered_rel: str, 
                                model_rels: List[str]) -> Optional[str]:
        """Map single discovered relationship to model relationship"""
        
        # Direct mapping first
        if discovered_rel in self.mapping_rules:
            mapped = self.mapping_rules[discovered_rel]
            if mapped in model_rels:
                return mapped
        
        # Semantic keyword mapping
        disc_lower = discovered_rel.lower()
        for keyword, target_rel in self.semantic_keywords.items():
            if keyword in disc_lower and target_rel in model_rels:
                return target_rel
        
        # Substring matching with model relationships
        for model_rel in model_rels:
            model_lower = model_rel.lower()
            if any(word in model_lower for word in disc_lower.split('_')):
                return model_rel
        
        # Default to most common relationship if available
        common_rels = ["involves_file", "triggered_by_process", "runs_on_host"]
        for common_rel in common_rels:
            if common_rel in model_rels:
                return common_rel
        
        return model_rels[0] if model_rels else None

# =============================================================================
# DYNAMIC R-GCN MODEL
# =============================================================================

class DynamicRelGraphLayer(nn.Module):
    """Relational graph layer that handles dynamic relationship mapping"""
    
    def __init__(self, in_dim: int, out_dim: int, base_rel_names: List[str], 
                 dropout: float = 0.1):
        super().__init__()
        self.base_rel_names = base_rel_names
        
        # Create weight matrices for each base relationship type
        self.rel_weights = nn.ModuleDict({
            rel: nn.Linear(in_dim, out_dim, bias=False) 
            for rel in base_rel_names
        })
        
        # Self-loop transformation
        self.self_loop = nn.Linear(in_dim, out_dim, bias=True)
        self.dropout = nn.Dropout(dropout)
        self.activation = nn.ReLU()
        
    def forward(self, node_features: torch.Tensor, 
                edges_by_rel: Dict[str, Tuple[torch.Tensor, torch.Tensor]],
                rel_mapping: Optional[RelationshipMapping] = None) -> torch.Tensor:
        """Forward pass with dynamic relationship handling"""
        
        N, _ = node_features.shape
        output = self.self_loop(node_features)
        
        # Process each base relationship type
        for base_rel in self.base_rel_names:
            if base_rel not in self.rel_weights:
                continue
                
            # Get edges for this relationship type
            src_indices, dst_indices = self._get_edges_for_base_rel(
                base_rel, edges_by_rel, rel_mapping
            )
            
            if src_indices.numel() == 0:
                continue
            
            # Apply relationship-specific transformation
            transformed_features = self.rel_weights[base_rel](node_features)
            
            # Message passing
            messages = transformed_features[src_indices]
            
            # Aggregate messages at destination nodes
            aggregated = torch.zeros_like(output)
            aggregated.index_add_(0, dst_indices, messages)
            
            # Degree normalization
            degree = torch.zeros(N, device=node_features.device)
            degree.index_add_(0, dst_indices, torch.ones_like(dst_indices, dtype=torch.float32))
            degree = degree.clamp_min(1.0).unsqueeze(1)
            
            output = output + (aggregated / degree)
        
        return self.dropout(self.activation(output))
    
    def _get_edges_for_base_rel(self, base_rel: str, 
                               edges_by_rel: Dict[str, Tuple[torch.Tensor, torch.Tensor]],
                               rel_mapping: Optional[RelationshipMapping]) -> Tuple[torch.Tensor, torch.Tensor]:
        """Get edges for base relationship, combining mapped relationships"""
        
        all_src = []
        all_dst = []
        
        if rel_mapping and base_rel in rel_mapping.model_to_discovered:
            # Use mapped discovered relationships
            for disc_rel in rel_mapping.model_to_discovered[base_rel]:
                if disc_rel in edges_by_rel:
                    src, dst = edges_by_rel[disc_rel]
                    if src.numel() > 0:
                        all_src.append(src)
                        all_dst.append(dst)
        else:
            # Direct lookup
            if base_rel in edges_by_rel:
                src, dst = edges_by_rel[base_rel]
                if src.numel() > 0:
                    all_src.append(src)
                    all_dst.append(dst)
        
        if all_src:
            return torch.cat(all_src), torch.cat(all_dst)
        else:
            return torch.empty(0, dtype=torch.long), torch.empty(0, dtype=torch.long)

class DynamicRGCN(nn.Module):
    """Dynamic R-GCN that adapts to discovered relationships"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__()
        
        self.config = config
        self.in_dim = config["in_dim"]
        self.hidden_dim = config["hidden"]
        self.out_dim = config["out_dim"]
        self.base_rel_names = config["rel_names"]
        self.dropout = config.get("dropout", 0.1)
        
        # Graph layers
        self.layer1 = DynamicRelGraphLayer(
            self.in_dim, self.hidden_dim, self.base_rel_names, self.dropout
        )
        self.layer2 = DynamicRelGraphLayer(
            self.hidden_dim, self.hidden_dim, self.base_rel_names, self.dropout
        )
        
        # Classification head
        self.classifier = nn.Sequential(
            nn.Dropout(self.dropout),
            nn.Linear(self.hidden_dim, self.out_dim)
        )
        
        self.relationship_mapper = RelationshipMapper()
    
    def forward(self, subgraph: DynamicSubgraph) -> Tuple[torch.Tensor, RelationshipMapping]:
        """Forward pass with dynamic subgraph"""
        
        # Create relationship mapping
        rel_mapping = self.relationship_mapper.create_mapping(
            subgraph.discovered_rel_types, 
            self.base_rel_names
        )
        
        # Two-layer R-GCN
        h1 = self.layer1(subgraph.features, subgraph.edges_by_rel, rel_mapping)
        h2 = self.layer2(h1, subgraph.edges_by_rel, rel_mapping)
        
        # Classification
        logits = self.classifier(h2)
        
        return logits, rel_mapping

# =============================================================================
# GNN PREDICTOR CLASS
# =============================================================================

class DynamicGNNPredictor:
    """Main GNN predictor with dynamic relationship discovery"""
    
    def __init__(self, neo4j_driver, database: str = "neo4j"):
        self.neo4j_driver = neo4j_driver
        self.database = database
        
        # Components
        self.relationship_discovery = RelationshipDiscovery(neo4j_driver, database)
        self.feature_encoder = DynamicFeatureEncoder()
        
        # Model and config (loaded when needed)
        self.model = None
        self.config = None
        self.labels = ["False Positive", "Escalate", "True Positive"]
        
        # Cache for performance
        self.subgraph_cache = {}
        self.model_cache = {}
    
    def load_model(self, checkpoint_path: str) -> bool:
        try:
            if checkpoint_path in self.model_cache:
                self.model, self.config = self.model_cache[checkpoint_path]
                return True

            ckpt = torch.load(checkpoint_path, map_location="cpu")

            # Accept multiple formats
            if isinstance(ckpt, dict) and "state_dict" in ckpt and "config" in ckpt:
                state_dict = ckpt["state_dict"]
                self.config = ckpt["config"]
            elif isinstance(ckpt, dict) and "state_dict" in ckpt:
                state_dict = ckpt["state_dict"]
                # Fallback config (sane defaults)
                self.config = {
                    "in_dim": 512,
                    "hidden": 256,
                    "out_dim": 3,
                    "rel_names": [
                        "involves_file","triggered_by_process","runs_on_host",
                        "executed_by_user","has_hash","enriched_by_threat_intel",
                        "detected_by_engine","mitigated_by_action"
                    ],
                    "dropout": 0.1
                }
            elif isinstance(ckpt, dict):
                # Could be a raw state dict
                state_dict = ckpt
                self.config = {
                    "in_dim": 512,
                    "hidden": 256,
                    "out_dim": 3,
                    "rel_names": [
                        "involves_file","triggered_by_process","runs_on_host",
                        "executed_by_user","has_hash","enriched_by_threat_intel",
                        "detected_by_engine","mitigated_by_action"
                    ],
                    "dropout": 0.1
                }
            else:
                raise RuntimeError("Unsupported checkpoint format")

            # Build model per config
            self.model = DynamicRGCN(self.config)

            # Load weights leniently; log issues
            missing, unexpected = self.model.load_state_dict(state_dict, strict=False)
            if missing or unexpected:
                print(f"[GNN] load_state_dict strict=False — missing: {len(missing)}, unexpected: {len(unexpected)}")
                if missing:   print("  MISSING:", missing[:20], "…")
                if unexpected:print("  UNEXPECTED:", unexpected[:20], "…")

            self.model.eval()
            self.model_cache[checkpoint_path] = (self.model, self.config)
            print(f"[GNN] Loaded model from {checkpoint_path} with base relationships: {self.config.get('rel_names')}")
            return True

        except Exception as e:
            print(f"[GNN] Failed to load model from {checkpoint_path}: {e}")
            return False

    def predict(self, alert_data: Dict[str, Any], 
                checkpoint_path: str = None) -> Dict[str, Any]:
        """Make prediction for alert data"""
        
        if checkpoint_path and not self.load_model(checkpoint_path):
            return self._error_response("Model loading failed")
        
        if not self.model:
            return self._error_response("No model loaded")
        
        # Extract alert ID
        alert_id = self._extract_alert_id(alert_data)
        if not alert_id:
            return self._error_response("Could not extract alert ID")
        
        start_time = datetime.now()
        
        # Try ego graph mode first
        subgraph = self.relationship_discovery.discover_alert_subgraph(alert_id, max_hops=3)
        
        if subgraph and self._has_meaningful_relationships(subgraph):
            # Ego graph mode
            result = self._predict_ego_mode(subgraph, alert_id)
            result["mode"] = "ego_dynamic"
            result["subgraph_stats"] = {
                "num_nodes": subgraph.N,
                "num_rel_types": len(subgraph.discovered_rel_types),
                "discovered_relationships": subgraph.discovered_rel_types
            }
        else:
            # Selfie mode fallback
            result = self._predict_selfie_mode(alert_data, alert_id)
            result["mode"] = "selfie"
            result["subgraph_stats"] = {"reason": "No meaningful relationships found"}
        
        # Add timing and metadata
        prediction_time = (datetime.now() - start_time).total_seconds() * 1000
        result["metadata"] = {
            "prediction_time_ms": int(prediction_time),
            "model_config": {k: v for k, v in self.config.items() if k != "state_dict"},
            "timestamp": datetime.now().isoformat()
        }
        
        return result
    
    def _predict_ego_mode(self, subgraph: DynamicSubgraph, 
                         alert_id: str) -> Dict[str, Any]:
        """Predict using ego graph mode"""
        
        try:
            with torch.no_grad():
                logits, rel_mapping = self.model(subgraph)
                target_logits = logits[subgraph.target_idx]
                
                # Convert to probabilities
                probs = torch.softmax(target_logits, dim=0).numpy()
                
                # Get prediction
                predicted_idx = int(np.argmax(probs))
                predicted_label = self.labels[predicted_idx]
                confidence = float(probs[predicted_idx])
                
                return {
                    "alert_id": alert_id,
                    "verdict": predicted_label,
                    "confidence": round(confidence * 100, 2),
                    "probabilities": {
                        self.labels[i]: round(float(probs[i]), 4) 
                        for i in range(len(self.labels))
                    },
                    "relationship_mapping": {
                        "coverage_score": round(rel_mapping.coverage_score, 3),
                        "mapped_relationships": rel_mapping.discovered_to_model,
                        "unmapped_relationships": rel_mapping.unmapped_discovered
                    },
                    "success": True
                }
                
        except Exception as e:
            return self._error_response(f"Ego mode prediction failed: {str(e)}")
    
    def _predict_selfie_mode(self, alert_data: Dict[str, Any], 
                            alert_id: str) -> Dict[str, Any]:
        """Predict using selfie mode (single node)"""
        
        try:
            # Create single-node features
            flattened_data = self._flatten_alert_data(alert_data)
            features = self.feature_encoder.encode_node(["Alert"], flattened_data)
            features_tensor = torch.tensor([features], dtype=torch.float32)
            
            # Create empty edges
            empty_edges = {}
            for rel_type in self.config["rel_names"]:
                empty_edges[rel_type] = (
                    torch.empty(0, dtype=torch.long),
                    torch.empty(0, dtype=torch.long)
                )
            
            # Create minimal subgraph
            selfie_subgraph = DynamicSubgraph(
                N=1, F=features_tensor.size(1),
                features=features_tensor,
                edges_by_rel=empty_edges,
                discovered_rel_types=[],
                target_idx=0,
                alert_id=alert_id,
                metadata={"mode": "selfie"}
            )
            
            with torch.no_grad():
                logits, _ = self.model(selfie_subgraph)
                target_logits = logits[0]
                
                # Convert to probabilities  
                probs = torch.softmax(target_logits, dim=0).numpy()
                
                # Get prediction
                predicted_idx = int(np.argmax(probs))
                predicted_label = self.labels[predicted_idx]
                confidence = float(probs[predicted_idx])
                
                return {
                    "alert_id": alert_id,
                    "verdict": predicted_label,
                    "confidence": round(confidence * 100, 2),
                    "probabilities": {
                        self.labels[i]: round(float(probs[i]), 4) 
                        for i in range(len(self.labels))
                    },
                    "success": True
                }
                
        except Exception as e:
            return self._error_response(f"Selfie mode prediction failed: {str(e)}")
    
    def _has_meaningful_relationships(self, subgraph: DynamicSubgraph) -> bool:
        """Check if subgraph has meaningful relationships for ego mode"""
        
        if not subgraph.discovered_rel_types:
            return False
        
        # Check if any relationships have actual edges
        total_edges = 0
        for rel_type, (src, dst) in subgraph.edges_by_rel.items():
            total_edges += src.numel()
        
        return total_edges > 0 and subgraph.N > 1
    
    def _extract_alert_id(self, alert_data: Dict[str, Any]) -> Optional[str]:
        """Extract alert ID from alert data using multiple strategies"""
        
        # Direct lookups
        direct_keys = ["alert_id", "alertId", "threat_id", "threatId", "id", "uid"]
        for key in direct_keys:
            if key in alert_data and alert_data[key]:
                return str(alert_data[key])
        
        # Nested lookups
        nested_paths = [
            ["alert", "id"],
            ["threat", "id"], 
            ["alert", "alert_id"],
            ["threat", "threat_id"]
        ]
        
        for path in nested_paths:
            try:
                value = alert_data
                for key in path:
                    value = value[key]
                if value:
                    return str(value)
            except (KeyError, TypeError):
                continue
        
        # Flatten and search
        flattened = self._flatten_alert_data(alert_data)
        for key, value in flattened.items():
            if any(id_key in key.lower() for id_key in ["id", "uid"]) and value:
                return str(value)
        
        return None
    
    def _flatten_alert_data(self, data: Any, parent_key: str = "") -> Dict[str, Any]:
        """Flatten nested alert data"""
        
        flat_dict = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                new_key = f"{parent_key}.{key}" if parent_key else key
                flat_dict.update(self._flatten_alert_data(value, new_key))
        elif isinstance(data, list):
            for i, item in enumerate(data[:10]):  # Limit list processing
                new_key = f"{parent_key}[{i}]"
                flat_dict.update(self._flatten_alert_data(item, new_key))
        else:
            flat_dict[parent_key] = data
        
        return flat_dict
    
    def _error_response(self, error_msg: str) -> Dict[str, Any]:
        """Generate standardized error response"""
        return {
            "success": False,
            "error": error_msg,
            "verdict": "Error",
            "confidence": 0,
            "probabilities": {label: 0.0 for label in self.labels},
            "timestamp": datetime.now().isoformat()
        }

# =============================================================================
# FASTAPI INTEGRATION
# =============================================================================

# Global GNN predictor instance
dynamic_gnn_predictor = None

def initialize_dynamic_gnn(neo4j_driver, database: str = "neo4j") -> bool:
    """Initialize the global GNN predictor"""
    global dynamic_gnn_predictor
    
    try:
        dynamic_gnn_predictor = DynamicGNNPredictor(neo4j_driver, database)
        print("Dynamic GNN Predictor initialized successfully")
        return True
    except Exception as e:
        print(f"Failed to initialize Dynamic GNN Predictor: {e}")
        return False

# =============================================================================
# FASTAPI ENDPOINTS
# =============================================================================

def add_dynamic_gnn_routes(app: FastAPI):
    """Add dynamic GNN routes to FastAPI app"""
    
    @app.post("/gnn/predict_dynamic")
    async def predict_dynamic(
        file: UploadFile = File(None),
        payload: dict = Body(None),
        checkpoint_path: str = Body(None)
    ):
        """
        Dynamic GNN prediction with automatic relationship discovery
        """
        global dynamic_gnn_predictor
        
        try:
            if not dynamic_gnn_predictor:
                raise HTTPException(
                    status_code=503, 
                    detail="Dynamic GNN predictor not initialized"
                )
            
            # Parse input data
            alert_data = None
            if file is not None:
                if not file.filename.endswith(".json"):
                    raise HTTPException(status_code=400, detail="Only JSON files supported")
                
                content = await file.read()
                alert_data = json.loads(content.decode("utf-8"))
                
            elif payload is not None:
                alert_data = payload
                
            else:
                raise HTTPException(
                    status_code=400, 
                    detail="Provide either JSON file or JSON payload"
                )
            
            # Use default checkpoint if not provided
            if not checkpoint_path:
                checkpoint_path = os.getenv("RGCN_CKPT", "models/rgcn_nodgl.pt")
            
            # Make prediction
            result = dynamic_gnn_predictor.predict(alert_data, checkpoint_path)
            
            return JSONResponse(content=result)
            
        except HTTPException:
            raise
        except Exception as e:
            print(f"Dynamic GNN prediction error: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            raise HTTPException(
                status_code=500, 
                detail=f"Dynamic GNN prediction failed: {str(e)}"
            )
    
    @app.post("/gnn/analyze_relationships")
    async def analyze_relationships(alert_id: str):
        """
        Analyze relationships discovered for an alert
        """
        global dynamic_gnn_predictor
        
        try:
            if not dynamic_gnn_predictor:
                raise HTTPException(
                    status_code=503,
                    detail="Dynamic GNN predictor not initialized"
                )
            
            # Discover subgraph
            subgraph = dynamic_gnn_predictor.relationship_discovery.discover_alert_subgraph(
                alert_id, max_hops=3
            )
            
            if not subgraph:
                return JSONResponse(content={
                    "alert_id": alert_id,
                    "found": False,
                    "message": "No subgraph found for alert"
                })
            
            # Analyze relationships
            mapper = RelationshipMapper()
            
            # Mock model relationships for analysis
            mock_model_rels = [
                "involves_file", "triggered_by_process", "runs_on_host",
                "executed_by_user", "has_hash", "enriched_by_threat_intel",
                "detected_by_engine", "mitigated_by_action"
            ]
            
            rel_mapping = mapper.create_mapping(
                subgraph.discovered_rel_types, 
                mock_model_rels
            )
            
            # Build relationship analysis
            relationship_analysis = {}
            for rel_type in subgraph.discovered_rel_types:
                src_indices, dst_indices = subgraph.edges_by_rel[rel_type]
                relationship_analysis[rel_type] = {
                    "edge_count": src_indices.numel(),
                    "mapped_to": rel_mapping.discovered_to_model.get(rel_type),
                    "is_mapped": rel_type in rel_mapping.discovered_to_model
                }
            
            return JSONResponse(content={
                "alert_id": alert_id,
                "found": True,
                "subgraph_stats": {
                    "num_nodes": subgraph.N,
                    "num_relationships": len(subgraph.discovered_rel_types),
                    "total_edges": sum(
                        src.numel() for src, _ in subgraph.edges_by_rel.values()
                    )
                },
                "discovered_relationships": subgraph.discovered_rel_types,
                "relationship_analysis": relationship_analysis,
                "mapping_stats": {
                    "coverage_score": rel_mapping.coverage_score,
                    "mapped_count": len(rel_mapping.discovered_to_model),
                    "unmapped_count": len(rel_mapping.unmapped_discovered),
                    "unmapped_relationships": rel_mapping.unmapped_discovered
                },
                "subgraph_metadata": subgraph.metadata
            })
            
        except Exception as e:
            print(f"Relationship analysis error: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Relationship analysis failed: {str(e)}"
            )
    
    @app.get("/gnn/model_info")
    async def get_model_info():
        """
        Get information about the loaded GNN model
        """
        global dynamic_gnn_predictor
        
        try:
            if not dynamic_gnn_predictor:
                return JSONResponse(content={
                    "initialized": False,
                    "message": "Dynamic GNN predictor not initialized"
                })
            
            model_info = {
                "initialized": True,
                "has_neo4j": dynamic_gnn_predictor.neo4j_driver is not None,
                "database": dynamic_gnn_predictor.database,
                "cache_size": len(dynamic_gnn_predictor.model_cache),
                "supported_labels": dynamic_gnn_predictor.labels
            }
            
            if dynamic_gnn_predictor.config:
                model_info["current_model"] = {
                    "in_dim": dynamic_gnn_predictor.config["in_dim"],
                    "hidden_dim": dynamic_gnn_predictor.config["hidden"],
                    "out_dim": dynamic_gnn_predictor.config["out_dim"],
                    "base_relationships": dynamic_gnn_predictor.config["rel_names"],
                    "dropout": dynamic_gnn_predictor.config.get("dropout", 0.1)
                }
            else:
                model_info["current_model"] = None
            
            return JSONResponse(content=model_info)
            
        except Exception as e:
            print(f"Model info error: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to get model info: {str(e)}"
            )
    
    @app.post("/gnn/test_subgraph")
    async def test_subgraph_discovery(
        alert_id: str, 
        max_hops: int = Body(3)
    ):
        """
        Test subgraph discovery for debugging
        """
        global dynamic_gnn_predictor
        
        try:
            if not dynamic_gnn_predictor:
                raise HTTPException(
                    status_code=503,
                    detail="Dynamic GNN predictor not initialized"
                )
            
            # Test subgraph discovery
            start_time = datetime.now()
            subgraph = dynamic_gnn_predictor.relationship_discovery.discover_alert_subgraph(
                alert_id, max_hops
            )
            discovery_time = (datetime.now() - start_time).total_seconds() * 1000
            
            if not subgraph:
                return JSONResponse(content={
                    "alert_id": alert_id,
                    "success": False,
                    "message": "No subgraph discovered",
                    "discovery_time_ms": int(discovery_time)
                })
            
            # Test relationship mapping
            mapper = RelationshipMapper()
            mock_model_rels = ["involves_file", "triggered_by_process", "runs_on_host"]
            
            rel_mapping = mapper.create_mapping(
                subgraph.discovered_rel_types, 
                mock_model_rels
            )
            
            # Test feature encoding
            sample_features = subgraph.features[subgraph.target_idx].tolist()
            
            return JSONResponse(content={
                "alert_id": alert_id,
                "success": True,
                "discovery_time_ms": int(discovery_time),
                "subgraph": {
                    "num_nodes": subgraph.N,
                    "feature_dim": subgraph.F,
                    "target_index": subgraph.target_idx,
                    "discovered_relationships": subgraph.discovered_rel_types,
                    "relationship_edge_counts": {
                        rel: src.numel() for rel, (src, _) in subgraph.edges_by_rel.items()
                    }
                },
                "relationship_mapping": {
                    "coverage_score": rel_mapping.coverage_score,
                    "mappings": rel_mapping.discovered_to_model,
                    "unmapped": rel_mapping.unmapped_discovered
                },
                "sample_features": {
                    "target_node_features": sample_features[:10],  # First 10 features
                    "feature_norm": float(torch.norm(subgraph.features[subgraph.target_idx]).item())
                },
                "metadata": subgraph.metadata
            })
            
        except Exception as e:
            print(f"Subgraph test error: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Subgraph test failed: {str(e)}"
            )



from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
from langchain_openai import ChatOpenAI
from langchain_neo4j import GraphCypherQAChain, Neo4jGraph
from langchain.tools import Tool
from langchain.agents import initialize_agent, AgentType
from langchain.memory import ConversationBufferMemory
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
from dataclasses import dataclass
import hashlib

# Import base AgenticGraphRAG class (assuming it's imported from the original module)
# from your_base_module import AgenticGraphRAG, InvestigationTask

@dataclass
class FirewallInvestigationTask:
    """Firewall-specific task wrapper for parallel investigation steps"""
    task_id: str
    task_type: str
    description: str
    priority: int
    dependencies: List[str]
    completed: bool = False
    result: Optional[str] = None
    error: Optional[str] = None
    firewall_context: Optional[Dict[str, Any]] = None


def _enhance_firewall_agentic_with_context(self, alert_id: str, context_data: dict) -> dict:
    """Enhance firewall agentic investigation with context data using agent tools"""
    
    try:
        print(f"Starting firewall agentic context enhancement for {alert_id}")
        
        # Extract firewall context for agentic analysis
        disposition = context_data.get('disposition', '').lower()
        action = context_data.get('unmapped_action', '').lower()
        src_endpoint = context_data.get('src_endpoint', {})
        dst_endpoint = context_data.get('dst_endpoint', {})
        network_info = context_data.get('network', {})
        file_info = context_data.get('file', {})
        http_info = context_data.get('http', {})
        rule_name = context_data.get('rule', {}).get('name', '').lower()
        indicator_name = context_data.get('unmapped_indicator_name', '').lower()
        
        # Use agentic tools for enhanced analysis
        enhanced_analysis_results = []
        
        # Use firewall network security analysis tool
        if src_endpoint.get('ip') and dst_endpoint.get('ip'):
            network_analysis = self._firewall_network_security_analysis_tool(
                f"Analyze communication security between {src_endpoint.get('ip')} and {dst_endpoint.get('ip')}"
            )
            enhanced_analysis_results.append(("Network Security", network_analysis))
        
        # Use threat intelligence correlation tool
        if 'ioc' in indicator_name or 'threat' in rule_name:
            threat_intel_analysis = self._firewall_threat_intelligence_tool(
                f"Correlate threat intelligence for rule {rule_name} and indicator {indicator_name}"
            )
            enhanced_analysis_results.append(("Threat Intelligence", threat_intel_analysis))
        
        # Use malicious download analysis tool
        if file_info.get('name'):
            download_analysis = self._firewall_malicious_download_tool(
                f"Analyze file download {file_info.get('name')} for malicious characteristics"
            )
            enhanced_analysis_results.append(("Malicious Download", download_analysis))
        
        # Use endpoint behavior analysis tool
        user_agent = http_info.get('user_agent', '').lower()
        if any(tool in user_agent for tool in ['curl', 'wget', 'powershell', 'bot']):
            behavior_analysis = self._firewall_endpoint_behavior_tool(
                f"Analyze automated behavior patterns from user agent {user_agent}"
            )
            enhanced_analysis_results.append(("Endpoint Behavior", behavior_analysis))
        
        # Use policy enforcement analysis tool
        if action in ['prevent', 'block', 'deny']:
            policy_analysis = self._firewall_policy_enforcement_tool(
                f"Analyze policy enforcement effectiveness for {action} action"
            )
            enhanced_analysis_results.append(("Policy Enforcement", policy_analysis))
        
        # Calculate agentic enhanced threat score
        agentic_threat_score = 0
        agentic_context_factors = []
        
        # Base firewall indicators
        if disposition == 'malicious':
            agentic_threat_score += 35
            agentic_context_factors.append("Firewall marked as malicious")
        
        if action in ['prevent', 'block', 'deny']:
            agentic_threat_score += 30
            agentic_context_factors.append(f"Traffic {action}ed by firewall")
        
        # Agentic tool results enhancement
        for tool_name, analysis_result in enhanced_analysis_results:
            if analysis_result and not self._is_empty_result(analysis_result):
                agentic_threat_score += 15
                agentic_context_factors.append(f"{tool_name} agentic analysis found threats")
        
        # Network pattern analysis
        bytes_in = network_info.get('bytes_in', 0)
        if bytes_in > 20000:
            agentic_threat_score += 20
            agentic_context_factors.append("Large data transfer detected by agentic analysis")
        
        # File type agentic analysis
        if file_info.get('type') and any(t in file_info.get('type', '').lower() for t in ['executable', 'archive', 'script']):
            agentic_threat_score += 25
            agentic_context_factors.append("Suspicious file type identified by agentic tools")
        
        # Threat intelligence agentic correlation
        if 'ioc' in indicator_name:
            agentic_threat_score += 30
            agentic_context_factors.append("IOC correlation confirmed by agentic threat intelligence")
        
        # Determine agentic enhanced verdict
        if agentic_threat_score >= 80:
            enhanced_verdict = "TRUE_POSITIVE"
            confidence = min(92 + (agentic_threat_score - 80), 98)
        elif agentic_threat_score <= 30:
            enhanced_verdict = "FALSE_POSITIVE"
            confidence = min(80 + (30 - agentic_threat_score), 88)
        else:
            enhanced_verdict = "ESCALATE"
            confidence = 60 + agentic_threat_score
        
        return {
            'enhanced_verdict': enhanced_verdict,
            'confidence': confidence,
            'context': '; '.join(agentic_context_factors),
            'threat_score': agentic_threat_score,
            'agentic_analysis_results': enhanced_analysis_results,
            'analysis_type': 'firewall_agentic_context_enhancement',
            'tools_used': len(enhanced_analysis_results)
        }
        
    except Exception as e:
        print(f"Error in firewall agentic context enhancement: {e}")
        return {
            'enhanced_verdict': "ESCALATE",
            'confidence': 50,
            'context': f"Agentic context enhancement error: {str(e)}",
            'threat_score': 0,
            'analysis_type': 'firewall_agentic_enhancement_error'
        }

# Add the method to the FirewallAgenticGraphRAG class

class FirewallAgenticGraphRAG:
    """Firewall-specific Agentic Graph RAG system with network security focus"""
    
    def __init__(self, neo4j_url: str, neo4j_username: str, neo4j_password: str, openai_api_key: str):
        # Initialize core components
        self.llm = ChatOpenAI(
            temperature=0,
            api_key=openai_api_key,
            model="gpt-4o-mini"
        )
        
        self.graph = Neo4jGraph(
            url=neo4j_url,
            username=neo4j_username,
            password=neo4j_password
        )
        
        self.chain = GraphCypherQAChain.from_llm(
            llm=self.llm,
            graph=self.graph,
            allow_dangerous_requests=True,
            verbose=True
        )
        
        # Initialize memory for conversation context
        self.memory = ConversationBufferMemory(
            memory_key="chat_history",
            return_messages=True
        )
        
        # Firewall-specific schema discovery
        self.firewall_schema = None
        self.firewall_node_types = []
        self.firewall_relationship_types = []
        self.firewall_property_patterns = {}
        
        # Define firewall-specific agent tools
        self.firewall_tools = self._create_firewall_agent_tools()
        
        # Initialize the firewall agent
        self.firewall_agent = initialize_agent(
            tools=self.firewall_tools,
            llm=self.llm,
            agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
            memory=self.memory,
            verbose=True,
            max_iterations=15,
            early_stopping_method="generate"
        )
        
        # Firewall investigation context
        self.firewall_investigation_context = {}
        self.firewall_qa_history = []
        
        # Parallel processing settings
        self.max_retries = 2
        self.retry_delay = 1
        self.max_parallel_requests = 3
        
        # Parallel processing components
        self.executor = ThreadPoolExecutor(max_workers=self.max_parallel_requests)
        self.firewall_task_queue = []
        self.firewall_completed_tasks = {}
        self.task_lock = threading.Lock()
        self.firewall_question_cache = set()
        
        # Initialize firewall schema discovery
        self._discover_firewall_schema()

    def _discover_firewall_schema(self):
        """Discover firewall-specific graph schema"""
        try:
            print("Discovering firewall graph schema...")
            
            # Get firewall node labels
            node_query = "CALL db.labels() YIELD label RETURN label"
            node_result = self.graph.query(node_query)
            self.firewall_node_types = [row['label'] for row in node_result]
            
            # Get firewall relationship types
            rel_query = "CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType"
            rel_result = self.graph.query(rel_query)
            self.firewall_relationship_types = [row['relationshipType'] for row in rel_result]
            
            # Firewall-specific property patterns
            firewall_nodes = ['FirewallAlert', 'SourceEndpoint', 'DestinationEndpoint', 'NetworkSession', 
                            'File', 'URL', 'HTTPTransaction', 'Policy', 'ThreatIntelligence']
            
            for node_type in firewall_nodes:
                if node_type in self.firewall_node_types:
                    prop_query = f"""
                    MATCH (n:{node_type})
                    WITH keys(n) AS props
                    UNWIND props AS prop
                    RETURN DISTINCT prop
                    LIMIT 20
                    """
                    try:
                        prop_result = self.graph.query(prop_query)
                        self.firewall_property_patterns[node_type] = [row['prop'] for row in prop_result]
                    except:
                        self.firewall_property_patterns[node_type] = []
            
            print(f"Firewall schema discovered: {len(self.firewall_node_types)} node types, {len(self.firewall_relationship_types)} relationship types")
            
        except Exception as e:
            print(f"Error discovering firewall schema: {e}")
            # Firewall fallback defaults
            self.firewall_node_types = ["FirewallAlert", "SourceEndpoint", "DestinationEndpoint", "NetworkSession", "File"]
            self.firewall_relationship_types = ["ALERT_ORIGINATED_FROM", "ALERT_TARGETED", "ALERT_INVOLVES_SESSION"]
            self.firewall_property_patterns = {}

    def _generate_firewall_question_hash(self, question: str, alert_id: str) -> str:
        """Generate unique hash for firewall questions"""
        normalized_question = question.lower().strip().replace(" ", "")
        content = f"fw_{normalized_question}_{alert_id}"
        return hashlib.md5(content.encode()).hexdigest()[:8]
    
    def _is_firewall_question_duplicate(self, question: str, alert_id: str) -> bool:
        """Check if firewall question has been asked"""
        question_hash = self._generate_firewall_question_hash(question, alert_id)
        return question_hash in self.firewall_question_cache
    
    def _mark_firewall_question_asked(self, question: str, alert_id: str):
        """Mark firewall question as asked"""
        question_hash = self._generate_firewall_question_hash(question, alert_id)
        self.firewall_question_cache.add(question_hash)

    def _generate_firewall_parallel_investigation_tasks(self, alert_id: str) -> List[FirewallInvestigationTask]:
        """Generate firewall-specific parallel investigation tasks"""
        
        tasks = []
        
        # Priority 1: Network security analysis (highest priority)
        tasks.append(FirewallInvestigationTask(
            task_id="network_security_analysis",
            task_type="network_security",
            description="Network communication security and threat analysis",
            priority=1,
            dependencies=[],
            firewall_context={"focus": "network_communications"}
        ))
        
        # Priority 2: Core firewall data gathering (parallel)
        core_tasks = [
            ("traffic_flow_analysis", "traffic_flow", "Network traffic patterns and flow analysis"),
            ("policy_enforcement_analysis", "policy_enforcement", "Firewall policy and rule enforcement analysis"),
            ("threat_intel_correlation", "threat_intel", "Threat intelligence and IOC correlation analysis"),
            ("malicious_download_analysis", "malicious_download", "File download and malware transfer analysis")
        ]
        
        for task_id, task_type, description in core_tasks:
            tasks.append(FirewallInvestigationTask(
                task_id=task_id,
                task_type=task_type,
                description=description,
                priority=2,
                dependencies=[],
                firewall_context={"analysis_type": task_type}
            ))
        
        # Priority 3: Advanced firewall analysis
        advanced_tasks = [
            ("endpoint_communication_behavior", "endpoint_behavior", "Endpoint communication behavior analysis", ["traffic_flow_analysis"]),
            ("network_attack_vector_analysis", "attack_vector", "Network attack vector and technique analysis", ["threat_intel_correlation"]),
            ("network_forensics_investigation", "network_forensics", "Network forensics and evidence investigation", ["malicious_download_analysis"])
        ]
        
        for task_id, task_type, description, deps in advanced_tasks:
            tasks.append(FirewallInvestigationTask(
                task_id=task_id,
                task_type=task_type,
                description=description,
                priority=3,
                dependencies=deps,
                firewall_context={"analysis_level": "advanced"}
            ))
        
        # Priority 4: Firewall evidence synthesis
        tasks.append(FirewallInvestigationTask(
            task_id="firewall_evidence_synthesis",
            task_type="firewall_synthesis",
            description="Comprehensive firewall evidence synthesis and verdict determination",
            priority=4,
            dependencies=["network_security_analysis", "traffic_flow_analysis", "policy_enforcement_analysis", "threat_intel_correlation"],
            firewall_context={"synthesis_type": "comprehensive"}
        ))
        
        return tasks

    def _create_firewall_agent_tools(self) -> List[Tool]:
        """Create firewall-specific dynamic tools"""
        
        return [
            Tool(
                name="firewall_network_security_analysis",
                description="Analyze network security posture and communication threats in firewall data",
                func=self._firewall_network_security_analysis_tool
            ),
            Tool(
                name="firewall_traffic_flow_query",
                description="Query network traffic flows, protocols, and communication patterns",
                func=self._firewall_traffic_flow_query_tool
            ),
            Tool(
                name="firewall_policy_enforcement_analysis",
                description="Analyze firewall policy enforcement, rule violations, and blocking actions",
                func=self._firewall_policy_enforcement_tool
            ),
            Tool(
                name="firewall_threat_intelligence_correlation",
                description="Correlate threat intelligence feeds, IOCs, and reputation data",
                func=self._firewall_threat_intelligence_tool
            ),
            Tool(
                name="firewall_malicious_download_analysis",
                description="Analyze malicious file downloads, URLs, and web-based threats",
                func=self._firewall_malicious_download_tool
            ),
            Tool(
                name="firewall_endpoint_behavior_analysis",
                description="Analyze endpoint communication behavior and automation patterns",
                func=self._firewall_endpoint_behavior_tool
            ),
            Tool(
                name="firewall_attack_vector_analysis",
                description="Identify network attack vectors, techniques, and threat patterns",
                func=self._firewall_attack_vector_tool
            ),
            Tool(
                name="firewall_forensics_investigation",
                description="Investigate network forensics evidence and communication artifacts",
                func=self._firewall_forensics_tool
            ),
            Tool(
                name="firewall_evidence_synthesis",
                description="Synthesize all firewall evidence for final security verdict",
                func=self._firewall_evidence_synthesis_tool
            )
        ]

    def _firewall_network_security_analysis_tool(self, alert_context: str) -> str:
        """Analyze network security aspects of firewall alert"""
        
        alert_id = self.firewall_investigation_context.get("alert_id", alert_context)
        
        security_analysis_queries = [
            f"What network security violations are present in firewall alert {alert_id}?",
            f"What communication security threats are detected for alert {alert_id}?",
            f"What network protocols and security issues exist in alert {alert_id}?"
        ]
        
        try:
            # Execute security analysis queries
            results = []
            for query in security_analysis_queries:
                if not self._is_firewall_question_duplicate(query, alert_id):
                    self._mark_firewall_question_asked(query, alert_id)
                    result = self._execute_firewall_cypher_query(query, alert_id)
                    if result and not self._is_empty_result(result):
                        results.append(result)
            
            combined_result = "\n".join(results) if results else "No network security violations detected"
            
            # Enhance with security analysis
            security_prompt = f"""
            Analyze network security threats from firewall data:
            
            Security Data: {combined_result}
            Alert ID: {alert_id}
            Available Schema: {self.firewall_node_types}
            
            Focus on:
            - Network communication security violations
            - Protocol abuse and anomalies  
            - Traffic patterns indicating threats
            - Policy enforcement effectiveness
            
            Provide 2-3 lines highlighting critical network security findings.
            """
            
            analysis = self.llm.invoke(security_prompt)
            result = analysis.content.strip()
            
            # Store in firewall Q&A history
            self.firewall_qa_history.append({
                "question": "What network security analysis reveals about this alert?",
                "answer": result,
                "timestamp": datetime.now().isoformat(),
                "analysis_type": "network_security"
            })
            
            return result
            
        except Exception as e:
            return f"Error in firewall network security analysis: {str(e)}"

    def _firewall_traffic_flow_query_tool(self, query: str) -> str:
        """Query firewall traffic flow and communication patterns"""
        
        alert_id = self.firewall_investigation_context.get("alert_id", "")
        
        # Check for duplicate
        if self._is_firewall_question_duplicate(query, alert_id):
            return "Traffic flow query already processed."
        
        self._mark_firewall_question_asked(query, alert_id)
        
        try:
            # Generate firewall traffic flow query
            traffic_query = f"Analyze network traffic flows and communication patterns for firewall alert {alert_id}: {query}"
            result = self._execute_firewall_cypher_query(traffic_query, alert_id)
            
            if self._is_empty_result(result):
                # Fallback query
                fallback_query = f"Find network session and traffic information for alert {alert_id}"
                result = self.chain.run(fallback_query)
            
            # Make concise
            concise_result = self._make_firewall_concise_response(
                question=query,
                result=result,
                focus="traffic flows, protocols, and communication patterns"
            )
            
            return concise_result
            
        except Exception as e:
            return f"Error in firewall traffic flow query: {str(e)}"

    def _firewall_policy_enforcement_tool(self, context: str) -> str:
        """Analyze firewall policy enforcement and rule violations"""
        
        alert_id = self.firewall_investigation_context.get("alert_id", "")
        
        policy_queries = [
            f"What firewall policies were triggered for alert {alert_id}?",
            f"What enforcement actions were taken for alert {alert_id}?",
            f"What rule violations occurred in alert {alert_id}?"
        ]
        
        try:
            results = []
            for query in policy_queries:
                if not self._is_firewall_question_duplicate(query, alert_id):
                    self._mark_firewall_question_asked(query, alert_id)
                    result = self._execute_firewall_cypher_query(query, alert_id)
                    if result and not self._is_empty_result(result):
                        results.append(result)
            
            combined_result = "\n".join(results) if results else "No policy enforcement data found"
            
            # Policy analysis enhancement
            policy_prompt = f"""
            Analyze firewall policy enforcement from investigation data:
            
            Policy Data: {combined_result}
            Investigation Context: {self.firewall_qa_history[-2:]}
            
            Focus on:
            - Policy rule effectiveness
            - Enforcement action appropriateness
            - Security posture gaps
            - Threat prevention success
            
            Provide 2-3 lines on policy enforcement effectiveness.
            """
            
            analysis = self.llm.invoke(policy_prompt)
            result = analysis.content.strip()
            
            self.firewall_qa_history.append({
                "question": "How effective was firewall policy enforcement?",
                "answer": result,
                "timestamp": datetime.now().isoformat(),
                "analysis_type": "policy_enforcement"
            })
            
            return result
            
        except Exception as e:
            return f"Error in firewall policy analysis: {str(e)}"

    def _firewall_threat_intelligence_tool(self, context: str) -> str:
        """Correlate threat intelligence and IOC data"""
        
        alert_id = self.firewall_investigation_context.get("alert_id", "")
        
        threat_intel_queries = [
            f"What threat intelligence indicators match alert {alert_id}?",
            f"What IOC feeds triggered for alert {alert_id}?",
            f"What reputation data exists for entities in alert {alert_id}?"
        ]
        
        try:
            results = []
            for query in threat_intel_queries:
                if not self._is_firewall_question_duplicate(query, alert_id):
                    self._mark_firewall_question_asked(query, alert_id)
                    result = self._execute_firewall_cypher_query(query, alert_id)
                    if result and not self._is_empty_result(result):
                        results.append(result)
            
            combined_result = "\n".join(results) if results else "No threat intelligence matches found"
            
            # Threat intelligence analysis
            ti_prompt = f"""
            Analyze threat intelligence correlation for firewall alert:
            
            Threat Intelligence Data: {combined_result}
            Alert Context: {self.firewall_investigation_context}
            
            Focus on:
            - IOC feed matches and confidence
            - Reputation scores and sources
            - Threat actor attribution
            - Attack campaign correlation
            
            Provide 2-3 lines on threat intelligence significance.
            """
            
            analysis = self.llm.invoke(ti_prompt)
            result = analysis.content.strip()
            
            self.firewall_qa_history.append({
                "question": "What threat intelligence correlation reveals?",
                "answer": result,
                "timestamp": datetime.now().isoformat(),
                "analysis_type": "threat_intelligence"
            })
            
            return result
            
        except Exception as e:
            return f"Error in threat intelligence correlation: {str(e)}"

    def _firewall_malicious_download_tool(self, context: str) -> str:
        """Analyze malicious file downloads and web-based threats"""
        
        alert_id = self.firewall_investigation_context.get("alert_id", "")
        
        download_queries = [
            f"What files were downloaded in alert {alert_id}?",
            f"What URLs and domains are involved in alert {alert_id}?",
            f"What HTTP transactions show malicious activity in alert {alert_id}?"
        ]
        
        try:
            results = []
            for query in download_queries:
                if not self._is_firewall_question_duplicate(query, alert_id):
                    self._mark_firewall_question_asked(query, alert_id)
                    result = self._execute_firewall_cypher_query(query, alert_id)
                    if result and not self._is_empty_result(result):
                        results.append(result)
            
            combined_result = "\n".join(results) if results else "No malicious download activity detected"
            
            # Download analysis enhancement
            download_prompt = f"""
            Analyze malicious download patterns from firewall data:
            
            Download Data: {combined_result}
            Previous Analysis: {self.firewall_qa_history[-2:]}
            
            Focus on:
            - File characteristics and reputation
            - URL and domain reputation
            - Download behavior patterns
            - Web-based attack indicators
            
            Provide 2-3 lines on malicious download assessment.
            """
            
            analysis = self.llm.invoke(download_prompt)
            result = analysis.content.strip()
            
            self.firewall_qa_history.append({
                "question": "What malicious download analysis shows?",
                "answer": result,
                "timestamp": datetime.now().isoformat(),
                "analysis_type": "malicious_download"
            })
            
            return result
            
        except Exception as e:
            return f"Error in malicious download analysis: {str(e)}"

    def _firewall_endpoint_behavior_tool(self, context: str) -> str:
        """Analyze endpoint communication behavior patterns"""
        
        alert_id = self.firewall_investigation_context.get("alert_id", "")
        
        behavior_queries = [
            f"What endpoint communication patterns exist in alert {alert_id}?",
            f"What automation indicators are present in alert {alert_id}?",
            f"What user agent and client behavior shows in alert {alert_id}?"
        ]
        
        try:
            results = []
            for query in behavior_queries:
                if not self._is_firewall_question_duplicate(query, alert_id):
                    self._mark_firewall_question_asked(query, alert_id)
                    result = self._execute_firewall_cypher_query(query, alert_id)
                    if result and not self._is_empty_result(result):
                        results.append(result)
            
            combined_result = "\n".join(results) if results else "No distinctive endpoint behavior detected"
            
            # Behavior analysis
            behavior_prompt = f"""
            Analyze endpoint communication behavior from firewall investigation:
            
            Behavior Data: {combined_result}
            Context: {self.firewall_investigation_context}
            
            Focus on:
            - Automated vs manual behavior
            - Communication frequency patterns
            - User agent analysis
            - Behavioral anomalies
            
            Provide 2-3 lines on endpoint behavior assessment.
            """
            
            analysis = self.llm.invoke(behavior_prompt)
            result = analysis.content.strip()
            
            self.firewall_qa_history.append({
                "question": "What endpoint behavior patterns indicate?",
                "answer": result,
                "timestamp": datetime.now().isoformat(),
                "analysis_type": "endpoint_behavior"
            })
            
            return result
            
        except Exception as e:
            return f"Error in endpoint behavior analysis: {str(e)}"

    def _firewall_attack_vector_tool(self, context: str) -> str:
        """Identify network attack vectors and techniques"""
        
        alert_id = self.firewall_investigation_context.get("alert_id", "")
        
        attack_queries = [
            f"What attack vectors are present in alert {alert_id}?",
            f"What network attack techniques are detected in alert {alert_id}?",
            f"What command and control patterns exist in alert {alert_id}?"
        ]
        
        try:
            results = []
            for query in attack_queries:
                if not self._is_firewall_question_duplicate(query, alert_id):
                    self._mark_firewall_question_asked(query, alert_id)
                    result = self._execute_firewall_cypher_query(query, alert_id)
                    if result and not self._is_empty_result(result):
                        results.append(result)
            
            combined_result = "\n".join(results) if results else "No clear attack vectors identified"
            
            # Attack vector analysis
            attack_prompt = f"""
            Analyze network attack vectors from firewall investigation:
            
            Attack Data: {combined_result}
            Investigation Summary: {self.firewall_qa_history[-3:]}
            
            Focus on:
            - Network attack methodologies
            - Command and control indicators
            - Data exfiltration patterns
            - Attack progression stages
            
            Provide 2-3 lines on attack vector assessment.
            """
            
            analysis = self.llm.invoke(attack_prompt)
            result = analysis.content.strip()
            
            self.firewall_qa_history.append({
                "question": "What attack vectors are identified?",
                "answer": result,
                "timestamp": datetime.now().isoformat(),
                "analysis_type": "attack_vector"
            })
            
            return result
            
        except Exception as e:
            return f"Error in attack vector analysis: {str(e)}"

    def _firewall_forensics_tool(self, context: str) -> str:
        """Investigate network forensics evidence"""
        
        alert_id = self.firewall_investigation_context.get("alert_id", "")
        
        forensics_queries = [
            f"What network forensics evidence exists for alert {alert_id}?",
            f"What packet capture data is available for alert {alert_id}?",
            f"What communication timeline emerges from alert {alert_id}?"
        ]
        
        try:
            results = []
            for query in forensics_queries:
                if not self._is_firewall_question_duplicate(query, alert_id):
                    self._mark_firewall_question_asked(query, alert_id)
                    result = self._execute_firewall_cypher_query(query, alert_id)
                    if result and not self._is_empty_result(result):
                        results.append(result)
            
            combined_result = "\n".join(results) if results else "Limited network forensics evidence available"
            
            # Forensics analysis
            forensics_prompt = f"""
            Analyze network forensics evidence from firewall investigation:
            
            Forensics Data: {combined_result}
            Alert Context: {alert_id}
            
            Focus on:
            - Evidence quality and completeness
            - Timeline reconstruction
            - Communication artifacts
            - Investigative value
            
            Provide 2-3 lines on forensics evidence assessment.
            """
            
            analysis = self.llm.invoke(forensics_prompt)
            result = analysis.content.strip()
            
            self.firewall_qa_history.append({
                "question": "What network forensics evidence shows?",
                "answer": result,
                "timestamp": datetime.now().isoformat(),
                "analysis_type": "network_forensics"
            })
            
            return result
            
        except Exception as e:
            return f"Error in network forensics investigation: {str(e)}"

    def _firewall_evidence_synthesis_tool(self, context: str) -> str:
        """Synthesize all firewall evidence for final verdict"""
        
        try:
            synthesis_prompt = f"""
            Based on comprehensive firewall investigation, determine final security verdict:
            
            Complete Investigation Results: {self.firewall_qa_history}
            Alert ID: {self.firewall_investigation_context.get('alert_id')}
            Schema Used: {self.firewall_node_types} nodes, {self.firewall_relationship_types} relationships
            
            Firewall Security Classification:
            TRUE_POSITIVE: Clear malicious network activity, policy violations, confirmed threats
            FALSE_POSITIVE: Legitimate network activity incorrectly flagged by firewall
            ESCALATE: Mixed evidence, requires human SOC analyst review
            
            Consider all firewall evidence:
            - Network security violations and threats
            - Traffic flow anomalies and patterns
            - Policy enforcement effectiveness
            - Threat intelligence correlation
            - Malicious download indicators
            - Endpoint behavior analysis
            - Attack vector identification
            - Network forensics evidence
            
            Provide: CLASSIFICATION, CONFIDENCE (0-100), KEY_FIREWALL_EVIDENCE, REASONING
            Focus on network security perspective and firewall-specific indicators.
            """
            
            synthesis = self.llm.invoke(synthesis_prompt)
            
            # Extract classification
            classification_prompt = f"""
            Extract exact firewall security classification:
            
            {synthesis.content}
            
            Format:
            CLASSIFICATION: [TRUE_POSITIVE|FALSE_POSITIVE|ESCALATE]
            CONFIDENCE: [0-100]
            """
            
            verdict_result = self.llm.invoke(classification_prompt)
            
            # Store firewall assessment
            self.firewall_investigation_context['firewall_agent_assessment'] = {
                'full_synthesis': synthesis.content,
                'verdict_extraction': verdict_result.content,
                'timestamp': datetime.now().isoformat(),
                'schema_used': {
                    'nodes': self.firewall_node_types, 
                    'relationships': self.firewall_relationship_types
                },
                'analysis_type': 'comprehensive_firewall_security'
            }
            
            return synthesis.content
            
        except Exception as e:
            return f"Error in firewall evidence synthesis: {str(e)}"

    def _execute_firewall_cypher_query(self, intent: str, alert_id: str) -> str:
        """Execute firewall-specific Cypher query"""
        
        try:
            # Generate firewall Cypher
            cypher_query = self._generate_firewall_cypher(intent, alert_id)
            
            print(f"Firewall Cypher: {cypher_query}")
            
            # Execute query
            result = self.graph.query(cypher_query)
            
            if result and not self._is_cypher_result_empty(result):
                return self._format_firewall_cypher_result(result, intent)
            else:
                # Fallback to LangChain
                fallback_query = f"For firewall alert_id '{alert_id}': {intent}"
                return self.chain.run(fallback_query)
                
        except Exception as e:
            print(f"Firewall Cypher error: {e}")
            try:
                fallback_query = f"For firewall alert_id '{alert_id}': {intent}"
                return self.chain.run(fallback_query)
            except:
                return f"Firewall query execution failed: {str(e)}"

    def _generate_firewall_cypher(self, intent: str, alert_id: str) -> str:
        """Generate firewall-specific Cypher queries"""
        
        firewall_schema_info = f"""
        Firewall Node Types: {self.firewall_node_types}
        Firewall Relationships: {self.firewall_relationship_types}
        """
        
        cypher_prompt = f"""
        Generate Cypher query for firewall analysis: {intent}
        Alert ID: {alert_id}
        
        Firewall graph schema:
        {firewall_schema_info}
        
        Firewall Query Rules:
        1. Find FirewallAlert node with alert_id property matching '{alert_id}'
        2. Use firewall-specific relationships: ALERT_ORIGINATED_FROM, ALERT_TARGETED, etc.
        3. Focus on network security entities: SourceEndpoint, DestinationEndpoint, NetworkSession
        4. Include threat intelligence and policy nodes if available
        5. Return firewall-relevant properties only
        
        Return only executable Cypher code.
        """
        
        try:
            response = self.llm.invoke(cypher_prompt)
            cypher_query = response.content.strip()
            
            # Clean response
            if "```" in cypher_query:
                parts = cypher_query.split("```")
                for part in parts:
                    if "MATCH" in part or "OPTIONAL" in part:
                        cypher_query = part
                        break
            
            cypher_query = cypher_query.replace("cypher", "").strip()
            
            return cypher_query
            
        except Exception as e:
            # Firewall fallback query
            return f"""
            MATCH (fa:FirewallAlert) WHERE fa.alert_id = '{alert_id}'
            OPTIONAL MATCH (fa)-[r]-(n)
            RETURN fa, r, n
            LIMIT 25
            """

    def _format_firewall_cypher_result(self, result, intent: str) -> str:
        """Format firewall Cypher results"""
        
        if not result:
            return "No firewall results found"
        
        formatted_output = []
        
        try:
            for i, row in enumerate(result[:8]):  # Limit for firewall context
                row_data = []
                
                for key, value in row.items():
                    if value is not None:
                        if isinstance(value, dict):
                            # Firewall node/relationship properties
                            props = ", ".join([f"{k}: {v}" for k, v in value.items() if v])
                            row_data.append(f"Firewall {key}: {{{props}}}")
                        else:
                            row_data.append(f"{key}: {value}")
                
                if row_data:
                    formatted_output.append(f"Firewall Result {i+1}: {'; '.join(row_data)}")
            
            return "\n".join(formatted_output) if formatted_output else "Firewall data found but no readable content"
            
        except Exception as e:
            return f"Error formatting firewall results: {str(e)}\nRaw result count: {len(result)}"

    def _make_firewall_concise_response(self, question: str, result: str, focus: str) -> str:
        """Make firewall responses concise while preserving network security details"""
        
        concise_prompt = f"""
        Summarize firewall analysis in EXACTLY 4-5 lines:
        
        Question: {question}
        Result: {result}
        Focus on: {focus}
        
        Requirements:
        - Maximum 4-5 lines total
        - Highlight critical network security findings
        - Include firewall-specific indicators
        - Direct, factual statements only
        """
        
        try:
            concise_result = self.llm.invoke(concise_prompt)
            response = concise_result.content.strip()
            
            # Enforce line limit
            lines = response.split('\n')
            if len(lines) > 5:
                response = '\n'.join(lines[:5])
            
            # Store in firewall Q&A history
            self.firewall_qa_history.append({
                "question": question,
                "answer": response,
                "timestamp": datetime.now().isoformat(),
                "method": "firewall_analysis"
            })
            
            return response
            
        except Exception as e:
            lines = result.split('\n')[:5]
            fallback_response = '\n'.join(lines) if lines else result[:250] + "..."
            
            self.firewall_qa_history.append({
                "question": question,
                "answer": fallback_response,
                "timestamp": datetime.now().isoformat(),
                "method": "firewall_fallback"
            })
            
            return fallback_response

    def _is_empty_result(self, result: str) -> bool:
        """Check if firewall result indicates no data"""
        empty_indicators = [
            "no data", "not found", "no results", "no information",
            "empty", "none found", "no firewall", "no network"
        ]
        
        result_lower = result.lower().strip()
        return any(indicator in result_lower for indicator in empty_indicators) or len(result_lower) < 15

    def _is_cypher_result_empty(self, result) -> bool:
        """Check if firewall Cypher result is empty"""
        if not result:
            return True
        
        if isinstance(result, list):
            if len(result) == 0:
                return True
            
            for row in result:
                if isinstance(row, dict):
                    non_null_values = [v for v in row.values() if v is not None and v != ""]
                    if non_null_values:
                        return False
            return True
        
        return False

    def _execute_firewall_task_parallel(self, task: FirewallInvestigationTask, alert_id: str) -> FirewallInvestigationTask:
        """Execute firewall task in parallel"""
        
        try:
            print(f"Executing firewall parallel task: {task.task_id}")
            
            # Map firewall task types to methods
            if task.task_type == "network_security":
                result = self._firewall_network_security_analysis_tool(alert_id)
            elif task.task_type == "traffic_flow":
                question = "What network traffic patterns, protocols, and data flows are present in this firewall alert?"
                if not self._is_firewall_question_duplicate(question, alert_id):
                    self._mark_firewall_question_asked(question, alert_id)
                    result = self._firewall_traffic_flow_query_tool(question)
                else:
                    result = "Traffic flow analysis completed in previous parallel task."
            elif task.task_type == "policy_enforcement":
                result = self._firewall_policy_enforcement_tool("")
            elif task.task_type == "threat_intel":
                result = self._firewall_threat_intelligence_tool("")
            elif task.task_type == "malicious_download":
                result = self._firewall_malicious_download_tool("")
            elif task.task_type == "endpoint_behavior":
                result = self._firewall_endpoint_behavior_tool("")
            elif task.task_type == "attack_vector":
                result = self._firewall_attack_vector_tool("")
            elif task.task_type == "firewall_synthesis":
                result = self._firewall_evidence_synthesis_tool("")
            else:
                result = f"Unknown firewall task type: {task.task_type}"
            
            task.result = result
            task.completed = True
            print(f"Completed firewall parallel task: {task.task_id}")
            
        except Exception as e:
            task.error = str(e)
            task.result = f"Error in firewall {task.task_id}: {str(e)}"
            print(f"Error in firewall parallel task {task.task_id}: {e}")
        
        return task

    def _wait_for_firewall_dependencies(self, task: FirewallInvestigationTask, completed_tasks: Dict[str, FirewallInvestigationTask]) -> bool:
        """Check if firewall task dependencies are satisfied"""
        for dep in task.dependencies:
            if dep not in completed_tasks or not completed_tasks[dep].completed:
                return False
        return True

    def investigate_firewall_alert_parallel(self, alert_id: str) -> Dict[str, Any]:
        """Main firewall investigation with parallel processing"""
        
        print(f"Starting parallel firewall investigation for alert: {alert_id}")
        start_time = time.time()
        
        # Reset firewall investigation context
        self.firewall_qa_history = []
        self.firewall_investigation_context = {"alert_id": alert_id}
        self.firewall_completed_tasks = {}
        self.firewall_question_cache = set()
        
        # Refresh firewall schema
        self._discover_firewall_schema()
        
        try:
            # Generate and execute firewall tasks
            tasks = self._generate_firewall_parallel_investigation_tasks(alert_id)
            completed_tasks = {}
            
            print(f"Starting firewall parallel investigation with {len(tasks)} tasks...")
            
            # Process by priority levels
            priority_levels = sorted(set(task.priority for task in tasks))
            
            for priority in priority_levels:
                priority_tasks = [task for task in tasks if task.priority == priority]
                
                # Submit tasks with satisfied dependencies
                current_futures = {}
                for task in priority_tasks:
                    if self._wait_for_firewall_dependencies(task, completed_tasks):
                        future = self.executor.submit(self._execute_firewall_task_parallel, task, alert_id)
                        current_futures[future] = task
                        print(f"Submitted firewall task: {task.task_id} (Priority {priority})")
                
                # Wait for current priority completion
                if current_futures:
                    for future in as_completed(current_futures):
                        task = current_futures[future]
                        try:
                            completed_task = future.result(timeout=35)
                            completed_tasks[task.task_id] = completed_task
                            
                            with self.task_lock:
                                self.firewall_completed_tasks[task.task_id] = completed_task
                            
                            print(f"Firewall parallel task completed: {task.task_id}")
                            
                        except concurrent.futures.TimeoutError:
                            print(f"Firewall task {task.task_id} timed out")
                            task.error = "Task timeout"
                            task.result = f"Firewall task {task.task_id} timed out"
                            completed_tasks[task.task_id] = task
                            
                        except Exception as e:
                            print(f"Firewall task {task.task_id} failed: {e}")
                            task.error = str(e)
                            task.result = f"Firewall task {task.task_id} failed: {str(e)}"
                            completed_tasks[task.task_id] = task
            
            # Generate firewall summary
            summary = self._generate_firewall_summary()
            
            # Extract firewall verdict
            agent_verdict = "ESCALATE"
            agent_confidence = 50
            
            if 'firewall_agent_assessment' in self.firewall_investigation_context:
                verdict_text = self.firewall_investigation_context['firewall_agent_assessment'].get('verdict_extraction', '')
                
                if 'CLASSIFICATION:' in verdict_text:
                    classification_lines = [line for line in verdict_text.split('\n') if 'CLASSIFICATION:' in line]
                    if classification_lines:
                        extracted_verdict = classification_lines[0].split('CLASSIFICATION:')[1].strip()
                        if extracted_verdict in ['TRUE_POSITIVE', 'FALSE_POSITIVE', 'ESCALATE']:
                            agent_verdict = extracted_verdict
                
                if 'CONFIDENCE:' in verdict_text:
                    confidence_lines = [line for line in verdict_text.split('\n') if 'CONFIDENCE:' in line]
                    if confidence_lines:
                        try:
                            confidence_str = confidence_lines[0].split('CONFIDENCE:')[1].strip()
                            agent_confidence = int(''.join(filter(str.isdigit, confidence_str)))
                            agent_confidence = min(max(agent_confidence, 0), 100)
                        except:
                            agent_confidence = 50
            
            execution_time = time.time() - start_time
            
            return {
                "alert_id": alert_id,
                "alert_type": "firewall",
                "qa_history": self.firewall_qa_history,
                "summary": summary,
                "agent_verdict": agent_verdict,
                "agent_confidence": agent_confidence,
                "schema_discovered": {
                    "node_types": self.firewall_node_types,
                    "relationship_types": self.firewall_relationship_types,
                    "property_patterns_count": len(self.firewall_property_patterns)
                },
                "investigation_method": "Firewall Dynamic Parallel Processing",
                "firewall_parallel_metrics": {
                    "total_tasks": len(completed_tasks),
                    "successful_tasks": len([t for t in completed_tasks.values() if t.completed and not t.error]),
                    "execution_time_seconds": round(execution_time, 2),
                    "firewall_focus": "network_security_analysis"
                }
            }
            
        except Exception as e:
            execution_time = time.time() - start_time
            return {
                "alert_id": alert_id,
                "alert_type": "firewall",
                "qa_history": self.firewall_qa_history,
                "summary": f"Firewall parallel investigation error: {str(e)}",
                "agent_verdict": "ESCALATE",
                "agent_confidence": 0,
                "schema_discovered": {
                    "node_types": self.firewall_node_types,
                    "relationship_types": self.firewall_relationship_types,
                    "property_patterns_count": len(self.firewall_property_patterns)
                },
                "investigation_method": "Firewall Parallel Processing (Error Recovery)",
                "firewall_parallel_metrics": {
                    "total_tasks": 0,
                    "successful_tasks": 0,
                    "execution_time_seconds": round(execution_time, 2),
                    "error": str(e)
                }
            }

    def _generate_firewall_summary(self) -> str:
        """Generate firewall investigation summary"""
        
        try:
            summary_prompt = f"""
            Create firewall investigation summary in EXACTLY 5-6 lines:
            
            Firewall Q&A History: {self.firewall_qa_history}
            Alert ID: {self.firewall_investigation_context.get('alert_id', 'Unknown')}
            Processing Method: Firewall Parallel Processing
            
            STRICT FORMAT:
            - Line 1: Alert ID and basic network threat info
            - Line 2: Network security analysis results
            - Line 3: Key firewall threat indicators
            - Line 4: Policy enforcement and blocking status
            - Line 5: Final firewall verdict and reasoning
            
            Maximum 5 lines total, focus on network security findings.
            """
            
            summary = self.llm.invoke(summary_prompt)
            response = summary.content.strip()
            
            # Enforce strict line limit
            lines = response.split('\n')
            if len(lines) > 6:
                response = '\n'.join(lines[:6])
            
            return response
            
        except Exception as e:
            # Fallback summary from firewall Q&A
            key_points = []
            for qa in self.firewall_qa_history[-3:]:
                if qa['answer'] and len(qa['answer']) > 20:
                    key_points.append(qa['answer'].split('.')[0] + '.')
            
            fallback = f"Firewall alert {self.firewall_investigation_context.get('alert_id', 'Unknown')} investigation completed using parallel processing. "
            fallback += ' '.join(key_points[:2])
            return fallback[:400]

    def cleanup_firewall_resources(self):
        """Cleanup firewall parallel processing resources"""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=True)
        print("Firewall parallel processing resources cleaned up.")

    def __del__(self):
        """Ensure firewall cleanup on deletion"""
        try:
            self.cleanup_firewall_resources()
        except:
            pass
FirewallAgenticGraphRAG._enhance_firewall_agentic_with_context = _enhance_firewall_agentic_with_context

# Global firewall investigator pool for resource efficiency
_firewall_investigator_pool = {}
_firewall_pool_lock = threading.Lock()

def get_firewall_agentic_investigator() -> FirewallAgenticGraphRAG:
    """Get or create firewall agentic investigator instance with proper resource management"""
    thread_id = threading.current_thread().ident
    
    with _firewall_pool_lock:
        if thread_id not in _firewall_investigator_pool:
            _firewall_investigator_pool[thread_id] = FirewallAgenticGraphRAG(
                neo4j_url=NEO4J_URI,
                neo4j_username=NEO4J_USERNAME,
                neo4j_password=NEO4J_PASSWORD,
                openai_api_key=OPENAI_API_KEY
            )
    
    return _firewall_investigator_pool[thread_id]

# Add this import at the top if not already present
from fastapi import HTTPException, Body
from typing import Optional

@app.post("/firewall-investigate-agentic/{alert_id}")
async def investigate_firewall_alert_agentic(
    alert_id: str,
    context_data: dict = Body(None),
    timeout: Optional[int] = Body(120)  # 2 minute default timeout
):
    """
    Conduct autonomous firewall agentic investigation with parallel processing.
    Enhanced with firewall-specific network security analysis and SOC analyst focus.
    """
    try:
        if not OPENAI_API_KEY:
            raise HTTPException(
                status_code=503,
                detail="OpenAI API key not configured for firewall agentic investigation"
            )
        
        # Validate firewall alert_id
        if not alert_id or len(alert_id.strip()) == 0:
            raise HTTPException(
                status_code=400,
                detail="Invalid firewall alert_id provided"
            )
        
        start_time = time.time()
        print(f"Starting firewall agentic investigation for alert: {alert_id}")
        
        # Create firewall agentic investigator with proper resource management
        firewall_investigator = get_firewall_agentic_investigator()
        
        try:
            # Run firewall agentic parallel investigation in thread pool
            result = await asyncio.get_event_loop().run_in_executor(
                None,  # Use default executor
                lambda: firewall_investigator.investigate_firewall_alert_parallel(alert_id)
            )
            
            # Enhanced result validation for firewall agentic
            if not isinstance(result, dict):
                raise HTTPException(
                    status_code=500,
                    detail="Firewall agentic investigation returned invalid result format"
                )
            
            execution_time = time.time() - start_time
            
            # Add firewall agentic API-specific metrics
            result.update({
                "api_metrics": {
                    "total_execution_time": round(execution_time, 2),
                    "parallel_processing_used": True,
                    "agentic_tools_used": True,
                    "endpoint": "firewall-investigate-agentic",
                    "timestamp": datetime.now().isoformat(),
                    "focus": "firewall_network_security_agentic_analysis"
                }
            })
            
            # Enhanced firewall agentic context data integration
            if (len(result.get('qa_history', [])) < 4 and 
                context_data and 
                result.get('agent_confidence', 0) < 75):
                
                print(f"Enhancing firewall agentic investigation with context data for {alert_id}")
                
                try:
                    # Process firewall context data with agentic enhancement
                    firewall_agentic_enhancement = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: firewall_investigator._enhance_firewall_agentic_with_context(
                            alert_id, 
                            context_data
                        )
                    )
                    
                    if firewall_agentic_enhancement:
                        result['agentic_context_enhancement'] = {
                            'used': True,
                            'enhancement_data': firewall_agentic_enhancement,
                            'enhancement_type': 'firewall_agentic_tools'
                        }
                        
                        # Update verdict if agentic enhancement provides stronger evidence
                        if (firewall_agentic_enhancement.get('enhanced_verdict') == 'TRUE_POSITIVE' and 
                            firewall_agentic_enhancement.get('confidence', 0) > result.get('agent_confidence', 0)):
                            result['agent_verdict'] = firewall_agentic_enhancement['enhanced_verdict']
                            result['agent_confidence'] = firewall_agentic_enhancement['confidence']
                            result['summary'] += f" Agentic enhancement: {firewall_agentic_enhancement.get('context')}"
                    
                except Exception as e:
                    print(f"Firewall agentic context enhancement failed: {str(e)}")
                    result['agentic_context_enhancement'] = {
                        'used': False,
                        'error': str(e),
                        'enhancement_type': 'firewall_agentic_tools_error'
                    }
            else:
                print(f"Firewall agentic context enhancement not needed or sufficient data available")
            
            # Ensure proper cleanup of firewall agentic resources
            if hasattr(firewall_investigator, 'firewall_question_cache'):
                firewall_investigator.firewall_question_cache.clear()
            if hasattr(firewall_investigator, 'firewall_investigation_context'):
                firewall_investigator.firewall_investigation_context.clear()
            
            print(f"Firewall agentic investigation completed for {alert_id} in {execution_time:.2f}s")
            
            return JSONResponse(content=result)
        
        finally:
            # Cleanup firewall agentic investigation-specific resources
            try:
                if hasattr(firewall_investigator, 'firewall_investigation_context'):
                    firewall_investigator.firewall_investigation_context.clear()
                if hasattr(firewall_investigator, 'firewall_completed_tasks'):
                    firewall_investigator.firewall_completed_tasks.clear()
                if hasattr(firewall_investigator, 'firewall_qa_history'):
                    firewall_investigator.firewall_qa_history = []
            except:
                pass
    
    except HTTPException:
        raise
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=408,
            detail=f"Firewall agentic investigation timeout for alert {alert_id}"
        )
    except Exception as e:
        print(f"Firewall agentic investigation error for {alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Firewall agentic investigation failed: {str(e)}")

def create_firewall_agentic_investigator(neo4j_url: str, neo4j_username: str, neo4j_password: str, openai_api_key: str):
    """Create and configure the firewall agentic investigator"""
    
    investigator = FirewallAgenticGraphRAG(
        neo4j_url=neo4j_url,
        neo4j_username=neo4j_username,
        neo4j_password=neo4j_password,
        openai_api_key=openai_api_key
    )
    
    return investigator


# Add the method to the FirewallAgenticGraphRAG class
FirewallAgenticGraphRAG._enhance_firewall_agentic_with_context = _enhance_firewall_agentic_with_context
# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
class SupervisorAgent:
    """Orchestrates parallel sub-agents with 100% weight to specialized agent - using raw confidence scores"""
    
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Source to agent mapping
        self.source_mapping = {
            "edr": "EDR",
            "endpoint": "EDR", 
            "sentinelone": "EDR",
            "crowdstrike": "EDR",
            "firewall": "Firewall",
            "palo_alto": "Firewall",
            "fortinet": "Firewall",
            "email": "Email",
            "proofpoint": "Email",
            "mimecast": "Email",
            "gnn": "GNN",
            "graph": "GNN"
        }
    
    async def run_edr_agent(self, edr_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run EDR agent using raw confidence scores without artificial caps"""
        try:
            # Check if global predictor is available
            global predictor
            if predictor is None:
                return self._error_response("EDR", "EDR predictor not loaded")
            
            # Use the predictor directly (similar to the /predict endpoint)
            result = predictor.predict(edr_data)
            
            # Handle error case
            if result.get('prediction', {}).get('predicted_verdict') == 'Error':
                error_msg = result.get('metadata', {}).get('error', 'Unknown EDR prediction error')
                return self._error_response("EDR", f"EDR prediction failed: {error_msg}")
            
            # Extract confidence score and convert to 0-100 scale
            confidence = result.get('prediction', {}).get('confidence', 0) * 100
            verdict = result.get('prediction', {}).get('predicted_verdict', 'Unknown')
            
            # Normalize verdict format to match your existing logic
            verdict_mapping = {
                'true_positive': 'True Positive',
                'false_positive': 'False Positive', 
                'undefined': 'Escalate',
                'escalate': 'Escalate',
                '0': 'False Positive',  # Handle numeric predictions
                '1': 'True Positive',
                '2': 'Escalate'
            }
            normalized_verdict = verdict_mapping.get(str(verdict).lower(), verdict)
            
            # Use raw confidence as risk score - no artificial caps
            risk_score = confidence
            
            # For False Positive, invert the confidence (high confidence in FP = low risk)
            if normalized_verdict == "False Positive":
                risk_score = 100 - confidence  # Invert: 85% confidence in FP = 15% risk score
            else:
                confidence = risk_score  # Invert: 85% confidence in FP = 15% risk score
                risk_score = confidence
            
            return {
                "agent": "EDR",
                "score": round(risk_score, 2),
                "verdict": normalized_verdict,
                "confidence": round(confidence, 2),
                "message": f"EDR Analysis: {normalized_verdict} with {confidence:.1f}% confidence",
                "details": {
                    "probabilities": result.get('prediction', {}).get('probabilities', {}),
                    "file_risk_score": result.get('metadata', {}).get('file_risk_score', 0),
                    "feature_importance": result.get('metadata', {}).get('feature_importance', {}),
                    "features_used_count": len(result.get('metadata', {}).get('features_used', [])),
                    "preprocessing_success": result.get('metadata', {}).get('preprocessing_success', False),
                    "raw_confidence": confidence,
                    "risk_calculation": "Inverted for False Positive" if normalized_verdict == "False Positive" else "Direct confidence"
                },
                "success": True
            }
                
        except Exception as e:
            return self._error_response("EDR", f"EDR agent error: {str(e)}")
    
    async def run_gnn_agent(self, gnn_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run GNN agent with raw confidence scores"""
        try:
            # Use the global instance created by create_dynamic_gnn_system()
            global dynamic_gnn_predictor
            if dynamic_gnn_predictor is None:
                return self._error_response("GNN", "Dynamic GNN predictor not initialized")

            # Delegate — predictor handles ego vs selfie internally and loads model on demand
            gnn_result = dynamic_gnn_predictor.predict(
                alert_data=gnn_data,
                checkpoint_path=DEFAULT_GNN_CKPT  # e.g., models/rgcn_nodgl.pt
            )

            if not gnn_result or not gnn_result.get("success", False):
                err = gnn_result.get("error", "Unknown GNN error") if isinstance(gnn_result, dict) else "Unknown GNN error"
                return self._error_response("GNN", err)

            verdict = gnn_result.get("verdict", "Escalate")
            confidence = float(gnn_result.get("confidence", 0.0))  # already 0–100 from predictor

            # Use raw confidence as risk score - no artificial caps
            risk_score = confidence
            
            # For False Positive, invert the confidence (high confidence in FP = low risk)
            if verdict == "False Positive":
                risk_score = 100 - confidence

            return {
                "agent": "GNN",
                "score": round(risk_score, 2),
                "verdict": verdict,
                "confidence": round(confidence, 2),
                "probabilities": gnn_result.get("probabilities", {}),
                "mode": gnn_result.get("mode", "selfie"),
                "message": f"GNN Analysis ({gnn_result.get('mode', 'selfie')}): {verdict} with {confidence:.1f}% confidence",
                "details": {
                    "alert_id": gnn_result.get("alert_id"),
                    "subgraph_stats": gnn_result.get("subgraph_stats"),
                    "raw_confidence": confidence,
                    "risk_calculation": "Inverted for False Positive" if verdict == "False Positive" else "Direct confidence"
                },
                "success": True
            }
        except Exception as e:
            return self._error_response("GNN", f"GNN agent error: {str(e)}")

    async def run_firewall_agent(self, firewall_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run Firewall agent using the SinglePKLFirewallPredictor"""
        try:
            # Check if global firewall predictor is available
            global firewall_predictor
            if firewall_predictor is None:
                return self._error_response("Firewall", "Firewall predictor not loaded")
            
            # Extract the actual firewall data from context if needed
            if isinstance(firewall_data, dict) and any(k in firewall_data for k in ["edr", "gnn"]):
                # If we received context data, try to extract firewall-relevant data
                # Use the EDR data or original alert data for firewall analysis
                actual_data = firewall_data.get("edr", firewall_data.get("gnn", firewall_data))
            else:
                actual_data = firewall_data
            
            # Use the firewall predictor
            result = firewall_predictor.predict(actual_data)
            
            # Handle error case
            if result.get('prediction', {}).get('predicted_verdict') == 'Error':
                error_msg = result.get('metadata', {}).get('error', 'Unknown Firewall prediction error')
                return self._error_response("Firewall", f"Firewall prediction failed: {error_msg}")
            
            # Extract confidence score (already in 0-100 scale from firewall predictor)
            confidence = result.get('prediction', {}).get('confidence', 0)
            verdict = result.get('prediction', {}).get('predicted_verdict', 'Unknown')
            
            # Normalize verdict format
            verdict_mapping = {
                'true_positive': 'True Positive',
                'false_positive': 'False Positive', 
                'undefined': 'Escalate',
                'escalate': 'Escalate',
                '0': 'False Positive',
                '1': 'True Positive',
                '2': 'Escalate'
            }
            normalized_verdict = verdict_mapping.get(str(verdict).lower(), verdict)
            
            # Use raw confidence as risk score
            risk_score = confidence
            
            # For False Positive, invert the confidence (high confidence in FP = low risk)
            if normalized_verdict == "False Positive":
                risk_score = 100 - confidence
            
            return {
                "agent": "Firewall",
                "score": round(risk_score, 2),
                "verdict": normalized_verdict,
                "confidence": round(confidence, 2),
                "message": f"Firewall Analysis: {normalized_verdict} with {confidence:.1f}% confidence",
                "details": {
                    "probabilities": result.get('prediction', {}).get('probabilities', {}),
                    "file_risk_score": result.get('metadata', {}).get('file_risk_score', 0),
                    "feature_importance": result.get('metadata', {}).get('feature_importance', {}),
                    "features_used_count": len(result.get('metadata', {}).get('features_used', [])),
                    "preprocessing_success": result.get('metadata', {}).get('preprocessing_success', False),
                    "raw_confidence": confidence,
                    "risk_calculation": "Inverted for False Positive" if normalized_verdict == "False Positive" else "Direct confidence"
                },
                "success": True
            }
            
        except Exception as e:
            return self._error_response("Firewall", f"Firewall agent error: {str(e)}")
    
    async def run_email_agent(self, context_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run Email agent (pluggable - currently returns 0)"""
        try:
            # Placeholder for email security analysis
            # This would integrate with email security tools, phishing detection, etc.
            # Could use either edr_data or gnn_data based on implementation needs
            
            return {
                "agent": "Email",
                "score": 0,
                "verdict": "No Analysis",
                "confidence": 0,
                "message": "Email agent not implemented - pluggable for future email security analysis",
                "details": {"status": "placeholder"},
                "success": True
            }
            
        except Exception as e:
            return self._error_response("Email", f"Email agent error: {str(e)}")
    
    def _error_response(self, agent_name: str, error_msg: str) -> Dict[str, Any]:
        """Generate standardized error response"""
        return {
            "agent": agent_name,
            "score": 0,
            "verdict": "Error",
            "confidence": 0,
            "message": error_msg,
            "details": {},
            "success": False
        }
    
    def _determine_final_decision_from_score(self, score: float, verdict: str) -> str:
        """Determine final decision based on score and original verdict"""
        # If we have a verdict from the agent, prefer that
        if verdict and verdict not in ["Error", "No Analysis", "Unknown"]:
            return verdict
        
        # Fallback to score-based decision
        if score >= 80:
            return "True Positive"
        elif score >= 50:
            return "Escalate"
        else:
            return "False Positive"
    
    async def run_all_agents_with_separate_data(self, source: str, edr_data: Dict[str, Any], gnn_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run all agents but only use the specialized agent's score (100% weight)"""
        
        print(f"Supervisor Agent: Running specialized agent analysis for source '{source}'")
        print(f"EDR data keys: {list(edr_data.keys()) if isinstance(edr_data, dict) else 'Invalid EDR data'}")
        print(f"GNN data keys: {list(gnn_data.keys()) if isinstance(gnn_data, dict) else 'Invalid GNN data'}")
        
        # Run all agents in parallel with appropriate data
        tasks = [
            self.run_edr_agent(edr_data),
            self.run_gnn_agent(gnn_data),
            self.run_firewall_agent({"edr": edr_data, "gnn": gnn_data}),  # Pass both for context
            self.run_email_agent({"edr": edr_data, "gnn": gnn_data})      # Pass both for context
        ]
        
        # Execute all tasks concurrently
        agent_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and handle any exceptions
        processed_results = []
        for result in agent_results:
            if isinstance(result, Exception):
                processed_results.append({
                    "agent": "Unknown",
                    "score": 0,
                    "verdict": "Error",
                    "confidence": 0,
                    "message": f"Agent execution failed: {str(result)}",
                    "success": False
                })
            else:
                processed_results.append(result)
        
        # Extract scores and identify specialized agent
        agent_scores = {result["agent"]: result["score"] for result in processed_results}
        
        # Determine specialized agent based on source mapping
        specialized_agent = self.source_mapping.get(source.lower(), "EDR")  # Default to EDR
        specialized_score = agent_scores.get(specialized_agent, 0)
        # 100% weight to specialized agent

        # Get specialized agent result for verdict and confidence
        specialized_result = next((r for r in processed_results if r["agent"] == specialized_agent), None)
        specialized_verdict = specialized_result.get("verdict", "Error") if specialized_result else "Error"
        specialized_confidence = specialized_result.get("confidence", 0) if specialized_result else 0
        
        # 100% weight to specialized agent
        consolidated_score = specialized_score
        if specialized_verdict == "False Positive":
            consolidated_score = (1 - (specialized_confidence / 100)) * 100
        else:
            consolidated_score = specialized_score
        weighting_strategy = f"Specialized agent only: {specialized_agent} gets 100% weight"
        
        # Determine final decision based on specialized agent's verdict and score
        final_decision = self._determine_final_decision_from_score(consolidated_score, specialized_verdict)
        
        # Calculate probabilities based on specialized agent's actual probabilities
        if specialized_result and specialized_result.get("details", {}).get("probabilities"):
            # Use the actual probabilities from the specialized agent
            agent_probs = specialized_result["details"]["probabilities"]
            probabilities = {
                "false_positive": round(agent_probs.get("false_positive", 0), 4),
                "escalate": round(agent_probs.get("escalate", agent_probs.get("undefined", 0)), 4),
                "true_positive": round(agent_probs.get("true_positive", 0), 4)
            }
        else:
            # Fallback probability calculation based on confidence and decision
            if final_decision == "True Positive":
                probabilities = {
                    "false_positive": round((100 - consolidated_score) / 100.0, 4),
                    "escalate": round(abs(consolidated_score - 65) / 100.0, 4),
                    "true_positive": round(consolidated_score / 100.0, 4)
                }
            elif final_decision == "False Positive":
                probabilities = {
                    "false_positive": round(consolidated_score / 100.0, 4),
                    "escalate": round(abs(consolidated_score - 50) / 100.0, 4),
                    "true_positive": round((100 - consolidated_score) / 100.0, 4)
                }
            else:  # Escalate
                probabilities = {
                    "false_positive": round((50 - consolidated_score) / 100.0, 4) if consolidated_score < 50 else 0.1,
                    "escalate": round(consolidated_score / 100.0, 4),
                    "true_positive": round((consolidated_score - 50) / 100.0, 4) if consolidated_score > 50 else 0.4
                }
        
        # Build comprehensive response in the requested format
        return {
            "prediction": {
                "predicted_verdict": final_decision,
                "confidence": round(specialized_confidence, 2),
                "consolidated_score": round(consolidated_score, 2),
                "probabilities": probabilities
            },
            "metadata": {
                "supervisor_analysis": {
                    "source": source,
                    "specialized_agent": specialized_agent,
                    "final_decision": final_decision,
                    "consolidated_score": round(consolidated_score, 2),
                    "specialized_agent_confidence": round(specialized_confidence, 2),
                    "weighting_applied": {
                        "specialized_weight": "100%",
                        "other_agents_weight": "0% (informational only)",
                        "strategy": weighting_strategy,
                        "score_calculation": "Raw confidence used - no artificial caps"
                    }
                },
                "agent_results": processed_results,
                "score_breakdown": {
                    "specialized_agent": specialized_agent,
                    "specialized_score": specialized_score,
                    "specialized_confidence": specialized_confidence,
                    "specialized_weighted": round(consolidated_score, 2),
                    "other_agents_scores": {k: v for k, v in agent_scores.items() if k != specialized_agent},
                    "final_consolidated": round(consolidated_score, 2),
                    "calculation_method": "Direct confidence mapping - inverted for False Positive verdicts"
                },
                "actionable_messages": [
                    result["message"] for result in processed_results if result.get("success", False)
                ],
                "data_sources": {
                    "edr_data_keys": list(edr_data.keys()) if isinstance(edr_data, dict) else "Invalid",
                    "gnn_data_keys": list(gnn_data.keys()) if isinstance(gnn_data, dict) else "Invalid"
                },
                "agent_agreement_analysis": self._analyze_specialized_agent_focus(processed_results, specialized_agent),
                "timestamp": datetime.utcnow().isoformat(),
                "execution_summary": {
                    "total_agents": len(processed_results),
                    "successful_agents": sum(1 for r in processed_results if r.get("success", False)),
                    "failed_agents": sum(1 for r in processed_results if not r.get("success", True)),
                    "decision_based_on": specialized_agent,
                    "confidence_mapping": "Raw confidence used without artificial limits"
                }
            }
        }
    
    def _analyze_specialized_agent_focus(self, agent_results: List[Dict[str, Any]], specialized_agent: str) -> Dict[str, Any]:
        """Analyze results with focus on specialized agent"""
        
        specialized_result = next((r for r in agent_results if r["agent"] == specialized_agent), None)
        other_agents = [r for r in agent_results if r["agent"] != specialized_agent and r.get("success", False)]
        
        if not specialized_result or not specialized_result.get("success", False):
            return {
                "agreement_status": "specialized_agent_failed",
                "description": f"Specialized agent {specialized_agent} failed to provide results",
                "consensus": "error",
                "decision_basis": "fallback_required"
            }
        
        specialized_verdict = specialized_result["verdict"]
        specialized_confidence = specialized_result.get("confidence", 0)
        
        # Check agreement with other successful agents (informational only)
        agreeing_agents = []
        disagreeing_agents = []
        
        for agent in other_agents:
            if agent["verdict"] == specialized_verdict:
                agreeing_agents.append({
                    "agent": agent["agent"],
                    "confidence": agent.get("confidence", 0)
                })
            else:
                disagreeing_agents.append({
                    "agent": agent["agent"], 
                    "verdict": agent["verdict"],
                    "confidence": agent.get("confidence", 0)
                })
        
        return {
            "agreement_status": "specialized_agent_primary",
            "description": f"Decision based entirely on {specialized_agent}: {specialized_verdict} ({specialized_confidence:.1f}% confidence)",
            "consensus": specialized_verdict,
            "decision_basis": specialized_agent,
            "specialized_agent_details": {
                "verdict": specialized_verdict,
                "confidence": specialized_confidence,
                "score": specialized_result.get("score", 0)
            },
            "informational_agreement": {
                "agreeing_agents": agreeing_agents,
                "disagreeing_agents": disagreeing_agents,
                "agreement_count": len(agreeing_agents),
                "disagreement_count": len(disagreeing_agents),
                "note": "Other agent results are informational only and do not affect the final decision"
            }
        }

# Initialize supervisor agent
supervisor_agent = SupervisorAgent()

def _looks_like_alert(obj: Any) -> bool:
    return isinstance(obj, dict) and any(k in obj for k in ("file", "threat", "device", "process", "alert"))

from fastapi import Request, Query

@app.post("/supervisor-agent")
async def run_supervisor_agent(
    request: Request,
    body: Dict[str, Any] = Body(..., description="Either {'alert_json': {...}} or the alert object directly"),
    source: str = Query("edr")
):
    """
    Accepted shapes:
      • {"alert_json": {...}}   <-- preferred
      • {"alert_data": {...}}   <-- alias
      • {...direct alert object...}  <-- tolerated
    Any provided gnn_json/gnn_data is ignored; we deliberately use the same object for both.
    """
    from datetime import datetime
    import pytz
    import time
    
    # Set up Indian Standard Time timezone
    ist = pytz.timezone('UTC')
    
    # Record start time with high precision
    start_timestamp = time.time()
    start_time_ist = datetime.now(ist).isoformat()
    
    try:
        # 1) Normalize input to edr_json
        edr_json: Optional[Dict[str, Any]] = None 
        
        if isinstance(body, dict):
            if "alert_json" in body and isinstance(body["alert_json"], dict):
                edr_json = body["alert_json"]
            elif "alert_data" in body and isinstance(body["alert_data"], dict):
                edr_json = body["alert_data"]
            elif _looks_like_alert(body):
                edr_json = body
        
        if edr_json is None:
            raise HTTPException(
                status_code=400,
                detail="Provide raw JSON as {'alert_json': {...}} or the alert object directly."
            )
        
        # 2) Force GNN input to be the same as EDR input
        gnn_json_data = edr_json
        
        # 3) Flexible processing
        edr_flexible = None
        gnn_flexible = None
        
        try:
            edr_flexible = FlexibleAlertInput(**edr_json)
            edr_processed = edr_flexible.to_raw_format()
        except Exception as e:
            print(f"EDR flexible processing failed: {e}")
            edr_processed = edr_json
        
        try:
            gnn_flexible = FlexibleAlertInput(**gnn_json_data)
            gnn_processed = gnn_flexible.to_raw_format()
        except Exception as e:
            print(f"GNN flexible processing failed: {e}")
            gnn_processed = gnn_json_data
        
        print(f"Supervisor Agent: Processing alert from source '{source}' with specialized agent focus and raw confidence")
        print(f"EDR processed keys: {list(edr_processed.keys()) if isinstance(edr_processed, dict) else 'Not a dict'}")
        print(f"GNN processed keys: {list(gnn_processed.keys()) if isinstance(gnn_processed, dict) else 'Not a dict'}")
        
        result = await supervisor_agent.run_all_agents_with_separate_data(source, edr_processed, gnn_processed) or {}
        
        # Record end time with high precision
        end_timestamp = time.time()
        end_time_ist = datetime.now(ist).isoformat()
        
        # Calculate processing time in seconds (including milliseconds)
        processing_time_seconds = round(end_timestamp - start_timestamp, 3)
        
        meta = result.setdefault("metadata", {})
        meta["input_processing"] = {
            "mode": "specialized_agent_only_raw_confidence",
            "both_inputs_same": True,
            "accepted_shape": (
                "alert_json" if "alert_json" in body else
                "alert_data" if "alert_data" in body else
                "direct_alert_object"
            ),
            "edr_mapped_alert_id": getattr(edr_flexible, "alert_id", None) if edr_flexible else None,
            "gnn_mapped_alert_id": getattr(gnn_flexible, "alert_id", None) if gnn_flexible else None,
            "flexible_parsing_success": edr_flexible is not None and gnn_flexible is not None,
            "specialized_agent_focus": True,
            "confidence_calculation": "Raw confidence used - inverted for False Positive verdicts"
        }
        
        # Add timing information
        result["start_time_supervisor"] = start_time_ist
        result["end_time_supervisor"] = end_time_ist
        result["timestamp_supervisor"] = processing_time_seconds
        
        return JSONResponse(content=result)
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"Supervisor Agent Error: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        
        # Record end time even for errors and calculate processing time
        end_timestamp = time.time()
        end_time_ist = datetime.now(ist).isoformat()
        processing_time_seconds = round(end_timestamp - start_timestamp, 3)
        
        raise HTTPException(status_code=500, detail=f"Supervisor agent failed: {str(e)} (Processing time: {processing_time_seconds}s)")
    
class PureInfoSummaryAgent:
    """Pure information-based summary using single comprehensive question"""
    
    def __init__(self, neo4j_url: str, neo4j_username: str, neo4j_password: str, openai_api_key: str):
        # Reuse existing AgenticGraphRAG for dynamic querying
        self.investigator = AgenticGraphRAG(
            neo4j_url=neo4j_url,
            neo4j_username=neo4j_username,
            neo4j_password=neo4j_password,
            openai_api_key=openai_api_key
        )
        
        self.llm = ChatOpenAI(
            temperature=0,
            api_key=openai_api_key,
            model="gpt-4o-mini"
        )
    
    def generate_summary(self, alert_id: str) -> Dict[str, Any]:
        """Generate summary by asking one comprehensive question"""
        
        print(f"Generating pure info summary for alert: {alert_id}")
        start_time = datetime.now()
        
        try:
            # Set investigation context
            self.investigator.investigation_context = {"alert_id": alert_id, "mode": "summary"}
            
            # Ask ONE comprehensive question to get all information
            comprehensive_question = f"Tell me everything you can find about alert {alert_id} including all connected information, entities, relationships, and analysis results"
            
            # Get comprehensive information using existing dynamic query tool
            comprehensive_info = self.investigator._dynamic_graph_query_tool(comprehensive_question)
            
            if self.investigator._is_empty_result(comprehensive_info):
                return {
                    "success": False,
                    "alert_id": alert_id,
                    "error": "No information found for this alert ID",
                    "timestamp": datetime.now().isoformat()
                }
            
            # Generate summary directly from the comprehensive information
            summary = self._create_summary_from_info(comprehensive_info, alert_id)
            
            generation_time = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return {
                "success": True,
                "alert_id": alert_id,
                "summary": summary,
                "metadata": {
                    "generation_time_ms": generation_time,
                    "method": "Single Comprehensive Question",
                    "info_length": len(comprehensive_info),
                    "schema_adaptive": True
                },
                "raw_information": comprehensive_info,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"Pure info summary error: {str(e)}")
            return {
                "success": False,
                "alert_id": alert_id,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _create_summary_from_info(self, info: str, alert_id: str) -> Dict[str, Any]:
        """Create structured summary from raw information"""
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(info, alert_id)
        
        # Extract key points
        key_points = self._extract_key_points(info)
        
        # Assess threat level
        threat_assessment = self._assess_threat_from_info(info)
        
        # Extract status information
        status_info = self._extract_status_info(info)
        
        return {
            "executive_summary": executive_summary,
            "key_points": key_points,
            "threat_assessment": threat_assessment,
            "status_information": status_info,
            "information_source": "Dynamic graph query results"
        }
    
    def _generate_executive_summary(self, info: str, alert_id: str) -> str:
        """Generate executive summary from information"""
        
        summary_prompt = f"""
        Create a concise 2-3 sentence executive summary for alert {alert_id} based on this information:
        
        {info}
        
        Focus on: what happened, threat level, and current status. Be direct and informative.
        """
        
        try:
            response = self.llm.invoke(summary_prompt)
            return response.content.strip()
        except Exception as e:
            # Simple fallback without LLM
            lines = info.split('\n')[:3]  # First 3 lines
            return f"Alert {alert_id}: {' '.join(lines)}"
    
    def _extract_key_points(self, info: str) -> List[str]:
        """Extract key points from information"""
        
        key_points_prompt = f"""
        Extract 4-6 key bullet points from this alert information:
        
        {info}
        
        Format as simple bullet points focusing on the most important facts.
        Return only the bullet points, no other text.
        """
        
        try:
            response = self.llm.invoke(key_points_prompt)
            points = response.content.strip().split('\n')
            # Clean up bullet points
            clean_points = []
            for point in points:
                clean_point = point.strip().lstrip('•').lstrip('-').lstrip('*').strip()
                if clean_point and len(clean_point) > 10:
                    clean_points.append(clean_point)
            return clean_points[:6]  
        except Exception as e:
            # Fallback: split info into sentences and take key ones
            sentences = info.split('.')[:4]
            return [sentence.strip() for sentence in sentences if len(sentence.strip()) > 20]
    
    def _assess_threat_from_info(self, info: str) -> Dict[str, Any]:
        """Assess threat level from information"""
        
        info_lower = info.lower()
        
        # Count threat indicators
        threat_words = ['malicious', 'trojan', 'virus', 'attack', 'compromise', 'breach', 'exploit', 'suspicious']
        benign_words = ['clean', 'legitimate', 'signed', 'valid', 'harmless', 'resolved']
        
        threat_count = sum(1 for word in threat_words if word in info_lower)
        benign_count = sum(1 for word in benign_words if word in info_lower)
        
        # Simple assessment
        if threat_count > benign_count and threat_count >= 2:
            level = "HIGH"
            reasoning = f"Multiple threat indicators found ({threat_count})"
        elif benign_count > threat_count and benign_count >= 2:
            level = "LOW" 
            reasoning = f"Multiple benign indicators found ({benign_count})"
        else:
            level = "MEDIUM"
            reasoning = f"Mixed indicators (threat: {threat_count}, benign: {benign_count})"
        
        return {
            "level": level,
            "reasoning": reasoning,
            "threat_indicators": threat_count,
            "benign_indicators": benign_count
        }
    
    def _extract_status_info(self, info: str) -> Dict[str, str]:
        """Extract status information from text"""
        
        status_prompt = f"""
        Extract status information from this alert data:
        
        {info}
        
        Return in this exact format:
        Incident Status: [status]
        Remediation Status: [status]
        Detection Status: [status]
        
        If not found, use "Unknown"
        """
        
        try:
            response = self.llm.invoke(status_prompt)
            status_text = response.content.strip()
            
            # Parse status information
            status_dict = {}
            for line in status_text.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    status_dict[key.strip()] = value.strip()
            
            return status_dict
        except Exception as e:
            # Fallback status extraction
            return {
                "Incident Status": "Unknown",
                "Remediation Status": "Unknown", 
                "Detection Status": "Unknown"
            }

# Initialize pure info summary agent
def create_pure_info_summary_agent():
    """Create pure information summary agent"""
    
    if not all([NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD, OPENAI_API_KEY]):
        return None
    
    try:
        return PureInfoSummaryAgent(
            neo4j_url=NEO4J_URI,
            neo4j_username=NEO4J_USERNAME,
            neo4j_password=NEO4J_PASSWORD,
            openai_api_key=OPENAI_API_KEY
        )
    except Exception as e:
        print(f"Failed to initialize pure info summary agent: {e}")
        return None

# Initialize the pure info summary agent
pure_info_summary_agent = create_pure_info_summary_agent()

@app.post("/summary/{alert_id}")
async def generate_fast_summary(
    alert_id: str,
    context_data: dict = Body(None)
):
    """
    Generate fast summary using single comprehensive information query.
    No hardcoded queries - uses existing dynamic query infrastructure.
    """
    try:
        if not pure_info_summary_agent:
            raise HTTPException(
                status_code=503,
                detail="Summary agent not available. Check Neo4j and OpenAI configuration."
            )
        
        # Generate summary using single question approach
        result = pure_info_summary_agent.generate_summary(alert_id)
        
        # Add context enhancement if provided and result was limited
        if (not result.get('success', False) and context_data):
            print(f"No graph data found, could use context for {alert_id}")
            try:
                flexible_input = FlexibleAlertInput(**context_data)
                result['metadata'] = result.get('metadata', {})
                result['metadata']['context_available'] = {
                    'context_alert_id': flexible_input.alert_id,
                    'context_fields': list(flexible_input.to_legacy_format().keys()),
                    'note': 'Context data available but graph query returned no results'
                }
            except Exception as e:
                pass
        
        return JSONResponse(content=result)
        
    except Exception as e:
        print(f"Fast summary error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))   
    
@app.on_event("shutdown")
def shutdown_event():
    """Cleanup on shutdown"""
    if neo4j_driver:
        neo4j_driver.close()

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    neo4j_status = False
    if neo4j_driver:
        try:
            neo4j_driver.verify_connectivity()
            neo4j_status = True
        except Exception:
            neo4j_status = False
    
    return {
        "status": "healthy",
        "neo4j_connected": neo4j_status,
        "openai_configured": OPENAI_API_KEY is not None,
        "graph_manager_ready": graph_manager is not None,
        "threat_analyzer_ready": threat_analyzer is not None,
        "timestamp": datetime.now().isoformat()
    }


class OptimizedFirewallSummaryAgent:
    """Optimized firewall summary agent with parallel data extraction for speed"""
    
    def __init__(self, neo4j_url: str, neo4j_username: str, neo4j_password: str, openai_api_key: str):
        # Initialize FirewallAgenticGraphRAG for data access
        self.firewall_investigator = FirewallAgenticGraphRAG(
            neo4j_url=neo4j_url,
            neo4j_username=neo4j_username,
            neo4j_password=neo4j_password,
            openai_api_key=openai_api_key
        )
        
        self.llm = ChatOpenAI(
            temperature=0,
            api_key=openai_api_key,
            model="gpt-4o-mini"
        )
        
        # Parallel processing executor
        self.executor = ThreadPoolExecutor(max_workers=4)
    
    def generate_summary(self, alert_id: str) -> Dict[str, Any]:
        """Generate summary using parallel data extraction"""
        
        print(f"Generating optimized firewall summary for alert: {alert_id}")
        start_time = datetime.now()
        
        try:
            # Set investigation context
            self.firewall_investigator.firewall_investigation_context = {"alert_id": alert_id, "mode": "summary"}
            self.firewall_investigator.firewall_question_cache = set()
            
            # Execute parallel data extraction
            comprehensive_info = self._extract_data_parallel(alert_id)
            
            if self.firewall_investigator._is_empty_result(comprehensive_info):
                return {
                    "success": False,
                    "alert_id": alert_id,
                    "error": "No information found for this firewall alert ID",
                    "timestamp": datetime.now().isoformat()
                }
            
            # Generate summary from extracted data
            summary = self._create_summary_from_info(comprehensive_info, alert_id)
            
            generation_time = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return {
                "success": True,
                "alert_id": alert_id,
                "summary": summary,
                "metadata": {
                    "generation_time_ms": generation_time,
                    "method": "Optimized Parallel Firewall Summary",
                    "info_length": len(comprehensive_info),
                    "parallel_processing": True
                },
                "raw_information": comprehensive_info,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"Optimized firewall summary error: {str(e)}")
            return {
                "success": False,
                "alert_id": alert_id,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        finally:
            # Cleanup
            try:
                self.executor.shutdown(wait=False)
            except:
                pass
    
    def _extract_data_parallel(self, alert_id: str) -> str:
        """Extract firewall data using parallel processing"""
        
        print(f"Starting parallel data extraction for {alert_id}")
        
        # Submit parallel extraction tasks
        futures = {
            self.executor.submit(self._extract_cypher_data, alert_id): "cypher",
            self.executor.submit(self._extract_network_security_data, alert_id): "network_security",
            self.executor.submit(self._extract_malicious_download_data, alert_id): "malicious_download",
            self.executor.submit(self._extract_policy_data, alert_id): "policy"
        }
        
        # Collect results as they complete
        results = {}
        for future in as_completed(futures, timeout=30):
            data_type = futures[future]
            try:
                result = future.result(timeout=10)
                if result and not self.firewall_investigator._is_empty_result(result):
                    results[data_type] = result
                    print(f"Parallel extraction succeeded: {data_type}")
                else:
                    print(f"Parallel extraction empty: {data_type}")
            except Exception as e:
                print(f"Parallel extraction failed: {data_type} - {e}")
                continue
        
        # Combine results
        if results:
            combined = "\n\n".join([f"{data_type.upper()}: {data}" for data_type, data in results.items()])
            print(f"Combined parallel results: {len(combined)} chars from {len(results)} sources")
            return combined
        else:
            print("All parallel extractions failed")
            return ""
    
    def _extract_cypher_data(self, alert_id: str) -> str:
        """Extract data using Cypher queries"""
        try:
            intent = f"Find comprehensive firewall alert information for {alert_id} including endpoints, files, and network details"
            return self.firewall_investigator._execute_firewall_cypher_query(intent, alert_id)
        except Exception as e:
            print(f"Cypher extraction error: {e}")
            return ""
    
    def _extract_network_security_data(self, alert_id: str) -> str:
        """Extract network security analysis data"""
        try:
            return self.firewall_investigator._firewall_network_security_analysis_tool(alert_id)
        except Exception as e:
            print(f"Network security extraction error: {e}")
            return ""
    
    def _extract_malicious_download_data(self, alert_id: str) -> str:
        """Extract malicious download analysis data"""
        try:
            return self.firewall_investigator._firewall_malicious_download_tool("")
        except Exception as e:
            print(f"Malicious download extraction error: {e}")
            return ""
    
    def _extract_policy_data(self, alert_id: str) -> str:
        """Extract policy enforcement data"""
        try:
            return self.firewall_investigator._firewall_policy_enforcement_tool("")
        except Exception as e:
            print(f"Policy extraction error: {e}")
            return ""
    
    def _create_summary_from_info(self, info: str, alert_id: str) -> Dict[str, Any]:
        """Create structured summary with parallel processing for speed"""
        
        # Submit summary generation tasks in parallel
        summary_futures = {
            self.executor.submit(self._generate_executive_summary, info, alert_id): "executive_summary",
            self.executor.submit(self._extract_key_points, info): "key_points",
            self.executor.submit(self._assess_threat_from_info, info): "threat_assessment",
            self.executor.submit(self._extract_status_info, info): "status_info"
        }
        
        # Collect summary components
        summary_components = {}
        for future in as_completed(summary_futures, timeout=20):
            component_type = summary_futures[future]
            try:
                result = future.result(timeout=10)
                summary_components[component_type] = result
            except Exception as e:
                print(f"Summary component failed: {component_type} - {e}")
                # Provide fallbacks
                if component_type == "executive_summary":
                    summary_components[component_type] = f"Firewall alert {alert_id} detected security activity requiring analysis."
                elif component_type == "key_points":
                    summary_components[component_type] = ["Alert detected in firewall system"]
                elif component_type == "threat_assessment":
                    summary_components[component_type] = {"level": "MEDIUM", "reasoning": "Analysis incomplete"}
                elif component_type == "status_info":
                    summary_components[component_type] = {"Incident Status": "Unknown"}
        
        return {
            "executive_summary": summary_components.get("executive_summary", f"Firewall alert {alert_id} analysis"),
            "key_points": summary_components.get("key_points", ["Alert information processed"]),
            "threat_assessment": summary_components.get("threat_assessment", {"level": "MEDIUM", "reasoning": "Standard assessment"}),
            "status_information": summary_components.get("status_info", {"Incident Status": "Unknown"}),
            "information_source": "Parallel firewall data extraction"
        }
    
    def _generate_executive_summary(self, info: str, alert_id: str) -> str:
        """Generate executive summary (optimized for parallel execution)"""
        
        summary_prompt = f"""
        Create a concise 2-3 sentence executive summary for firewall alert {alert_id}:
        
        {info[:2000]}  # Limit input for speed
        
        Focus on: what happened, threat level, network details. Be direct and informative.
        """
        
        try:
            response = self.llm.invoke(summary_prompt)
            return response.content.strip()
        except Exception as e:
            lines = info.split('\n')[:2]
            return f"Firewall alert {alert_id}: {' '.join(lines)}"
    
    def _extract_key_points(self, info: str) -> List[str]:
        """Extract key points (optimized for parallel execution)"""
        
        key_points_prompt = f"""
        Extract 4-5 key bullet points from this firewall information:
        
        {info[:1500]}  # Limit input for speed
        
        Focus on specific details: IP addresses, files, protocols, security findings.
        Return only bullet points, no other text.
        """
        
        try:
            response = self.llm.invoke(key_points_prompt)
            points = response.content.strip().split('\n')
            clean_points = []
            for point in points:
                clean_point = point.strip().lstrip('•').lstrip('-').lstrip('*').strip()
                if clean_point and len(clean_point) > 10:
                    clean_points.append(clean_point)
            return clean_points[:5]  # Limit for speed
        except Exception as e:
            sentences = info.split('.')[:3]
            return [sentence.strip() for sentence in sentences if len(sentence.strip()) > 15]
    
    def _assess_threat_from_info(self, info: str) -> Dict[str, Any]:
        """Assess threat level (optimized for parallel execution)"""
        
        info_lower = info.lower()
        
        # Quick threat assessment
        threat_words = ['malicious', 'blocked', 'denied', 'attack', 'exploit', 'suspicious', 'violation']
        benign_words = ['clean', 'legitimate', 'allowed', 'valid', 'normal']
        
        threat_count = sum(1 for word in threat_words if word in info_lower)
        benign_count = sum(1 for word in benign_words if word in info_lower)
        
        if threat_count > benign_count and threat_count >= 2:
            level = "HIGH"
            reasoning = f"Multiple threat indicators ({threat_count})"
        elif benign_count > threat_count and benign_count >= 2:
            level = "LOW"
            reasoning = f"Multiple benign indicators ({benign_count})"
        else:
            level = "MEDIUM"
            reasoning = f"Mixed indicators (threat: {threat_count}, benign: {benign_count})"
        
        return {
            "level": level,
            "reasoning": reasoning,
            "threat_indicators": threat_count,
            "benign_indicators": benign_count
        }
    
    def _extract_status_info(self, info: str) -> Dict[str, str]:
        """Extract status information (optimized for parallel execution)"""
        
        # Quick status extraction using keyword matching
        info_lower = info.lower()
        
        status_dict = {}
        
        # Quick incident status detection
        if 'resolved' in info_lower or 'closed' in info_lower:
            status_dict['Incident Status'] = 'Resolved'
        elif 'open' in info_lower or 'active' in info_lower:
            status_dict['Incident Status'] = 'Active'
        else:
            status_dict['Incident Status'] = 'Unknown'
        
        # Quick remediation status
        if 'quarantined' in info_lower or 'blocked' in info_lower:
            status_dict['Remediation Status'] = 'Mitigated'
        elif 'monitoring' in info_lower:
            status_dict['Remediation Status'] = 'Monitoring'
        else:
            status_dict['Remediation Status'] = 'Unknown'
        
        # Quick detection status
        if 'detected' in info_lower or 'alert' in info_lower:
            status_dict['Detection Status'] = 'Detected'
        else:
            status_dict['Detection Status'] = 'Unknown'
        
        return status_dict

# Optimized endpoint
@app.post("/summary-firewall/{alert_id}")
async def generate_optimized_firewall_summary(
    alert_id: str,
    context_data: dict = Body(None)
):
    """
    Generate optimized firewall summary using parallel data extraction and processing.
    Designed for speed while maintaining accuracy.
    """
    try:
        if not all([NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD, OPENAI_API_KEY]):
            raise HTTPException(
                status_code=503,
                detail="Optimized firewall summary agent not available."
            )
        
        start_time = time.time()
        
        # Create optimized agent
        optimized_agent = OptimizedFirewallSummaryAgent(
            neo4j_url=NEO4J_URI,
            neo4j_username=NEO4J_USERNAME,
            neo4j_password=NEO4J_PASSWORD,
            openai_api_key=OPENAI_API_KEY
        )
        
        try:
            # Generate summary with parallel processing
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: optimized_agent.generate_summary(alert_id)
            )
            
            # Add execution metrics
            execution_time = time.time() - start_time
            if 'metadata' in result:
                result['metadata']['total_execution_time'] = round(execution_time, 2)
                result['metadata']['optimization_used'] = True
            
            # Add context enhancement if needed
            if (not result.get('success', False) and context_data):
                print(f"No firewall data found, context available for {alert_id}")
                result['context_available'] = {
                    'provided': True,
                    'context_keys': list(context_data.keys()) if context_data else [],
                    'note': 'Context data available but graph query failed'
                }
            
            return JSONResponse(content=result)
        
        finally:
            # Cleanup
            try:
                if hasattr(optimized_agent, 'firewall_investigator'):
                    if hasattr(optimized_agent.firewall_investigator, 'firewall_investigation_context'):
                        optimized_agent.firewall_investigator.firewall_investigation_context.clear()
            except:
                pass
        
    except Exception as e:
        print(f"Optimized firewall summary error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    
def create_dynamic_gnn_system(neo4j_driver, database: str = "neo4j") -> bool:
    """
    Create and initialize the complete dynamic GNN system
    """
    success = initialize_dynamic_gnn(neo4j_driver, database)
    
    if success:
        print("Dynamic GNN System initialized successfully")
        print("Available endpoints:")
        print("  POST /gnn/predict_dynamic - Make predictions")
        print("  POST /gnn/analyze_relationships - Analyze relationships")
        print("  GET  /gnn/model_info - Get model information")
        print("  POST /gnn/test_subgraph - Test subgraph discovery")
    else:
        print("Failed to initialize Dynamic GNN System")
    
    return success



try:
    if neo4j_driver:
        create_dynamic_gnn_system(neo4j_driver, NEO4J_DATABASE)
        add_dynamic_gnn_routes(app)
    else:
        print("Dynamic GNN: Skipped init because Neo4j driver is not available")
except Exception as e:
    print(f"Failed to initialize Dynamic GNN system: {e}")


if __name__ == "__main__":
    uvicorn.run("app-firewall-parallel:app", host="0.0.0.0", port=2000, reload=True)