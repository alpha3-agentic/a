#!/usr/bin/env python3

import asyncio
import json
import logging
import os
import sys
import time
import pathlib
from typing import Any, Dict, List, Optional, Sequence
import ipaddress

# Load environment variables from .env if present
from dotenv import load_dotenv
load_dotenv()

# MCP imports
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent, CallToolRequest, CallToolResult

# HTTP and validation
import httpx
from pydantic import BaseModel, Field

# Configure logging to stderr (MCP requirement)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

# VirusTotal Configuration
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3/files/"

# Check Point Reputation Service Configuration - FIXED ENDPOINTS
CP_AUTH_URL = "https://rep.checkpoint.com/rep-auth/service/v1.0/request"
CP_FILE_URL = "https://rep.checkpoint.com/file-rep/service/v3.0/query"
CP_API_KEY = os.getenv("CP_API_KEY", "")
CP_TOKEN_CACHE = pathlib.Path.home() / ".cp_rep_token"

# Cyberint Configuration
CYBERINT_BASE_URL = os.getenv("CYBERINT_BASE_URL", "https://chkp-india.cyberint.io/ioc/api/v1")
CYBERINT_ACCESS_TOKEN = os.getenv("CYBERINT_ACCESS_TOKEN", "")

# AbuseIPDB Configuration
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"

# SentinelOne Configuration
S1_API_TOKEN = os.getenv("S1_API_TOKEN", "")
S1_CONSOLE_URL = os.getenv("S1_CONSOLE_URL", "")



# Alerts directory
ALERTS_DIR = os.path.join(os.path.dirname(__file__), "Alerts")

class FileInfo(BaseModel):
    path: Optional[str] = None
    sha256: Optional[str] = None
    sha1: Optional[str] = None
    md5: Optional[str] = None
    extension: Optional[str] = None
    size: Optional[int] = None

class Alert(BaseModel):
    id: str
    source_path: str
    file: FileInfo
    meta: Dict[str, Any] = Field(default_factory=dict)

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def safe_get(data: Dict[str, Any], path: List[str]) -> Optional[Any]:
    """Safely extract nested values from dictionary."""
    current = data
    for key in path:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None
    return current

def choose_best_hash(sha256: Optional[str], sha1: Optional[str], md5: Optional[str]) -> tuple[str, str]:
    """Choose the best available hash for lookup."""
    if sha256:
        return "sha256", sha256
    if sha1:
        return "sha1", sha1
    if md5:
        return "md5", md5
    return "", ""

def parse_alert_file(file_path: str) -> Optional[Alert]:
    """Parse a single alert JSON file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to read alert file {file_path}: {e}")
        return None

    # Extract ID from JSON or use filename
    file_id = (
        safe_get(data, ["id"]) \
        or safe_get(data, ["alert_id"]) \
        or os.path.splitext(os.path.basename(file_path))[0]
    )

    # Extract hashes from various EDR formats
    sha256 = (
        safe_get(data, ["file", "hashes", "sha256"]) \
        or safe_get(data, ["file", "sha256"]) \
        or safe_get(data, ["sha256"]) \
        or safe_get(data, ["threatInfo", "sha256"])
    )
    
    sha1 = (
        safe_get(data, ["file", "hashes", "sha1"]) \
        or safe_get(data, ["file", "sha1"]) \
        or safe_get(data, ["sha1"]) \
        or safe_get(data, ["threatInfo", "sha1"])
    )
    
    md5 = (
        safe_get(data, ["file", "hashes", "md5"]) \
        or safe_get(data, ["file", "md5"]) \
        or safe_get(data, ["md5"]) \
        or safe_get(data, ["threatInfo", "md5"])
    )

    # Extract file metadata
    file_path_data = safe_get(data, ["file", "path"]) or safe_get(data, ["file_path"])
    extension = safe_get(data, ["file", "extension"]) or safe_get(data, ["file_extension"])
    size = safe_get(data, ["file", "size"]) or safe_get(data, ["file_size"])

    # Extract metadata
    meta = {}
    for key in ("detected_time", "threat_detected_time", "vendor", "source_vendor"):
        value = safe_get(data, [key]) or safe_get(data, ["meta", key])
        if value is not None:
            meta[key] = value
    
    # Preserve threatInfo
    threat_info = safe_get(data, ["threatInfo"])
    if threat_info:
        meta["threatInfo"] = threat_info

    return Alert(
        id=str(file_id),
        source_path=file_path,
        file=FileInfo(
            path=file_path_data,
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            extension=extension,
            size=size,
        ),
        meta=meta,
    )

def scan_alerts(folder: str, limit: int = 100) -> List[Alert]:
    """Scan a folder for alert JSON files and parse them."""
    if not os.path.exists(folder):
        logger.warning(f"Alerts folder does not exist: {folder}")
        return []
        
    try:
        files = sorted([f for f in os.listdir(folder) if f.endswith(".json")])
    except Exception as e:
        logger.error(f"Failed to list files in {folder}: {e}")
        return []
    
    alerts = []
    for filename in files[:limit]:
        alert = parse_alert_file(os.path.join(folder, filename))
        if alert:
            alerts.append(alert)
    
    return alerts

# =============================================================================
# VIRUSTOTAL FUNCTIONS
# =============================================================================

async def fetch_vt_report(hash_value: str, api_key: str) -> Dict[str, Any]:
    """Fetch VirusTotal report with proper error handling."""
    if not api_key:
        return {
            "found": False,
            "error": "api_key_not_configured",
            "message": "Please set VIRUSTOTAL_API_KEY in your .env"
        }
    
    headers = {"x-apikey": api_key}
    url = f"{VT_BASE_URL}{hash_value}"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers)

            if response.status_code == 200:
                return {"found": True, "status": 200, "json": response.json()}
            elif response.status_code == 404:
                return {"found": False, "status": 404, "message": "File not found in VirusTotal"}
            elif response.status_code == 403:
                return {
                    "found": False,
                    "status": 403,
                    "error": "api_forbidden",
                    "message": "VirusTotal API key is invalid"
                }
            else:
                return {
                    "found": False,
                    "error": "http_error",
                    "message": f"HTTP {response.status_code}: {response.text}"
                }

    except Exception as e:
        return {
            "found": False,
            "error": "request_failed",
            "message": f"Failed to query VirusTotal: {str(e)}"
        }

# =============================================================================
# CHECK POINT FUNCTIONS - FIXED TO MATCH WORKING SCRIPT
# =============================================================================

def _cached_token() -> Optional[str]:
    """Check for cached token - matching working script logic"""
    if CP_TOKEN_CACHE.exists():
        try:
            tok = CP_TOKEN_CACHE.read_text().strip()
            if tok.startswith("exp="):
                # Extract expiration time from token
                exp = int(tok.split("~")[0].split("=")[1])
                if exp > int(time.time()) + 60:
                    return tok
            else:
                return tok
        except Exception as e:
            logger.warning(f"Failed reading cached token: {e}")
    return None

async def _fetch_token(api_key: str) -> Dict[str, Any]:
    """Fetch new token from Check Point - matching working script"""
    logger.info("Fetching new Check Point token...")
    
    try:
        # Use Client-Key header like in working script
        headers = {"Client-Key": api_key}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(CP_AUTH_URL, headers=headers)
            
            if response.status_code == 200:
                token = response.text.strip().strip('"')
                if token:
                    # Cache the token
                    try:
                        CP_TOKEN_CACHE.write_text(token)
                        logger.info("Token cached successfully")
                    except Exception as e:
                        logger.warning(f"Failed to cache token: {e}")
                    
                    return {"success": True, "token": token, "cached": False}
                else:
                    return {"success": False, "status": 200, "message": "Empty token returned"}
            else:
                return {
                    "success": False, 
                    "status": response.status_code, 
                    "message": f"Auth failed: {response.text}"
                }
                
    except Exception as e:
        return {"success": False, "error": "request_failed", "message": str(e)}

async def obtain_cp_token() -> Dict[str, Any]:
    """Obtain Check Point token, using cache when possible"""
    if not CP_API_KEY:
        return {
            "success": False,
            "error": "cp_api_key_not_configured",
            "message": "Please set CP_API_KEY in your environment or .env",
        }

    # Check cache first
    cached = _cached_token()
    if cached:
        return {"success": True, "token": cached, "cached": True}

    # Fetch new token
    return await _fetch_token(CP_API_KEY)

async def fetch_cp_file_reputation(hash_value: str) -> Dict[str, Any]:
    """Query Check Point File Reputation - matching working script logic"""
    token_result = await obtain_cp_token()
    if not token_result.get("success"):
        return {"found": False, "auth_error": token_result}

    token = token_result.get("token", "")
    
    # Use the same headers as working script
    headers = {
        "Content-Type": "application/json",
        "Client-Key": CP_API_KEY,
        "token": token
    }
    
    # Use same request format as working script
    params = {"resource": hash_value}
    body = {"request": [{"resource": hash_value}]}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(CP_FILE_URL, headers=headers, params=params, json=body)
            
            if response.status_code == 403:
                # Token expired, refresh and retry
                logger.info("Token expired, refreshing...")
                new_token_result = await _fetch_token(CP_API_KEY)
                if new_token_result.get("success"):
                    headers["token"] = new_token_result["token"]
                    response = await client.post(CP_FILE_URL, headers=headers, params=params, json=body)
                else:
                    return {"found": False, "error": "token_refresh_failed", "details": new_token_result}
            
            if response.status_code == 200:
                resp_json = response.json()
                resp_list = resp_json.get("response", [])
                if resp_list:
                    result = resp_list[0]
                    if "resource" not in result:
                        result["resource"] = hash_value
                    return {"found": True, "status": 200, "json": result}
                else:
                    return {"found": False, "status": 200, "message": "Empty response", "json": {"resource": hash_value, "no_data": True}}
            else:
                return {
                    "found": False,
                    "status": response.status_code,
                    "message": f"CP query failed: {response.status_code}",
                    "response": response.text
                }
                
    except Exception as e:
        return {"found": False, "error": "request_failed", "message": str(e)}
# =============================================================================
# CYBERINT FUNCTIONS
# =============================================================================

def _cyberint_summarize(obj: Any) -> Dict[str, Any]:
    """
    Best-effort summary across possible response shapes.
    Tries to pick out risk / severity / classification; collects any IOC values seen.
    """
    out = {"risk": None, "severity": None, "classification": None, "matches": []}
    
    def walk(x: Any):
        if isinstance(x, dict):
            # normalize for matching but preserve values
            low = {str(k).lower(): k for k in x.keys()}
            for k in ("risk", "score", "risk_score"):
                if out["risk"] is None and k in low:
                    out["risk"] = x[low[k]]
            for k in ("severity", "sev"):
                if out["severity"] is None and k in low:
                    out["severity"] = x[low[k]]
            for k in ("classification", "class", "verdict", "label", "category"):
                if out["classification"] is None and k in low:
                    out["classification"] = x[low[k]]
            if "ioc" in low:
                out["matches"].append(x[low["ioc"]])
            if "value" in low:
                out["matches"].append(x[low["value"]])
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    
    walk(obj)
    return out

async def fetch_cyberint_report(sha256: str) -> Dict[str, Any]:
    """Query Cyberint for a file SHA-256."""
    if not sha256:
        return {"found": False, "error": "no_sha256", "message": "SHA-256 hash is required"}
    
    if not CYBERINT_ACCESS_TOKEN:
        return {
            "found": False,
            "error": "token_not_configured",
            "message": "Please set CYBERINT_ACCESS_TOKEN in your .env"
        }
    
    url = f"{CYBERINT_BASE_URL.rstrip('/')}/file/sha256"
    headers = {
        "Accept": "application/json",
        "Cookie": f"access_token={CYBERINT_ACCESS_TOKEN}",
    }
    params = {"value": sha256}
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers, params=params)
            
            try:
                data = response.json()
            except Exception:
                return {
                    "found": False,
                    "error": "non_json_response",
                    "status": response.status_code,
                    "message": f"Non-JSON response: {response.text[:200]}"
                }
            
            if response.status_code == 200:
                return {
                    "found": True,
                    "status": 200,
                    "endpoint": "GET file/sha256",
                    "summary": _cyberint_summarize(data),
                    "json": data
                }
            elif response.status_code in (401, 403):
                return {
                    "found": False,
                    "status": response.status_code,
                    "error": "unauthorized",
                    "message": "Cyberint access token is invalid or expired",
                    "json": data
                }
            else:
                return {
                    "found": False,
                    "status": response.status_code,
                    "error": f"http_{response.status_code}",
                    "message": f"HTTP {response.status_code}",
                    "json": data
                }
                
    except Exception as e:
        return {
            "found": False,
            "error": "request_failed",
            "message": f"Failed to query Cyberint: {str(e)}"
        }

# =============================================================================
# ABUSEIPDB FUNCTIONS
# =============================================================================

def extract_ip_from_alert(alert_data: Dict[str, Any]) -> Optional[str]:
    """Extract an IP address from diverse alert formats.
    Checks flat and nested fields and validates using ipaddress.
    """

    def _maybe_ip(value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        candidate = str(value)
        # Strip surrounding brackets and split host:port if present
        if candidate.startswith("[") and candidate.endswith("]"):
            candidate = candidate[1:-1]
        if ":" in candidate and candidate.count(":") == 1 and candidate.replace(":", "").replace(".", "").isdigit():
            # naive split for host:port (avoid IPv6 which has multiple ':')
            candidate = candidate.split(":", 1)[0]
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except Exception:
            return None

    # 1) Flat src/dst
    for key in ("src", "dst"):
        ip_val = _maybe_ip(alert_data.get(key))
        if ip_val:
            return ip_val

    # 2) Nested common fields
    nested_paths = [
        ["src_endpoint", "ip"],
        ["dst_endpoint", "ip"],
        ["proxy", "src", "ip"],
        ["http", "host"],  # may include host:port
        ["url", "domain"],  # may include host:port
    ]

    for path in nested_paths:
        cur: Any = alert_data
        for seg in path:
            if isinstance(cur, dict) and seg in cur:
                cur = cur[seg]
            else:
                cur = None
                break
        ip_val = _maybe_ip(cur) if isinstance(cur, (str, int)) else None
        if ip_val:
            return ip_val

    return None

async def fetch_abuseipdb_report(ip_address: str) -> Dict[str, Any]:
    """Query AbuseIPDB for IP reputation."""
    if not ip_address:
        return {"found": False, "error": "no_ip", "message": "IP address is required"}
    
    if not ABUSEIPDB_API_KEY:
        return {
            "found": False,
            "error": "api_key_not_configured",
            "message": "Please set ABUSEIPDB_API_KEY in your .env"
        }
    
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": True}
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(ABUSEIPDB_API_URL, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                
                # Filter to keep only required fields
                filtered_data = {
                    "ipAddress": data.get("ipAddress"),
                    "totalReports": data.get("totalReports"),
                    "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                    "countryCode": data.get("countryCode"),
                    "domain": data.get("domain"),
                    "isTor": data.get("isTor"),
                    "lastReportedAt": data.get("lastReportedAt")
                }
                
                return {
                    "found": True,
                    "status": 200,
                    "json": filtered_data
                }
            elif response.status_code == 403:
                return {
                    "found": False,
                    "status": 403,
                    "error": "api_forbidden",
                    "message": "AbuseIPDB API key is invalid"
                }
            elif response.status_code == 429:
                return {
                    "found": False,
                    "status": 429,
                    "error": "rate_limited",
                    "message": "AbuseIPDB rate limit exceeded"
                }
            else:
                return {
                    "found": False,
                    "status": response.status_code,
                    "error": f"http_{response.status_code}",
                    "message": f"HTTP {response.status_code}: {response.text}"
                }
                
    except Exception as e:
        return {
            "found": False,
            "error": "request_failed",
            "message": f"Failed to query AbuseIPDB: {str(e)}"
        }




# =============================================================================
# SENTINELONE FUNCTIONS - ADD THESE TO YOUR MCP SERVER
# =============================================================================

def extract_hostname_from_alert(alert_data: Dict[str, Any]) -> Optional[str]:
    """Extract hostname from various alert formats."""
    # Direct hostname field
    hostname = alert_data.get("hostname")
    if hostname:
        return hostname
    
    # Nested in device object
    device = alert_data.get("device")
    if device and isinstance(device, dict):
        hostname = device.get("hostname")
        if hostname:
            return hostname
    
    # Other common locations
    for path in [
        ["endpoint", "hostname"],
        ["agent", "hostname"], 
        ["host", "name"],
        ["computer_name"],
        ["machine_name"]
    ]:
        current = alert_data
        for key in path:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                current = None
                break
        if current and isinstance(current, str):
            return current
    
    return None

async def fetch_s1_assets_by_hostname(hostname: str) -> Dict[str, Any]:
    """Query SentinelOne XDR Assets API by hostname."""
    if not hostname:
        return {"found": False, "error": "no_hostname", "message": "Hostname is required"}
    
    if not S1_API_TOKEN:
        return {
            "found": False,
            "error": "token_not_configured", 
            "message": "Please set S1_API_TOKEN in your .env"
        }
    
    if not S1_CONSOLE_URL:
        return {
            "found": False,
            "error": "console_url_not_configured",
            "message": "Please set S1_CONSOLE_URL in your .env"
        }
    
    # Build URL - match your working script exactly
    url = f"{S1_CONSOLE_URL.rstrip('/')}/web/api/v2.1/xdr/assets"
    headers = {
        "Authorization": f"ApiToken {S1_API_TOKEN}",
        "Content-Type": "application/json"
    }
    params = {"names": hostname}
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json().get("data", [])
                
                # Filter the data exactly like your working script
                filtered_assets = []
                for asset in data:
                    filtered_assets.append({
                        "tags": asset.get("tags", []),
                        "alerts": asset.get("alerts", []), 
                        "alertsCount": asset.get("alertsCount", []),
                        "subCategory": asset.get("subCategory", None)
                    })
                
                return {
                    "found": True,
                    "status": 200,
                    "hostname_queried": hostname,
                    "assets_count": len(filtered_assets),
                    "json": filtered_assets
                }
            elif response.status_code == 401:
                return {
                    "found": False,
                    "status": 401,
                    "error": "unauthorized",
                    "message": "SentinelOne API token is invalid"
                }
            elif response.status_code == 403:
                return {
                    "found": False, 
                    "status": 403,
                    "error": "forbidden",
                    "message": "Insufficient permissions for SentinelOne XDR Assets API"
                }
            elif response.status_code == 404:
                return {
                    "found": False,
                    "status": 404, 
                    "error": "not_found",
                    "message": f"No assets found for hostname: {hostname}"
                }
            else:
                return {
                    "found": False,
                    "status": response.status_code,
                    "error": f"http_{response.status_code}",
                    "message": f"HTTP {response.status_code}: {response.text[:200]}"
                }
                
    except Exception as e:
        return {
            "found": False,
            "error": "request_failed", 
            "message": f"Failed to query SentinelOne: {str(e)}"
        }
# =============================================================================
# MCP SERVER SETUP
# =============================================================================

# Create MCP server
server = Server("edr-enrichment")

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available MCP tools."""
    return [
        Tool(
            name="list_alerts",
            description="List EDR alerts from the alerts directory",
            inputSchema={
                "type": "object",
                "properties": {
                    "folder": {
                        "type": "string",
                        "description": "Directory to scan for alerts (optional)"
                    },
                    "limit": {
                        "type": "integer", 
                        "description": "Maximum number of alerts to return",
                        "default": 100
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="enrich_virustotal",
            description="Enrich alert with VirusTotal threat intelligence only",
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "ID of the alert to enrich"
                    },
                    "folder": {
                        "type": "string",
                        "description": "Directory to search for alert (optional)"
                    }
                },
                "required": ["alert_id"]
            }
        ),
        Tool(
            name="enrich_checkpoint",
            description="Enrich alert with Check Point reputation data only",
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "ID of the alert to enrich"
                    },
                    "folder": {
                        "type": "string",
                        "description": "Directory to search for alert (optional)"
                    }
                },
                "required": ["alert_id"]
            }
        ),
        Tool(
            name="enrich_alert_combined",
            description="Enrich alert with both VirusTotal Check Point AbuseIPDB data",
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "ID of the alert to enrich"
                    },
                    "folder": {
                        "type": "string",
                        "description": "Directory to search for alert (optional)"
                    }
                },
                "required": ["alert_id"]
            }
        ),
        Tool(
            name="checkpoint_status",
            description="Diagnose Check Point integration status and test authentication",
            inputSchema={
                "type": "object",
                "properties": {
                    "test_hash": {
                        "type": "string",
                        "description": "Optional file hash to test CP reputation query"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="enrich_cyberint",
            description="Enrich alert with Cyberint threat intelligence only",
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "ID of the alert to enrich"
                    },
                    "folder": {
                        "type": "string",
                        "description": "Directory to search for alert (optional)"
                    }
                },
                "required": ["alert_id"]
            }
        ),
        Tool(
            name="cyberint_status",
            description="Diagnose Cyberint integration status and test authentication",
            inputSchema={
                "type": "object",
                "properties": {
                    "test_hash": {
                        "type": "string",
                        "description": "Optional file hash to test Cyberint query"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="enrich_abuseipdb",
            description="Enrich alert with AbuseIPDB IP reputation data only",
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "ID of the alert to enrich"
                    },
                    "folder": {
                        "type": "string",
                        "description": "Directory to search for alert (optional)"
                    }
                },
                "required": ["alert_id"]
            }
        ),
        Tool(
            name="enrich_s1_assets",
            description="Enrich alert with SentinelOne Assets data by hostname",
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "ID of the alert to enrich"
                    },
                    "folder": {
                        "type": "string",
                        "description": "Directory to search for alert (optional)"
                    }
                },
                "required": ["alert_id"]
            }
        ),
        Tool(
            name="s1_status",
            description="Diagnose SentinelOne integration status and test query",
            inputSchema={
                "type": "object",
                "properties": {
                    "test_hostname": {
                        "type": "string",
                        "description": "Optional hostname to test S1 assets query"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="abuseipdb_status",
            description="Diagnose AbuseIPDB integration status and test authentication",
            inputSchema={
                "type": "object",
                "properties": {
                    "test_ip": {
                        "type": "string",
                        "description": "Optional IP address to test AbuseIPDB query"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="create_sample_alert",
            description="Create a sample alert file for testing",
            inputSchema={
                "type": "object", 
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "ID for the sample alert",
                        "default": "sample-001"
                    }
                },
                "required": []
            }
        )
    ]
        
@server.call_tool()
async def call_tool(name: str, arguments: dict) -> Sequence[TextContent]:
    """Handle tool calls."""
    logger.info(f"Tool called: {name} with arguments: {arguments}")
    
    try:
        if name == "list_alerts":
            folder = arguments.get("folder", ALERTS_DIR)
            limit = arguments.get("limit", 100)
            
            alerts = scan_alerts(folder, limit)
            
            result = {
                "success": True,
                "count": len(alerts),
                "folder_scanned": folder,
                "alerts": [
                    {
                        "id": alert.id,
                        "file_path": alert.file.path,
                        "sha256": alert.file.sha256,
                        "sha1": alert.file.sha1,
                        "md5": alert.file.md5,
                        "extension": alert.file.extension,
                        "size": alert.file.size,
                        "source_path": alert.source_path,
                    }
                    for alert in alerts
                ]
            }
            
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        elif name == "enrich_cyberint":
            alert_id = arguments["alert_id"]
            folder = arguments.get("folder", ALERTS_DIR)
            
            # Find the alert
            alert_path = os.path.join(folder, f"{alert_id}.json")
            alert = None
            
            if os.path.exists(alert_path):
                alert = parse_alert_file(alert_path)
            else:
                # Fallback: scan directory
                alerts = scan_alerts(folder, 1000)
                alert = next((a for a in alerts if a.id == alert_id), None)
            
            if not alert:
                return [TextContent(type="text", text=json.dumps({
                    "error": "alert_not_found",
                    "alert_id": alert_id,
                    "searched_in": folder
                }))]
            
            # Get SHA-256 hash (Cyberint requires SHA-256)
            sha256 = alert.file.sha256
            
            if not sha256:
                return [TextContent(type="text", text=json.dumps({
                    "error": "no_sha256_available",
                    "alert_id": alert_id,
                    "message": "Cyberint requires SHA-256 hash, but none found in alert"
                }))]
            
            # Query Cyberint
            cyb_result = await fetch_cyberint_report(sha256)
            
            # Save result
            cyb_dir = os.path.join(ALERTS_DIR, "Cyberint")
            os.makedirs(cyb_dir, exist_ok=True)
            cyb_saved_path = os.path.join(cyb_dir, f"{alert_id}.json")
            
            try:
                with open(cyb_saved_path, "w", encoding="utf-8") as f:
                    json.dump(cyb_result, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save Cyberint result: {e}")
                cyb_saved_path = None
            
            result = {
                "success": True,
                "alert_id": alert_id,
                "hash_used": f"sha256: {sha256}",
                "cyberint": cyb_result,
                "saved_path": cyb_saved_path
            }
            
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "cyberint_status":
            test_hash = arguments.get("test_hash")
            
            status = {
                "cyberint_token_present": bool(CYBERINT_ACCESS_TOKEN),
                "cyberint_token_length": len(CYBERINT_ACCESS_TOKEN) if CYBERINT_ACCESS_TOKEN else 0,
                "cyberint_base_url": CYBERINT_BASE_URL,
                "endpoint": f"{CYBERINT_BASE_URL}/file/sha256"
            }
            
            # Test query if hash provided
            if test_hash:
                cyb_result = await fetch_cyberint_report(test_hash)
                status["test_hash"] = test_hash
                status["test_result"] = cyb_result
            
            return [TextContent(type="text", text=json.dumps(status, indent=2))]
            
        elif name == "enrich_virustotal":
            alert_id = arguments["alert_id"]
            folder = arguments.get("folder", ALERTS_DIR)
            
            # Find the alert
            alert_path = os.path.join(folder, f"{alert_id}.json")
            alert = None
            
            if os.path.exists(alert_path):
                alert = parse_alert_file(alert_path)
            else:
                # Fallback: scan directory
                alerts = scan_alerts(folder, 1000)
                alert = next((a for a in alerts if a.id == alert_id), None)
            
            if not alert:
                return [TextContent(type="text", text=json.dumps({
                    "error": "alert_not_found",
                    "alert_id": alert_id,
                    "searched_in": folder
                }))]
            
            # Get best hash
            algo, hash_value = choose_best_hash(alert.file.sha256, alert.file.sha1, alert.file.md5)
            
            if not hash_value:
                return [TextContent(type="text", text=json.dumps({
                    "error": "no_hash_available",
                    "alert_id": alert_id,
                    "message": "No file hash found in alert"
                }))]
            
            # Query VirusTotal
            vt_result = await fetch_vt_report(hash_value, VT_API_KEY)
            
            # Save result
            vt_dir = os.path.join(ALERTS_DIR, "VirusTotal")
            os.makedirs(vt_dir, exist_ok=True)
            vt_saved_path = os.path.join(vt_dir, f"{alert_id}.json")
            
            try:
                with open(vt_saved_path, "w", encoding="utf-8") as f:
                    json.dump(vt_result, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save VirusTotal result: {e}")
                vt_saved_path = None
            
            result = {
                "success": True,
                "alert_id": alert_id,
                "hash_used": f"{algo}: {hash_value}",
                "virustotal": vt_result,
                "saved_path": vt_saved_path
            }
            
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        elif name == "enrich_abuseipdb":
            alert_id = arguments["alert_id"]
            folder = arguments.get("folder", ALERTS_DIR)
            
            # Find the alert
            alert_path = os.path.join(folder, f"{alert_id}.json")
            alert = None
            
            if os.path.exists(alert_path):
                alert = parse_alert_file(alert_path)
            else:
                # Fallback: scan directory
                alerts = scan_alerts(folder, 1000)
                alert = next((a for a in alerts if a.id == alert_id), None)
            
            if not alert:
                return [TextContent(type="text", text=json.dumps({
                    "error": "alert_not_found",
                    "alert_id": alert_id,
                    "searched_in": folder
                }))]
            
            # Load original alert data to extract IP
            try:
                with open(alert.source_path, "r", encoding="utf-8") as f:
                    alert_data = json.load(f)
            except Exception as e:
                return [TextContent(type="text", text=json.dumps({
                    "error": "failed_to_read_alert",
                    "alert_id": alert_id,
                    "message": str(e)
                }))]
            
            # Extract IP address
            ip_address = extract_ip_from_alert(alert_data)
            
            if not ip_address:
                return [TextContent(type="text", text=json.dumps({
                    "error": "no_ip_available",
                    "alert_id": alert_id,
                    "message": "No IP address found in alert (checked 'src' and 'dst' fields)"
                }))]
            
            # Query AbuseIPDB
            abuse_result = await fetch_abuseipdb_report(ip_address)
            
            # Save result
            abuse_dir = os.path.join(ALERTS_DIR, "AbuseIPDB")
            os.makedirs(abuse_dir, exist_ok=True)
            abuse_saved_path = os.path.join(abuse_dir, f"{alert_id}.json")
            
            try:
                with open(abuse_saved_path, "w", encoding="utf-8") as f:
                    json.dump({
                        "alert_file": f"{alert_id}.json",
                        "ip_checked": ip_address,
                        "result": abuse_result
                    }, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save AbuseIPDB result: {e}")
                abuse_saved_path = None
            
            result = {
                "success": True,
                "alert_id": alert_id,
                "ip_checked": ip_address,
                "abuseipdb": abuse_result,
                "saved_path": abuse_saved_path
            }
            
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "abuseipdb_status":
            test_ip = arguments.get("test_ip")
            
            status = {
                "abuseipdb_api_key_present": bool(ABUSEIPDB_API_KEY),
                "abuseipdb_api_key_length": len(ABUSEIPDB_API_KEY) if ABUSEIPDB_API_KEY else 0,
                "abuseipdb_api_url": ABUSEIPDB_API_URL
            }
            
            # Test query if IP provided
            if test_ip:
                abuse_result = await fetch_abuseipdb_report(test_ip)
                status["test_ip"] = test_ip
                status["test_result"] = abuse_result
            
            return [TextContent(type="text", text=json.dumps(status, indent=2))]

        elif name == "enrich_s1_assets":
            alert_id = arguments["alert_id"]
            folder = arguments.get("folder", ALERTS_DIR)
            alert_path = os.path.join(folder, f"{alert_id}.json")
            alert = None
            if os.path.exists(alert_path):
                alert = parse_alert_file(alert_path)
            else:
                alerts = scan_alerts(folder, 1000)
                alert = next((a for a in alerts if a.id == alert_id), None)
            if not alert:
                return [TextContent(type="text", text=json.dumps({
                    "error": "alert_not_found",
                    "alert_id": alert_id,
                    "searched_in": folder
                }))]

            # Load original alert JSON to extract hostname
            try:
                with open(alert.source_path, "r", encoding="utf-8") as f:
                    alert_data = json.load(f)
            except Exception as e:
                return [TextContent(type="text", text=json.dumps({
                    "error": "failed_to_read_alert",
                    "alert_id": alert_id,
                    "message": str(e)
                }))]

            hostname = extract_hostname_from_alert(alert_data)
            if not hostname:
                return [TextContent(type="text", text=json.dumps({
                    "error": "no_hostname_available",
                    "alert_id": alert_id,
                    "message": "No hostname found in alert (checked 'hostname' and 'device.hostname')"
                }))]

            s1_result = await fetch_s1_assets_by_hostname(hostname)

            # Save
            s1_dir = os.path.join(ALERTS_DIR, "SentinelOne")
            os.makedirs(s1_dir, exist_ok=True)
            s1_saved_path = os.path.join(s1_dir, f"{alert_id}.json")
            try:
                with open(s1_saved_path, "w", encoding="utf-8") as f:
                    json.dump({
                        "alert_file": f"{alert_id}.json",
                        "hostname": hostname,
                        "result": s1_result
                    }, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save S1 result: {e}")
                s1_saved_path = None

            result = {
                "success": True,
                "alert_id": alert_id,
                "hostname": hostname,
                "sentinelone": s1_result,
                "saved_path": s1_saved_path
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "s1_status":
            test_hostname = arguments.get("test_hostname")
            status = {
                "s1_token_present": bool(S1_API_TOKEN),
                "s1_token_length": len(S1_API_TOKEN) if S1_API_TOKEN else 0,
                "s1_console_url": S1_CONSOLE_URL,
                "assets_endpoint": f"{S1_CONSOLE_URL.rstrip('/')}/web/api/v2.1/xdr/assets" if S1_CONSOLE_URL else None
            }
            if test_hostname:
                status["test_hostname"] = test_hostname
                status["test_result"] = await fetch_s1_assets_by_hostname(test_hostname)
            return [TextContent(type="text", text=json.dumps(status, indent=2))]


        elif name == "enrich_checkpoint":
            alert_id = arguments["alert_id"]
            folder = arguments.get("folder", ALERTS_DIR)
            
            # Find the alert
            alert_path = os.path.join(folder, f"{alert_id}.json")
            alert = None
            
            if os.path.exists(alert_path):
                alert = parse_alert_file(alert_path)
            else:
                # Fallback: scan directory
                alerts = scan_alerts(folder, 1000)
                alert = next((a for a in alerts if a.id == alert_id), None)
            
            if not alert:
                return [TextContent(type="text", text=json.dumps({
                    "error": "alert_not_found",
                    "alert_id": alert_id,
                    "searched_in": folder
                }))]
            
            # Get best hash
            algo, hash_value = choose_best_hash(alert.file.sha256, alert.file.sha1, alert.file.md5)
            
            if not hash_value:
                return [TextContent(type="text", text=json.dumps({
                    "error": "no_hash_available",
                    "alert_id": alert_id,
                    "message": "No file hash found in alert"
                }))]
            
            # Query Check Point
            cp_result = await fetch_cp_file_reputation(hash_value)
            
            # Save result
            cp_dir = os.path.join(ALERTS_DIR, "Checkpoint")
            os.makedirs(cp_dir, exist_ok=True)
            cp_saved_path = os.path.join(cp_dir, f"{alert_id}.json")
            
            try:
                with open(cp_saved_path, "w", encoding="utf-8") as f:
                    json.dump(cp_result, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save Check Point result: {e}")
                cp_saved_path = None
            
            result = {
                "success": True,
                "alert_id": alert_id,
                "hash_used": f"{algo}: {hash_value}",
                "checkpoint": cp_result,
                "saved_path": cp_saved_path
            }
            
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        elif name == "enrich_alert_combined":
            alert_id = arguments["alert_id"]
            folder = arguments.get("folder", ALERTS_DIR)
            
            # Find the alert
            alert_path = os.path.join(folder, f"{alert_id}.json")
            alert = None
            
            if os.path.exists(alert_path):
                alert = parse_alert_file(alert_path)
            else:
                # Fallback: scan directory
                alerts = scan_alerts(folder, 1000)
                alert = next((a for a in alerts if a.id == alert_id), None)
            
            if not alert:
                return [TextContent(type="text", text=json.dumps({
                    "error": "alert_not_found",
                    "alert_id": alert_id,
                    "searched_in": folder
                }))]
            
            # Get best hash
            algo, hash_value = choose_best_hash(alert.file.sha256, alert.file.sha1, alert.file.md5)
            
            if not hash_value:
                return [TextContent(type="text", text=json.dumps({
                    "error": "no_hash_available",
                    "alert_id": alert_id,
                    "message": "No file hash found in alert"
                }))]
            
            # Query all services
            vt_result = await fetch_vt_report(hash_value, VT_API_KEY)
            cp_result = await fetch_cp_file_reputation(hash_value)
            
            # Cyberint only works with SHA-256
            cyb_result = None
            if alert.file.sha256:
                cyb_result = await fetch_cyberint_report(alert.file.sha256)
            else:
                cyb_result = {
                    "found": False,
                    "error": "no_sha256",
                    "message": "Cyberint requires SHA-256 hash"
                }
            # Query AbuseIPDB (for IP addresses)
            abuse_result = None
            ip_address = None
            try:
                with open(alert.source_path, "r", encoding="utf-8") as f:
                    alert_data = json.load(f)
                ip_address = extract_ip_from_alert(alert_data)
                if ip_address:
                    abuse_result = await fetch_abuseipdb_report(ip_address)
                else:
                    abuse_result = {
                        "found": False,
                        "error": "no_ip",
                        "message": "No IP address found in alert (checked 'src' and 'dst' fields)"
                    }
            except Exception as e:
                abuse_result = {
                    "found": False,
                    "error": "ip_extraction_failed",
                    "message": str(e)
                }
            # SentinelOne by hostname
            s1_result = None
            s1_hostname = None
            try:
                with open(alert.source_path, "r", encoding="utf-8") as f:
                    alert_data_for_s1 = json.load(f)
                s1_hostname = extract_hostname_from_alert(alert_data_for_s1)
                if s1_hostname:
                    s1_result = await fetch_s1_assets_by_hostname(s1_hostname)
                else:
                    s1_result = {
                        "found": False,
                        "error": "no_hostname",
                        "message": "No hostname found in alert"
                    }
            except Exception as e:
                s1_result = {"found": False, "error": "hostname_extraction_failed", "message": str(e)}

            # Save results
            vt_dir = os.path.join(ALERTS_DIR, "VirusTotal")
            cp_dir = os.path.join(ALERTS_DIR, "Checkpoint")
            cyb_dir = os.path.join(ALERTS_DIR, "Cyberint")
            abuse_dir = os.path.join(ALERTS_DIR, "AbuseIPDB")
            s1_dir = os.path.join(ALERTS_DIR, "SentinelOne")
            os.makedirs(vt_dir, exist_ok=True)
            os.makedirs(cp_dir, exist_ok=True)
            os.makedirs(cyb_dir, exist_ok=True)
            os.makedirs(abuse_dir, exist_ok=True)
            os.makedirs(s1_dir, exist_ok=True)

            vt_saved_path = os.path.join(vt_dir, f"{alert_id}.json")
            cp_saved_path = os.path.join(cp_dir, f"{alert_id}.json")
            cyb_saved_path = os.path.join(cyb_dir, f"{alert_id}.json")
            abuse_saved_path = os.path.join(abuse_dir, f"{alert_id}.json")
            s1_saved_path = os.path.join(s1_dir, f"{alert_id}.json")
            
            try:
                with open(vt_saved_path, "w", encoding="utf-8") as f:
                    json.dump(vt_result, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save VirusTotal result: {e}")
                vt_saved_path = None
                
            try:
                with open(cp_saved_path, "w", encoding="utf-8") as f:
                    json.dump(cp_result, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save Check Point result: {e}")
                cp_saved_path = None
                
            try:
                with open(cyb_saved_path, "w", encoding="utf-8") as f:
                    json.dump(cyb_result, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save Cyberint result: {e}")
                cyb_saved_path = None
            try:
                with open(abuse_saved_path, "w", encoding="utf-8") as f:
                    json.dump({
                        "alert_file": f"{alert_id}.json",
                        "ip_checked": ip_address,
                        "result": abuse_result
                    }, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save AbuseIPDB result: {e}")
                abuse_saved_path = None
            try:
                with open(s1_saved_path, "w", encoding="utf-8") as f:
                    json.dump({
                        "alert_file": f"{alert_id}.json",
                        "hostname": s1_hostname,
                        "result": s1_result
                    }, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save SentinelOne result: {e}")
                s1_saved_path = None
                        
            result = {
                "success": True,
                "alert_id": alert_id,
                "hash_used": f"{algo}: {hash_value}",
                "virustotal": vt_result,
                "checkpoint": cp_result,
                "cyberint": cyb_result,
                "abuseipdb": abuse_result,
                "sentinelone": s1_result,
                "saved_paths": {
                    "virustotal": vt_saved_path,
                    "checkpoint": cp_saved_path,
                    "cyberint": cyb_saved_path,
                    "abuseipdb": abuse_saved_path,
                    "sentinelone": s1_saved_path
                }
            }
            
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
            
        elif name == "checkpoint_status":
            test_hash = arguments.get("test_hash")
            
            status = {
                "cp_api_key_present": bool(CP_API_KEY),
                "cp_api_key_length": len(CP_API_KEY) if CP_API_KEY else 0,
                "token_cache_path": str(CP_TOKEN_CACHE),
                "cache_exists": CP_TOKEN_CACHE.exists(),
                "auth_url": CP_AUTH_URL,
                "file_url": CP_FILE_URL
            }
            
            # Test token retrieval
            token_result = await obtain_cp_token()
            status["token_result"] = token_result
            
            # Test file reputation query if hash provided
            if test_hash and token_result.get("success"):
                rep_result = await fetch_cp_file_reputation(test_hash)
                status["test_hash"] = test_hash
                status["reputation_result"] = rep_result
            
            return [TextContent(type="text", text=json.dumps(status, indent=2))]
            
        elif name == "create_sample_alert":
            alert_id = arguments.get("alert_id", "sample-001")
            
            sample_data = {
                "id": alert_id,
                "file": {
                    "path": "C:\\temp\\suspicious_file.exe",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "sha1": "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc",
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "size": 2048,
                    "extension": ".exe"
                },
                "detected_time": "2024-01-15T10:30:00Z",
                "vendor": "TestEDR",
                "meta": {"severity": "high"},
                "threatInfo": {
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "classification": "malware"
                }
            }
            
            # Create directory and file
            os.makedirs(ALERTS_DIR, exist_ok=True)
            file_path = os.path.join(ALERTS_DIR, f"{alert_id}.json")
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(sample_data, f, indent=2)
            
            result = {
                "success": True,
                "message": f"Sample alert created: {alert_id}",
                "file_path": file_path
            }
            
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
            
        else:
            return [TextContent(type="text", text=json.dumps({
                "error": "unknown_tool",
                "tool_name": name
            }))]
            
    except Exception as e:
        logger.error(f"Tool execution failed: {e}")
        return [TextContent(type="text", text=json.dumps({
            "error": "tool_execution_failed",
            "tool_name": name,
            "message": str(e)
        }))]

async def main():
    """Main entry point."""
    logger.info("Starting EDR Enrichment MCP Server...")
    logger.info(f"Alerts directory: {ALERTS_DIR}")
    logger.info(f"VirusTotal API key present: {'yes' if bool(VT_API_KEY) else 'no'}")
    logger.info(f"Check Point API key present: {'yes' if bool(CP_API_KEY) else 'no'}")
    logger.info(f"Cyberint access token present: {'yes' if bool(CYBERINT_ACCESS_TOKEN) else 'no'}")
    logger.info(f"AbuseIPDB API key present: {'yes' if bool(ABUSEIPDB_API_KEY) else 'no'}")
    logger.info(f"SentinelOne API token present: {'yes' if bool(S1_API_TOKEN) else 'no'}")
    logger.info(f"SentinelOne console URL present: {'yes' if bool(S1_CONSOLE_URL) else 'no'}")
    

    # Create alerts directory if it doesn't exist
    os.makedirs(ALERTS_DIR, exist_ok=True)
    
    # Run the server
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())