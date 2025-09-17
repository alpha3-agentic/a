import asyncio
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

class SimpleMCPClient:
    """Simple MCP client that uses hardcoded prompts to communicate with the MCP server"""
    
    def __init__(self, server_script_path: str = "server.py"):
        self.server_script_path = server_script_path
        
        # Hardcoded prompts for different enrichment tasks
        self.prompts = {
            "enrich_virustotal": "enrich this alert with virustotal threat intelligence",
            "enrich_checkpoint": "enrich this alert with checkpoint reputation data", 
            "enrich_cyberint": "enrich this alert with cyberint threat intelligence","enrich_edr" : "For this enirch the alert from all the tools except the ",
            "enrich_combined": "enrich this alert with all available threat intelligence sources"
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

class ScoringTool:
    """Tool for scoring alerts based on heuristic rules and MCP-based threat intelligence"""
    
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
    def flatten_alert(cls, raw: Any, parent_key: str = "") -> Dict[str, Any]:
        """Recursively flattens dicts/lists with better error handling"""
        flat: Dict[str, Any] = {}
        
        try:
            if parent_key == "" and not isinstance(raw, (dict, list)):
                print(f"WARNING: Alert data is not a dict/list, type: {type(raw)}")
                if hasattr(raw, '__dict__'):
                    raw = raw.__dict__
                else:
                    return {"raw_data": str(raw)}

            if isinstance(raw, dict):
                if parent_key == "":
                    print(f"DEBUG: flatten_alert - received {len(raw)} top-level keys")
                for k, v in raw.items():
                    nk = f"{parent_key}.{k}" if parent_key else k
                    try:
                        flat.update(cls.flatten_alert(v, nk))
                    except Exception as e:
                        print(f"Error flattening key {nk}: {str(e)}")
                        flat[nk] = str(v)
                        
            elif isinstance(raw, list):
                for i, v in enumerate(raw):
                    nk = f"{parent_key}[{i}]"
                    try:
                        flat.update(cls.flatten_alert(v, nk))
                    except Exception as e:
                        print(f"Error flattening list item {nk}: {str(e)}")
                        flat[nk] = str(v)
            else:
                if raw is None:
                    flat[parent_key] = None
                elif isinstance(raw, (str, int, float, bool)):
                    flat[parent_key] = raw
                else:
                    flat[parent_key] = str(raw)

        except Exception as e:
            print(f"Critical error in flatten_alert: {str(e)}")
            flat["flattening_error"] = str(e)
            flat["original_data_type"] = str(type(raw))
            
        return flat

    @classmethod
    def _extract_sha256_from_alert(cls, flat: Dict[str, Any]) -> str:
        """Extract SHA256 hash from flattened alert data"""
        possible_keys = [
            "file.hashes.sha256",
            "threat.sha256", 
            "file.sha256",
            "hash.sha256",
            "sha256"
        ]
        
        for key in possible_keys:
            if key in flat and flat[key]:
                return str(flat[key]).lower()
        
        # Also check for any key containing 'sha256'
        for key, value in flat.items():
            if 'sha256' in key.lower() and value:
                return str(value).lower()
                
        return ""

    async def score_agent2(self, flat: Dict[str, Any]) -> Dict[str, dict]:
        """Agent2: MCP-based scoring using hardcoded prompts for threat intelligence"""
        scores = {}
        
        print("=== AGENT2 SCORING START (MCP with Hardcoded Prompts) ===")
        print(f"Available keys: {list(flat.keys())}")

        # Extract SHA256 hash from alert
        sha256_hash = self._extract_sha256_from_alert(flat)
        
        if not sha256_hash:
            print("No SHA256 hash found in alert data")
            scores["ti_no_hash"] = {
                "value": "No hash available",
                "risk_score": 0,
                "description": "No SHA256 hash found for threat intelligence lookup"
            }
            return scores

        print(f"Found SHA256 hash: {sha256_hash}")

        try:
            # Use hardcoded prompt: "enrich this alert with all available threat intelligence sources"
            print("\n" + "="*50)
            print("SENDING HARDCODED PROMPT TO MCP SERVER:")
            print("'enrich this alert with all available threat intelligence sources'")
            print("="*50)
            
            enrichment_result = await self.mcp_client.enrich_alert(
                sha256_hash, 
                prompt_type="enrich_combined"
            )
            
            if "error" in enrichment_result:
                print(f"MCP enrichment failed: {enrichment_result['error']}")
                scores["ti_mcp_error"] = {
                    "value": enrichment_result.get("error", "unknown_error"),
                    "risk_score": 10,
                    "description": f"MCP threat intelligence lookup failed: {enrichment_result.get('error', 'unknown')}"
                }
                return scores

            print("✓ MCP Server successfully processed the prompt!")
            print(f"Received enrichment data for hash: {enrichment_result.get('hash_used', 'unknown')}")

            # Process the enrichment results
            enrichment_sources = 0
            
            # Process VirusTotal results
            vt_data = enrichment_result.get("virustotal", {})
            if vt_data.get("found"):
                vt_scores = self._process_virustotal_data(vt_data)
                scores.update(vt_scores)
                enrichment_sources += 1
                print(f"✓ VirusTotal: Added {len(vt_scores)} risk indicators")
            
            # Process Check Point results
            cp_data = enrichment_result.get("checkpoint", {})
            if cp_data.get("found"):
                cp_scores = self._process_checkpoint_data(cp_data)
                scores.update(cp_scores)
                enrichment_sources += 1
                print(f"✓ Check Point: Added {len(cp_scores)} risk indicators")
            
            # Process Cyberint results
            cyb_data = enrichment_result.get("cyberint", {})
            if cyb_data.get("found"):
                cyb_scores = self._process_cyberint_data(cyb_data)
                scores.update(cyb_scores)
                enrichment_sources += 1
                print(f"✓ Cyberint: Added {len(cyb_scores)} risk indicators")

            # Summary of enrichment
            if enrichment_sources == 0:
                scores["ti_no_intelligence"] = {
                    "value": "File not found in threat intelligence",
                    "risk_score": 5,
                    "description": "File hash not found in any threat intelligence source"
                }
                print("⚠ No threat intelligence data found for this file")
            else:
                print(f"✓ Successfully enriched with {enrichment_sources} threat intelligence sources")

        except Exception as e:
            print(f"MCP communication error: {str(e)}")
            traceback.print_exc()
            scores["ti_communication_error"] = {
                "value": str(e),
                "risk_score": 15,
                "description": f"Failed to communicate with MCP server: {str(e)}"
            }

        # Calculate total score
        agent2_total = sum(score_data.get("risk_score", 0) for score_data in scores.values())
        print(f"=== AGENT2 TOTAL SCORE (MCP): {agent2_total} ===")
        
        # Add summary score entry
        scores["ti_mcp_summary"] = {
            "value": f"MCP enrichment completed",
            "risk_score": 0,  # Don't double-count
            "description": f"MCP-based threat intelligence analysis completed with {len(scores)} indicators"
        }
        
        return scores

    def _process_virustotal_data(self, vt_data: dict) -> dict:
        """Process VirusTotal data from MCP response"""
        scores = {}
        
        if not vt_data.get("found") or "json" not in vt_data:
            return scores
            
        attributes = vt_data.get("json", {}).get("data", {}).get("attributes", {})
        if not attributes:
            return scores

        # 1. Malicious detections
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        malicious_count = last_analysis_stats.get("malicious", 0)
        
        if malicious_count > 0:
            risk_score = min(15 * math.log2(malicious_count + 1), 50)
            scores["vt_malicious_detections"] = {
                "value": malicious_count,
                "risk_score": risk_score,
                "description": f"VirusTotal malicious detections: {malicious_count}"
            }

        # 2. Suspicious detections
        suspicious_count = last_analysis_stats.get("suspicious", 0)
        if suspicious_count > 0:
            risk_score = min(8 * math.log2(suspicious_count + 1), 25)
            scores["vt_suspicious_detections"] = {
                "value": suspicious_count,
                "risk_score": risk_score,
                "description": f"VirusTotal suspicious detections: {suspicious_count}"
            }

        # 3. Reputation score
        reputation = attributes.get("reputation", 0)
        if reputation < 0:
            risk_score = min(abs(reputation) * 2, 30)
            scores["vt_negative_reputation"] = {
                "value": reputation,
                "risk_score": risk_score,
                "description": f"VirusTotal negative reputation: {reputation}"
            }

        return scores

    def _process_checkpoint_data(self, cp_data: dict) -> dict:
        """Process Check Point data from MCP response"""
        scores = {}
        
        if not cp_data.get("found") or "json" not in cp_data:
            return scores
            
        cp_result = cp_data.get("json", {})

        # Check reputation status
        rep_status = cp_result.get("reputation", {}).get("status", "")
        if rep_status:
            if rep_status.lower() in ["malicious", "malware"]:
                scores["cp_malicious_reputation"] = {
                    "value": rep_status,
                    "risk_score": 45,
                    "description": f"Check Point malicious reputation: {rep_status}"
                }
            elif rep_status.lower() in ["suspicious", "potentially_unwanted"]:
                scores["cp_suspicious_reputation"] = {
                    "value": rep_status,
                    "risk_score": 25,
                    "description": f"Check Point suspicious reputation: {rep_status}"
                }

        return scores

    def _process_cyberint_data(self, cyb_data: dict) -> dict:
        """Process Cyberint data from MCP response"""
        scores = {}
        
        if not cyb_data.get("found") or "summary" not in cyb_data:
            return scores
            
        summary = cyb_data.get("summary", {})

        # Process risk score
        risk = summary.get("risk")
        if risk:
            if isinstance(risk, (int, float)) and risk > 50:
                scores["cyb_high_risk"] = {
                    "value": risk,
                    "risk_score": min(risk / 2, 40),
                    "description": f"Cyberint high risk score: {risk}"
                }

        # Process classification
        classification = summary.get("classification")
        if classification and isinstance(classification, str):
            if classification.lower() in ["malware", "trojan", "virus", "backdoor"]:
                scores["cyb_malware_classification"] = {
                    "value": classification,
                    "risk_score": 40,
                    "description": f"Cyberint malware classification: {classification}"
                }

        return scores

    # Keep the existing score_agent1 method unchanged
    @classmethod
    def score_agent1(cls, flat: Dict[str, Any]) -> Dict[str, dict]:
        """Agent1: Heuristic-based scoring"""
        scores = {}
        
        print("=== AGENT1 SCORING START ===")
        print(f"Available keys: {list(flat.keys())}")

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
        print(f"Severity: {sev} -> score: {sev * 10}")

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
            print(f"File signing: {fv} -> score: 25")

        # 3. Suspicious file path
        fp = flat.get("file.path", "")
        fp = str(fp) if fp is not None else ""
        if cls.EVIL_PATH_REGEX.search(fp):
            scores["file_path"] = {
                "value": fp,
                "risk_score": 15,
                "description": "File located in suspicious directory"
            }
            print(f"Suspicious file path: {fp} -> score: 15")

        # 4. Parent process (LOLBins)
        parent = flat.get("process.name", "")
        parent = str(parent).lower() if parent is not None else ""
        if any(bin_name in parent for bin_name in cls.LOLBINS):
            scores["parent_process"] = {
                "value": parent,
                "risk_score": 20,
                "description": "Parent process is a known LOLBin"
            }
            print(f"LOLBin parent process: {parent} -> score: 20")

        # 5. Command line patterns
        cli = flat.get("process.cmd.args")
        cli = str(cli) if cli is not None else ""
        if cli and cls.SUSP_ARGS_RE.search(cli):
            scores["command_line"] = {
                "value": cli,
                "risk_score": 15,
                "description": "Contains suspicious command line patterns"
            }
            print(f"Suspicious command line -> score: 15")

        # 6. Threat confidence
        conf_raw = flat.get("threat.confidence")
        conf = ""
        if isinstance(conf_raw, str):
            conf = conf_raw.lower()
        else:
            conf = str(conf_raw).lower() if conf_raw is not None else ""
            
        risk_score = cls.CONF_WEIGHTS.get(conf, 0)
        scores["confidence_level"] = {
            "value": conf,
            "risk_score": risk_score,
            "description": f"Vendor confidence: {conf}"
        }
        print(f"Threat confidence: {conf} -> score: {risk_score}")

        # 7. Asset type
        asset = flat.get("device.type", "")
        asset = str(asset).lower() if asset is not None else ""
        asset_score = cls.ASSET_WEIGHTS.get(asset, 0)
        scores["asset_type"] = {
            "value": asset,
            "risk_score": asset_score,
            "description": f"Asset type: {asset}"
        }
        print(f"Asset type: {asset} -> score: {asset_score}")

        # 8. Process user privileges
        process_user = flat.get("actor.process.user.name", "")
        process_user = str(process_user) if process_user is not None else ""
        if process_user.lower() in ["system", "administrator", "root"]:
            scores["process_user"] = {
                "value": process_user,
                "risk_score": 10,
                "description": "Process running with elevated privileges"
            }
            print(f"Elevated process user: {process_user} -> score: 10")

        agent1_total = sum(score_data.get("risk_score", 0) for score_data in scores.values())
        print(f"=== AGENT1 TOTAL SCORE: {agent1_total} ===")
        return scores

class TriageAgent:
    """Agent specialized in alert triage using heuristic analysis and MCP-based threat intelligence"""
    
    def __init__(self, mcp_server_path: str = "server.py"):
        self.role = "Alert Triage Specialist - Uses hardcoded prompts to enrich alerts via MCP server"
        self.tools = ["ScoringTool", "SimpleMCPClient"]
        self.mcp_client = SimpleMCPClient(mcp_server_path)
        self.scoring_tool = ScoringTool(self.mcp_client)

    async def analyze_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze alert using both Agent1 (heuristic) and Agent2 (MCP-based) scoring"""
        
        print("=" * 60)
        print("STARTING TRIAGE ANALYSIS WITH SIMPLE MCP CLIENT")
        print("=" * 60)
        
        # Flatten and validate data
        flat_data = self.scoring_tool.flatten_alert(alert_data)
        
        if not flat_data:
            print("ERROR: No valid alert data received")
            return {
                "error": "No valid alert data provided",
                "timestamp": datetime.utcnow().isoformat()
            }
        
        print(f"Processing alert with {len(flat_data)} fields")
        
        # Run both scoring agents
        print("\n" + "="*40 + " AGENT1 " + "="*40)
        agent1_scores = self.scoring_tool.score_agent1(flat_data)
        
        print("\n" + "="*40 + " AGENT2 " + "="*40)
        agent2_scores = await self.scoring_tool.score_agent2(flat_data)
        
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
        
        # Determine verdict
        if normalized_score >= 80:
            verdict = "True Positive"
        elif normalized_score >= 25:
            verdict = "Escalate"
        else:
            verdict = "False Positive"
        
        print(f"Normalized Score: {normalized_score}")
        print(f"Final Verdict: {verdict}")
        
        # Combine all attributes
        all_attributes = {}
        all_attributes.update(agent1_scores)
        all_attributes.update(agent2_scores)
        
        result = {
            "prediction": {
                "predicted_verdict": verdict,
                "risk_score": confidence * 100
            },
            "metadata": {
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
                    "attributes": agent2_scores,
                    "mcp_integration": True,
                    "hardcoded_prompts": True
                },
                "combined_attribute_analysis": all_attributes,
                "scoring_breakdown": {
                    "agent1_contribution": f"{weighted_agent1:.2f} points (40% weight)",
                    "agent2_contribution": f"{weighted_agent2:.2f} points (60% weight)",
                    "total_weighted": f"{total_weighted_score:.2f} points"
                },
                "agent_role": self.role,
                "tools_used": self.tools
            },
            "timestamp": datetime.utcnow().isoformat(),
            "model_version": "3.0_Simple_MCP"
        }
        
        print("=" * 60)
        print("TRIAGE ANALYSIS COMPLETE")
        print("=" * 60)
        
        return result

# Usage example
async def main():
    """Example usage of the Simple MCP-integrated TriageAgent"""
    triage_agent = TriageAgent("server.py")
    
    # Sample alert data with a real hash for testing
    sample_alert = {
  "agentDetectionInfo": {
    "accountId": "2202822069622178056",
    "accountName": "Indian Oil Corporation Limited",
    "agentDetectionState": "install_to_dynamic",
    "agentDomain": "WORKGROUP",
    "agentIpV4": "192.168.58.138",
    "agentIpV6": "fe80::f104:b01f:59c3:c605,2001:0:348b:fb58:24fd:3617:f170:185,fe80::24fd:3617:f170:185",
    "agentLastLoggedInUpn": None,
    "agentLastLoggedInUserMail": None,
    "agentLastLoggedInUserName": "agent1",
    "agentMitigationMode": "protect",
    "agentOsName": "Windows 10 Enterprise",
    "agentOsRevision": "10586",
    "agentRegisteredAt": "2025-09-08T08:26:32.378961Z",
    "agentUuid": "fa63db8af65e49d68d0f533edd1b4aa0",
    "agentVersion": "24.2.3.471",
    "assetVersion": "0",
    "cloudProviders": {},
    "externalIp": "14.143.254.122",
    "groupId": "2202822071174070618",
    "groupName": "Default Group",
    "siteId": "2202822071148904793",
    "siteName": "Default site"
  },
  "agentRealtimeInfo": {
    "accountId": "2202822069622178056",
    "accountName": "Indian Oil Corporation Limited",
    "activeThreats": 0,
    "agentComputerName": "DESKTOP-2PK4GIN",
    "agentDecommissionedAt": None,
    "agentDomain": "WORKGROUP",
    "agentId": "2299243569166632040",
    "agentInfected": False,
    "agentIsActive": False,
    "agentIsDecommissioned": False,
    "agentMachineType": "desktop",
    "agentMitigationMode": "protect",
    "agentNetworkStatus": "connected",
    "agentOsName": "Windows 10 Enterprise",
    "agentOsRevision": "10586",
    "agentOsType": "windows",
    "agentUuid": "fa63db8af65e49d68d0f533edd1b4aa0",
    "agentVersion": "24.2.3.471",
    "groupId": "2202822071174070618",
    "groupName": "Default Group",
    "networkInterfaces": [
      {
        "id": "2299243569200186477",
        "inet": [],
        "inet6": [
          "2001:0:348b:fb58:452:cc5:f170:185",
          "fe80::452:cc5:f170:185"
        ],
        "name": "Teredo Tunneling Pseudo-Interface",
        "physical": "00:00:00:00:00:00"
      },
      {
        "id": "2299243569175020649",
        "inet": [
          "192.168.58.138"
        ],
        "inet6": [
          "fe80::f104:b01f:59c3:c605"
        ],
        "name": "Ethernet0",
        "physical": "00:0c:29:aa:a8:2c"
      }
    ],
    "operationalState": "na",
    "rebootRequired": False,
    "scanAbortedAt": "2025-09-08T08:28:06.450592Z",
    "scanFinishedAt": "2025-09-08T08:43:13.682982Z",
    "scanStartedAt": "2025-09-08T08:27:06.043933Z",
    "scanStatus": "finished",
    "siteId": "2202822071148904793",
    "siteName": "Default site",
    "storageName": None,
    "storageType": None,
    "userActionsNeeded": []
  },
  "containerInfo": {
    "id": None,
    "image": None,
    "isContainerQuarantine": None,
    "labels": None,
    "name": None
  },
  "ecsInfo": {
    "clusterName": None,
    "serviceArn": None,
    "serviceName": None,
    "taskArn": None,
    "taskAvailabilityZone": None,
    "taskDefinitionArn": None,
    "taskDefinitionFamily": None,
    "taskDefinitionRevision": None,
    "type": None,
    "version": None
  },
  "id": "2299297289741728059",
  "indicators": [],
  "kubernetesInfo": {
    "cluster": None,
    "controllerKind": None,
    "controllerLabels": None,
    "controllerName": None,
    "isContainerQuarantine": None,
    "namespace": None,
    "namespaceLabels": None,
    "node": None,
    "nodeLabels": None,
    "pod": None,
    "podLabels": None
  },
  "mitigationStatus": [
    {
      "action": "quarantine",
      "actionsCounters": {
        "failed": 0,
        "notFound": 0,
        "pendingReboot": 0,
        "success": 1,
        "total": 1
      },
      "agentSupportsReport": True,
      "groupNotFound": False,
      "lastUpdate": "2025-09-08T10:13:16.625619Z",
      "latestReport": "/threats/mitigation-report/2299297291830492757",
      "mitigationEndedAt": "2025-09-08T10:14:34.576000Z",
      "mitigationStartedAt": "2025-09-08T10:14:34.576000Z",
      "reportId": "2299297291830492757",
      "status": "success"
    },
    {
      "action": "kill",
      "actionsCounters": None,
      "agentSupportsReport": True,
      "groupNotFound": False,
      "lastUpdate": "2025-09-08T10:13:16.532050Z",
      "latestReport": None,
      "mitigationEndedAt": "2025-09-08T10:13:16.518783Z",
      "mitigationStartedAt": "2025-09-08T10:13:16.518781Z",
      "reportId": "2299297291041962747",
      "status": "success"
    }
  ],
  "threatInfo": {
    "analystVerdict": "undefined",
    "analystVerdictDescription": "Undefined",
    "automaticallyResolved": False,
    "browserType": None,
    "certificateId": "",
    "classification": "Malware",
    "classificationSource": "Engine",
    "cloudFilesHashVerdict": "black",
    "collectionId": "2299297289850779978",
    "confidenceLevel": "malicious",
    "createdAt": "2025-09-08T10:13:16.375559Z",
    "detectionEngines": [
      {
        "key": "sentinelone_cloud",
        "title": "SentinelOne Cloud"
      }
    ],
    "detectionType": "static",
    "engines": [
      "SentinelOne Cloud"
    ],
    "externalTicketExists": False,
    "externalTicketId": None,
    "failedActions": False,
    "fileExtension": "",
    "fileExtensionType": "None",
    "filePath": "\\Device\\HarddiskVolume4\\Users\\agent1\\Desktop\\23294096120\\4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784",
    "fileSize": 10253,
    "fileVerificationType": "NotSigned",
    "identifiedAt": "2025-09-08T10:13:16.356812Z",
    "incidentStatus": "unresolved",
    "incidentStatusDescription": "Unresolved",
    "initiatedBy": "agent_policy",
    "initiatedByDescription": "Agent Policy",
    "initiatingUserId": None,
    "initiatingUsername": None,
    "isFileless": False,
    "isValidCertificate": False,
    "macroModules": None,
    "maliciousProcessArguments": None,
    "md5": None,
    "mitigatedPreemptively": False,
    "mitigationStatus": "mitigated",
    "mitigationStatusDescription": "Mitigated",
    "originatorProcess": "explorer.exe",
    "pendingActions": False,
    "processUser": "DESKTOP-2PK4GIN\\agent1",
    "publisherName": "",
    "reachedEventsLimit": False,
    "rebootRequired": False,
    "rootProcessUpn": None,
    "sha1": "06727ffda60359236a8029e0b3e8a0fd11c23313",
    "sha256": "4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784",
    "storyline": "503043FDEEC7D915",
    "threatId": "2299297289741728059",
    "threatName": "4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784",
    "updatedAt": "2025-09-08T10:13:16.621617Z"
  },
  "whiteningOptions": [
    "hash"
  ]
}
    
    try:
        result = await triage_agent.analyze_alert(sample_alert)
        print("\n" + "="*60)
        print("FINAL TRIAGE RESULT:")
        print("="*60)
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        print(f"Analysis failed: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())