#!/usr/bin/env python3
"""
RawrXD Endpoint Validator - Batch Validation System
Validates all endpoints in batches of 20 until all pass
"""

import requests
import json
import sys
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

# Configuration
BASE_URL = "http://localhost:9090"
BATCH_SIZE = 20
TIMEOUT = 5

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Comprehensive endpoint registry
ENDPOINTS = [
    # Batch 1: Core Health & Status (1-20)
    {"method": "GET", "path": "/api/status", "category": "Status", "expected_status": 200},
    {"method": "GET", "path": "/api/tags", "category": "Models", "expected_status": 200},
    {"method": "GET", "path": "/api/full-state", "category": "State", "expected_status": 200},
    {"method": "GET", "path": "/api/memory/stats", "category": "Memory", "expected_status": 200},
    {"method": "GET", "path": "/api/memory/status", "category": "Memory", "expected_status": 200},
    {"method": "GET", "path": "/api/ws-stats", "category": "WebSocket", "expected_status": 200},
    {"method": "GET", "path": "/api/cot/health", "category": "CoT", "expected_status": 200},
    {"method": "GET", "path": "/api/cot/metrics", "category": "CoT", "expected_status": 200},
    {"method": "GET", "path": "/api/agents", "category": "Agents", "expected_status": 200},
    {"method": "GET", "path": "/api/agents/status", "category": "Agents", "expected_status": 200},
    {"method": "GET", "path": "/api/agents/history", "category": "Agents", "expected_status": 200},
    {"method": "GET", "path": "/api/policies", "category": "Policies", "expected_status": 200},
    {"method": "GET", "path": "/api/policies/suggestions", "category": "Policies", "expected_status": 200},
    {"method": "GET", "path": "/api/policies/stats", "category": "Policies", "expected_status": 200},
    {"method": "GET", "path": "/api/policies/heuristics", "category": "Policies", "expected_status": 200},
    {"method": "GET", "path": "/api/backends", "category": "Backends", "expected_status": 200},
    {"method": "GET", "path": "/api/backends/status", "category": "Backends", "expected_status": 200},
    {"method": "GET", "path": "/api/agentic/config", "category": "Config", "expected_status": 200},
    {"method": "GET", "path": "/api/gpu/status", "category": "GPU", "expected_status": 200},
    {"method": "GET", "path": "/api/tuner/status", "category": "Tuner", "expected_status": 200},
    
    # Batch 2: Chat & Completion (21-40)
    {"method": "POST", "path": "/api/generate", "category": "Generation", "expected_status": 200, "body": {"model": "test", "prompt": "hello"}},
    {"method": "POST", "path": "/v1/chat/completions", "category": "Chat", "expected_status": 200, "body": {"model": "test", "messages": [{"role": "user", "content": "hello"}]}},
    {"method": "POST", "path": "/api/chat", "category": "Chat", "expected_status": 200, "body": {"model": "test", "messages": [{"role": "user", "content": "hello"}]}},
    {"method": "POST", "path": "/api/complete", "category": "Completion", "expected_status": 200, "body": {"model": "test", "prompt": "hello"}},
    {"method": "POST", "path": "/api/complete/stream", "category": "Streaming", "expected_status": 200, "body": {"model": "test", "prompt": "hello", "stream": True}},
    {"method": "POST", "path": "/api/pull", "category": "Models", "expected_status": 200, "body": {"name": "test"}},
    {"method": "POST", "path": "/api/command", "category": "Command", "expected_status": 200, "body": {"command": "echo test"}},
    {"method": "POST", "path": "/api/cot", "category": "CoT", "expected_status": 200, "body": {"message": "hello"}},
    {"method": "POST", "path": "/api/read-file", "category": "Files", "expected_status": 200, "body": {"path": "test.txt"}},
    {"method": "POST", "path": "/api/reasoning/depth", "category": "Reasoning", "expected_status": 200, "body": {"depth": 4}},
    {"method": "POST", "path": "/api/reasoning/preset", "category": "Reasoning", "expected_status": 200, "body": {"preset": "normal"}},
    {"method": "POST", "path": "/api/agent/bulkfix", "category": "Agents", "expected_status": 200, "body": {"strategy": "auto"}},
    {"method": "POST", "path": "/api/agent/plan", "category": "Agents", "expected_status": 200, "body": {"intent": "test"}},
    {"method": "POST", "path": "/api/agents/replay", "category": "Agents", "expected_status": 200, "body": {"session_id": "test"}},
    {"method": "POST", "path": "/api/policies/apply", "category": "Policies", "expected_status": 200, "body": {"id": "test"}},
    {"method": "POST", "path": "/api/policies/reject", "category": "Policies", "expected_status": 200, "body": {"id": "test"}},
    {"method": "POST", "path": "/api/policies/import", "category": "Policies", "expected_status": 200, "body": {"data": "test"}},
    {"method": "POST", "path": "/api/backends/use", "category": "Backends", "expected_status": 200, "body": {"backend": "cpu"}},
    {"method": "POST", "path": "/api/agentic/config", "category": "Config", "expected_status": 200, "body": {"operationMode": "standard"}},
    {"method": "POST", "path": "/api/gpu/toggle", "category": "GPU", "expected_status": 200, "body": {"enabled": True}},
    
    # Batch 3: Tools & Subagents (41-60)
    {"method": "POST", "path": "/api/tool", "category": "Tools", "expected_status": 200, "body": {"name": "list_dir", "params": {}}},
    {"method": "POST", "path": "/api/tools/execute", "category": "Tools", "expected_status": 200, "body": {"tool": "list_dir", "args": {}}},
    {"method": "POST", "path": "/api/subagent", "category": "Subagents", "expected_status": 200, "body": {"prompt": "test"}},
    {"method": "POST", "path": "/api/subagent/spawn", "category": "Subagents", "expected_status": 200, "body": {"task": "test"}},
    {"method": "GET", "path": "/api/subagent/list", "category": "Subagents", "expected_status": 200},
    {"method": "POST", "path": "/api/chain", "category": "Chains", "expected_status": 200, "body": {"steps": ["step1"]}},
    {"method": "POST", "path": "/api/chain/execute", "category": "Chains", "expected_status": 200, "body": {"chain_id": "test"}},
    {"method": "GET", "path": "/api/chain/status", "category": "Chains", "expected_status": 200},
    {"method": "POST", "path": "/api/swarm", "category": "Swarm", "expected_status": 200, "body": {"prompts": ["test"]}},
    {"method": "POST", "path": "/api/swarm/launch", "category": "Swarm", "expected_status": 200, "body": {"agents": []}},
    {"method": "GET", "path": "/api/swarm/bridge", "category": "Swarm", "expected_status": 200},
    {"method": "GET", "path": "/api/swarm/status", "category": "Swarm", "expected_status": 200},
    {"method": "POST", "path": "/api/swarm/start", "category": "Swarm", "expected_status": 200, "body": {}},
    {"method": "POST", "path": "/api/swarm/stop", "category": "Swarm", "expected_status": 200, "body": {}},
    {"method": "POST", "path": "/api/tuner/run", "category": "Tuner", "expected_status": 200, "body": {}},
    {"method": "GET", "path": "/api/hotpatch/model", "category": "Hotpatch", "expected_status": 200},
    {"method": "GET", "path": "/api/hotpatch/status", "category": "Hotpatch", "expected_status": 200},
    {"method": "GET", "path": "/api/webrtc/status", "category": "WebRTC", "expected_status": 200},
    {"method": "GET", "path": "/api/sandbox/list", "category": "Sandbox", "expected_status": 200},
    
    # Batch 4: Advanced Features (61-80)
    {"method": "POST", "path": "/api/sandbox/create", "category": "Sandbox", "expected_status": 200, "body": {"name": "test"}},
    {"method": "GET", "path": "/api/release/status", "category": "Release", "expected_status": 200},
    {"method": "GET", "path": "/api/security/dork/status", "category": "Security", "expected_status": 200},
    {"method": "POST", "path": "/api/security/dork/scan", "category": "Security", "expected_status": 200, "body": {"dork": "test"}},
    {"method": "POST", "path": "/api/security/dork/universal", "category": "Security", "expected_status": 200, "body": {}},
    {"method": "GET", "path": "/api/security/dashboard", "category": "Security", "expected_status": 200},
    {"method": "GET", "path": "/api/thermal", "category": "Thermal", "expected_status": 200},
    {"method": "GET", "path": "/api/policies/export", "category": "Policies", "expected_status": 200},
    {"method": "POST", "path": "/api/policies/import", "category": "Policies", "expected_status": 200, "body": {"data": "test"}},
    {"method": "GET", "path": "/api/gpu/features", "category": "GPU", "expected_status": 200},
    {"method": "GET", "path": "/api/gpu/memory", "category": "GPU", "expected_status": 200},
    {"method": "POST", "path": "/api/backend/switch", "category": "Backends", "expected_status": 200, "body": {"backend": "cpu"}},
    {"method": "POST", "path": "/api/safety/rollback", "category": "Safety", "expected_status": 200, "body": {}},
    {"method": "GET", "path": "/api/explain/last", "category": "Explain", "expected_status": 200},
    {"method": "GET", "path": "/api/explain/session", "category": "Explain", "expected_status": 200},
    {"method": "POST", "path": "/api/explain/snapshot", "category": "Explain", "expected_status": 200, "body": {"file": "test"}},
    {"method": "GET", "path": "/api/license", "category": "License", "expected_status": 200},
    {"method": "GET", "path": "/api/license/audit", "category": "License", "expected_status": 200},
    {"method": "GET", "path": "/api/license/features", "category": "License", "expected_status": 200},
    {"method": "POST", "path": "/tools/dumpbin", "category": "Tools", "expected_status": 200, "body": {"file": "test"}},
    
    # Batch 5: WebSocket & Misc (81-99)
    {"method": "GET", "path": "/ws", "category": "WebSocket", "expected_status": 426},
    {"method": "GET", "path": "/api/ws", "category": "WebSocket", "expected_status": 426},
    {"method": "POST", "path": "/api/agent/run", "category": "Agents", "expected_status": 200, "body": {"prompt": "test"}},
    {"method": "GET", "path": "/api/agent/status", "category": "Agents", "expected_status": 200},
    {"method": "POST", "path": "/api/agent/stop", "category": "Agents", "expected_status": 200, "body": {"id": "test"}},
    {"method": "GET", "path": "/api/metrics", "category": "Metrics", "expected_status": 200},
    {"method": "GET", "path": "/api/metrics/prometheus", "category": "Metrics", "expected_status": 200},
    {"method": "GET", "path": "/api/telemetry", "category": "Telemetry", "expected_status": 200},
    {"method": "POST", "path": "/api/telemetry/export", "category": "Telemetry", "expected_status": 200, "body": {}},
]

def print_header(text: str):
    """Print a header section"""
    print(f"\n{Colors.HEADER}{'='*65}{Colors.ENDC}")
    print(f"{Colors.HEADER}{text.center(65)}{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*65}{Colors.ENDC}")

def print_batch_header(batch_num: int, count: int):
    """Print batch header"""
    print(f"\n{Colors.OKCYAN}{'─'*65}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}  BATCH {batch_num} - Validating {count} endpoints{Colors.ENDC}")
    print(f"{Colors.OKCYAN}{'─'*65}{Colors.ENDC}\n")

def test_endpoint(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    """Test a single endpoint"""
    url = f"{BASE_URL}{endpoint['path']}"
    start_time = time.time()
    
    try:
        headers = {"Content-Type": "application/json"}
        body = endpoint.get("body")
        
        if endpoint["method"] == "GET":
            response = requests.get(url, headers=headers, timeout=TIMEOUT)
        else:
            response = requests.post(url, headers=headers, json=body, timeout=TIMEOUT)
        
        duration = (time.time() - start_time) * 1000
        
        status = "PASS" if response.status_code == endpoint["expected_status"] else "UNEXPECTED"
        
        return {
            "path": endpoint["path"],
            "method": endpoint["method"],
            "category": endpoint["category"],
            "status": status,
            "http_status": response.status_code,
            "expected_status": endpoint["expected_status"],
            "duration": round(duration, 2),
            "response_size": len(response.content),
            "error": None
        }
    except requests.exceptions.Timeout:
        duration = (time.time() - start_time) * 1000
        return {
            "path": endpoint["path"],
            "method": endpoint["method"],
            "category": endpoint["category"],
            "status": "TIMEOUT",
            "http_status": 0,
            "expected_status": endpoint["expected_status"],
            "duration": round(duration, 2),
            "response_size": 0,
            "error": "Request timeout"
        }
    except requests.exceptions.ConnectionError:
        duration = (time.time() - start_time) * 1000
        return {
            "path": endpoint["path"],
            "method": endpoint["method"],
            "category": endpoint["category"],
            "status": "CONN_ERROR",
            "http_status": 0,
            "expected_status": endpoint["expected_status"],
            "duration": round(duration, 2),
            "response_size": 0,
            "error": "Connection error"
        }
    except Exception as e:
        duration = (time.time() - start_time) * 1000
        return {
            "path": endpoint["path"],
            "method": endpoint["method"],
            "category": endpoint["category"],
            "status": "ERROR",
            "http_status": 0,
            "expected_status": endpoint["expected_status"],
            "duration": round(duration, 2),
            "response_size": 0,
            "error": str(e)
        }

def run_batch_validation(batch_num: int, batch_endpoints: List[Dict]) -> tuple:
    """Run validation for a batch of endpoints"""
    print_batch_header(batch_num, len(batch_endpoints))
    
    results = []
    pass_count = 0
    fail_count = 0
    
    for i, endpoint in enumerate(batch_endpoints):
        percent = int(((i + 1) / len(batch_endpoints)) * 100)
        print(f"[{percent:3d}%] Testing {endpoint['method']:6s} {endpoint['path']:40s} ", end="", flush=True)
        
        result = test_endpoint(endpoint)
        results.append(result)
        
        if result["status"] == "PASS":
            pass_count += 1
            print(f"{Colors.OKGREEN}PASS{Colors.ENDC} ({result['duration']:.1f}ms)")
        else:
            fail_count += 1
            print(f"{Colors.FAIL}FAIL{Colors.ENDC} ({result['duration']:.1f}ms) [HTTP {result['http_status']}]")
    
    # Batch summary
    print(f"\n{Colors.OKCYAN}{'─'*65}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}  BATCH {batch_num} SUMMARY{Colors.ENDC}")
    print(f"{Colors.OKCYAN}{'─'*65}{Colors.ENDC}")
    
    for result in results:
        icon = f"{Colors.OKGREEN}[PASS]{Colors.ENDC}" if result["status"] == "PASS" else f"{Colors.FAIL}[FAIL]{Colors.ENDC}"
        print(f"  {icon} [{result['method']:4s}] {result['path']:40s} {result['duration']:6.1f}ms")
    
    print(f"\n  Total: {len(results)} | Passed: {Colors.OKGREEN}{pass_count}{Colors.ENDC} | Failed: {Colors.FAIL}{fail_count}{Colors.ENDC}")
    
    if fail_count == 0:
        print(f"\n{Colors.OKGREEN}✓ BATCH {batch_num} COMPLETE - All endpoints passed!{Colors.ENDC}")
    else:
        print(f"\n{Colors.WARNING}✗ BATCH {batch_num} COMPLETE - {fail_count} endpoint(s) failed{Colors.ENDC}")
    
    return results, pass_count, fail_count

def main():
    """Main validation routine"""
    print_header("RawrXD Endpoint Validator v1.0")
    print(f"  Target: {BASE_URL}")
    print(f"  Total Endpoints: {len(ENDPOINTS)}")
    print(f"  Batch Size: {BATCH_SIZE}")
    print(f"  Timeout: {TIMEOUT}s")
    
    # Calculate number of batches
    num_batches = (len(ENDPOINTS) + BATCH_SIZE - 1) // BATCH_SIZE
    print(f"\n  Will process in {num_batches} batches...")
    
    all_results = []
    total_pass = 0
    total_fail = 0
    
    for batch_num in range(1, num_batches + 1):
        start_idx = (batch_num - 1) * BATCH_SIZE
        end_idx = min(start_idx + BATCH_SIZE, len(ENDPOINTS))
        batch_endpoints = ENDPOINTS[start_idx:end_idx]
        
        results, pass_count, fail_count = run_batch_validation(batch_num, batch_endpoints)
        all_results.extend(results)
        total_pass += pass_count
        total_fail += fail_count
        
        # Small delay between batches
        if batch_num < num_batches:
            time.sleep(0.5)
    
    # Final summary
    print_header("FINAL VALIDATION REPORT")
    
    # Category breakdown
    categories = {}
    for result in all_results:
        cat = result["category"]
        if cat not in categories:
            categories[cat] = {"pass": 0, "fail": 0, "total": 0}
        categories[cat]["total"] += 1
        if result["status"] == "PASS":
            categories[cat]["pass"] += 1
        else:
            categories[cat]["fail"] += 1
    
    print(f"\n{Colors.BOLD}Category Breakdown:{Colors.ENDC}")
    print(f"{Colors.OKCYAN}{'─'*65}{Colors.ENDC}")
    
    for cat, stats in sorted(categories.items()):
        percent = (stats["pass"] / stats["total"]) * 100 if stats["total"] > 0 else 0
        color = Colors.OKGREEN if stats["fail"] == 0 else Colors.WARNING
        print(f"  {cat:15s} : {stats['pass']:2d}/{stats['total']:2d} passed ({percent:5.1f}%)")
    
    print(f"\n{Colors.OKCYAN}{'─'*65}{Colors.ENDC}")
    print(f"{Colors.BOLD}Overall Statistics:{Colors.ENDC}")
    print(f"{Colors.OKCYAN}{'─'*65}{Colors.ENDC}")
    print(f"  Total Endpoints Tested: {len(all_results)}")
    print(f"  Passed: {Colors.OKGREEN}{total_pass}{Colors.ENDC}")
    print(f"  Failed: {Colors.FAIL}{total_fail}{Colors.ENDC}")
    success_rate = (total_pass / len(all_results)) * 100 if all_results else 0
    print(f"  Success Rate: {success_rate:.1f}%")
    
    print()
    
    if total_fail == 0:
        print(f"{Colors.OKGREEN}{'='*65}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{'ALL ENDPOINTS VALIDATED SUCCESSFULLY'.center(65)}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{'='*65}{Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}{'='*65}{Colors.ENDC}")
        print(f"{Colors.FAIL}{'VALIDATION COMPLETE WITH FAILURES'.center(65)}{Colors.ENDC}")
        print(f"{Colors.FAIL}{'='*65}{Colors.ENDC}")
        
        print(f"\n{Colors.FAIL}Failed Endpoints:{Colors.ENDC}")
        failed = [r for r in all_results if r["status"] != "PASS"]
        for f in failed:
            print(f"  {Colors.FAIL}[FAIL]{Colors.ENDC} [{f['method']:4s}] {f['path']:40s} HTTP {f['http_status']}")
    
    print()
    
    # Export results to JSON
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"d:\\RawrXD\\endpoint_validation_{timestamp}.json"
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"Results exported to: {output_file}")
    
    return 0 if total_fail == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
