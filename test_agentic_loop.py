import urllib.request
import json
import time

BASE_URL = "http://127.0.0.1:23959"

def make_request(endpoint, data):
    """Make HTTP request to RawrEngine."""
    req = urllib.request.Request(
        f'{BASE_URL}{endpoint}',
        data=json.dumps(data).encode(),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

def execute_tool_call(tool_call):
    """Execute a tool call and return the result."""
    tool = tool_call.get("tool")
    params = tool_call.get("params", {})
    
    if tool == "file_reader":
        return make_request("/api/fs/read", {"path": params.get("target", ".")})
    elif tool == "code_edit":
        # For simplicity, we'll use write
        return make_request("/api/fs/write", params)
    elif tool == "terminal_exec":
        return make_request("/api/terminal/exec", params)
    elif tool == "fs_list":
        return make_request("/api/fs/list", params)
    elif tool == "search":
        return make_request("/api/search", params)
    elif tool == "git_status":
        return make_request("/api/git/status", params)
    else:
        return {"error": f"Unknown tool: {tool}"}

def run_agentic_task(wish, max_steps=10):
    """Run a full agentic task with tool execution."""
    print(f"Starting task: {wish}")
    
    # Initial wish
    response = make_request("/api/agent/wish", {
        "model": "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
        "mode": "full",
        "wish": wish
    })
    
    print(f"Initial response: {response.get('response', '')[:200]}")
    tool_calls = response.get("tool_calls", [])
    
    step = 0
    while tool_calls and step < max_steps:
        step += 1
        print(f"\n--- Step {step} ---")
        
        for tc in tool_calls:
            tool = tc.get("tool")
            params = tc.get("params", {})
            print(f"Executing tool: {tool} with params: {params}")
            
            # Execute the tool
            result = execute_tool_call(tc)
            print(f"Tool result: {str(result)[:300]}")
            
            # Feed result back as a new wish
            followup = f"Tool {tool} returned: {json.dumps(result)}. Continue with the task."
            response = make_request("/api/agent/wish", {
                "model": "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
                "mode": "full",
                "wish": followup
            })
            
            tool_calls = response.get("tool_calls", [])
            print(f"Followup response: {response.get('response', '')[:200]}")
    
    print(f"\nTask completed after {step} steps")
    return response

# Test with the buggy factorial fix
wish = """The file test_factorial_buggy.py has a bug in the factorial function. 
The loop range is wrong - it should be range(1, n + 1) not range(1, n). 
Please:
1. Read the file to see the bug
2. Fix the bug by changing the loop range
3. Run the test to verify the fix works"""

result = run_agentic_task(wish, max_steps=5)
print("\nFinal result:", json.dumps(result, indent=2)[:500])