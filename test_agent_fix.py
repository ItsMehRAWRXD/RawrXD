import urllib.request
import json

# Test agent/wish with full mode to fix the buggy code
req = urllib.request.Request(
    'http://127.0.0.1:23959/api/agent/wish',
    data=json.dumps({
        'model': 'tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf',
        'mode': 'full',
        'wish': 'The file test_factorial_buggy.py has a bug in the factorial function. The loop range is wrong - it should be range(1, n + 1) not range(1, n). Please read the file, fix the bug, and run the test to verify the fix works.'
    }).encode(),
    headers={'Content-Type': 'application/json'},
    method='POST'
)

with urllib.request.urlopen(req) as resp:
    print(resp.read().decode())