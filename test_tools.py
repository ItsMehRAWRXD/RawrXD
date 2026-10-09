import urllib.request
import json

# Test file operations
# 1. List directory
with urllib.request.urlopen('http://127.0.0.1:23959/api/fs/list?path=.') as resp:
    print('List:', resp.read().decode()[:500])

# 2. Read a file
req = urllib.request.Request(
    'http://127.0.0.1:23959/api/fs/read',
    data=json.dumps({'path': 'backend/deep2_backend.py'}).encode(),
    headers={'Content-Type': 'application/json'},
    method='POST'
)
with urllib.request.urlopen(req) as resp:
    data = resp.read().decode()
    print('Read:', data[:200])

# 3. Write a file
content = 'print("Hello from Deep2!")'
req = urllib.request.Request(
    'http://127.0.0.1:23959/api/fs/write',
    data=json.dumps({'path': 'test_hello.py', 'content': content}).encode(),
    headers={'Content-Type': 'application/json'},
    method='POST'
)
with urllib.request.urlopen(req) as resp:
    print('Write:', resp.read().decode())

# 4. Execute command - use full Python path
python_path = r'C:\Users\Garrett\AppData\Local\Programs\Python\Python313\python.exe'
req = urllib.request.Request(
    'http://127.0.0.1:23959/api/terminal/exec',
    data=json.dumps({'command': f'{python_path} test_hello.py', 'cwd': '.'}).encode(),
    headers={'Content-Type': 'application/json'},
    method='POST'
)
with urllib.request.urlopen(req) as resp:
    print('Exec:', resp.read().decode())