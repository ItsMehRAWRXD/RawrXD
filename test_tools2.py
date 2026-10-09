import urllib.request
import json

# Test search
req = urllib.request.Request(
    'http://127.0.0.1:23959/api/search',
    data=json.dumps({'query': 'Deep2Backend', 'path': '.'}).encode(),
    headers={'Content-Type': 'application/json'},
    method='POST'
)
with urllib.request.urlopen(req) as resp:
    print('Search:', resp.read().decode()[:500])

# Test git status
with urllib.request.urlopen('http://127.0.0.1:23959/api/git/status') as resp:
    print('Git status:', resp.read().decode()[:500])