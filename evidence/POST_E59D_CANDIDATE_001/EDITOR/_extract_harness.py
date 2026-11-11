import json, re, pathlib
p = pathlib.Path(r'C:\Users\Garrett\.cursor\projects\g-dev\agent-transcripts\6b07b21a-8849-48e7-ad99-08e68b944167\subagents\b991de66-2553-4dbf-8f22-385ca38ccec6.jsonl')
best = None
for line in p.open(encoding='utf-8', errors='replace'):
    try:
        o = json.loads(line)
    except Exception:
        continue
    c = o.get('message', {}).get('content')
    if not isinstance(c, list):
        continue
    for part in c:
        if part.get('type') != 'tool_use':
            continue
        inp = part.get('input') or {}
        cmd = inp.get('command') or ''
        if 'FINISH_25 Phase2 T06-T10' not in cmd:
            continue
        m = re.search(r"@'(.*)'@\s*\|\s*Set-Content", cmd, re.S)
        if not m:
            m = re.search(r"@'(.*)'@", cmd, re.S)
        if m:
            body = m.group(1)
            if best is None or len(body) > len(best):
                best = body
print('BEST_LEN', 0 if best is None else len(best))
if best:
    out = pathlib.Path(r'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\EDITOR\_recovered_phase2_snippet.ps1')
    out.write_text(best, encoding='utf-8')
    print('WROTE', out)
    print('HAS_ADDTYPE', 'Add-Type' in best)
    print('HAS_STARTIDE', 'Start-Ide' in best or 'function Start-Ide' in best)
