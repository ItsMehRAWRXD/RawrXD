import json, pathlib
src = pathlib.Path(r'C:\Users\Garrett\.cursor\projects\g-dev\agent-transcripts\6b07b21a-8849-48e7-ad99-08e68b944167\6b07b21a-8849-48e7-ad99-08e68b944167.jsonl')
targets = {
    r'F:\rawrxd\evidence\REAL_EDIT_7_PHYSICAL_ACCEPT_001\harness_tests_07_15.ps1': None,
    r'F:\rawrxd\evidence\REAL_EDIT_7_PHYSICAL_ACCEPT_001\harness_tests_01_06.ps1': None,
}
for line in src.open(encoding='utf-8', errors='replace'):
    try:
        o = json.loads(line)
    except Exception:
        continue
    c = o.get('message', {}).get('content')
    if not isinstance(c, list):
        continue
    for part in c:
        if part.get('type') != 'tool_use' or part.get('name') != 'Write':
            continue
        inp = part.get('input') or {}
        path = inp.get('path')
        if path in targets:
            body = inp.get('contents') or ''
            # keep longest (final) write
            if targets[path] is None or len(body) > len(targets[path]):
                targets[path] = body
out_dir = pathlib.Path(r'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\EDITOR')
for path, body in targets.items():
    if not body:
        print('MISSING', path)
        continue
    name = pathlib.Path(path).name
    dest = out_dir / ('_recovered_' + name)
    dest.write_text(body, encoding='utf-8')
    print('WROTE', dest, 'LEN', len(body), 'ADDTYPE', 'Add-Type' in body)
