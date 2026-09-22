import os
import csv
import hashlib
from datetime import datetime

G_ROOT = r'G:\~dev\rawrxd'
OUT_PATH = r'F:\~dev\rawrxd_recovery_20260922\manifest_g.csv'

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb', buffering=0) as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

lines = []
root_len = len(G_ROOT)
for dirpath, dirnames, filenames in os.walk(G_ROOT):
    for fn in filenames:
        fp = os.path.join(dirpath, fn)
        rel = fp[root_len:].lstrip('\\')
        size = os.path.getsize(fp)
        try:
            sha = sha256_file(fp)
        except Exception:
            sha = 'ERROR'
        mtime = datetime.fromtimestamp(os.path.getmtime(fp)).strftime('%Y-%m-%d %H:%M:%S')
        lines.append([rel, size, sha, mtime])

with open(OUT_PATH, 'w', newline='', encoding='utf-8') as f:
    w = csv.writer(f)
    w.writerow(['RelativePath', 'Size', 'SHA256', 'LastWriteTime'])
    w.writerows(lines)

print(f'Wrote {len(lines)} files to manifest_g.csv')
