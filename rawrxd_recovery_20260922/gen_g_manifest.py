import os, hashlib, time

base = r'G:\~dev\rawrxd'
out = r'F:\~dev\rawrxd_recovery_20260922\manifest_g.csv'
root_len = len(base)
lines = []
count = 0

for dirpath, dirnames, filenames in os.walk(base):
    for fn in filenames:
        fp = os.path.join(dirpath, fn)
        rel = fp[root_len:].lstrip('\\')
        size = os.path.getsize(fp)
        try:
            h = hashlib.sha256()
            with open(fp, 'rb', buffering=0) as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            sha = h.hexdigest()
        except Exception:
            sha = 'ERROR'
        mtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(fp)))
        lines.append(f"{rel}|{size}|{sha}|{mtime}")
        count += 1
        if count % 1000 == 0:
            print(f"Processed {count}")

lines.sort()
with open(out, 'w', encoding='utf-8') as f:
    for l in lines:
        f.write(l + '\n')

print(f"DONE: {count} files written to {out}")
