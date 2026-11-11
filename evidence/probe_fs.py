import os, sys
root = r"F:\rawrxd"
def exists(p): return os.path.exists(p)
print("NUGVERSE_MANIFEST_DIR:", "EXISTS" if exists(os.path.join(root, "evidence", "NUGVERSE_ESTIMATOR_001")) else "MISSING")
if exists(os.path.join(root, "evidence", "NUGVERSE_ESTIMATOR_001")):
    d = os.path.join(root, "evidence", "NUGVERSE_ESTIMATOR_001")
    try:
        for n in sorted(os.listdir(d))[:25]:
            fp = os.path.join(d, n)
            print("   ", n, ("" if os.path.isdir(fp) else str(os.path.getsize(fp))+" bytes"))
    except Exception as e:
        print("   listdir error:", e)

# find any .gguf under root (depth-limited via os.walk)
ggufs = []
for dirpath, dirnames, fnames in os.walk(root):
    # depth guard: stop descending deep
    depth = dirpath.replace(root, "").count(os.sep)
    if depth >= 6:
        dirnames[:] = []
        continue
    for f in fnames:
        if f.lower().endswith(".gguf"):
            ggufs.append(os.path.join(dirpath, f))
    if len(ggufs) > 20:
        break
print("GGUF_FILES_FOUND:", len(ggufs))
for g in ggufs[:20]:
    print("   ", os.path.getsize(g), g)

gdir = os.path.join(root, "generated", "DeepSeek-V2-Lite-Chat")
print("GENERATED_DIR:", "EXISTS" if exists(gdir) else "MISSING")
if exists(gdir):
    for n in sorted(os.listdir(gdir))[:30]:
        fp = os.path.join(gdir, n)
        print("   ", n, ("" if os.path.isdir(fp) else str(os.path.getsize(fp))+" bytes"))

print("EXE:", "EXISTS" if exists(os.path.join(root, "build-modelgenie-tools", "bin", "rawrxd_modelgenie_token0_execution.exe")) else "MISSING")
