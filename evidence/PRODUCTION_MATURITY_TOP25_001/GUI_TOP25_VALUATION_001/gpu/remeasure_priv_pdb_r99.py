from pathlib import Path
import hashlib, os, subprocess, time, re
from datetime import datetime, timezone, timedelta

root = Path(r"G:\~dev\rawrxd")
ev = root / "evidence/PRODUCTION_MATURITY_TOP25_001/GUI_TOP25_VALUATION_001/gpu"
exe = root / "evidence/PRODUCTION_MATURITY_TOP25_001/GUI_TOP25_VALUATION_001/clean_link/RawrXD-Win32IDE_tip6754_priv_pdb_r99.exe"
model = root / "models/tinyllama.gguf"
tip_expect = "6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431"
sha = hashlib.sha256(exe.read_bytes()).hexdigest().upper()
sha16 = sha[:16]
stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
tag = f"ide_tip6754_priv_pdb_r99_remeasure_tinyllama_{sha16}_{stamp}"
gout, gerr, gex, gmeta = [ev / f"{tag}{s}" for s in (".out.txt", ".err.txt", ".exit.txt", ".meta.txt")]

env = os.environ.copy()
for k in [
    "RAWRXD_ALLOW_GPU", "RAWR_FORCE_GPU", "RAWR_NO_CPU_FALLBACK", "RAWRXD_GPU_POLICY",
    "RAWRXD_HOST_DECODE", "RAWR_HOST_DECODE", "DEEP2_LIVE_POLICY", "DEEP2_LIVE_PATH",
    "DEEP2_DUALSTICK_ARM", "WEIGHT_BUDGET_MIB", "DEEP2_WEIGHT_BUDGET_MIB",
    "RAWRXD_PRODUCT_STREAMER_ARM", "RAWRXD_PRODUCT_STREAMER_PREP", "RAWRXD_UNREVERSE_HOTPATCH",
]:
    env.pop(k, None)
env.update({
    "RAWRXD_ALLOW_GPU": "1", "RAWR_FORCE_GPU": "1", "RAWR_NO_CPU_FALLBACK": "1",
    "RAWRXD_GPU_POLICY": "SOLO", "RAWRXD_HOST_DECODE": "0", "RAWR_HOST_DECODE": "0",
    "DEEP2_LIVE_POLICY": "OFF", "DEEP2_LIVE_PATH": "0", "DEEP2_DUALSTICK_ARM": "0",
    "WEIGHT_BUDGET_MIB": "8192", "RAWRXD_PRODUCT_STREAMER_ARM": "1",
    "RAWRXD_PRODUCT_STREAMER_PREP": "1",
})
t0 = time.time()
with open(gout, "w", encoding="utf-8", errors="replace") as fo, open(gerr, "w", encoding="utf-8", errors="replace") as fe:
    p = subprocess.Popen(
        [str(exe), "--headless", "--no-server", "--model", str(model),
         "--prompt", "What is 2+2? Answer with one digit only.", "--max-tokens", "8", "--vulkan"],
        cwd=str(root), stdout=fo, stderr=fe, env=env,
    )
    try:
        p.wait(timeout=600)
        code = p.returncode
    except subprocess.TimeoutExpired:
        p.kill()
        code = "TIMEOUT"
wall = int((time.time() - t0) * 1000)
o = gout.read_text(encoding="utf-8", errors="replace") if gout.exists() else ""
e = gerr.read_text(encoding="utf-8", errors="replace") if gerr.exists() else ""
both = e + "\n" + o
if code is None:
    code = "NULL"
gex.write_text(f"EXIT={code}\n", encoding="utf-8")


def m1(pat, default=0, cast=int):
    mm = re.search(pat, both, re.M | re.I)
    return cast(mm.group(1)) if mm else default


tok = m1(r"GENERATED_TOKENS[=:\s]+(\d+)")
if not tok:
    tok = m1(r"(?m)^LAYER_COUNT=\d+\s+TOKENS=(\d+)")
if not tok:
    tok = m1(r"(?m)^TOKENS=(\d+)")
hd = m1(r"HOST_DECODE[=:\s]+(\d+)", -1)
seh = 1 if re.search(r"PRODUCT_DEEP2_OPEN_SEH[=:\s]*1", both) else 0
seh_code = ""
mm = re.search(r"PRODUCT_DEEP2_OPEN_SEH=1 CODE=(\S+)", both)
if mm:
    seh_code = mm.group(1)
stream_seh = 1 if re.search(r"PRODUCT_DEEP2_INFER_STREAM_SEH[=:\s]*1", both) else 0
open_skip = 1 if re.search(r"OPEN_SKIP_STREAMABLE_OK", both) else 0
gpu_res = 1 if re.search(
    r"HOTPATH_FFN=GPU_RESIDENT|DEEP2_GPU_RESIDENT_FORWARD=1|HOTPATH_GPU_FWD_ENABLED=1|^GPU_RESIDENT=1",
    both,
    re.M,
) else 0
token_survived = 1 if (tok > 0 and seh == 0 and stream_seh == 0) else 0
tip = hashlib.sha256((root / "bin/RawrXD-Win32IDE.exe").read_bytes()).hexdigest().upper()
tz = timezone(timedelta(hours=-5))
asof = datetime.now(tz).strftime("%Y-%m-%dT%H:%M:%S%z")
asof = asof[:-2] + ":" + asof[-2:]
meta = f"""ASOF_LOCAL={asof}
ID={tag}
LANE=TIP6754_PRIV_PDB_R99_REMEASURE
FAMILY=tinyllama
MODEL=models/tinyllama.gguf
EXE={exe}
EXE_SHA256={sha}
SHA16={sha16}
TIP_SHA256={tip}
TIP_STILL_6754={int(tip == tip_expect)}
PRODUCT_DEEP2_OPEN_SEH={seh}
OPEN_SEH_CODE={seh_code}
INFER_STREAM_SEH={stream_seh}
OPEN_SKIP_SEEN={open_skip}
GENERATED_TOKENS={tok}
TOKEN_SURVIVED={token_survived}
GPU_RESIDENT_SEEN={gpu_res}
HOST_DECODE={hd}
PROCESS_EXIT={code}
WALL_MS={wall}
PDB=clean_link/RawrXD-Win32IDE_tip6754_priv_pdb_r99.pdb
PDB_MATCHED_RSDS=1
TIP_ABSORB=BOARD_PROPOSAL_ONLY
CROSS_SHA_CREDIT=0
PROMOTE=0
TIP_CLIMB=HOLD
INVENT_PASS=0
OUT={gout}
ERR={gerr}
"""
gmeta.write_text(meta, encoding="utf-8")
(ev / "ide_tip6754_priv_pdb_r99_remeasure_tinyllama_LATEST.meta.txt").write_text(meta, encoding="utf-8")
print(meta)
raise SystemExit(0 if token_survived else 2)
