# 77f504 Deep2Engine with NO GemvAvxWqNext — isolate lib dirt. PROMOTE=0
import subprocess
from pathlib import Path

cwd = r"G:\~dev\rawrxd"
base = subprocess.check_output(
    ["git", "show", "77f5043af7:src/deep2/Deep2Engine.cpp"], cwd=cwd
)
text = base.decode("utf-8").replace("\r\n", "\n")
out = Path(cwd) / "src" / "deep2" / "_Deep2Engine_r89_wq_clean.cpp"
out.write_bytes(text.encode("utf-8"))
print("wrote", out, "GemvAvxWqNext", text.count("GemvAvxWqNext"))
