# Clean Deep2Engine = 77f5043af7 (FA006-era) + GemvAvxWqNext only. PROMOTE=0
import subprocess
from pathlib import Path

cwd = r"G:\~dev\rawrxd"
base = subprocess.check_output(
    ["git", "show", "77f5043af7:src/deep2/Deep2Engine.cpp"], cwd=cwd
)
text = base.decode("utf-8")
old = (
    "         wt.type == (int)GGMLType::GGML_TYPE_Q6_K)) {\r\n"
    "        const bool ok = vc->DispatchGEMVQuant("
)
new = (
    "         wt.type == (int)GGMLType::GGML_TYPE_Q6_K)) {\r\n"
    "        /* R89: llama-AVX Q4 square pipe for attn_q.weight only (not wo). */\r\n"
    "        if (wt.type == (int)GGMLType::GGML_TYPE_Q4_K &&\r\n"
    '            wt.name.find("attn_q.weight") != std::string::npos)\r\n'
    "            vc->GemvAvxWqNext();\r\n"
    "        const bool ok = vc->DispatchGEMVQuant("
)
if old not in text:
    old = old.replace("\r\n", "\n")
    new = new.replace("\r\n", "\n")
    if old not in text:
        i = text.find("GGML_TYPE_Q6_K)) {")
        raise SystemExit("patch site missing: " + repr(text[i : i + 200]))
    print("patched LF")
else:
    print("patched CRLF")
text = text.replace(old, new, 1)
out = Path(cwd) / "src" / "deep2" / "_Deep2Engine_r89_wq_clean.cpp"
# Normalize to LF for cl; keep content
out.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))
print("wrote", out, "bytes", out.stat().st_size)
print("GemvAvxWqNext", text.count("GemvAvxWqNext"))
print("AVX8_default", "Default: AVX8" in text)
print("double_default", "Default: ggml_float=double" in text)
