from pathlib import Path
import re

err_p = Path(r"F:\rawrxd-native-agent-001\evidence\oracle_probe_raw.err")
out_p = Path(r"F:\rawrxd-native-agent-001\evidence\oracle_probe_raw.out")
clean_p = Path(r"F:\rawrxd-native-agent-001\evidence\oracle_probe_raw.err.utf8.txt")

raw = err_p.read_bytes()
nulls = raw.count(0)
print(f"ERR_BYTES={len(raw)}")
print(f"ERR_NULLS={nulls}")
print(f"OUT_BYTES={out_p.stat().st_size}")

if nulls > len(raw) // 4:
    text = raw.decode("utf-16-le", errors="replace")
else:
    text = raw.replace(b"\x00", b"").decode("utf-8", errors="replace")

clean_p.write_text(text, encoding="utf-8", errors="replace")
lines = [ln for ln in text.splitlines() if ln.strip()]
print(f"CLEAN_NONEMPTY_LINES={len(lines)}")
print("=== ERR_HEAD ===")
for ln in lines[:45]:
    print(ln[:240])
print("=== ERR_TAIL ===")
for ln in lines[-35:]:
    print(ln[:240])
print("=== KEY_HITS ===")
keys = ("n_predict", "n_ctx", "n_batch", "sampling", "seed", "top_k", "temperature", "window", "2048", "256")
for ln in lines:
    low = ln.lower()
    if any(k in low for k in keys):
        print(ln[:240])

int_seq = 0
sample = ""
for ln in lines:
    nums = re.findall(r"\b\d{1,7}\b", ln)
    if len(nums) >= 8:
        int_seq += 1
        if not sample:
            sample = " ".join(nums[:20])
print(f"INT_SEQ_LINES={int_seq}")
if sample:
    print(f"INT_SEQ_SAMPLE={sample}")

low = text.lower()
print(f"HAS_LLAMA_={('llama_' in low)}")
print(f"HAS_N_PREDICT={('n_predict' in low)}")
print(f"N_PREDICT_256={bool(re.search(r'n_predict[^\\n]{{0,60}}256|n_predict\\s*=\\s*256', low))}")
print(f"WINDOW_256={('window=256' in low or 'window = 256' in low)}")
print(f"CTX_2048={('2048' in low or 'n_ctx' in low)}")
out = out_p.read_text(encoding="utf-8", errors="replace")
print(f"OUT_HAS_REPL_BANNER={('available commands' in out.lower())}")
print(f"OUT_HAS_CTX_ERROR={('exceeds the available context' in out.lower())}")
print("DONE")
Path(r"F:\rawrxd-native-agent-001\evidence\oracle_classify_receipt.txt").write_text(
    "\n".join([
        f"ERR_BYTES={len(raw)}",
        f"ERR_NULLS={nulls}",
        f"OUT_BYTES={out_p.stat().st_size}",
        f"CLEAN_NONEMPTY_LINES={len(lines)}",
        f"INT_SEQ_LINES={int_seq}",
        f"INT_SEQ_SAMPLE={sample}",
        f"HAS_LLAMA_={('llama_' in low)}",
        f"HAS_N_PREDICT={('n_predict' in low)}",
        f"N_PREDICT_256={bool(re.search(r'n_predict[^\\n]{{0,60}}256|n_predict\\s*=\\s*256', low))}",
        f"WINDOW_256={('window=256' in low or 'window = 256' in low)}",
        f"CTX_2048={('2048' in low or 'n_ctx' in low)}",
        f"OUT_HAS_REPL_BANNER={('available commands' in out.lower())}",
        f"OUT_HAS_CTX_ERROR={('exceeds the available context' in out.lower())}",
        "ERR_HEAD:",
        *[ln[:200] for ln in lines[:25]],
        "ERR_TAIL:",
        *[ln[:200] for ln in lines[-20:]],
    ]),
    encoding="utf-8",
)
