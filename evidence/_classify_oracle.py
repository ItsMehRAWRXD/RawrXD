from pathlib import Path
import re

out_p = Path(r"F:\rawrxd-native-agent-001\evidence\oracle_probe_raw.out")
err_p = Path(r"F:\rawrxd-native-agent-001\evidence\oracle_probe_raw.err")
meta_p = Path(r"F:\rawrxd-native-agent-001\evidence\oracle_probe_meta.txt")

out_b = out_p.read_bytes()
err_b = err_p.read_bytes()
print(f"OUT_BYTES={len(out_b)}")
print(f"ERR_BYTES={len(err_b)}")
print(f"ERR_NULLS={err_b.count(0)}")

out = out_b.decode("utf-8", errors="replace")
err = err_b.replace(b"\x00", b"").decode("utf-8", errors="replace")

print("=== FULL_OUT ===")
print(out[:4000])

elines = [ln for ln in err.splitlines() if ln.strip()]
print("=== ERR_CLEAN_HEAD ===")
for ln in elines[:40]:
    print(ln[:240])
print("=== ERR_CLEAN_TAIL ===")
for ln in elines[-30:]:
    print(ln[:240])

print("=== SEARCH_KEYS ===")
keys = ("n_predict", "n_ctx", "n_batch", "n-predict", "256", "2048", "sampling", "seed", "top_k", "temperature", "window")
for ln in elines:
    low = ln.lower()
    if any(k.lower() in low for k in keys):
        print(ln[:240])

# cheap int-seq: look for 8+ consecutive integer tokens on a line
int_seq = 0
sample = ""
for ln in elines + out.splitlines():
    nums = re.findall(r"\b\d{1,7}\b", ln)
    if len(nums) >= 8:
        int_seq += 1
        if not sample:
            sample = " ".join(nums[:24])
print(f"INT_SEQ_LINES={int_seq}")
if sample:
    print(f"INT_SEQ_SAMPLE={sample}")

print("=== META ===")
print(meta_p.read_text(errors="replace"))

combo = (out + "\n" + err).lower()
print(f"OUT_CLASS={'ERROR_TEXT' if 'error:' in out.lower() else 'GENERATION_OR_MIXED'}")
print(f"ERR_CLASS={'RAW_VERBOSE' if ('llama_' in combo or 'ggml_' in combo or err_b.count(0) > 1000) else 'UNKNOWN'}")
print(f"N_PREDICT_256={'n_predict' in combo and '256' in combo}")
print(f"CTX_2048_IN_OUT={'2048' in out}")
print(f"WINDOW_256={'window=256' in combo or 'window = 256' in combo}")
print(f"CTX_OVERFLOW={'exceeds the available context' in combo}")
