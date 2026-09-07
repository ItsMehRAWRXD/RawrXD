#!/usr/bin/env python3
"""Authority reconcile: SPARSE_TIP_001 operands vs L1_CLEAN_001."""
import hashlib
import struct
from pathlib import Path


def fnv1a64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def load_f32(path):
    b = Path(path).read_bytes()
    n = len(b) // 4
    return list(struct.unpack(f"<{n}f", b)), b


def stats(a, b):
    assert len(a) == len(b)
    max_abs = 0.0
    first = -1
    exact = 0
    for i, (x, y) in enumerate(zip(a, b)):
        d = abs(x - y)
        if d == 0:
            exact += 1
        if d > max_abs:
            max_abs = d
        if first < 0 and d > 0:
            first = i
    return max_abs, exact, first, len(a)


def report(name, pa, pb):
    pa, pb = Path(pa), Path(pb)
    if not pa.exists():
        print(f"{name}: MISSING A {pa}")
        return None
    if not pb.exists():
        print(f"{name}: MISSING B {pb}")
        return None
    fa, ba = load_f32(pa)
    fb, bb = load_f32(pb)
    sha_a = hashlib.sha256(ba).hexdigest()[:16]
    sha_b = hashlib.sha256(bb).hexdigest()[:16]
    fnv_a = fnv1a64(ba)
    fnv_b = fnv1a64(bb)
    identical = ba == bb
    if len(fa) != len(fb):
        print(f"{name}: LEN_MISMATCH {len(fa)} vs {len(fb)}")
        print(f"  A sha={sha_a} fnv={fnv_a:016x} bytes={len(ba)}")
        print(f"  B sha={sha_b} fnv={fnv_b:016x} bytes={len(bb)}")
        return None
    max_abs, exact, first, n = stats(fa, fb)
    if identical:
        gate = "IDENTICAL"
    elif max_abs <= 1e-6:
        gate = "PASS"
    elif max_abs <= 1e-5:
        gate = "INSPECT"
    else:
        gate = "FAIL"
    print(f"{name}: {gate} max_abs={max_abs:.6e} exact={exact}/{n} first_bad={first}")
    print(f"  A sha16={sha_a} fnv={fnv_a:016x} n={n}")
    print(f"  B sha16={sha_b} fnv={fnv_b:016x} n={n}")
    print(f"  pathA={pa}")
    print(f"  pathB={pb}")
    return max_abs


def main():
    entry = Path(r"F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L1_ENTRY_001")
    clean = Path(r"F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L1_CLEAN_001")
    sparse = Path(r"F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_SPARSE_TIP_001")

    print("=== Deep2 sparse(deep2_l1pre) vs CLEAN deep2 ===")
    pairs = [
        (
            "SPARSE_vs_CLEAN Deep2 PRE_O_1",
            sparse / "deep2_l1pre" / "deep2_ATTN_PRE_O_1_pos0_layer0_full_n2048_seq022.bin",
            clean / "deep2" / "deep2_ATTN_PRE_O_1_pos0_layer0_full_n2048_seq022.bin",
        ),
        (
            "SPARSE_vs_CLEAN Deep2 V_1",
            sparse / "deep2_l1pre" / "deep2_V_1_pos0_layer0_full_n256_seq021.bin",
            clean / "deep2" / "deep2_V_1_pos0_layer0_full_n256_seq021.bin",
        ),
        (
            "SPARSE_vs_CLEAN Deep2 ATTN_OUT_1",
            sparse / "deep2_l1pre" / "deep2_ATTN_OUT_1_pos0_layer0_full_n2048_seq023.bin",
            clean / "deep2" / "deep2_ATTN_OUT_1_pos0_layer0_full_n2048_seq023.bin",
        ),
        (
            "ENTRY_frozen_vs_CLEAN Deep2 ATTN_OUT_1",
            entry / "deep2_frozen" / "deep2_ATTN_OUT_1_pos0_layer0_full_n2048_seq023.bin",
            clean / "deep2" / "deep2_ATTN_OUT_1_pos0_layer0_full_n2048_seq023.bin",
        ),
        (
            "ENTRY_frozen_vs_SPARSE Deep2 ATTN_OUT_1",
            entry / "deep2_frozen" / "deep2_ATTN_OUT_1_pos0_layer0_full_n2048_seq023.bin",
            sparse / "deep2_l1pre" / "deep2_ATTN_OUT_1_pos0_layer0_full_n2048_seq023.bin",
        ),
    ]
    for p in pairs:
        report(*p)

    print()
    print("=== Llama ENTRY (sparse oracle) presence ===")
    entry_pre_o1 = list(entry.glob("llama_ATTN_PRE_O_1*pos0*.bin"))
    entry_forced1 = list(entry.glob("llama_ATTN_PRE_O_FORCED_1*"))
    print(f"ENTRY llama_ATTN_PRE_O_1 pos0 bins: {len(entry_pre_o1)}")
    print(f"ENTRY llama_ATTN_PRE_O_FORCED_1 bins: {len(entry_forced1)}")
    forced0 = list(entry.glob("llama_ATTN_PRE_O_FORCED_pos0*.bin"))
    print(f"ENTRY PRE_O_FORCED (L0 only): {[p.name for p in forced0]}")

    print()
    print("=== Llama ENTRY ATTN_OUT_1 vs CLEAN ATTN_OUT_1 ===")
    entry_attn = sorted(entry.glob("llama_TENS_attn_out_1_pos0*.bin"))
    clean_attn = clean / "llama" / "llama_ATTN_OUT_1_pos0_layer0_full_n2048_seq235.bin"
    print(f"ENTRY candidates: {[p.name for p in entry_attn]}")
    for ea in entry_attn:
        report(f"ENTRY_TENS vs CLEAN ATTN_OUT_1 ({ea.name})", ea, clean_attn)

    print()
    print("=== Llama V_1 ENTRY vs CLEAN ===")
    clean_v = sorted((clean / "llama").glob("llama_V_1_pos0*n256*.bin"))
    entry_v = sorted(entry.glob("llama_V_1_pos0*n256*.bin"))
    print("CLEAN V:", [p.name for p in clean_v])
    print("ENTRY V:", [p.name for p in entry_v])
    for ev in entry_v:
        for cv in clean_v:
            if ev.stat().st_size == cv.stat().st_size:
                report(f"ENTRY_V vs CLEAN_V ({ev.name} vs {cv.name})", ev, cv)

    print()
    print("=== CLEAN oracle sanity ===")
    report(
        "CLEAN PRE_O_1 vs FORCED_1",
        clean / "llama" / "llama_ATTN_PRE_O_1_pos0_layer0_full_n2048_seq232.bin",
        clean / "llama" / "llama_ATTN_PRE_O_FORCED_1_pos0_layer0_full_n2048_seq231.bin",
    )
    report(
        "Deep2 PRE_O_1 vs CLEAN llama FORCED_1",
        clean / "deep2" / "deep2_ATTN_PRE_O_1_pos0_layer0_full_n2048_seq022.bin",
        clean / "llama" / "llama_ATTN_PRE_O_FORCED_1_pos0_layer0_full_n2048_seq231.bin",
    )

    print()
    print("=== Reconstruct sparse ATTN_OUT compare ===")
    d_attn = sparse / "deep2_l1pre" / "deep2_ATTN_OUT_1_pos0_layer0_full_n2048_seq023.bin"
    for ea in entry_attn:
        report(f"SPARSE Deep2 ATTN_OUT_1 vs ENTRY {ea.name}", d_attn, ea)
    report("SPARSE Deep2 ATTN_OUT_1 vs CLEAN llama ATTN_OUT_1", d_attn, clean_attn)

    # Weight identity: same model path from run logs if available
    print()
    print("=== WO weight authority (model path) ===")
    for label, logp in [
        ("CLEAN deep2.stdout", clean / "deep2.stdout.txt"),
        ("CLEAN llama.stdout", clean / "llama.stdout.txt"),
        ("ENTRY llama_force_dump", entry / "llama_force_dump.txt"),
    ]:
        if logp.exists():
            text = logp.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                if "gguf" in line.lower() or "model" in line.lower()[:40]:
                    if "tinyllama" in line.lower() or ".gguf" in line.lower():
                        print(f"{label}: {line.strip()[:200]}")
                        break


if __name__ == "__main__":
    main()
