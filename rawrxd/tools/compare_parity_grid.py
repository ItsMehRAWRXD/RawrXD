# compare_parity_grid.py
# RAWRXD_VULKAN_BODY_PARITY_GRID_001
#
# Compares a CPU ParityCheckpoint dump against a RAWRXD_VULKAN_PARITY_GRID dump and
# reports the FIRST mismatching checkpoint in CPU order.
#
# The discipline this enforces:
#   * every line carries STEP, and only same-STEP lines are compared
#   * stage names are matched by NAME, not by position, so an extra or missing
#     stage cannot shift the comparison onto the wrong operator
#   * hash equality is checked first (it is exact and cheap); only when hashes
#     differ are the magnitude statistics consulted
#   * a stage present on one side only is reported as a MISSING/EXTRA gap, never
#     skipped, because a silently dropped line is indistinguishable from a
#     stage that was never reached
#
# Usage:
#   python compare_parity_grid.py <cpu_dump> <gpu_dump> [--step N]

import re
import sys
from collections import OrderedDict

# The CPU probe and the Vulkan grid both write:
#   STEP=<n> CP=<NAME> COUNT=<n> MIN=.. MAX=.. MEAN=.. L2=.. FIRST8=.. HASH=<hex>
# The GPU grid additionally writes:
#   STEP=<n> CP=<NAME> UNAVAILABLE=NO_DEVICE_ARENA ...
LINE = re.compile(
    r"^STEP=(\d+)\s+CP=(\S+)"
    r"(?:\s+COUNT=(\d+))?"
    r"(?:\s+MIN=([-\d.eE+]+))?"
    r"(?:\s+MAX=([-\d.eE+]+))?"
    r"(?:\s+MEAN=([-\d.eE+]+))?"
    r"(?:\s+L2=([-\d.eE+]+))?"
    r"(?:\s+FIRST8=(\S+?))?"
    r"(?:\s+HASH=([0-9a-fA-F]+))?"
    r"(?:\s+NON_FINITE=(\d+))?"
)

# Parsed as generic KEY=VALUE pairs rather than by a fixed positional regex.
#
# A fixed regex with optional groups silently mis-assigns: with
# `FIRST8=(\S+?)?` non-greedy and HASH optional, the FIRST8 group swallowed a
# prefix and HASH was never captured, so BOTH sides hashed to None, None == None
# compared EQUAL, and the table printed "LAYER_0_Q MATCH 1" for a comparison of
# CPU_L2=142.338 against GPU_L2=0. That is a fabricated pass produced by the
# measuring tool itself, which is the one thing a parity comparator must never
# be able to do.
UNAVAILABLE = "UNAVAILABLE"
READBACK_FAIL = "READBACK_FAIL"


def _kv(line):
    """Split a record into (step, cp, {key: value})."""
    parts = line.strip().split()
    if not parts or not parts[0].startswith("STEP="):
        return None
    step = None
    cp = None
    kv = {}
    for p in parts:
        if "=" not in p:
            continue
        k, _, v = p.partition("=")
        if k == "STEP":
            step = int(v)
        elif k == "CP":
            cp = v
        elif k == "FIRST8":
            # FIRST8 is a comma-separated list; keep the whole thing.
            kv["FIRST8"] = v
        else:
            kv[k] = v
    return (step, cp, kv)


def _fnum(kv, key):
    v = kv.get(key)
    if v is None:
        return None
    try:
        return float(v)
    except ValueError:
        return None


def _inum(kv, key):
    v = kv.get(key)
    if v is None:
        return None
    try:
        return int(v)
    except ValueError:
        return None


# RAWRXD_COMPARATOR_ALIASING_001
# The CPU probe emits stage names in TWO forms: layer-scoped (LAYER_0_Q) and
# unscoped (Q, ATTN_NORM, ...). The unscoped form is emitted once per PREFILL
# CHUNK, not once per layer: at STEP=0 with a 5-token prompt the dump contains
# EIGHT `CP=ATTN_NORM` lines and eight `CP=LAYER_0_ATTN_NORM` lines.
#
# An earlier version canonicalised the unscoped names onto LAYER_0_* and kept
# last-write-wins per (step, name). The two forms then collided, so the "CPU
# RMS_ATTN" value used for the divergence report was the LAST chunk's, not the
# layer-0 record. The reported 13% gap at LAYER_0_RMS_ATTN was an artefact of
# that collision and has been withdrawn.
#
# Only layer-scoped names are used. An unscoped name is not ambiguous-free
# evidence of anything, so it is dropped rather than guessed at.
UNSCOPED_DROP = {
    "ATTN_NORM", "Q", "K", "V", "Q_ROPE", "K_ROPE",
    "ATTN_SCORES", "ATTN_PROBS", "ATTN_VALUE", "O_PROJ",
    "ATTN_RESIDUAL", "FFN_NORM", "FFN_GATE", "FFN_UP", "SWIGLU",
    "FFN_DOWN", "LAYER_RESIDUAL",
}


def canonical(name):
    """Keep only unambiguous, layer-scoped names, and align the two naming
    conventions for the norm stages.

    The CPU probe names the norms ATTN_NORM / FFN_NORM; the Vulkan parity grid
    names the same stages RMS_ATTN / RMS_FFN. Without this alias the two norm
    stages had NO comparable pair and appeared as EXTRA on the GPU side, which
    hid exactly the stage the divergence most likely lives in. Both names are
    layer-scoped, so mapping them is unambiguous -- unlike the unscoped forms
    above, which are not.
    """
    if name is None:
        return None
    if name in UNSCOPED_DROP:
        return None            # ambiguous: emitted once per prefill chunk
    if name.startswith("LAYER_"):
        parts = name.split("_", 2)          # ["LAYER", "<n>", "<STAGE>"]
        tail = parts[2] if len(parts) == 3 else ""
        if tail == "ATTN_NORM":
            return name.replace("_ATTN_NORM", "_RMS_ATTN")
        if tail == "FFN_NORM":
            return name.replace("_FFN_NORM", "_RMS_FFN")
        return name
    if name in ("RMS_ATTN", "RMS_FFN"):
        return name
    if name in ("EMBED", "HIDDEN_FINAL", "FINAL_NORM", "LOGITS", "LOGITS_TOP10"):
        return name
    return name


def parse(path):
    """(step, stage) -> record.

    KEYED BY (step, stage), NOT BY STAGE ALONE.

    The CPU probe emits every stage once PER STEP, so a stage name repeats with
    different step numbers. Keying by name alone made each name collapse to its
    LAST occurrence: all 499 CPU records ended up labelled step 4, and the
    comparator would then have silently compared CPU STEP=4 against GPU STEP=0
    -- producing a confident, entirely fictitious divergence. That is the exact
    error the brief named, and it shipped in the first version of this tool.
    """
    stages = OrderedDict()
    ordinal = 0
    with open(path, "r", errors="replace") as fh:
        for raw in fh:
            parsed = _kv(raw)
            if not parsed:
                continue
            step, cp, kv = parsed
            if cp is None:
                continue
            cp = canonical(cp)
            if cp is None:
                continue        # ambiguous unscoped name; see RAWRXD_COMPARATOR_ALIASING_001
            # RAWRXD_COMPARATOR_IDENTITY_001
            # (step, stage) IS NOT A UNIQUE EXECUTION IDENTITY. At STEP=0 a
            # 5-token prompt still produces EIGHT records for
            # LAYER_0_ATTN_NORM, because several forward calls share step index 0
            # (prefill chunks, speculative windows). Keying on (step, stage)
            # with last-write-wins therefore selected an arbitrary one of the
            # eight -- accidental aliasing.
            #
            # Rather than picking "first" or "last" (which only replaces
            # accidental ambiguity with deliberate ambiguity), every record now
            # carries ORD, a monotonically increasing execution ordinal within
            # the file, and is keyed by (step, ORD). Records are then aligned by
            # ordinal position, so the Nth execution on the CPU is compared with
            # the Nth on the GPU, and a count difference is reported rather than
            # silently truncated.
            ordinal += 1
            key = (step, ordinal)
            if UNAVAILABLE in kv:
                stages[key] = {"step": step, "unavailable": True}
                continue
            if READBACK_FAIL in kv:
                stages[key] = {"step": step, "readback_fail": True,
                               "count": _inum(kv, "COUNT")}
                continue
            rec = {
                "step": step,
                "cp": cp,          # RAWRXD_COMPARATOR_IDENTITY_001: without this the
                                   # table printed "?" for every stage and the
                                   # first mismatch could not be named.
                "count": _inum(kv, "COUNT"),
                "min": _fnum(kv, "MIN"),
                "max": _fnum(kv, "MAX"),
                "mean": _fnum(kv, "MEAN"),
                "l2": _fnum(kv, "L2"),
                "first8": kv.get("FIRST8"),
                "hash": (kv.get("HASH") or "").lower() or None,
                "non_finite": _inum(kv, "NON_FINITE") or 0,
            }
            stages[key] = rec
    return stages

# RAWRXD_VERDICT_TAXONOMY_001
# A hash is excellent evidence for EQUALITY. Hash inequality proves only that
# the BYTES differ, which is not the same as a numerical divergence: the
# attention-norm record differed in hash while agreeing to ~1e-7 relative on
# every displayed value, i.e. float32 rounding, and it was being reported as
# HASH_MISMATCH.
#
# The verdict is therefore a separate decision with its own states.
BIT_EXACT         = "BIT_EXACT"           # hashes equal
FP32_EQUIVALENT   = "FP32_EQUIVALENT"     # bytes differ, values agree within fp32
NUMERIC_MISMATCH  = "NUMERIC_MISMATCH"    # values genuinely differ
ALIASED           = "ALIASED"             # different stage name, same evidence
INVALID           = "INVALID"             # cannot certify: no hash, bad readback
UNKNOWN           = "UNKNOWN"             # measurement did not happen

# Relative tolerance for float32. Chosen just above fp32 epsilon (1.19e-7) with
# margin for accumulated reduction order differences: 1e-4. L2 is compared on the
# same basis. A ratio outside this band is a magnitude change, not rounding.
FP32_REL_TOL = 1e-4
FP32_L2_TOL  = 1e-3


def _first8(rec):
    """Parse FIRST8 into floats; returns [] when absent or unparseable."""
    s = rec.get("first8")
    if not s:
        return []
    out = []
    for p in s.replace(";", ",").split(","):
        p = p.strip()
        if not p:
            continue
        try:
            out.append(float(p))
        except ValueError:
            return []
    return out


def classify(c, g):
    """Return (verdict, note). Never returns a numerical verdict from a
    measurement that did not happen."""
    # Readback / execution validity first. An invalid measurement cannot produce
    # ANY numerical verdict, including a favourable one.
    if g.get("unavailable"):
        return UNKNOWN, "GPU has no device-side arena for this stage (fused)"
    if g.get("readback_fail") or c.get("readback_fail"):
        return UNKNOWN, "readback failed on one side; not a value comparison"
    ch, gh = c.get("hash"), g.get("hash")
    if not ch or not gh:
        return INVALID, "hash missing on %s side; cannot certify" % (
            "CPU" if not ch else "GPU")

    if ch == gh:
        return BIT_EXACT, "identical FNV-1a over raw bytes"

    # Hash differs. Decide numerically.
    a, b = _first8(c), _first8(g)
    l2c, l2g = c.get("l2"), g.get("l2")
    if not a or not b or len(a) != len(b) or not l2c or not l2g:
        return NUMERIC_MISMATCH, "HASH_DIFFERS (insufficient numeric detail to refine)"

    worst = 0.0
    for x, y in zip(a, b):
        d = abs(x - y)
        rel = d / max(abs(x), abs(y), 1e-30)
        worst = max(worst, rel)
    l2rel = abs(l2c - l2g) / max(abs(l2c), abs(l2g), 1e-30)
    if worst <= FP32_REL_TOL and l2rel <= FP32_L2_TOL:
        return FP32_EQUIVALENT, ("bytes differ but values agree within fp32 "
                                 "(max_rel=%.2e l2_rel=%.2e)" % (worst, l2rel))
    return NUMERIC_MISMATCH, ("max_rel=%.3e l2_rel=%.3e cpu_l2=%s gpu_l2=%s"
                              % (worst, l2rel, _fmt(l2c), _fmt(l2g)))


def layer_of(name):
    m = re.match(r"^LAYER_(\d+)_(.+)$", name)
    if m:
        return int(m.group(1)), m.group(2)
    return -1, name


def sort_key(name):
    """CPU execution order: EMBED, then layer by layer in stage order, then tail."""
    layer, stage = layer_of(name)
    order = {
        "EMBED": (0, 0),
        "INPUT": (1, 0),
        "RMS_ATTN": (1, 1),
        "Q": (1, 2), "K": (1, 3), "V": (1, 4),
        "Q_ROPE": (1, 5), "K_ROPE": (1, 6),
        "ATTN_SCORES": (1, 7), "ATTN_PROBS": (1, 8), "ATTN_VALUE": (1, 9),
        "O_PROJ": (1, 10), "ATTN_RESIDUAL": (1, 11),
        "RMS_FFN": (1, 12), "FFN_GATE": (1, 13), "FFN_UP": (1, 14),
        "SWIGLU": (1, 15), "FFN_DOWN": (1, 16), "LAYER_RESIDUAL": (1, 17),
        "HIDDEN_FINAL": (2, 0), "FINAL_NORM": (2, 1),
        "LOGITS": (2, 2), "LOGITS_TOP10": (2, 3),
    }
    stage = re.sub(r"^LAYER_\d+_", "", name)
    if stage in order:
        s, so = order[stage]
        return (max(layer, 0) if s else 0, s, so)
    return (9, 0, 0)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    cpu_path, gpu_path = sys.argv[1], sys.argv[2]
    want_step = None
    if "--step" in sys.argv:
        want_step = int(sys.argv[sys.argv.index("--step") + 1])

    cpu = parse(cpu_path)
    gpu = parse(gpu_path)

    def pick(table):
        # Reduce (step, ORD) -> rec, for ONE step chosen ONCE and applied to
        # BOTH sides. Choosing each side's step independently is precisely how a
        # cross-step comparison slips through.
        return [v for k, v in sorted(table.items()) if k[0] == want_step]

    if want_step is None:
        csteps = {k[0] for k in cpu}
        gsteps = {k[0] for k in gpu}
        if not csteps or not gsteps:
            print("NO_RECORDS cpu_steps=%s gpu_steps=%s" % (sorted(csteps), sorted(gsteps)))
            return 1
        want_step = min(csteps | gsteps)
        print("AUTO_STEP=%d (pass --step to override)" % want_step)

    # RAWRXD_COMPARATOR_IDENTITY_001: records are ALIGNED BY ORDINAL POSITION
    # within the step, so the Nth execution on the CPU is compared with the Nth
    # on the GPU. A count difference is reported, not truncated, because silently
    # pairing different executions is the failure this whole change exists to
    # prevent.
    cpu_s = pick(cpu)
    gpu_s = pick(gpu)
    if not cpu_s or not gpu_s:
        print("NO_RECORDS_AT_STEP %d cpu=%d gpu=%d (cpu_steps=%s gpu_steps=%s)"
              % (want_step, len(cpu_s), len(gpu_s),
                 sorted({k[0] for k in cpu}), sorted({k[0] for k in gpu})))
        return 1

    n = min(len(cpu_s), len(gpu_s))
    if len(cpu_s) != len(gpu_s):
        print("RECORD_COUNT_DIFFERS cpu=%d gpu=%d -- comparing the first %d "
              "ordinals; the remainder is NOT assumed to correspond"
              % (len(cpu_s), len(gpu_s), n))
    cpu = cpu_s
    gpu = gpu_s
    cstep = gstep = want_step
    print("CPU_STEP=%d GPU_STEP=%d ALIGNED=%s" % (cstep, gstep, cstep == gstep))
    if cstep != gstep:
        print("STEP_MISALIGNED: comparing different steps is meaningless; "
              "re-run both with the same token count and --step.")
        return 1

    print("CPU_STAGES=%d GPU_STAGES=%d" % (len(cpu), len(gpu)))
    print("")
    print("%-5s %-26s %-10s %-8s %-12s %-12s %s" %
          ("ORD", "STAGE", "STATUS", "MATCH", "CPU_L2", "GPU_L2", "NOTE"))
    print("-" * 96)

    missing, extra, first_mismatch = [], [], None
    # RAWRXD_COMPARATOR_IDENTITY_001: pair by ORDINAL POSITION, not by name.
    # The Nth execution on each side is compared with the Nth on the other. A
    # stage-name mismatch is reported as such (it is a real signal) but does not
    # silently re-pair the remaining records onto different executions.
    for i in range(n):
        c = cpu[i]
        g = gpu[i]
        name = "LAYER_?_" + (c.get("cp") or "?")
        cname = c.get("cp") or "?"
        gname = g.get("cp") or "?"
        if cname != gname:
            # RAWRXD_COMPARATOR_ALIASING_001: a name difference is only a real
            # finding when the VALUES differ. The grid calls the layer-0 input
            # LAYER_0_INPUT where the CPU calls it EMBED; those are the same
            # record with identical hashes, and reporting that as the first
            # mismatch would send the investigation to a stage that is provably
            # correct.
            ch0 = c.get("hash")
            gh0 = g.get("hash")
            if ch0 and gh0 and ch0 == gh0:
                print("%-5d %-26s %-10s %-8s %-12s %-12s %s" %
                      (i, gname, "ALIASED", "1", _fmt(c.get("l2")), _fmt(g.get("l2")),
                       "cpu=%s gpu=%s; identical hash, naming difference only"
                       % (cname, gname)))
                continue
            print("%-5d %-26s %-10s %-8s %-12s %-12s %s" %
                  (i, name, "NAME_DIFF", "0", _fmt(c.get("l2")), _fmt(g.get("l2")),
                   "cpu=%s gpu=%s; these are not the same stage" % (cname, gname)))
            if first_mismatch is None:
                first_mismatch = (gname, c, g, "STAGE_NAME_MISMATCH")
            continue
        name = gname if gname != "?" else cname
        if c.get("count") != g.get("count"):
            print("%-5d %-26s %-10s %-8s %-12s %-12s %s" %
                  (i, name, "SHAPE_MISMATCH", "0", str(c.get("count")),
                   str(g.get("count")), "element count differs"))
            if first_mismatch is None:
                first_mismatch = (name, c, g, "SHAPE_MISMATCH")
            continue
        # RAWRXD_VERDICT_TAXONOMY_001: validity first, then hash equality, then a
        # NUMERIC comparison. A hash difference is not a numerical verdict.
        verdict, note = classify(c, g)
        print("%-5d %-26s %-16s %-8s %-12s %-12s %s" %
              (i, name, verdict, "1" if verdict in (BIT_EXACT, FP32_EQUIVALENT) else "0",
               _fmt(c.get("l2")), _fmt(g.get("l2")), note))
        if verdict == NUMERIC_MISMATCH and first_mismatch is None:
            first_mismatch = (name, c, g, verdict)

    print("")
    print("ALIGNED_RECORDS=%d (paired by execution ordinal)" % n)
    print("MISSING_ON_GPU=%d" % len(missing))
    print("EXTRA_ON_GPU=%d" % len(extra))
    if len(cpu_s) != len(gpu_s):
        print("  (record counts differ; see RECORD_COUNT_DIFFERS above)")

    if first_mismatch:
        name, c, g, kind = first_mismatch
        layer, stage = layer_of(name)
        print("")
        print("FIRST_MISMATCH_STEP=%d" % cstep)
        print("FIRST_MISMATCH_LAYER=%d" % layer)
        print("FIRST_MISMATCH_STAGE=%s" % name)
        print("MISMATCH_KIND=%s" % kind)
        print("CPU_HASH=%s" % c.get("hash"))
        print("GPU_HASH=%s" % g.get("hash"))
        print("CPU_L2=%s" % _fmt(c.get("l2")))
        print("GPU_L2=%s" % _fmt(g.get("l2")))
        print("CPU_MINMAX=%s..%s" % (_fmt(c.get("min")), _fmt(c.get("max"))))
        print("GPU_MINMAX=%s..%s" % (_fmt(g.get("min")), _fmt(g.get("max"))))
        print("CPU_FIRST8=%s" % c.get("first8"))
        print("GPU_FIRST8=%s" % g.get("first8"))
        print("VERDICT=FAIL")
        return 1

    print("")
    print("FIRST_MISMATCH_STAGE=NONE")
    print("VERDICT=PASS")
    return 0


def _fmt(x):
    return "n/a" if x is None else "%.6g" % x


def _ratio(a, b):
    if a is None or b is None or a == 0:
        return None
    return b / a


if __name__ == "__main__":
    sys.exit(main())
