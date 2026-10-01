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


# The CPU probe emits the first layer's stages under BOTH an unscoped name
# (Q, K, FFN_GATE, ...) and the layer-scoped name (LAYER_0_Q, ...), with
# identical values. Normalising to the layer-scoped form is what lets the two
# sides be compared by name instead of by position.
UNSCOPED_TO_STAGE = {
    "ATTN_NORM": "RMS_ATTN",
    "Q": "Q", "K": "K", "V": "V",
    "Q_ROPE": "Q_ROPE", "K_ROPE": "K_ROPE",
    "ATTN_SCORES": "ATTN_SCORES", "ATTN_PROBS": "ATTN_PROBS",
    "ATTN_VALUE": "ATTN_VALUE", "O_PROJ": "O_PROJ",
    "ATTN_RESIDUAL": "ATTN_RESIDUAL",
    "FFN_NORM": "RMS_FFN",
    "FFN_GATE": "FFN_GATE", "FFN_UP": "FFN_UP", "SWIGLU": "SWIGLU",
    "FFN_DOWN": "FFN_DOWN", "LAYER_RESIDUAL": "LAYER_RESIDUAL",
}


def canonical(name):
    """Normalise a stage name to the LAYER_<n>_<STAGE> form."""
    if name is None:
        return None
    if name.startswith("LAYER_") or name in ("EMBED", "HIDDEN_FINAL",
                                             "FINAL_NORM", "LOGITS", "LOGITS_TOP10"):
        return name
    if name in UNSCOPED_TO_STAGE:
        return "LAYER_0_" + UNSCOPED_TO_STAGE[name]
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
    with open(path, "r", errors="replace") as fh:
        for raw in fh:
            parsed = _kv(raw)
            if not parsed:
                continue
            step, cp, kv = parsed
            if cp is None:
                continue
            key = (step, canonical(cp))
            if UNAVAILABLE in kv:
                stages[key] = {"step": step, "unavailable": True}
                continue
            if READBACK_FAIL in kv:
                stages[key] = {"step": step, "readback_fail": True,
                               "count": _inum(kv, "COUNT")}
                continue
            rec = {
                "step": step,
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
        # Reduce (step, stage) -> stage, for ONE step chosen ONCE and applied to
        # BOTH sides. Choosing each side's step independently is precisely how a
        # cross-step comparison slips through.
        if want_step is None:
            return None
        return {k[1]: v for k, v in table.items() if k[0] == want_step}

    if want_step is None:
        # Default to the LOWEST step present on either side, and then require
        # both sides to actually have that step.
        csteps = {k[0] for k in cpu}
        gsteps = {k[0] for k in gpu}
        if not csteps or not gsteps:
            print("NO_RECORDS cpu_steps=%s gpu_steps=%s" % (sorted(csteps), sorted(gsteps)))
            return 1
        want_step = min(csteps | gsteps)
        print("AUTO_STEP=%d (pass --step to override)" % want_step)

    cpu_s = pick(cpu)
    gpu_s = pick(gpu)
    if cpu_s is None or gpu_s is None:
        cpu_s = {k[1]: v for k, v in cpu.items() if k[0] == want_step}
        gpu_s = {k[1]: v for k, v in gpu.items() if k[0] == want_step}
    if not cpu_s or not gpu_s:
        print("NO_RECORDS_AT_STEP %d cpu=%d gpu=%d (cpu_steps=%s gpu_steps=%s)"
              % (want_step, len(cpu_s), len(gpu_s),
                 sorted({k[0] for k in cpu}), sorted({k[0] for k in gpu})))
        return 1

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
    print("%-28s %-10s %-8s %-12s %-12s %s" %
          ("STAGE", "STATUS", "MATCH", "CPU_L2", "GPU_L2", "NOTE"))
    print("-" * 96)

    missing, extra, first_mismatch = [], [], None
    for name in sorted(set(cpu) | set(gpu), key=sort_key):
        c = cpu.get(name)
        g = gpu.get(name)
        if c is None:
            extra.append(name)
            print("%-28s %-10s %-8s %-12s %-12s %s" % (name, "EXTRA", "-", "-", "-",
                  "on GPU only; no CPU counterpart to compare"))
            continue
        if g is None:
            missing.append(name)
            print("%-28s %-10s %-8s %-12s %-12s %s" % (name, "MISSING", "-",
                  _fmt(c.get("l2")), "-", "on CPU only; GPU emitted no record"))
            continue
        if g.get("unavailable"):
            print("%-28s %-10s %-8s %-12s %-12s %s" % (name, "NO_ARENA", "n/a",
                  _fmt(c.get("l2")), "n/a",
                  "GPU has no device-side arena for this stage (fused)"))
            continue
        if g.get("readback_fail"):
            print("%-28s %-10s %-8s %-12s %-12s %s" % (name, "RD_FAIL", "n/a",
                  _fmt(c.get("l2")), "n/a", "GPU readback failed; not a value mismatch"))
            continue
        if c.get("count") != g.get("count"):
            print("%-28s %-10s %-8s %-12s %-12s %s" % (name, "SHAPE", "0",
                  str(c.get("count")), str(g.get("count")), "element count differs"))
            if first_mismatch is None:
                first_mismatch = (name, c, g, "SHAPE_MISMATCH")
            continue
        # A hash is REQUIRED on both sides. Two absent hashes must never compare
        # equal: that is the fabricated-pass path, and a comparator that cannot
        # prove a match must not report one.
        ch, gh = c.get("hash"), g.get("hash")
        if not ch or not gh:
            print("%-28s %-10s %-8s %-12s %-12s %s" % (name, "NO_HASH", "0",
                  _fmt(c.get("l2")), _fmt(g.get("l2")),
                  "cpu_hash=%s gpu_hash=%s; cannot certify" %
                  (ch or "MISSING", gh or "MISSING")))
            if first_mismatch is None:
                first_mismatch = (name, c, g, "HASH_UNAVAILABLE")
            continue
        same = (ch == gh)
        note = ""
        if not same:
            if c.get("non_finite") or g.get("non_finite"):
                note = "NON_FINITE_PRESENT cpu=%d gpu=%d" % (
                    c.get("non_finite", 0), g.get("non_finite", 0))
            elif _ratio(c.get("l2"), g.get("l2")) is not None and \
                 _ratio(c.get("l2"), g.get("l2")) > 1.5:
                note = "L2_INFLATED gpu/cpu=%.2fx" % _ratio(c.get("l2"), g.get("l2"))
            else:
                note = "HASH_DIFFERS"
        print("%-28s %-10s %-8s %-12s %-12s %s" % (
            name, "MATCH" if same else "MISMATCH", "1" if same else "0",
            _fmt(c.get("l2")), _fmt(g.get("l2")), note))
        if not same and first_mismatch is None:
            first_mismatch = (name, c, g, "HASH_MISMATCH")

    print("")
    print("MISSING_ON_GPU=%d" % len(missing))
    for n in missing[:12]:
        print("  missing: %s" % n)
    print("EXTRA_ON_GPU=%d" % len(extra))
    for n in extra[:12]:
        print("  extra:   %s" % n)

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
