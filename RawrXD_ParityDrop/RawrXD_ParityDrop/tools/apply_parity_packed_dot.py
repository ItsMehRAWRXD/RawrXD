#!/usr/bin/env python3
"""Fail-closed, reversible source-only integration into RawrXD's shared executor.

No external packages. Run from the drop directory:
  py -3 tools\apply_parity_packed_dot.py F:\rawrxd
  py -3 tools\apply_parity_packed_dot.py F:\rawrxd --revert
The header is copied to the target project and source patched idempotently.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import shutil
import sys

MARK = '// RAWRXD_DEEP2_PACKED_DOT_AB_001: opt-in packed-dot probe'
INCLUDE = '#include "RawrXDParityPackedDot.hpp"  // RAWRXD_DEEP2_PACKED_DOT_AB_001'
ORIGINAL = '        quantized.assign(input, input + in);\n        GGMLPreQuantizeActivation(quantized, view->type);\n        return DotRows(weight, quantized.data(), output, in, out);'
REPLACEMENT = '''        // RAWRXD_DEEP2_PACKED_DOT_AB_001: opt-in packed-dot probe.
        // This bypasses the dequantize-to-float + double accumulation path,
        // but preserves baseline behavior unless explicitly enabled.
        if (RawrXDParityPackedDot::Enabled() &&
            (view->type == ModelGenie::GGMLType::Q4_K ||
             view->type == ModelGenie::GGMLType::Q6_K)) {
            const auto kind = view->type == ModelGenie::GGMLType::Q4_K
                ? RawrXDParityPackedDot::Kind::Q4_K
                : RawrXDParityPackedDot::Kind::Q6_K;
            return RawrXDParityPackedDot::MatVec(
                kind, view->data, static_cast<size_t>(view->bytes),
                in, out, input, output);
        }
        if (!weight) return false;
        quantized.assign(input, input + in);
        GGMLPreQuantizeActivation(quantized, view->type);
        return DotRows(weight, quantized.data(), output, in, out);'''
# Fast raw-packed path should not request an expanded float copy of each
# Q4_K/Q6_K ROM tensor first. This saves RAM and avoids needless work.
GET_WEIGHT = '''        auto getWeight = [&](const GEN::OperationIR& op, uint32_t idx) -> const float* {
            return ResolveWeight(op, idx, romResolver);
        };'''
GET_WEIGHT_REPLACEMENT = '''        auto getWeight = [&](const GEN::OperationIR& op, uint32_t idx) -> const float* {
            // RAWRXD_DEEP2_PACKED_DOT_AB_001: retain the original ROM bytes.
            // LinearFwd can consume Q4_K/Q6_K directly; avoid full F32 expansion.
            if (RawrXDParityPackedDot::Enabled() && idx == 0 &&
                (op.requiredPrimitive == Primitive::LinearFwd ||
                 op.requiredPrimitive == Primitive::RouterFwd ||
                 op.requiredPrimitive == Primitive::LMHeadFwd)) {
                const auto ref = GenWeight(op, idx);
                if (ref.domain == MG::OperandDomain::RomTensor) {
                    const TensorView* v = romResolver.Resolve(ref.id);
                    if (v && v->rank == 2 &&
                        (v->type == ModelGenie::GGMLType::Q4_K ||
                         v->type == ModelGenie::GGMLType::Q6_K)) return nullptr;
                }
            }
            return ResolveWeight(op, idx, romResolver);
        };'''
CHECK_WEIGHT = 'if (!view || view->rank != 2 || !input || !weight || !output) return false;'
CHECK_WEIGHT_REPLACEMENT = 'if (!view || view->rank != 2 || !input || !output) return false;'
COUNTER_ANCHOR = '''        // Capture the authoritative logits snapshot (same buffer used for sampling)
        logits_.assign(logitsPtr, logitsPtr + kExpectedVocab);'''
COUNTER_REPLACEMENT = COUNTER_ANCHOR + '''
        if (RawrXDParityPackedDot::Enabled()) {
            const auto c = RawrXDParityPackedDot::Snapshot();
            std::fprintf(stderr,
                "[PARITY_PACKED_DOT] q4_calls=%llu q6_calls=%llu rows=%llu packed_bytes=%llu\\n",
                static_cast<unsigned long long>(c.q4Calls),
                static_cast<unsigned long long>(c.q6Calls),
                static_cast<unsigned long long>(c.rows),
                static_cast<unsigned long long>(c.packedBytesRead));
        }'''
# In the existing AttentionFwd, capture vectors are only populated when a
# differential capture was requested. A default g_debug_pos=1 otherwise reads
# empty vectors. Guard all debug logging of these arrays.
DEBUG1 = 'if (layerIdx == 0 && position == g_debug_pos && head == 0) {'
DEBUG2 = 'if (layerIdx == 0 && position == 2 && head == 0) {'
DEBUG3 = 'if (layerIdx == 0 && position == g_debug_pos) {\n            debug_stats_tensor("Attention_Scores_L0P1"'

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    parser.add_argument('--revert', action='store_true')
    args = parser.parse_args()
    source = args.root/'src'/'modelgenie'/'ModelGenieExecutor.cpp'
    destination = args.root/'src'/'modelgenie'/'RawrXDParityPackedDot.hpp'
    header = Path(__file__).resolve().parents[1]/'src'/'modelgenie'/'RawrXDParityPackedDot.hpp'
    if not source.is_file():
        raise RuntimeError(f'Missing shared production executor: {source}')
    before = source.read_text(encoding='utf-8-sig')
    if args.revert:
        if INCLUDE not in before: raise RuntimeError('Patch not installed')
        after = before.replace(INCLUDE+'\n', '', 1).replace(REPLACEMENT, ORIGINAL, 1)
        after = after.replace(GET_WEIGHT_REPLACEMENT, GET_WEIGHT, 1)
        after = after.replace(CHECK_WEIGHT_REPLACEMENT, CHECK_WEIGHT, 1)
        after = after.replace(COUNTER_REPLACEMENT, COUNTER_ANCHOR, 1)
        # Only the exact debug guards introduced by this drop are reverted.
        after = after.replace('if (capture_scores && layerIdx == 0 && position == g_debug_pos && head == 0) {', DEBUG1)
        after = after.replace('if (capture_scores && layerIdx == 0 && position == 2 && head == 0) {', DEBUG2)
        after = after.replace('if (capture_scores && layerIdx == 0 && position == g_debug_pos) {\n            debug_stats_tensor("Attention_Scores_L0P1"', DEBUG3)
        if REPLACEMENT in after or INCLUDE in after or GET_WEIGHT_REPLACEMENT in after: raise RuntimeError('Revert refused: unexpected source layout')
        source.write_text(after, encoding='utf-8')
        print('REVERTED', source, sha(source))
        return 0
    if INCLUDE in before:
        if REPLACEMENT in before and destination.is_file() and destination.read_bytes() == header.read_bytes():
            print('ALREADY_INSTALLED', source, sha(source))
            return 0
        raise RuntimeError('Partial or conflicting patch detected: no changes made')
    if before.count(ORIGINAL) != 1: raise RuntimeError('LinearFwd integration anchor not unique: no changes made')
    if before.count(GET_WEIGHT) != 1: raise RuntimeError('ROM weight accessor anchor not unique')
    if before.count(CHECK_WEIGHT) != 1: raise RuntimeError('LinearFwd validation anchor not unique')
    if before.count(COUNTER_ANCHOR) != 1: raise RuntimeError('Logit receipt anchor not unique')
    if before.count('#include "ModelGenieExecutor.hpp"') != 1: raise RuntimeError('Include anchor missing')
    if before.count(DEBUG1) < 1 or before.count(DEBUG2) < 1 or before.count(DEBUG3) != 1:
        raise RuntimeError('Attention debug guards changed; refusing unattended integration')
    # Replace only the debug conditions in AttentionFwd (not earlier unrelated debug blocks).
    a = before.index('    static bool AttentionFwd(')
    b = before.index('    static bool MlaDecompressFwd(', a)
    attn = before[a:b]
    if attn.count(DEBUG1) != 1 or attn.count(DEBUG2) != 1 or attn.count(DEBUG3) != 1:
        raise RuntimeError('Attention block differs; refusing unattended integration')
    attn = attn.replace(DEBUG1, 'if (capture_scores && layerIdx == 0 && position == g_debug_pos && head == 0) {')
    attn = attn.replace(DEBUG2, 'if (capture_scores && layerIdx == 0 && position == 2 && head == 0) {')
    attn = attn.replace(DEBUG3, 'if (capture_scores && layerIdx == 0 && position == g_debug_pos) {\n            debug_stats_tensor("Attention_Scores_L0P1"')
    after = before[:a] + attn + before[b:]
    after = after.replace('#include "ModelGenieExecutor.hpp"', '#include "ModelGenieExecutor.hpp"\n'+INCLUDE, 1)
    after = after.replace(ORIGINAL, REPLACEMENT, 1)
    after = after.replace(GET_WEIGHT, GET_WEIGHT_REPLACEMENT, 1)
    after = after.replace(CHECK_WEIGHT, CHECK_WEIGHT_REPLACEMENT, 1)
    after = after.replace(COUNTER_ANCHOR, COUNTER_REPLACEMENT, 1)
    if (after.count(INCLUDE) != 1 or after.count(REPLACEMENT) != 1 or
        after.count(GET_WEIGHT_REPLACEMENT) != 1 or after.count(COUNTER_REPLACEMENT) != 1):
        raise RuntimeError('Postcondition failed; refusing to write')
    if destination.exists() and destination.read_bytes() != header.read_bytes():
        raise RuntimeError(f'Existing header conflict: {destination}')
    backup = source.with_suffix('.cpp.pre_parity_packed_dot_001.bak')
    if backup.exists():
        if backup.read_text(encoding='utf-8-sig') != before:
            raise RuntimeError('Backup already exists and differs; refusing to overwrite')
    else:
        shutil.copyfile(source, backup)
    shutil.copyfile(header, destination)
    source.write_text(after, encoding='utf-8')
    print('SOURCE_PATCHED', source, sha(source))
    print('BACKUP', backup, sha(backup))
    print('HEADER', destination, sha(destination))
    print('BASELINE=default; set RAWRXD_PARITY_PACKED_DOT=1 to opt in')
    return 0

if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as exc:
        print('PATCH_FAIL_CLOSED:', exc, file=sys.stderr)
        sys.exit(1)
