#!/usr/bin/env python3
"""Apply guarded Deep2 differential-capture and optional RoPE-sign repairs.

Base: 4fcb181f2979ea905a0dcbd621109d1fadd0d99b
No third-party packages. Run in a clean RawrXD checkout from the target commit.
"""
import argparse
import difflib
from pathlib import Path
import subprocess
import sys

BASELINE = '4fcb181f2979ea905a0dcbd621109d1fadd0d99b'
REL = Path('tools/rawrxd_modelgenie_ir_executor.cpp')


def once(s: str, old: str, new: str, name: str) -> str:
    n = s.count(old)
    if n != 1:
        raise RuntimeError(f'{name}: expected 1 matching source anchor, found {n}; no source modified')
    return s.replace(old, new, 1)


def between(s: str, left: str, right: str, replacement: str, name: str) -> str:
    if s.count(left) != 1:
        raise RuntimeError(f'{name}: missing/nonunique start anchor; no source modified')
    start = s.index(left)
    end = s.find(right, start)
    if end < 0:
        raise RuntimeError(f'{name}: missing end anchor; no source modified')
    return s[:start] + replacement + s[end:]


def patch_capture(s: str) -> str:
    s = once(s, '#include <cstdio>\n', '#include <cstdio>\n#include <fstream>\n', 'fstream direct include')
    s = once(s,
        '    std::string output_dir;\n    \n    void Enable',
        '    std::string output_dir;\n'
        '    size_t capture_position = (std::numeric_limits<size_t>::max)();\n'
        '    bool ShouldRecord(size_t pos) const {\n'
        '        return enabled && (capture_position == (std::numeric_limits<size_t>::max)() || capture_position == pos);\n'
        '    }\n'
        '    \n    void Enable', 'position-filter state')
    s = once(s, '        if (!enabled) return;\n        \n        ActivationRecord rec;',
        '        if (!ShouldRecord(position) || !data || shape.empty()) return;\n'
        '        \n        ActivationRecord rec;', 'position-filter capture')
    s = once(s,
        '        for (int64_t d : shape) total *= d;\n',
        '        for (int64_t d : shape) {\n'
        '            if (d <= 0 || static_cast<uint64_t>(d) > 200000u / total) {\n'
        '                std::fprintf(stderr, "[DIFF] Invalid or oversized tensor: %s\\n", op_name.c_str());\n'
        '                return;\n'
        '            }\n'
        '            total *= static_cast<size_t>(d);\n'
        '        }\n', 'validated tensor shape')
    s = once(s,
        '        for (const auto& rec : records) {\n            char fname[512];\n            sprintf_s(fname, "%s\\\\rec_%s_l%u_p%zu_%s.bin", \n                     output_dir.c_str(), rec.op_name.c_str(), rec.layer_idx, rec.position, rec.tensor_type.c_str());',
        '        for (size_t record_index = 0; record_index < records.size(); ++record_index) {\n'
        '            const auto& rec = records[record_index];\n'
        '            char fname[1024];\n'
        '            const int nchars = std::snprintf(fname, sizeof(fname),\n'
        '                "%s\\\\rec_%06zu_op%u_%s_l%u_p%zu_%s.bin",\n'
        '                output_dir.c_str(), record_index, rec.op_id, rec.op_name.c_str(),\n'
        '                rec.layer_idx, rec.position, rec.tensor_type.c_str());\n'
        '            if (nchars < 0 || static_cast<size_t>(nchars) >= sizeof(fname)) {\n'
        '                std::fprintf(stderr, "[DIFF] Record output path too long\\n");\n'
        '                continue;\n'
        '            }', 'unique differential filenames')
    s = once(s, '            uint32_t op_id = 0;\n            uint32_t layer = 0;\n            size_t pos = 0;\n',
        '            const uint32_t op_id = rec.op_id;\n', 'true op ID')
    s = between(s,
        '    if (argc >= 4) {\n        std::string arg3 = argv[3];',
        '    std::fprintf(stderr, "=============================================================================\\n");',
        '''    // Order-independent CLI options. Differential flags are never parsed as token IDs.
    size_t diff_position = (std::numeric_limits<size_t>::max)();
    auto parse_uint = [](const char* raw, uint32_t& value) -> bool {
        if (!raw || !raw[0] || raw[0] == '-') return false;
        try {
            size_t consumed = 0;
            const unsigned long long parsed = std::stoull(raw, &consumed, 10);
            if (consumed != std::strlen(raw) ||
                parsed > (std::numeric_limits<uint32_t>::max)()) return false;
            value = static_cast<uint32_t>(parsed);
            return true;
        } catch (const std::exception&) { return false; }
    };
    for (int i = 3; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--teacher-forced") {
            teacher_forced = true;
        } else if (arg == "--differential") {
            differential = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') differential_dir = argv[++i];
        } else if (arg == "--diff-position") {
            uint32_t p = 0;
            if (i + 1 >= argc || !parse_uint(argv[++i], p)) {
                std::fprintf(stderr, "ERROR: --diff-position needs an unsigned integer\\n");
                return 2;
            }
            diff_position = p;
        } else if (arg == "--multitoken") {
            multitoken = true;
            max_tokens = 16;
            uint32_t n = 0;
            if (i + 1 < argc && parse_uint(argv[i + 1], n)) {
                ++i;
                if (n == 0 || n > 1024) { std::fprintf(stderr, "ERROR: invalid token count\\n"); return 2; }
                max_tokens = static_cast<int>(n);
            }
        } else {
            uint32_t n = 0;
            if (!parse_uint(argv[i], n)) {
                std::fprintf(stderr, "ERROR: unknown option or invalid token: %s\\n", argv[i]);
                return 2;
            }
            if (teacher_forced) forced_tokens.push_back(n);
            else if (i == 3 && n > 0 && n <= 1024) { multitoken = true; max_tokens = static_cast<int>(n); }
            else { std::fprintf(stderr, "ERROR: numeric token requires --teacher-forced\\n"); return 2; }
        }
    }
    if (differential && differential_dir.empty()) differential_dir = evidenceDir + "\\\\differential";
    if (teacher_forced && forced_tokens.empty()) {
        std::fprintf(stderr, "ERROR: --teacher-forced needs at least one token\\n"); return 2;
    }
    if (teacher_forced && multitoken) {
        std::fprintf(stderr, "ERROR: choose teacher-forced or multitoken, not both\\n"); return 2;
    }
    if (diff_position != (std::numeric_limits<size_t>::max)() &&
        (!differential || !teacher_forced || diff_position >= forced_tokens.size())) {
        std::fprintf(stderr, "ERROR: --diff-position requires an in-range teacher-forced position and --differential\\n");
        return 2;
    }

''', 'order-independent CLI parse')
    s = once(s,
        '            DIFF_ENABLE(differential_dir);\n            DIFF_CLEAR();',
        '            DIFF_ENABLE(differential_dir);\n'
        '            g_differential_recorder.capture_position = diff_position;\n'
        '            DIFF_CLEAR();', 'capture-target setup')
    s = once(s,
        '            sprintf_s(fname, "F:\\\\rawrxd\\\\evidence\\\\NUGVERSE_ESTIMATOR_001\\\\native_tf_logits_pos%zu.bin", step);',
        '            sprintf_s(fname, "%s\\\\native_tf_logits_pos%zu.bin", evidenceDir.c_str(), step);',
        'portable logit evidence location')
    s = once(s,
        '                std::fprintf(stderr, "ERROR: Execution failed at step %zu\\n", step);\n                return 1;',
        '                std::fprintf(stderr, "ERROR: Execution failed at step %zu\\n", step);\n'
        '                if (differential) DIFF_SAVE(); // preserve partial evidence\n'
        '                return 1;', 'save partial evidence')
    s = once(s,
        '            if (differential) {\n                DIFF_SAVE();\n            }\n            \n            executor.AdvancePosition();',
        '            executor.AdvancePosition();', 'avoid repeatedly saving all records')
    s = once(s,
        '        if (differential) {\n            DIFF_DISABLE();\n        }',
        '        if (differential) {\n            DIFF_SAVE();\n            DIFF_DISABLE();\n        }', 'single differential flush')
    s = once(s,
        '            // DIFF: Record key intermediate activations\n',
        '''            // Capture the persistent prefix (including all earlier positions) after
            // the current position has been written into the layer's cache.
            if (executed && op.requiredPrimitive == MG::Primitive::MlaDecompressFwd &&
                g_differential_recorder.ShouldRecord(position_)) {
                const size_t layer = op.blockIndex == UINT32_MAX ? 0 : op.blockIndex;
                if (layer < kvCache_.layers.size()) {
                    const auto& cache = kvCache_.layers[layer];
                    const size_t count = cache.Size() * cache.kv_size;
                    if (count && count <= 200000u)
                        DIFF_RECORD("MLA_CacheKV_Prefix", op.opId, static_cast<uint32_t>(layer),
                                    position_, "kv_prefix", cache.ReadAllKV(),
                                    (std::vector<int64_t>{static_cast<int64_t>(cache.Size()), static_cast<int64_t>(cache.kv_size)}));
                }
            }

            // DIFF: Record key intermediate activations
''', 'persistent KV prefix capture')
    s = once(s,
        '                    } else if (op.requiredPrimitive == ModelGenie::Primitive::RmsNormFwd) {',
        '                    } else if (op.requiredPrimitive == ModelGenie::Primitive::TopKFwd) {\n'
        '                        tensor_type = "MoE_TopK";\n'
        '                    } else if (op.requiredPrimitive == ModelGenie::Primitive::RmsNormFwd) {',
        'MoE TopK capture')
    s = once(s,
        '                return AttentionFwd(q,kv,output,arena.Size(qr.id),arena.Size(kr.id),\n                                    arena.Size(op.output.id), kvCache, layerIdx, position);',
        '                return AttentionFwd(q,kv,output,arena.Size(qr.id),arena.Size(kr.id),\n'
        '                                    arena.Size(op.output.id), kvCache, layerIdx, position, op.opId);',
        'actual attention op ID')
    s = once(s,
        '        const float* all_kv = kvCache->layers[layerIdx].ReadAllKV();\n',
        '        if (layerIdx >= kvCache->layers.size() || kvCache->layers[layerIdx].Size() != seq_len) {\n'
        '            std::fprintf(stderr, "[KV] Invalid layer or prefix at position %zu, layer %zu\\n", position, layerIdx);\n'
        '            return false;\n'
        '        }\n'
        '        const float* all_kv = kvCache->layers[layerIdx].ReadAllKV();\n', 'KV length guard')
    s = once(s,
        '        const float scale = 1.0f / sqrtf(static_cast<float>(key)); // 1/sqrt(192)\n',
        '''        const float scale = 1.0f / sqrtf(static_cast<float>(key)); // 1/sqrt(192)
        const bool capture_scores = g_differential_recorder.ShouldRecord(position);
        std::vector<float> captured_scores, captured_weights;
        if (capture_scores) {
            captured_scores.resize(heads * seq_len);
            captured_weights.resize(heads * seq_len);
        }
''', 'score vectors')
    s = once(s,
        '                score *= scale;\n                \n                if (score > max_score) max_score = score;',
        '                score *= scale;\n'
        '                if (capture_scores) captured_scores[head * seq_len + pos] = score;\n'
        '                \n                if (score > max_score) max_score = score;', 'attention score capture')
    s = once(s,
        '                float exp_score = expf(score - max_score);\n                denom += exp_score;',
        '                float exp_score = expf(score - max_score);\n'
        '                if (capture_scores) captured_weights[head * seq_len + pos] = exp_score;\n'
        '                denom += exp_score;', 'unnormalized weight capture')
    s = once(s,
        '                out_head[i] = out_acc[i] / denom;\n            }\n        }\n        \n        // DIFF: Record attention output',
        '                out_head[i] = out_acc[i] / denom;\n'
        '            }\n'
        '            if (capture_scores)\n'
        '                for (size_t pos = 0; pos < seq_len; ++pos)\n'
        '                    captured_weights[head * seq_len + pos] /= denom;\n'
        '        }\n'
        '        if (capture_scores) {\n'
        '            DIFF_RECORD("Attention_Scores", opId, layerIdx, position, "scaled_scores",\n'
        '                        captured_scores.data(), (std::vector<int64_t>{static_cast<int64_t>(heads), static_cast<int64_t>(seq_len)}));\n'
        '            DIFF_RECORD("Attention_Weights", opId, layerIdx, position, "softmax",\n'
        '                        captured_weights.data(), (std::vector<int64_t>{static_cast<int64_t>(heads), static_cast<int64_t>(seq_len)}));\n'
        '        }\n'
        '        \n        // DIFF: Record attention output', 'attention score and probability snapshots')
    s = once(s,
        '            if (!kvCache->layers[layerIdx].Write(latent.data(), output)) return false;',
        '            if (layerIdx >= kvCache->layers.size() ||\n'
        '                kvCache->layers[layerIdx].Size() != position) {\n'
        '                std::fprintf(stderr, "[KV] Duplicate/gap write at position %zu layer %zu\\n", position, layerIdx);\n'
        '                return false;\n'
        '            }\n'
        '            if (!kvCache->layers[layerIdx].Write(latent.data(), output)) return false;',
        'KV sequential write guard')
    return s


def patch_rope(s: str) -> str:
    s = once(s,
        '            // Use NEGATIVE alpha for key RoPE to match query convention (both negative)',
        '            // Use POSITIVE alpha for cached key RoPE, matching query rotation.',
        'RoPE comment')
    s = once(s,
        '                float alpha = -static_cast<float>(position) * theta;',
        '                float alpha = static_cast<float>(position) * theta;',
        'RoPE key sign')
    return s


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repo', type=Path, default=Path('.'), help='RawrXD checkout root')
    ap.add_argument('--stage', choices=['capture', 'rope', 'all'], default='all',
                    help='Use capture first, then rope separately for a controlled A/B test')
    ap.add_argument('--no-git-guard', action='store_true', help='Skip SHA check; source anchors still enforced')
    ap.add_argument('--dry-run', action='store_true', help='Show change counts only')
    args = ap.parse_args()
    root = args.repo.resolve()
    path = root / REL
    if not path.is_file():
        ap.error(f'not found: {path}')
    if not args.no_git_guard:
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
        if head != BASELINE:
            ap.error(f'head {head[:12]} != expected {BASELINE[:12]}; use baseline or --no-git-guard deliberately')
        dirty = subprocess.check_output(['git', 'status', '--porcelain', '--', str(REL)], cwd=root, text=True).strip()
        if dirty:
            ap.error(f'{REL} is modified; preserve your local edits first')
    raw = path.read_bytes()
    if b'\x00' in raw: ap.error('not a text source')
    # Git sources use LF. Normalize only for matching; retain the original newline convention.
    crlf = b'\r\n' in raw
    old = raw.decode('utf-8-sig').replace('\r\n', '\n')
    new = old
    if args.stage in ('capture', 'all'): new = patch_capture(new)
    if args.stage in ('rope', 'all'): new = patch_rope(new)
    diff = list(difflib.unified_diff(old.splitlines(), new.splitlines(),
                                     fromfile='a/'+str(REL).replace('\\','/'),
                                     tofile='b/'+str(REL).replace('\\','/'),
                                     lineterm=''))
    adds = sum(line.startswith('+') and not line.startswith('+++') for line in diff)
    subs = sum(line.startswith('-') and not line.startswith('---') for line in diff)
    print(f'STAGE={args.stage} CHANGED_ADDED_LINES={adds} CHANGED_REMOVED_LINES={subs}')
    if args.dry_run:
        print('DRY_RUN=PASS (all guarded anchors matched)')
        return 0
    backup = path.with_name(path.name + f'.pre_pos2_fix_{args.stage}_4fcb181f29.bak')
    if backup.exists(): ap.error(f'backup already exists: {backup}')
    backup.write_bytes(raw)
    output = new.replace('\n', '\r\n') if crlf else new
    path.write_bytes(output.encode('utf-8'))
    print(f'PATCHED={path}')
    print(f'BACKUP={backup}')
    print('STATUS=PATCH_APPLIED_NOT_RUNTIME_VALIDATED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
