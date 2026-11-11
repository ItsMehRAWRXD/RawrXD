#!/usr/bin/env python3
"""Source-only, fail-closed repairs for RawrXD ModelGenie IR executor.

Target: F:/rawrxd/tools/rawrxd_modelgenie_ir_executor.cpp
Source base: GitHub feat/hexmag-polymorphic-repeat-tuner-masm @ 88b3d052bc.

Does NOT invent MLA/attention/MoE kernels, numerical parity, or PASS evidence.
The script checks every patch anchor BEFORE writing, creates a .bak, and is
intentionally one-shot: a second application fails rather than silently edits.
"""
from __future__ import annotations
import argparse
import difflib
from pathlib import Path
import sys
import tempfile
import os


def apply(original: str) -> str:
    s = original.replace('\r\n', '\n')
    def exactly(old: str, new: str):
        nonlocal s
        count = s.count(old)
        if count != 1:
            raise ValueError(f'Expected exactly one anchor (found {count}): {old[:100]!r}')
        s = s.replace(old, new, 1)

    def span(start: str, end: str, replacement: str):
        nonlocal s
        a = s.find(start)
        if a < 0:
            raise ValueError(f'Missing start: {start[:100]!r}')
        b = s.find(end, a + len(start))
        if b < 0:
            raise ValueError(f'Missing end: {end[:100]!r}')
        s = s[:a] + replacement.rstrip() + '\n\n' + s[b:]

    exactly('#include <algorithm>', '#include <algorithm>\n#include <array>\n#include <cstdlib>')

    span('static float FP16ToFloat(uint16_t h)', '//=============================================================================\n// Dequantizer', r'''
static float FP16ToFloat(uint16_t h)
{
    const uint32_t sign = (h >> 15) & 1u;
    const uint32_t exp  = (h >> 10) & 31u;
    const uint32_t mant = h & 1023u;
    if (!exp) {
        float v = std::ldexp(static_cast<float>(mant), -24);
        return sign ? -v : v;
    }
    uint32_t bits = (sign << 31) |
        ((exp == 31 ? 255u : (exp + 112u)) << 23) | (mant << 13);
    float result;
    std::memcpy(&result, &bits, sizeof(result));
    return result;
}''')

    span('        case ModelGenie::GGMLType::Q5_0:\n        {\n            struct Q50Block',
         '        default:\n            memset(out.data()', r'''
        case ModelGenie::GGMLType::Q5_0:
        {
            // GGML Q5_0 low nibbles: elements 0..15; high nibbles: 16..31.
            struct Q50Block { uint16_t d; uint8_t qh[4]; uint8_t qs[16]; };
            static_assert(sizeof(Q50Block) == 22, "Q5_0 block size");
            const auto* src = reinterpret_cast<const Q50Block*>(tv.data);
            for (size_t b = 0; b < tv.bytes / 22; ++b) {
                const float d = FP16ToFloat(src[b].d);
                uint32_t highBits = 0;
                std::memcpy(&highBits, src[b].qh, 4);
                for (int j = 0; j < 16; ++j) {
                    const int lo = (src[b].qs[j] & 15) | (((highBits >> j) & 1) << 4);
                    const int hi = (src[b].qs[j] >> 4) | (((highBits >> (j + 16)) & 1) << 4);
                    out[b * 32 + j] = d * (lo - 16);
                    out[b * 32 + j + 16] = d * (hi - 16);
                }
            }
            break;
        }
        case ModelGenie::GGMLType::Q6_K:
        {
            // GGML Q6_K: 16 *signed* subgroup scales and one FP16 multiplier.
            struct Q6KBlock { uint8_t ql[128]; uint8_t qh[64]; int8_t scales[16]; uint16_t d; };
            static_assert(sizeof(Q6KBlock) == 210, "Q6_K block size");
            const auto* src = reinterpret_cast<const Q6KBlock*>(tv.data);
            for (size_t b = 0; b < tv.bytes / 210; ++b) {
                const float d = FP16ToFloat(src[b].d);
                for (int half = 0; half < 2; ++half) {
                    const uint8_t* ql = src[b].ql + half * 64;
                    const uint8_t* qh = src[b].qh + half * 32;
                    const int8_t* scales = src[b].scales + half * 8;
                    const size_t base = b * 256 + half * 128;
                    for (int j = 0; j < 32; ++j) {
                        const int g = j / 16;
                        const int q0 = ((ql[j] & 15) | ((qh[j] & 3) << 4)) - 32;
                        const int q1 = ((ql[j + 32] & 15) | (((qh[j] >> 2) & 3) << 4)) - 32;
                        const int q2 = ((ql[j] >> 4) | (((qh[j] >> 4) & 3) << 4)) - 32;
                        const int q3 = ((ql[j + 32] >> 4) | (((qh[j] >> 6) & 3) << 4)) - 32;
                        out[base + j]      = d * scales[g]     * q0;
                        out[base + j + 32] = d * scales[g + 2] * q1;
                        out[base + j + 64] = d * scales[g + 4] * q2;
                        out[base + j + 96] = d * scales[g + 6] * q3;
                    }
                }
            }
            break;
        }''')

    exactly('                    // Skip this block to avoid propagating NaN\n                    continue;',
            '                    throw std::runtime_error("Q4_K non-finite scale");')

    exactly('// TensorStats for numerical boundary isolation', r'''
// Decode a contiguous quantized row without expanding its parent tensor.
static bool DequantizeRow(const TensorView& tv, uint64_t offset,
                          uint64_t count, std::vector<float>& out)
{
    if (!tv.data || !count || offset > tv.elementCount || count > tv.elementCount - offset)
        return false;
    uint64_t blockSize = 0, blockBytes = 0;
    switch (tv.type) {
        case ModelGenie::GGMLType::F32:
            if (offset > tv.bytes / 4 || count > tv.bytes / 4 - offset) return false;
            out.resize(static_cast<size_t>(count));
            std::memcpy(out.data(), tv.data + offset * 4, static_cast<size_t>(count) * 4);
            return true;
        case ModelGenie::GGMLType::Q4_K: blockSize = 256; blockBytes = 144; break;
        case ModelGenie::GGMLType::Q6_K: blockSize = 256; blockBytes = 210; break;
        case ModelGenie::GGMLType::Q5_0: blockSize = 32; blockBytes = 22; break;
        case ModelGenie::GGMLType::Q8_0: blockSize = 32; blockBytes = 34; break;
        default: return false;
    }
    if (offset % blockSize || count % blockSize) return false;
    const uint64_t firstByte = offset / blockSize * blockBytes;
    const uint64_t byteCount = count / blockSize * blockBytes;
    if (firstByte > tv.bytes || byteCount > tv.bytes - firstByte) return false;
    TensorView slice = tv;
    slice.data += firstByte;
    slice.bytes = byteCount;
    slice.elementCount = count;
    DequantizeTensor(slice, out);
    return out.size() == count;
}

// TensorStats for numerical boundary isolation''')

    # Identity: don't assume that GGUF tensor directory and generated tensor IDs
    # agree without verifying each name, shape, type, offset and physical range.
    span('    const TensorView* Resolve(uint32_t romTensorId) const',
         '    // Get dequantized weight tensor (cached)', r'''
    const TensorView* Resolve(uint32_t romTensorId) const
    {
        if (!IsValid() || romTensorId >= Generated::ModelConfig::kTensorCount) return nullptr;
        const auto& rom = Generated::kTensorROMTable[romTensorId];
        if (rom.tensorId != romTensorId || rom.tensorId >= romFile_.liveTensors.size())
            return nullptr;
        const auto& live = romFile_.liveTensors[rom.tensorId];
        if (live.name != rom.name || live.type != rom.type ||
            live.dataOffset != rom.dataOffset || live.encodedBytes != rom.encodedBytes ||
            live.dims.size() != rom.rank) return nullptr;
        for (uint32_t i = 0; i < rom.rank; ++i)
            if (live.dims[i] != rom.dims[i]) return nullptr;
        if (romFile_.ggufDataOffset != Generated::ModelConfig::kDataStart ||
            romFile_.ggufDataOffset > romFile_.size) return nullptr;
        const uint64_t available = romFile_.size - romFile_.ggufDataOffset;
        if (live.dataOffset > available || live.encodedBytes > available - live.dataOffset)
            return nullptr;
        // Stable per-ID views; the old thread_local singleton aliased every lookup.
        auto& view = views_[romTensorId];
        view = {static_cast<Generated::TensorId>(rom.tensorId),
                romFile_.base + romFile_.ggufDataOffset + live.dataOffset,
                live.encodedBytes, live.type, rom.dims.data(), rom.rank,
                rom.elementCount, rom.name};
        return &view;
    }''')
    exactly('    mutable std::unordered_map<uint32_t, std::vector<float>> dequantCache_;',
            '    mutable std::unordered_map<uint32_t, std::vector<float>> dequantCache_;\n'
            '    mutable std::array<TensorView, Generated::ModelConfig::kTensorCount> views_{};')
    exactly('        // Dequantize\n        std::vector<float> dequantized;',
            '        // Large weight tensors must use packed row decoding or VWA, not cached F32.\n'
            '        if (view->elementCount > 1048576ULL) {\n'
            '            std::fprintf(stderr, "[IR] Refused full-F32 cache: %s\\n", view->name);\n'
            '            return nullptr;\n'
            '        }\n'
            '        // Dequantize\n        std::vector<float> dequantized;')

    exactly('    const float* Get(uint32_t activationId) const\n    {',
            '    size_t Size(uint32_t activationId) const {\n'
            '        auto it = activations.find(activationId);\n'
            '        return it == activations.end() ? 0 : it->second.size();\n'
            '    }\n\n    const float* Get(uint32_t activationId) const\n    {')
    span('static float* ResolveOutput(const GEN::OperationIR& op, ActivationArena& arena, const ROMResolver& romResolver)',
         '//=============================================================================\n// Primitive Dispatcher', r'''
static float* ResolveOutput(const GEN::OperationIR& op, ActivationArena& arena,
                            const ROMResolver& romResolver)
{
    if (op.output.domain != MG::OperandDomain::Activation) return nullptr;
    using P = ModelGenie::Primitive;
    size_t count = 0;
    const TensorView* weight = nullptr;
    if (op.weightCount && GenWeight(op, 0).domain == MG::OperandDomain::RomTensor)
        weight = romResolver.Resolve(GenWeight(op, 0).id);
    switch (op.requiredPrimitive) {
        case P::LinearFwd: case P::RouterFwd: case P::LMHeadFwd:
            if (!weight || weight->rank != 2) return nullptr;
            // GGML tensor dimension 0 is contiguous input features, dimension 1 outputs.
            count = GenInput(op, 0).domain == MG::OperandDomain::RuntimeScalar ?
                weight->dims[0] : weight->dims[1];
            break;
        case P::RmsNormFwd:
            if (!weight || weight->rank != 1) return nullptr;
            count = weight->dims[0]; break;
        case P::MlaDecompressFwd:
            count = (GEN::ModelConfig::kKeyLength + GEN::ModelConfig::kValueLength) *
                    GEN::ModelConfig::kHeadCount; break;
        case P::AttentionFwd:
            count = GEN::ModelConfig::kHeadCount * GEN::ModelConfig::kValueLength; break;
        case P::TopKFwd:
            count = 2 * GEN::ModelConfig::kExpertUsedCount; break;
        case P::MoEExecuteFwd: case P::ResidualAddFwd:
            count = GEN::ModelConfig::kEmbeddingLength; break;
        default: return nullptr;
    }
    if (!count || count > GEN::ModelConfig::kVocabSize) return nullptr;
    return arena.GetOrCreate(op.output.id, count);
}''')

    # Correctly execute embedding, regular matrix-vector and two-input FFN down.
    span('    // Linear forward pass (matrix-vector: output = input @ weight.T)',
         '    // Attention forward pass', r'''
    // Stream GGML rows: contiguous dims[0] input features; dims[1] output rows.
    // The two-input dense FFN-down op must consume silu(gate) * up, not gate alone.
    static bool LinearFwd(const float* input, float* output,
                          const TensorView* weight, const MG::OperandRef& inputRef,
                          const float* up = nullptr)
    {
        if (!input || !output || !weight || weight->rank != 2) return false;
        const uint32_t cols = weight->dims[0], rows = weight->dims[1];
        if (!cols || !rows) return false;
        std::vector<float> row;
        if (inputRef.domain == MG::OperandDomain::RuntimeScalar) {
            if (!std::isfinite(input[0]) || input[0] < 0 ||
                input[0] >= static_cast<float>(rows) ||
                input[0] != std::floor(input[0])) return false;
            const uint32_t tokenId = static_cast<uint32_t>(input[0]);
            if (!DequantizeRow(*weight, uint64_t(tokenId) * cols, cols, row)) return false;
            std::memcpy(output, row.data(), static_cast<size_t>(cols) * sizeof(float));
            return true;
        }
        for (uint32_t i = 0; i < rows; ++i) {
            if (!DequantizeRow(*weight, uint64_t(i) * cols, cols, row)) return false;
            double sum = 0.0;
            for (uint32_t j = 0; j < cols; ++j) {
                float x = input[j];
                if (up) x = (x / (1.0f + std::exp(-x))) * up[j];
                sum += double(row[j]) * x;
            }
            output[i] = static_cast<float>(sum);
        }
        return true;
    }
''')

    linear_case = r'''
            case Primitive::LinearFwd: {
                const auto ref = GenInput(op, 0);
                const auto wref = GenWeight(op, 0);
                if (wref.domain != MG::OperandDomain::RomTensor) return false;
                const TensorView* view = romResolver.Resolve(wref.id);
                const float* input = getInput(op, 0);
                const float* up = op.inputCount == 2 ? getInput(op, 1) : nullptr;
                if (!view || !input || view->rank != 2 ||
                    (op.inputCount != 1 && op.inputCount != 2) ||
                    (op.inputCount == 2 && !up)) return false;
                if (ref.domain == MG::OperandDomain::Activation &&
                    arena.Size(ref.id) != view->dims[0]) return false;
                if (op.inputCount == 2 &&
                    arena.Size(GenInput(op, 1).id) != view->dims[0]) return false;
                float* output = getOutput(op);
                return output && LinearFwd(input, output, view, ref, up);
            }
'''
    span('            case Primitive::LinearFwd: {', '            case Primitive::MatMulFwd:', linear_case)
    span('            case Primitive::RouterFwd: {', '            case Primitive::TopKFwd:', r'''
            case Primitive::RouterFwd: {
                const auto wref = GenWeight(op, 0);
                const auto iref = GenInput(op, 0);
                if (wref.domain != MG::OperandDomain::RomTensor ||
                    iref.domain != MG::OperandDomain::Activation) return false;
                const TensorView* view = romResolver.Resolve(wref.id);
                if (!view || view->rank != 2 ||
                    arena.Size(iref.id) != view->dims[0]) return false;
                const float* input = getInput(op, 0);
                float* output = getOutput(op);
                return input && output && LinearFwd(input, output, view, iref);
            }''')
    span('            case Primitive::LMHeadFwd: {', '            default:\n', r'''
            case Primitive::LMHeadFwd: {
                const auto wref = GenWeight(op, 0);
                const auto iref = GenInput(op, 0);
                if (wref.domain != MG::OperandDomain::RomTensor ||
                    iref.domain != MG::OperandDomain::Activation) return false;
                const TensorView* view = romResolver.Resolve(wref.id);
                if (!view || view->rank != 2 ||
                    arena.Size(iref.id) != view->dims[0]) return false;
                const float* input = getInput(op, 0);
                float* output = getOutput(op);
                return input && output && LinearFwd(input, output, view, iref);
            }''')
    # Every unimplemented numerical operation must return false, not claim success.
    span('            case Primitive::AttentionFwd: {', '            case Primitive::MlaDecompressFwd:', r'''
            case Primitive::AttentionFwd: {
                std::fprintf(stderr, "[IR] AttentionFwd op=%u NOT_IMPLEMENTED\n", op.opId);
                return false;
            }''')
    span('            case Primitive::MlaDecompressFwd: {', '            case Primitive::RouterFwd:', r'''
            case Primitive::MlaDecompressFwd: {
                std::fprintf(stderr, "[IR] MlaDecompressFwd op=%u NOT_IMPLEMENTED\n", op.opId);
                return false;
            }''')
    span('            case Primitive::TopKFwd: {', '            case Primitive::MoEExecuteFwd:', r'''
            case Primitive::TopKFwd: {
                std::fprintf(stderr, "[IR] TopKFwd op=%u NOT_IMPLEMENTED\n", op.opId);
                return false;
            }''')
    span('            case Primitive::MoEExecuteFwd: {', '            case Primitive::ResidualAddFwd:', r'''
            case Primitive::MoEExecuteFwd: {
                std::fprintf(stderr, "[IR] MoEExecuteFwd op=%u NOT_IMPLEMENTED\n", op.opId);
                return false;
            }''')
    exactly('                    RmsNormFwd(input, weight, output, op);\n                    return true;',
            '                    if (GenInput(op, 0).domain != MG::OperandDomain::Activation ||\n'
            '                        arena.Size(GenInput(op, 0).id) != GEN::ModelConfig::kEmbeddingLength ||\n'
            '                        arena.Size(op.output.id) != GEN::ModelConfig::kEmbeddingLength)\n'
            '                        return false;\n'
            '                    RmsNormFwd(input, weight, output, op);\n                    return true;')
    exactly('                    ResidualAddFwd(input0, input1, output, op);\n                    return true;',
            '                    if (arena.Size(GenInput(op, 0).id) != GEN::ModelConfig::kEmbeddingLength ||\n'
            '                        arena.Size(GenInput(op, 1).id) != GEN::ModelConfig::kEmbeddingLength)\n'
            '                        return false;\n'
            '                    ResidualAddFwd(input0, input1, output, op);\n                    return true;')

    # Emit measured execution numbers, not constants or inferred success.
    exactly('        uint32_t opsDispatched = 0;\n        uint32_t opsVisited = 0;\n        uint32_t opsSkipped = 0;',
            '        opsExecuted_ = opsVisited_ = opsSkipped_ = 0;\n'
            '        uint32_t& opsDispatched = opsExecuted_;\n'
            '        uint32_t& opsVisited = opsVisited_;\n'
            '        uint32_t& opsSkipped = opsSkipped_;')
    exactly('        // Capture logits from final LM Head output (activation 299 based on IR table)\n'
            '        const float* logitsPtr = arena_.Get(299);\n'
            '        if (logitsPtr) {\n'
            '            // Vocab size is 102400\n'
            '            logits_.assign(logitsPtr, logitsPtr + 102400);\n'
            '        }\n        \n        return opsSkipped == 0;',
            '        // Do not emit or sample logits after a missing numerical operation.\n'
            '        if (opsSkipped != 0 || opsDispatched != GEN::kExecutionOpCount) return false;\n'
            '        const auto& last = GEN::kExecutionIRTable[GEN::kExecutionOpCount-1];\n'
            '        if (last.requiredPrimitive != ModelGenie::Primitive::LMHeadFwd ||\n'
            '            arena_.Size(last.output.id) != GEN::ModelConfig::kVocabSize) return false;\n'
            '        const float* logitsPtr = arena_.Get(last.output.id);\n'
            '        if (!logitsPtr) return false;\n'
            '        logits_.assign(logitsPtr, logitsPtr + GEN::ModelConfig::kVocabSize);\n'
            '        return true;')
    exactly('    uint32_t SampleToken() const;\n',
            '    uint32_t SampleToken() const;\n'
            '    uint32_t OpsVisited() const { return opsVisited_; }\n'
            '    uint32_t OpsExecuted() const { return opsExecuted_; }\n'
            '    uint32_t OpsSkipped() const { return opsSkipped_; }\n')
    exactly('    std::vector<float> logits_;\n',
            '    std::vector<float> logits_;\n'
            '    uint32_t opsVisited_ = 0, opsExecuted_ = 0, opsSkipped_ = 0;\n')

    exactly('    // Run IR executor with token 0 (first token)\n    IRExecutor executor(ggufPath, 0);',
            '    // Match the reference token0 gate: runtime.Forward(1).\n'
            '    IRExecutor executor(ggufPath, 1);')
    exactly('    std::fprintf(stderr, "IR_OPS_VISITED=%u\\n", GEN::kExecutionOpCount);',
            '    std::fprintf(stderr, "IR_OPS_VISITED=%u\\n", executor.OpsVisited());\n'
            '    std::fprintf(stderr, "IR_OPS_EXECUTED=%u\\n", executor.OpsExecuted());\n'
            '    std::fprintf(stderr, "IR_OPS_SKIPPED=%u\\n", executor.OpsSkipped());')
    exactly('    std::fprintf(stderr, "TOKEN_PARITY=%d\\n", (predictedToken == 93633) ? 1 : 0);',
            '    std::fprintf(stderr, "TOKEN_PARITY=%d\\n", (success && logitsFinite && predictedToken == 93633) ? 1 : 0);')
    if 'IRExecutor executor(ggufPath, 1);' not in s or 'return output && LinearFwd' not in s:
        raise ValueError('Post-patch authority checks failed')
    return s


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', type=Path, help='Path to rawrxd_modelgenie_ir_executor.cpp')
    p.add_argument('--dry-run', action='store_true', help='Validate all source anchors without writing')
    args = p.parse_args()
    original_bytes = args.source.read_bytes()
    original = original_bytes.decode('utf-8-sig')
    edited = apply(original)
    if original == edited:
        raise SystemExit('No changes made; refusing empty patch')
    if args.dry_run:
        print(f'PATCH_ANCHORS=PASS\nPATCH_BYTES={len(edited.encode())}\nDRY_RUN=PASS')
        return
    backup = args.source.with_suffix(args.source.suffix + '.pre_ir_frontier.bak')
    if backup.exists():
        raise SystemExit(f'Refusing to overwrite existing backup: {backup}')
    backup.write_bytes(original_bytes)
    payload = edited.replace('\n', '\r\n') if b'\r\n' in original_bytes else edited
    encoding = 'utf-8-sig' if original_bytes.startswith(b'\xef\xbb\xbf') else 'utf-8'
    fd, tmp = tempfile.mkstemp(prefix='.ir_frontier_', suffix='.tmp', dir=args.source.parent)
    try:
        with os.fdopen(fd, 'w', encoding=encoding, newline='') as f:
            f.write(payload)
        os.replace(tmp, args.source)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print(f'PATCH=APPLIED\nBACKUP={backup}\nSOURCE={args.source}\nBUILD_AND_RUNTIME=UNVERIFIED')


if __name__ == '__main__':
    main()
