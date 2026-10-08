#!/usr/bin/env python3
"""Native ModelGenie IR executor source patch (stdlib-only, fail-closed).

Expected input: tools/rawrxd_modelgenie_ir_executor.cpp at the 88b3d052bc frontier.
Does not edit generated headers or the GGUF. Defaults to --dry-run.
"""
from __future__ import annotations
import argparse
import difflib
import pathlib
import sys

class PatchError(RuntimeError):
    pass


def patch(source: str) -> tuple[str, list[str]]:
    s = source
    changed = []
    def one(old: str, new: str, name: str) -> None:
        nonlocal s
        matches = s.count(old)
        if matches != 1:
            raise PatchError(f'{name}: expected one exact anchor, found {matches}. Input changed; no edits applied.')
        s = s.replace(old, new, 1)
        changed.append(name)
    def between(begin: str, end: str, replacement: str, name: str) -> None:
        nonlocal s
        i, j = s.find(begin), s.find(end, s.find(begin) + len(begin))
        if i < 0 or j < 0 or s.find(begin, i + len(begin)) >= 0:
            raise PatchError(f'{name}: ambiguous or missing anchors; no edits applied.')
        s = s[:i] + replacement + s[j:]
        changed.append(name)

    one('#include <algorithm>\n', '#include <algorithm>\n#include <array>\n#include <numeric>\n', 'standard includes')
    one('    void Close()\n', '    ~GGUFROM() { Close(); }\n\n    void Close()\n', 'mapped ROM cleanup')
    between('static float FP16ToFloat(uint16_t h)\n{', '//=============================================================================\n// Dequantizer for GGUF tensor types', '''static float FP16ToFloat(uint16_t h)
{
    const float sign = (h & 0x8000u) ? -1.0f : 1.0f;
    const uint32_t exp = (h >> 10) & 31u, mant = h & 1023u;
    if (!exp) return sign * std::ldexp(static_cast<float>(mant), -24);
    if (exp == 31u) return mant ? std::numeric_limits<float>::quiet_NaN()
                                : sign * std::numeric_limits<float>::infinity();
    return sign * std::ldexp(1.0f + float(mant) / 1024.0f, int(exp) - 15);
}

''', 'FP16 subnormal and INF handling')
    between('        case ModelGenie::GGMLType::Q5_0:\n        {', '        case ModelGenie::GGMLType::Q6_K:\n        {', '''        case ModelGenie::GGMLType::Q5_0:
        {
            struct Block { uint16_t d; uint8_t qh[4]; uint8_t qs[16]; };
            static_assert(sizeof(Block) == 22, "Q5_0 block size");
            const auto* blocks = reinterpret_cast<const Block*>(tv.data);
            for (size_t b = 0; b < tv.bytes/sizeof(Block); ++b) {
                uint32_t qh = 0;
                std::memcpy(&qh, blocks[b].qh, sizeof(qh));
                const float d = FP16ToFloat(blocks[b].d);
                for (int j = 0; j < 16; ++j) {
                    const int lo = int((blocks[b].qs[j] & 15u) | (((qh >> j) & 1u)<<4)) - 16;
                    const int hi = int((blocks[b].qs[j] >> 4) | (((qh >> (j+16)) & 1u)<<4)) - 16;
                    out[b*32+j] = d*lo;
                    out[b*32+j+16] = d*hi;
                }
            }
            break;
        }
''', 'canonical Q5_0 nibbles')
    between('        case ModelGenie::GGMLType::Q6_K:\n        {', '        default:\n            memset(out.data()', '''        case ModelGenie::GGMLType::Q6_K:
        {
            struct Block { uint8_t ql[128]; uint8_t qh[64]; int8_t scales[16]; uint16_t d; };
            static_assert(sizeof(Block) == 210, "Q6_K block size");
            const auto* blocks = reinterpret_cast<const Block*>(tv.data);
            for (size_t b = 0; b < tv.bytes/sizeof(Block); ++b) {
                const float d = FP16ToFloat(blocks[b].d);
                for (int half = 0; half < 2; ++half) {
                    const uint8_t* ql = blocks[b].ql + 64*half;
                    const uint8_t* qh = blocks[b].qh + 32*half;
                    const int8_t* sc = blocks[b].scales + 8*half;
                    float* dst = out.data() + 256*b + 128*half;
                    for (int l = 0; l < 32; ++l) {
                        const int g = l/16;
                        dst[l]    = d*sc[g]   * (int((ql[l]&15)    | ((qh[l]&3)<<4))-32);
                        dst[l+32] = d*sc[g+2] * (int((ql[l+32]&15) | (((qh[l]>>2)&3)<<4))-32);
                        dst[l+64] = d*sc[g+4] * (int((ql[l]>>4)    | (((qh[l]>>4)&3)<<4))-32);
                        dst[l+96] = d*sc[g+6] * (int((ql[l+32]>>4) | (((qh[l]>>6)&3)<<4))-32);
                    }
                }
            }
            break;
        }
''', 'canonical Q6_K scales and bit planes')
    one('    const float* Get(uint32_t activationId) const\n', '''    size_t Size(uint32_t activationId) const
    {
        auto it = activations.find(activationId);
        return it == activations.end() ? 0u : it->second.size();
    }

    const float* Get(uint32_t activationId) const
''', 'activation shape tracking')
    between('    const TensorView* Resolve(uint32_t romTensorId) const\n    {', '    // Get dequantized weight tensor (cached)', '''    const TensorView* Resolve(uint32_t id) const
    {
        if (!romFile_.base || id >= GEN::ModelConfig::kTensorCount) return nullptr;
        const auto& rom = GEN::kTensorROMTable[id];
        if (rom.tensorId >= romFile_.liveTensors.size()) return nullptr;
        const auto& live = romFile_.liveTensors[rom.tensorId];
        if (live.name != rom.name || live.type != rom.type ||
            live.dataOffset != rom.dataOffset || live.encodedBytes != rom.encodedBytes ||
            live.dims.size() != rom.rank) return nullptr;
        for (size_t d = 0; d < live.dims.size(); ++d)
            if (live.dims[d] != rom.dims[d]) return nullptr;
        if (live.dataOffset > romFile_.size - romFile_.ggufDataOffset) return nullptr;
        const uint64_t start = romFile_.ggufDataOffset + live.dataOffset;
        if (start > romFile_.size || live.encodedBytes > romFile_.size - start) return nullptr;
        auto& view = views_[id];
        view.id = static_cast<GEN::TensorId>(rom.tensorId);
        view.data = romFile_.base + start;
        view.bytes = live.encodedBytes;
        view.type = live.type;
        view.dims = rom.dims.data(); // lifetime is the immutable generated table
        view.rank = rom.rank;
        view.elementCount = rom.elementCount;
        view.name = rom.name;
        return &view;
    }

    bool GetExpertSlice(uint32_t id, uint32_t expert, std::vector<float>& out) const
    {
        const TensorView* v = Resolve(id);
        if (!v || v->rank != 3 || expert >= v->dims[2] ||
            !v->dims[2] || v->bytes % v->dims[2] ||
            v->elementCount % v->dims[2]) return false;
        const uint64_t bytesPerExpert = v->bytes / v->dims[2];
        const uint64_t elementsPerExpert = v->elementCount / v->dims[2];
        const uint32_t shape[2] = {v->dims[0], v->dims[1]};
        if (elementsPerExpert != uint64_t(shape[0])*shape[1]) return false;
        TensorView slice = *v;
        slice.data += bytesPerExpert*expert;
        slice.bytes = bytesPerExpert;
        slice.elementCount = elementsPerExpert;
        slice.dims = shape;
        slice.rank = 2;
        DequantizeTensor(slice, out);
        return out.size() == elementsPerExpert;
    }

''', 'stable ROM view / expert slice / source provenance')
    one('    GGUFROM romFile_;\n    mutable std::unordered_map', '    GGUFROM romFile_;\n    mutable std::array<TensorView, GEN::ModelConfig::kTensorCount> views_{};\n    mutable std::unordered_map', 'stable tensor views')
    between('static float* ResolveOutput(const GEN::OperationIR& op, ActivationArena& arena, const ROMResolver& romResolver) {', '//=============================================================================\n// Primitive Dispatcher', '''static float* ResolveOutput(const GEN::OperationIR& op, ActivationArena& arena,
                            const ROMResolver& rom)
{
    if (op.output.domain != MG::OperandDomain::Activation) return nullptr;
    size_t count = 0;
    switch (op.requiredPrimitive) {
        case MG::Primitive::MlaDecompressFwd:
            count = GEN::ModelConfig::kHeadCount *
                    (GEN::ModelConfig::kKeyLength + GEN::ModelConfig::kValueLength);
            break;
        case MG::Primitive::AttentionFwd:
        case MG::Primitive::MoEExecuteFwd:
            count = GEN::ModelConfig::kEmbeddingLength;
            break;
        case MG::Primitive::TopKFwd:
            count = 2 * GEN::ModelConfig::kExpertUsedCount;
            break;
        case MG::Primitive::ResidualAddFwd:
            count = arena.Size(GenInput(op, 0).id);
            break;
        case MG::Primitive::RmsNormFwd:
        case MG::Primitive::LinearFwd:
        case MG::Primitive::RouterFwd:
        case MG::Primitive::LMHeadFwd: {
            if (!op.weightCount) break;
            const auto ref = GenWeight(op, 0);
            const TensorView* view = ref.domain == MG::OperandDomain::RomTensor ?
                                     rom.Resolve(ref.id) : nullptr;
            if (!view) break;
            if (op.requiredPrimitive == MG::Primitive::RmsNormFwd && view->rank == 1)
                count = view->dims[0];
            else if (view->rank == 2)
                count = GenInput(op, 0).domain == MG::OperandDomain::RuntimeScalar ?
                        view->dims[0] : view->dims[1];
            break;
        }
        default: break;
    }
    return count ? arena.GetOrCreate(op.output.id, count) : nullptr;
}

''', 'output shapes by opcode and GGML dimensions')
    between('    // Linear forward pass (matrix-vector: output = input @ weight.T)', '    // Attention forward pass', '''    // All GGUF 2D tensors are [inputWidth, outputWidth], row-major on dim[0].
    static bool LinearFwd(const float* input, const float* weight, float* output,
                          const TensorView* view, const MG::OperandRef& inputRef,
                          size_t inputN, size_t outputN, const float* gate = nullptr)
    {
        if (!view || view->rank != 2 || !input || !weight || !output) return false;
        const size_t in = view->dims[0], out = view->dims[1];
        if (inputRef.domain == MG::OperandDomain::RuntimeScalar) {
            const uint32_t token = static_cast<uint32_t>(input[0]);
            if (token >= out || outputN != in) return false;
            std::memcpy(output, weight + size_t(token)*in, in*sizeof(float));
            return true;
        }
        if (inputN != in || outputN != out) return false;
        std::vector<float> gated;
        if (gate) {
            gated.resize(in);
            for (size_t j = 0; j < in; ++j)
                gated[j] = (input[j] / (1.0f + std::exp(-input[j]))) * gate[j];
            input = gated.data();
        }
        return DotRows(weight, input, output, in, out);
    }

    static bool DotRows(const float* weight, const float* input, float* output,
                        size_t in, size_t out)
    {
        if (!weight || !input || !output || !in || !out) return false;
        #pragma omp parallel for schedule(static) if(out >= 128)
        for (int64_t i = 0; i < static_cast<int64_t>(out); ++i) {
            const float* row = weight + size_t(i)*in;
            __m512 acc = _mm512_setzero_ps();
            size_t j = 0;
            for (; j+16 <= in; j += 16)
                acc = _mm512_fmadd_ps(_mm512_loadu_ps(row+j),
                                      _mm512_loadu_ps(input+j), acc);
            float sum = _mm512_reduce_add_ps(acc);
            for (; j < in; ++j) sum += row[j]*input[j];
            output[i] = sum;
        }
        return true;
    }

''', 'SIMD GGML matvec, scalar-token embedding, gated dense FFN')
    between('    // Attention forward pass', '    // ResidualAdd forward pass', '''    // For position 0 with a single causal token, attention softmax contains one
    // element and is exactly 1.0: the output is V regardless of Q/K scores.
    // This is ONLY a token-zero kernel, not an autoregressive KV-cache kernel.
    static bool AttentionFwd(const float* q, const float* kv, float* output,
                             size_t qN, size_t kvN, size_t outputN)
    {
        const size_t heads = GEN::ModelConfig::kHeadCount;
        const size_t kSize = heads * GEN::ModelConfig::kKeyLength;
        const size_t vSize = heads * GEN::ModelConfig::kValueLength;
        if (!q || !kv || !output || qN != kSize || kvN != kSize+vSize || outputN != vSize)
            return false;
        std::memcpy(output, kv + kSize, vSize*sizeof(float));
        return true;
    }

    // Input x[2048] -> A projection [576] -> RMSnorm latent [512] ->
    // B projection [4096] -> [16*192 key, 16*128 value] = 5120 floats.
    static bool MlaDecompressFwd(const float* input, const float* norm,
                                 const float* kvA, const float* kvB, float* output,
                                 const TensorView* normView, const TensorView* aView,
                                 const TensorView* bView, size_t inputN, size_t outputN)
    {
        const size_t hidden = GEN::ModelConfig::kEmbeddingLength;
        const size_t rank = GEN::ModelConfig::kKvLoraRank;
        const size_t rope = GEN::ModelConfig::kRopeDimensionCount;
        const size_t heads = GEN::ModelConfig::kHeadCount;
        const size_t key = GEN::ModelConfig::kKeyLength;
        const size_t value = GEN::ModelConfig::kValueLength;
        const size_t noRope = key-rope;
        if (!input || !norm || !kvA || !kvB || !output ||
            !normView || !aView || !bView ||
            rank+rope != 576 || noRope != value ||
            normView->rank != 1 || normView->dims[0] != rank ||
            aView->rank != 2 || aView->dims[0] != hidden || aView->dims[1] != rank+rope ||
            bView->rank != 2 || bView->dims[0] != rank ||
            bView->dims[1] != heads*(noRope+value) ||
            inputN != hidden || outputN != heads*(key+value)) return false;
        std::vector<float> latent(rank+rope), expanded(heads*(noRope+value));
        if (!DotRows(kvA, input, latent.data(), hidden, rank+rope)) return false;
        double ss = 0;
        for (size_t j = 0; j < rank; ++j) ss += double(latent[j])*latent[j];
        const float factor = 1.0f / std::sqrt(float(ss/rank) + float(GEN::ModelConfig::kRmsEps));
        for (size_t j = 0; j < rank; ++j) latent[j] *= factor*norm[j];
        if (!DotRows(kvB, latent.data(), expanded.data(), rank, expanded.size())) return false;
        const size_t kSize = heads*key;
        for (size_t head = 0; head < heads; ++head) {
            const size_t src = head*(noRope+value);
            const size_t dst = head*key;
            std::memcpy(output+dst, expanded.data()+src, noRope*sizeof(float));
            // Rotary component is shared across heads at position zero (RoPE identity).
            std::memcpy(output+dst+noRope, latent.data()+rank, rope*sizeof(float));
            std::memcpy(output+kSize+head*value, expanded.data()+src+noRope, value*sizeof(float));
        }
        return true;
    }

    // Encode selected expert indices and normalized routing probabilities in
    // a 12-float activation: [indices 0..5, probabilities 0..5].
    static bool TopKFwd(const float* input, float* output, size_t inputN, size_t outputN)
    {
        constexpr uint32_t total = GEN::ModelConfig::kExpertCount;
        constexpr uint32_t k = GEN::ModelConfig::kExpertUsedCount;
        if (!input || !output || inputN != total || outputN != 2*k) return false;
        double maxV = -std::numeric_limits<double>::infinity();
        for (size_t i=0;i<total;++i) {
            if (!std::isfinite(input[i])) return false;
            maxV = (std::max)(maxV, double(input[i]));
        }
        std::array<double, total> prob{};
        double sum = 0.0;
        for (size_t i=0;i<total;++i) { prob[i] = std::exp(double(input[i])-maxV); sum += prob[i]; }
        if (!(sum > 0.0)) return false;
        std::array<uint32_t,total> ids{};
        std::iota(ids.begin(), ids.end(), 0u);
        std::stable_sort(ids.begin(), ids.end(), [&](uint32_t a, uint32_t b) { return prob[a] > prob[b]; });
        double chosen = 0.0;
        for (uint32_t i=0;i<k;++i) chosen += prob[ids[i]];
        if (!(chosen > 0.0)) return false;
        for (uint32_t i=0;i<k;++i) {
            output[i] = float(ids[i]);
            output[k+i] = float(prob[ids[i]] / chosen);
        }
        return true;
    }

    static bool MoEExecuteFwd(const float* input, const float* choices, float* output,
                              const GEN::OperationIR& op, const ROMResolver& rom,
                              size_t inputN, size_t choicesN, size_t outputN)
    {
        constexpr uint32_t experts = GEN::ModelConfig::kExpertCount;
        constexpr uint32_t selected = GEN::ModelConfig::kExpertUsedCount;
        constexpr size_t hidden = GEN::ModelConfig::kEmbeddingLength;
        constexpr size_t ffn = GEN::ModelConfig::kExpertFfnLength;
        if (!input || !choices || !output || inputN != hidden ||
            choicesN != 2*selected || outputN != hidden || op.blockIndex == 0 ||
            op.blockIndex >= GEN::ModelConfig::kBlockCount || op.weightCount < 3)
            return false;
        const auto gateId = GenWeight(op,0), downId = GenWeight(op,1), upId = GenWeight(op,2);
        if (gateId.domain != MG::OperandDomain::RomTensor ||
            downId.domain != MG::OperandDomain::RomTensor ||
            upId.domain != MG::OperandDomain::RomTensor) return false;
        const auto& b = GEN::kBlockGenomeTable[op.blockIndex];
        if (!b.ffnGateShExp || !b.ffnUpShExp || !b.ffnDownShExp) return false;
        std::fill(output, output+outputN, 0.0f);
        std::vector<float> gateW, upW, downW;
        std::vector<float> g(ffn), u(ffn), tmp(hidden);
        for (uint32_t i=0;i<selected;++i) {
            const float idF = choices[i], score = choices[selected+i];
            if (!std::isfinite(idF) || !std::isfinite(score) ||
                idF < 0 || idF >= experts || float(uint32_t(idF)) != idF) return false;
            const uint32_t id = uint32_t(idF);
            if (!rom.GetExpertSlice(gateId.id,id,gateW) ||
                !rom.GetExpertSlice(upId.id,id,upW) ||
                !rom.GetExpertSlice(downId.id,id,downW) ||
                gateW.size() != ffn*hidden || upW.size() != ffn*hidden ||
                downW.size() != hidden*ffn) return false;
            if (!DotRows(gateW.data(),input,g.data(),hidden,ffn) ||
                !DotRows(upW.data(),input,u.data(),hidden,ffn)) return false;
            for (size_t j=0;j<ffn;++j)
                g[j] = (g[j] / (1.0f + std::exp(-g[j]))) * u[j];
            if (!DotRows(downW.data(),g.data(),tmp.data(),ffn,hidden)) return false;
            for (size_t j=0;j<hidden;++j) output[j] += score*tmp[j];
        }
        // Two always-active shared experts are concatenated into a single FFN.
        const auto* gateView = rom.Resolve(*b.ffnGateShExp);
        const auto* upView = rom.Resolve(*b.ffnUpShExp);
        const auto* downView = rom.Resolve(*b.ffnDownShExp);
        const float* sharedGate = rom.GetDequantizedWeight(*b.ffnGateShExp);
        const float* sharedUp = rom.GetDequantizedWeight(*b.ffnUpShExp);
        const float* sharedDown = rom.GetDequantizedWeight(*b.ffnDownShExp);
        const size_t shared = ffn*GEN::ModelConfig::kExpertSharedCount;
        if (!gateView || !upView || !downView || !sharedGate || !sharedUp || !sharedDown ||
            gateView->rank!=2 || gateView->dims[0]!=hidden || gateView->dims[1]!=shared ||
            upView->rank!=2 || upView->dims[0]!=hidden || upView->dims[1]!=shared ||
            downView->rank!=2 || downView->dims[0]!=shared || downView->dims[1]!=hidden)
            return false;
        g.resize(shared);u.resize(shared);
        if (!DotRows(sharedGate,input,g.data(),hidden,shared) ||
            !DotRows(sharedUp,input,u.data(),hidden,shared)) return false;
        for (size_t j=0;j<shared;++j) g[j] = (g[j]/(1.0f+std::exp(-g[j])))*u[j];
        if (!DotRows(sharedDown,g.data(),tmp.data(),shared,hidden)) return false;
        for (size_t j=0;j<hidden;++j) output[j] += tmp[j];
        return true;
    }

''', 'token-zero MLA, attention, router top-k, sparse routed/shared MoE')
    # Two old utility kernels are invalid in this file even though currently not
    # exercised by Dispatch. Correct them so future refactors cannot reuse poison.
    between('static void RMSNorm(float* out, const float* in, const float* w, int n, float eps)\n{', 'static void Softmax(float* x, int n)\n{', '''static void RMSNorm(float* out, const float* in, const float* w, int n, float eps)
{
    if (!out || !in || !w || n <= 0) return;
    double ss = 0.0;
    for (int i=0;i<n;++i) ss += double(in[i])*in[i];
    const float scale = 1.0f/std::sqrt(float(ss/n)+eps);
    for (int i=0;i<n;++i) out[i] = in[i]*w[i]*scale;
}

''', 'RMSNorm utility overflow fix')
    between('static void Softmax(float* x, int n)\n{', 'static void MatMul(const float* A', '''static void Softmax(float* x, int n)
{
    if (!x || n<=0) return;
    float m = x[0];
    for (int i=1;i<n;++i) m=(std::max)(m,x[i]);
    double sum=0.0;
    for (int i=0;i<n;++i) {x[i]=std::exp(x[i]-m);sum+=x[i];}
    if (sum>0) for (int i=0;i<n;++i) x[i] = float(x[i]/sum);
}

''', 'portable stable softmax')
    between('static void MatMul(const float* A', 'static void VecAdd(', '''static void MatMul(const float* A, const float* B, float* C, int M, int K, int N)
{
    // Conventional row-major: C[M,N] = A[M,K] * B[K,N].
    #pragma omp parallel for schedule(static)
    for (int i=0;i<M;++i)
        for (int j=0;j<N;++j) {
            double sum=0.0;
            for (int k=0;k<K;++k) sum+=double(A[i*K+k])*B[k*N+j];
            C[i*N+j]=float(sum);
        }
}

''', 'GEMM stride correctness')
    # Route supported dispatch cases through shape validated kernels.
    between('            case Primitive::RmsNormFwd: {', '            case Primitive::MatMulFwd: {', '''            case Primitive::RmsNormFwd: {
                const float* x=getInput(op,0), *w=getWeight(op,0);
                float* y=getOutput(op);
                const auto wr=GenWeight(op,0), xr=GenInput(op,0);
                const TensorView* v=wr.domain==MG::OperandDomain::RomTensor ? romResolver.Resolve(wr.id) : nullptr;
                if (!x||!w||!y||!v||v->rank!=1 || xr.domain!=MG::OperandDomain::Activation ||
                    arena.Size(xr.id)!=v->dims[0] || arena.Size(op.output.id)!=v->dims[0]) return false;
                RmsNormFwd(x,w,y,op);
                return true;
            }
            case Primitive::LinearFwd: {
                const float* x=getInput(op,0), *w=getWeight(op,0);
                float* y=getOutput(op);
                const auto wr=GenWeight(op,0), xr=GenInput(op,0);
                const TensorView* v=wr.domain==MG::OperandDomain::RomTensor ? romResolver.Resolve(wr.id):nullptr;
                const float* second=op.inputCount>1 ? getInput(op,1) : nullptr;
                if (op.inputCount>1 && (!second || arena.Size(GenInput(op,1).id)!=arena.Size(xr.id)))
                    return false;
                return LinearFwd(x,w,y,v,xr,arena.Size(xr.id),arena.Size(op.output.id),second);
            }
''', 'RMSNorm and Linear dispatch')
    between('            case Primitive::AttentionFwd: {', '            case Primitive::RouterFwd: {', '''            case Primitive::AttentionFwd: {
                const auto qr=GenInput(op,0), kr=GenInput(op,1);
                const float* q=getInput(op,0), *kv=getInput(op,1);
                float* output=getOutput(op);
                return AttentionFwd(q,kv,output,arena.Size(qr.id),arena.Size(kr.id),
                                    arena.Size(op.output.id));
            }
            case Primitive::MlaDecompressFwd: {
                const auto xr=GenInput(op,0), n=GenWeight(op,0), a=GenWeight(op,1),b=GenWeight(op,2);
                const float* input=getInput(op,0), *wn=getWeight(op,0);
                const float* wa=getWeight(op,1), *wb=getWeight(op,2);
                float* output=getOutput(op);
                if (n.domain!=MG::OperandDomain::RomTensor || a.domain!=MG::OperandDomain::RomTensor ||
                    b.domain!=MG::OperandDomain::RomTensor) return false;
                return MlaDecompressFwd(input,wn,wa,wb,output,romResolver.Resolve(n.id),
                                         romResolver.Resolve(a.id),romResolver.Resolve(b.id),
                                         arena.Size(xr.id),arena.Size(op.output.id));
            }
''', 'MLA and attention dispatch')
    between('            case Primitive::RouterFwd: {', '            case Primitive::ResidualAddFwd: {', '''            case Primitive::RouterFwd: {
                const auto xr=GenInput(op,0), wr=GenWeight(op,0);
                const float* input=getInput(op,0), *weight=getWeight(op,0);
                float* output=getOutput(op);
                const TensorView* v=wr.domain==MG::OperandDomain::RomTensor ? romResolver.Resolve(wr.id):nullptr;
                return LinearFwd(input,weight,output,v,xr,arena.Size(xr.id),arena.Size(op.output.id));
            }
            case Primitive::TopKFwd: {
                const auto r=GenInput(op,0);
                return TopKFwd(getInput(op,0),getOutput(op),arena.Size(r.id),arena.Size(op.output.id));
            }
            case Primitive::MoEExecuteFwd: {
                const auto a=GenInput(op,0),b=GenInput(op,1);
                return MoEExecuteFwd(getInput(op,0),getInput(op,1),getOutput(op),
                                     op,romResolver,arena.Size(a.id),arena.Size(b.id),
                                     arena.Size(op.output.id));
            }
''', 'Router, TopK and sparse MoE dispatch')
    between('            case Primitive::ResidualAddFwd: {', '            default:\n                std::fprintf(stderr, "[IR] Unsupported primitive:', '''            case Primitive::ResidualAddFwd: {
                const auto ar=GenInput(op,0), br=GenInput(op,1);
                const size_t n=arena.Size(ar.id);
                const float* a=getInput(op,0),*b=getInput(op,1);
                float* out=getOutput(op);
                if (!n || n!=arena.Size(br.id) || n!=arena.Size(op.output.id) || !a || !b || !out)
                    return false;
                for (size_t j=0;j<n;++j) out[j]=a[j]+b[j];
                return true;
            }
            case Primitive::LMHeadFwd: {
                const auto xr=GenInput(op,0),wr=GenWeight(op,0);
                const float* input=getInput(op,0), *weight=getWeight(op,0);
                float* output=getOutput(op);
                const TensorView* v=wr.domain==MG::OperandDomain::RomTensor ? romResolver.Resolve(wr.id):nullptr;
                return LinearFwd(input,weight,output,v,xr,arena.Size(xr.id),arena.Size(op.output.id));
            }
''', 'Residual and LM head dispatch')
    one('        uint32_t opsSkipped = 0;\n', '        uint32_t opsSkipped = 0;\n        visited_ = dispatched_ = skipped_ = 0;\n        logits_.clear();\n', 'persisted counter reset')
    one('        // Capture logits from final LM Head output (activation 299 based on IR table)', '''        visited_ = opsVisited;
        dispatched_ = opsDispatched;
        skipped_ = opsSkipped;
        // Capture logits from final LM Head output (activation 299 based on IR table)''', 'counter snapshot')
    one('    uint32_t SampleToken() const;\n', '''    uint32_t SampleToken() const;
    uint32_t Visited() const { return visited_; }
    uint32_t Dispatched() const { return dispatched_; }
    uint32_t Skipped() const { return skipped_; }
''', 'receipt accessors')
    one('    std::vector<float> logits_;\n', '    std::vector<float> logits_;\n    uint32_t visited_ = 0, dispatched_ = 0, skipped_ = 0;\n', 'receipt counters')
    one('    IRExecutor executor(ggufPath, 0);', '    IRExecutor executor(ggufPath, 1);', 'baseline token ID one')
    between('    // Get actual dispatched/skipped counts from executor', '    std::fprintf(stderr, "\\n=============================================================================\\n");', '''    // All receipt counters are obtained from the actual IR interpreter.
    // Table visibility does not by itself prove execution authority.
''', 'remove false accounting note')
    one('    std::fprintf(stderr, "IR_TABLE_AUTHORITY=1\\n");', '''    std::fprintf(stderr, "IR_TABLE_AUTHORITY=%d\\n",
        (success && executor.Visited()==GEN::kExecutionOpCount &&
         executor.Dispatched()==GEN::kExecutionOpCount && executor.Skipped()==0) ? 1 : 0);''', 'IR authority receipt')
    one('    std::fprintf(stderr, "IR_OPS_VISITED=%u\\n", GEN::kExecutionOpCount);', '''    std::fprintf(stderr, "IR_OPS_VISITED=%u\\n", executor.Visited());
    std::fprintf(stderr, "IR_OPS_EXECUTED=%u\\n", executor.Dispatched());
    std::fprintf(stderr, "IR_OPS_SKIPPED=%u\\n", executor.Skipped());''', 'exact dispatch counts')
    # Finite activations are now a strict condition on every completed operation.
    one('            if (executed) {\n                opsDispatched++;', '''            if (executed && op.output.domain == MG::OperandDomain::Activation) {
                const float* result = arena_.Get(op.output.id);
                const size_t n = arena_.Size(op.output.id);
                if (!result || !n) executed = false;
                else for (size_t j=0;j<n;++j)
                    if (!std::isfinite(result[j])) {
                        std::fprintf(stderr,"[IR] NONFINITE op=%u offset=%zu\\n",op.opId,j);
                        executed = false;
                        break;
                    }
            }
            if (executed) {
                opsDispatched++;''', 'per-op numerical gate')
    if 'NOT_IMPLEMENTED' in s or 'not implemented' in s:
        raise PatchError('A not-implemented marker survived replacement')
    if s.count('case Primitive::MoEExecuteFwd:') != 1:
        raise PatchError('Duplicate MoE switch arm')
    if s.count('case Primitive::MlaDecompressFwd:') != 1:
        raise PatchError('Duplicate MLA switch arm')
    return s, changed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source', type=pathlib.Path, default=pathlib.Path(r'F:\rawrxd\tools\rawrxd_modelgenie_ir_executor.cpp'))
    ap.add_argument('--apply', action='store_true', help='write a backed-up source; default is dry-run only')
    ap.add_argument('--diff', type=pathlib.Path, help='save a unified patch without applying')
    args = ap.parse_args()
    try:
        raw = args.source.read_bytes()
        if b'\r\n' in raw:
            newline = b'\r\n'
        else:
            newline = b'\n'
        original = raw.decode('utf-8-sig').replace('\r\n','\n')
        edited, changes = patch(original)
        diff = ''.join(difflib.unified_diff(original.splitlines(True),edited.splitlines(True),
                   fromfile='a/tools/rawrxd_modelgenie_ir_executor.cpp',
                   tofile='b/tools/rawrxd_modelgenie_ir_executor.cpp'))
        print('PATCH_TRANSFORMS=' + str(len(changes)))
        for c in changes: print('  + ' + c)
        print('CHANGED=' + str(original != edited))
        if args.diff:
            args.diff.parent.mkdir(parents=True,exist_ok=True)
            args.diff.write_text(diff,encoding='utf-8')
            print('DIFF_FILE=' + str(args.diff))
        if args.apply:
            backup = args.source.with_name(args.source.name + '.pre_ir_completion.bak')
            if backup.exists(): raise PatchError('Backup already exists: ' + str(backup))
            backup.write_bytes(raw)
            args.source.write_bytes(edited.replace('\n',newline.decode()).encode('utf-8'))
            print('APPLIED=' + str(args.source))
            print('BACKUP=' + str(backup))
        else: print('DRY_RUN=1 (source untouched)')
        return 0
    except (OSError, UnicodeError, PatchError) as ex:
        print('PATCH_VERDICT=FAIL: ' + str(ex), file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
