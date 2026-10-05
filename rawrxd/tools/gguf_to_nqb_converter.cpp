// gguf_to_nqb_converter.cpp
// RAWRXD_GGUF_TO_NQB_CONVERTER_001
//
// Converts a GGUF model to a Nanof32Braid (.nqb) file using q0 (lossless
// dense F32) encoding.  This is a one-way bridge: every Q2_K weight tensor
// is dequantised to float32, every architecture field is copied from GGUF
// metadata, and the vocabulary is serialised into the braid vocabulary
// section so the resulting .nqb is fully self-contained.
//
// WHY THIS FILE EXISTS
// --------------------
// The real-weight numerical oracle requires feeding *identical* token IDs
// to two engine paths (GGUF and NQB) and comparing logits.  The only honest
// way to do that is to produce the NQB file from the same GGUF source,
// preserving weights and vocabulary exactly.
//
// HONESTY CONSTRAINTS
// -------------------
//  * SYNTHETIC_WEIGHTS=0 in every receipt this tool produces.
//  * QUANT_TYPE=NQBRAID_DENSE_F32 (0), i.e. no compression.
//  * Every weight is dequantised via the *production* registry kernel so the
//    NQB path uses the same float values the GGUF CPU path uses.
//  * No expected-output string is written anywhere in this file.

#include "deep2/GGUFLoader.hpp"
#include "deep2/QuantKernelRegistry.hpp"
#include "deep2/Nanof32BraidFormat.hpp"
#include "deep2/Nanof32BraidWriter.hpp"
#include "rawr_build_identity_gguf_to_nqb_converter.hpp"

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <fstream>
#include "deep2/BP16Streamer.hpp"

// ---------------------------------------------------------------------------
// RAWRXD_GGUF_TO_NQB_FIDELITY_001
//
// The reader (Nanof32BraidStreamer) materialises every tensor as bfloat16, even
// when the file stores NQBRAID_DENSE_F32. So a "lossless" F32 container is NOT
// a lossless path: the F32 -> BF16 narrowing is the dominant error term the
// downstream logit oracle will ever see, and it is invisible unless measured.
//
// Therefore every tensor is measured twice in the same pass:
//   * source finiteness  (is the GGUF weight itself already broken?)
//   * bf16 round-trip    (what does the reader hand the engine?)
// Both are reported. Neither is assumed.
// ---------------------------------------------------------------------------
struct TensorFidelity {
    size_t elements      = 0;
    size_t nonFinite     = 0;   // NaN + Inf in the source float buffer
    float  min           = 0.0f;
    float  max           = 0.0f;
    double l2             = 0.0; // sqrt(sum of squares)
    double bf16MaxAbsErr = 0.0; // max |f32 - (float)bf16(f32)|
    double bf16MeanAbsErr= 0.0;
    bool   allFinite      = true;
};

static TensorFidelity measureFidelity(const std::vector<float>& f) {
    TensorFidelity s;
    s.elements = f.size();
    if (f.empty()) { s.allFinite = true; return s; }

    s.min = f[0];
    s.max = f[0];
    double sumSq = 0.0;
    double errSum = 0.0;
    for (float v : f) {
        if (std::isnan(v) || std::isinf(v)) {
            ++s.nonFinite;
            s.allFinite = false;
            continue;   // excluded from statistics so one bad value cannot
                        // poison the aggregate and hide the rest of the tensor
        }
        if (v < s.min) s.min = v;
        if (v > s.max) s.max = v;
        sumSq += static_cast<double>(v) * static_cast<double>(v);

        const float round = Deep2::bfloat16_t(v).toFloat();
        const double err = std::fabs(static_cast<double>(v) - static_cast<double>(round));
        errSum += err;
        if (err > s.bf16MaxAbsErr) s.bf16MaxAbsErr = err;
    }
    const double finite = static_cast<double>(s.elements - s.nonFinite);
    if (finite > 0.0) {
        s.l2 = std::sqrt(sumSq);
        s.bf16MeanAbsErr = errSum / finite;
    }
    return s;
}


static void usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s <input.gguf> <output.nqb>\n"
        "  Converts a GGUF model to a lossless dense-F32 .nqb file.\n",
        prog);
}

int main(int argc, char** argv) {
    if (argc != 3) { usage(argv[0]); return 64; }
    const char* ggufPath  = argv[1];
    const char* nqbPath   = argv[2];

    std::fprintf(stderr, "GATE=GGUF_TO_NQB_CONVERTER\n");
    // RAWRXD_CERT_BINARY_BUILD_IDENTITY_001 -- state which source produced this
    // binary before stating anything it measured. A receipt whose provenance is
    // unknown cannot certify anything downstream.
    RAWRXD_PRINT_BUILD_IDENTITY();
    std::fprintf(stderr, "SOURCE_GGUF=%s\n", ggufPath);
    std::fprintf(stderr, "TARGET_NQB=%s\n", nqbPath);

    // ----------------------------------------------------------------
    // 1. Load GGUF
    // ----------------------------------------------------------------
    Deep2::QuantKernelRegistry::Instance().Initialize();

    Deep2::GGUFLoader loader;
    if (!loader.load(ggufPath)) {
        std::fprintf(stderr, "FAIL=gguf_load: %s\n", loader.error().c_str());
        return 1;
    }
    std::fprintf(stderr, "GGUF_LOADED=1 version=%u tensors=%zu\n",
                 loader.version(), loader.tensorCount());

    // ----------------------------------------------------------------
    // 2. Extract architecture metadata from GGUF key/value store
    // ----------------------------------------------------------------
    Deep2::Nanof32BraidArchMeta archMeta{};
    std::snprintf(archMeta.modelName, sizeof archMeta.modelName, "%s",
                  loader.getMetaString("general.name", "unknown").c_str());
    std::snprintf(archMeta.archName, sizeof archMeta.archName, "%s",
                  loader.getMetaString("general.architecture", "llama").c_str());

    archMeta.numLayers       = static_cast<uint32_t>(loader.getMetaInt("llama.block_count", 0));
    archMeta.hiddenDim       = static_cast<uint32_t>(loader.getMetaInt("llama.embedding_length", 0));
    archMeta.numHeads        = static_cast<uint32_t>(loader.getMetaInt("llama.attention.head_count", 0));
    archMeta.numKVHeads      = static_cast<uint32_t>(loader.getMetaInt("llama.attention.head_count_kv", 0));
    // RAWRXD_NQBRAID_HEAD_DIM_DERIVED_001
    //
    // This read:
    //     archMeta.headDim = getMetaInt("llama.attention.head_dim", 64);
    // llama3.2-3b-Q2_K does not carry that key, so the DEFAULT was written into
    // the file and consumed as fact by the loader. headDim 64 instead of 128
    // halves both derived dimensions:
    //     [ALLOC] qDim=1536 kvDim=512 numHeads=24 headDim=64 numKVHeads=8
    // where the GGUF path on the same model reports
    //     [ALLOC] qDim=3072 kvDim=1024 numHeads=24 headDim=128 numKVHeads=8
    // It also sizes the KV cache from modelWeights.headDim, so the cache was
    // half the width it should be. Nothing reported an error: the file was
    // structurally valid, every tensor was finite, and the arithmetic was wrong
    // -- which is why this is a derived-value fix and not a bounds check.
    //
    // head_dim is by definition embedding_length / head_count, so derive it when
    // the key is absent rather than assuming a constant that is wrong for every
    // model whose hidden size is not 64*heads.
    archMeta.headDim         = static_cast<uint32_t>(loader.getMetaInt("llama.attention.head_dim", 0));
    if (archMeta.headDim == 0 && archMeta.hiddenDim != 0 && archMeta.numHeads != 0) {
        // RAWRXD_ARCH_HEAD_DERIVE_OR_FAIL_001
        //
        // head_dim is by definition embedding_length / head_count, so derive it
        // when the key is absent rather than assuming a constant. Assuming 64
        // wrote a wrong architectural truth into the file while every structural
        // check still passed; the cost only appeared in logits, where headDim
        // 64 against 128-wide weights roughly tripled the error.
        archMeta.headDim = archMeta.hiddenDim / archMeta.numHeads;
        std::fprintf(stderr,
            "HEAD_DIM_DERIVED value=%u from hidden=%u / heads=%u "
            "(key llama.attention.head_dim absent)\n",
            archMeta.headDim, archMeta.hiddenDim, archMeta.numHeads);
    }
    // Derive-or-fail: a guessed head dimension must never reach the file.
    if (archMeta.headDim == 0 || archMeta.numHeads == 0 ||
        (archMeta.hiddenDim % archMeta.numHeads) != 0) {
        std::fprintf(stderr,
            "GEOMETRY_FATAL hidden=%u heads=%u headDim=%u hidden%%heads=%u\n",
            archMeta.hiddenDim, archMeta.numHeads, archMeta.headDim,
            archMeta.numHeads ? (archMeta.hiddenDim % archMeta.numHeads) : 0u);
        return 3;   // 3 = geometry unusable, distinct from 2 = conversion failed
    }
    // The tensor is the authority: blk.0.attn_q is [numHeads*headDim, hiddenDim].
    {
        const Deep2::GGUFTensor* q0 = loader.getTensor("blk.0.attn_q.weight");
        if (q0 && q0->shape.size() >= 2 && q0->shape[0] > 0) {
            const uint64_t implied = q0->shape[0] / (archMeta.numHeads ? archMeta.numHeads : 1);
            if (implied != archMeta.headDim) {
                std::fprintf(stderr,
                    "GEOMETRY_FATAL attn_q_rows=%llu implies headDim=%llu but metadata says %u\n",
                    (unsigned long long)q0->shape[0], (unsigned long long)implied,
                    archMeta.headDim);
                return 3;
            }
            std::fprintf(stderr, "GEOMETRY_CONSISTENT=1 headDim=%u confirmed_by_attn_q_rows\n",
                         archMeta.headDim);
        }
    }
    archMeta.intermediateDim = static_cast<uint32_t>(loader.getMetaInt("llama.feed_forward_length", 0));
    archMeta.vocabSize       = static_cast<uint32_t>(loader.getMetaInt("llama.vocab_size", 0));
    archMeta.contextLength   = static_cast<uint32_t>(loader.getMetaInt("llama.context_length", 2048));
    archMeta.normEps         = static_cast<float>(loader.getMetaFloat("llama.attention.layer_norm_rms_epsilon", 1e-5));
    archMeta.ropeTheta       = static_cast<float>(loader.getMetaFloat("llama.rope.freq_base", 10000.0));

    // RAWRXD_ARCH_CONTEXT_INVARIANT_001
    //
    // A silent context discrepancy is a silent KV-cache discrepancy. The GGUF
    // engine came up with maxSeqLen=2048 while the braid engine, reading the
    // same value out of the file, came up with 131072 -- a 64x disagreement
    // about how much state the model has, established without anybody deciding
    // it. Report both sides so the two engines can be compared on one number.
    std::fprintf(stderr,
        "CONTEXT_GEOMETRY arch_context=%u engine_context_default=%u kv_cache_context=arch\n",
        archMeta.contextLength, 2048u);
    archMeta.ropeType        = 1; // NeoX for Llama-style models

    // MLA / MoE: not yet supported for conversion; leave defaults
    archMeta.numExperts      = 0;
    archMeta.activeExperts   = 0;
    archMeta.moeGateDim      = 0;
    archMeta.hasSharedExperts= 0;

    // Override with architecture-specific keys
    if (std::strcmp(archMeta.archName, "deepseek2") == 0) {
        archMeta.ropeType = 3;
        archMeta.qLoraRank    = static_cast<uint32_t>(loader.getMetaInt("deepseek2.q_lora_rank", 0));
        archMeta.kvLoraRank   = static_cast<uint32_t>(loader.getMetaInt("deepseek2.kv_lora_rank", 0));
        archMeta.qkNopeHeadDim= static_cast<uint32_t>(loader.getMetaInt("deepseek2.qk_nope_head_dim", 0));
        archMeta.qkRopeHeadDim= static_cast<uint32_t>(loader.getMetaInt("deepseek2.qk_rope_head_dim", 0));
        archMeta.vHeadDim     = static_cast<uint32_t>(loader.getMetaInt("deepseek2.v_head_dim", 0));
    }

    // ----------------------------------------------------------------
    // 2b. Vocabulary (extract from GGUF metadata)
    // ----------------------------------------------------------------
    Deep2::Nanof32VocabSpec vocabSpec{};
    bool hasVocab = false;
    // Distinguishes "the GGUF carried no tokenizer array at all" (a property of
    // the source model) from "we found it but failed to encode it" (a defect of
    // this tool). Collapsing the two would hide the second.
    bool vocabPresentInGguf = false;
    {
        std::vector<std::string> tokens;
        std::vector<float> scores;
        std::vector<int32_t> types;
        std::vector<std::string> merges;
        if (loader.getMetaStringArray("tokenizer.ggml.tokens", tokens)) {
            if (!loader.getMetaFloatArray("tokenizer.ggml.scores", scores) || scores.size() != tokens.size())
                scores.assign(tokens.size(), 0.0f);
            if (!loader.getMetaInt32Array("tokenizer.ggml.token_type", types) || types.size() != tokens.size())
                types.assign(tokens.size(), 1); // TOK_NORMAL
            loader.getMetaStringArray("tokenizer.ggml.merges", merges);
            vocabSpec.tokens = std::move(tokens);
            vocabSpec.scores = std::move(scores);
            vocabSpec.types  = std::move(types);
            vocabSpec.merges = std::move(merges);
            vocabSpec.model  = loader.getMetaString("tokenizer.ggml.model", "llama");
            std::string modelLower = vocabSpec.model;
            std::transform(modelLower.begin(), modelLower.end(), modelLower.begin(),
                           [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (modelLower == "gpt2" || modelLower == "gpt-2") vocabSpec.kind = 1; // GPT2BPE
            else vocabSpec.kind = 2; // SentencePiece (llama, etc.)
            vocabSpec.bosId = static_cast<int32_t>(loader.getMetaInt("tokenizer.ggml.bos_token_id", -1));
            vocabSpec.eosId = static_cast<int32_t>(loader.getMetaInt("tokenizer.ggml.eos_token_id", -1));
            vocabSpec.unkId = static_cast<int32_t>(loader.getMetaInt("tokenizer.ggml.unknown_token_id", -1));
            vocabSpec.sepId = static_cast<int32_t>(loader.getMetaInt("tokenizer.ggml.separator_token_id", -1));
            vocabSpec.padId = static_cast<int32_t>(loader.getMetaInt("tokenizer.ggml.padding_token_id", -1));
            vocabSpec.addBos = loader.getMetaInt("tokenizer.ggml.add_bos_token", 0) != 0;
            vocabSpec.addEos = loader.getMetaInt("tokenizer.ggml.add_eos_token", 0) != 0;
            vocabPresentInGguf = !vocabSpec.tokens.empty();
            hasVocab = vocabPresentInGguf;

            // RAWRXD_GGUF_TO_NQB_CONVERTER_AUTHORITY_001 -- vocabSize.
            //
            // archMeta.vocabSize was taken from "llama.vocab_size", which is
            // absent in the model that was actually converted, so the field was
            // 0 and the loader then correctly refused the file:
            //     [NQBRAID] ERROR: vocabulary has 32000 entries but the model
            //     embedding has only 0 rows
            // That is NQB_INVARIANT_TOKEN_DOMAIN_001 doing its job against a
            // header that understated its own embedding. The authoritative
            // source for the vocabulary size is the token array the section was
            // built from, and the element count of token_embd is the embedding
            // row count. Both are MEASURED; the metadata key is only a fallback.
            if (archMeta.vocabSize == 0) {
                archMeta.vocabSize = static_cast<uint32_t>(vocabSpec.tokens.size());
                std::fprintf(stderr,
                    "ARCH_META vocabSize_from_metadata=0 vocabSize_from_token_array=%u\n",
                    archMeta.vocabSize);
            }
        }
    }

    // ----------------------------------------------------------------
    // 3+4. Open the ONE container writer, transactionally.
    //
    // RAWRXD_NQB_ONE_FORMAT_AUTHORITY_001
    //
    // This tool used to serialize the container itself: its own ofstream, its
    // own header struct, its own appendTensor(), its own header backfill. The
    // writer in Nanof32BraidWriter.cpp did the same thing independently. Two
    // serializers is how the tree ended up with THREE different answers for
    // bitsPerWeight on a dense-F32 file (160, 320, 0) and a shipped artifact
    // whose paramCount was 0 while its payload held 3,212,749,888 elements.
    //
    // Both now go through Nanof32BraidStreamWriter, so the footer layout, the
    // census accumulation and the header backfill exist exactly once.
    //
    // TRANSACTIONAL: the container is written to "<path>.building" and only
    // renamed into place after finalize() AND the verdict checks pass. A
    // converter killed halfway through therefore leaves no artifact that a
    // reader could mistake for a model.
    // ----------------------------------------------------------------
const std::string buildingPath = std::string(nqbPath) + ".building";
    std::remove(nqbPath);            // never leave a previous artifact in place
    std::remove(buildingPath.c_str());
    std::wstring nqbPathW(nqbPath, nqbPath + std::strlen(nqbPath));
    std::wstring buildingPathW(buildingPath.begin(), buildingPath.end());

    Deep2::Nanof32BraidStreamWriter writer;
    if (!writer.open(buildingPath, archMeta, hasVocab ? &vocabSpec : nullptr)) {
        std::fprintf(stderr, "FAIL=container_open: %s\n", writer.error().c_str());
        return 1;
    }
    std::vector<uint8_t> vocabBytes;
    if (hasVocab) vocabBytes = Deep2::nanof32EncodeVocabSection(vocabSpec);

// ----------------------------------------------------------------
    // 5. Enumerate all GGUF tensors, dequantise, append as dense F32
    // ----------------------------------------------------------------
    size_t convertedCount = 0;
    size_t skippedCount   = 0;
    std::vector<float>     floatBuf;
    std::vector<uint8_t> payload;

    size_t globalNonFiniteTensors = 0;
    size_t globalNonFiniteValues  = 0;
    size_t globalElements         = 0;
    double globalBf16MaxAbsErr    = 0.0;
    uint64_t globalParamCount     = 0;   // measured, for hdr.paramCount
    uint64_t measuredEmbedRows     = 0;   // token_embd row count, measured

    for (const std::string& name : loader.listTensors()) {
        Deep2::GGUFTensor* pt = loader.getTensor(name);
        if (!pt) continue;
        const Deep2::GGUFTensor& tensor = *pt;
        size_t numElements = tensor.numElements();
        if (numElements == 0) {
            std::fprintf(stderr, "SKIP=%s zero_elements\n", tensor.name.c_str());
            ++skippedCount;
            continue;
        }

        Deep2::Nanof32TensorSpec spec{};
        spec.name  = tensor.name;
        spec.rows  = static_cast<uint64_t>(tensor.shape.empty() ? 1 : tensor.shape[0]);
        spec.cols  = static_cast<uint64_t>(tensor.shape.size() > 1 ? tensor.shape[1] : 1);
        // Measure the embedding row count rather than trusting the metadata
        // key: this is the row count NQB_INVARIANT_TOKEN_DOMAIN_001 compares
        // the vocabulary against, and it is also the cross-check on
        // archMeta.vocabSize. If the two disagree the header is wrong and the
        // file must not be written as if it were right.
        if (tensor.name == "token_embd.weight") {
            // Derive the row count from ELEMENT COUNT / hiddenDim, not from
            // shape[0]. GGUF stores token_embd as ne = [n_embd, n_vocab], so
            // shape[0] is the HIDDEN dimension (2048) and shape[1] is the
            // vocabulary (32000). Reading shape[0] as rows reported 2048 and
            // produced two spurious failures:
            //     FAIL=TOKEN_DOMAIN_VIOLATION_EMBED_LT_VOCAB
            //     FAIL=EMBED_ROWS_VOCAB_SIZE_DISAGREE
            // Both were the CHECK being wrong, not the model. Dividing by
            // hiddenDim is transpose-independent.
            if (archMeta.hiddenDim > 0) {
                measuredEmbedRows = numElements / archMeta.hiddenDim;
            }
        }
        spec.quant = Deep2::NQBRAID_DENSE_F32;
        spec.expertIndex = 0xFFFFFFFFu;

        // Dequantise to float32 if quantised; pass through if already F32/BF16/F16
        floatBuf.resize(numElements);
        if (tensor.type == Deep2::GGMLType::GGML_TYPE_F32) {
            std::memcpy(floatBuf.data(), tensor.data, numElements * sizeof(float));
        } else if (tensor.type == Deep2::GGMLType::GGML_TYPE_F16) {
            // Need f16_to_f32 — use registry dequant if available, else stub
            auto fn = Deep2::QuantKernelRegistry::Instance().GetDequant(static_cast<int>(tensor.type));
            if (fn) {
                fn(tensor.data, floatBuf.data(), numElements);
            } else {
                std::fprintf(stderr, "SKIP=%s no_f16_dequant_kernel\n", tensor.name.c_str());
                ++skippedCount;
                continue;
            }
        } else if (tensor.type == Deep2::GGMLType::GGML_TYPE_BF16) {
            auto fn = Deep2::QuantKernelRegistry::Instance().GetDequant(static_cast<int>(tensor.type));
            if (fn) {
                fn(tensor.data, floatBuf.data(), numElements);
            } else {
                std::fprintf(stderr, "SKIP=%s no_bf16_dequant_kernel\n", tensor.name.c_str());
                ++skippedCount;
                continue;
            }
        } else {
            // Quantised types: use production dequant kernel
            auto fn = Deep2::QuantKernelRegistry::Instance().GetDequant(static_cast<int>(tensor.type));
            if (!fn) {
                std::fprintf(stderr, "SKIP=%s no_dequant_kernel type=%d\n",
                             tensor.name.c_str(), static_cast<int>(tensor.type));
                ++skippedCount;
                continue;
            }
            fn(tensor.data, floatBuf.data(), numElements);
        }

        // ---- measure, do not assume -------------------------------------
        const TensorFidelity fid = measureFidelity(floatBuf);

        globalNonFiniteTensors += fid.nonFinite ? 1u : 0u;
        globalNonFiniteValues  += fid.nonFinite;
        globalElements         += fid.elements;
        globalBf16MaxAbsErr     = std::max(globalBf16MaxAbsErr, fid.bf16MaxAbsErr);
        // Accumulated only for tensors that were actually written, so a skip
        // cannot make the header claim more parameters than the file holds.
        globalParamCount += numElements;

        // Scale range for footer (dense F32 doesn't use it, but the footer
        // still requires valid values).
        const float lo = fid.allFinite ? fid.min : 0.0f;
        const float hi = fid.allFinite ? fid.max : 0.0f;
        const float pad = std::max(1e-6f, std::fabs(hi - lo) * 1e-3f);
        spec.scaleMin = lo - pad;
        spec.scaleMax = hi + pad;

        // Encode as dense F32
        payload.resize(numElements * sizeof(float));
        std::memcpy(payload.data(), floatBuf.data(), payload.size());

        // Append through the ONE container writer. The census inside it is
        // accumulated from what was actually emitted, so a tensor that failed
        // to encode is simply not counted -- there is no path by which the
        // header can claim a tensor the file does not contain.
        if (!writer.appendTensor(spec.name, spec.rows, spec.cols, spec.quant,
                                 floatBuf.data(), numElements,
                                 spec.scaleMin, spec.scaleMax,
                                 spec.expertIndex)) {
            std::fprintf(stderr, "FAIL=append_tensor name=%s: %s\n",
                         spec.name.c_str(), writer.error().c_str());
            writer.abort();
            return 1;
        }
        ++convertedCount;

        if (fid.nonFinite) {
            std::fprintf(stderr, "TENSOR=%s type=%d elements=%zu nonfinite=%zu "
                                  "MIN=n/a MAX=n/a L2=n/a  <-- SOURCE BROKEN\n",
                         tensor.name.c_str(), static_cast<int>(tensor.type),
                         numElements, fid.nonFinite);
        } else {
            std::fprintf(stderr,
                         "TENSOR=%s type=%d elements=%zu nonfinite=0 "
                         "min=%.6g max=%.6g l2=%.6g bf16maxabs=%.6g bf16meanabs=%.6g\n",
                         tensor.name.c_str(), static_cast<int>(tensor.type),
                         numElements, fid.min, fid.max, fid.l2,
                         fid.bf16MaxAbsErr, fid.bf16MeanAbsErr);
        }
    }

    // ----------------------------------------------------------------
    // 6. Finalise: the header is backfilled by the writer from its own census.
    //
    // RAWRXD_GGUF_TO_NQB_CONVERTER_AUTHORITY_001 -- header completeness.
    //
    // paramCount and bitsPerWeight were both left at 0, so a converted real
    // model announced itself as:
    //     [NQBRAID] OPEN: params=0 bitsPerWeight=0.00 tensors=201
    // which is a header that lies about its own contents. That shipped: the real
    // artifact carried paramCount=0 and bitsPerWeight=0 while its payload held
    // 3,212,749,888 elements at 4 bytes each.
    //
    // RAWRXD_NQB_BITS_PER_WEIGHT_UNIT_001 -- an intermediate repair here wrote
    //     "the field is documented as 115 == 1.15 bits/weight, so 32 bits is 320"
    // which drops a factor of 100 (115 hundredths == 1.15, so 32.00 is 3200), and
    // a second repair set the WRITER to 320 and failed identically:
    //     EXPECTED_BITS_PER_WEIGHT=32  DECODED_BITS_PER_WEIGHT=3.2
    //
    // Both are gone. The field is now DERIVED from the bytes actually written:
    //     bpw100 = round(payloadBytes * 800 / paramCount)
    // computed once, in nanof32DeriveBitsPerWeight100(). It is measured rather
    // than predicted, so it stays correct for a mixed-codec artifact and cannot
    // be edited into a different plausible wrong value at a second site.
    // ----------------------------------------------------------------
    if (!writer.finalize()) {
        std::fprintf(stderr, "FAIL=finalize: %s\n", writer.error().c_str());
        writer.abort();
        return 1;
    }

    const Deep2::Nanof32Census& census = writer.census();
    const uint64_t fileSize = writer.bytesWritten();
    const uint32_t headerNumTensors = static_cast<uint32_t>(census.tensorCount);
    const uint64_t headerParamCount = census.paramCount;
    const uint32_t headerBpw100 = census.bpw100;

    // On-disk size must equal what the header claims, or the reverse reader's
    // backward walk starts at the wrong offset and silently reads garbage.
    uint64_t onDisk = 0;
    {
        std::ifstream probe(buildingPath, std::ios::binary | std::ios::ate);
        if (probe) onDisk = static_cast<uint64_t>(probe.tellg());
    }

    // ----------------------------------------------------------------
    // 7. Verdict — computed from the observations above
    // ----------------------------------------------------------------
    std::vector<std::string> failures;
    const size_t ggufTensorCount = loader.tensorCount();

    if (convertedCount == 0)              failures.push_back("NO_TENSORS_CONVERTED");
    if (skippedCount > 0)                 failures.push_back("TENSORS_SKIPPED");
    if (convertedCount != ggufTensorCount) failures.push_back("TENSOR_COUNT_LOSS");
    if (globalNonFiniteValues > 0)         failures.push_back("SOURCE_NONFINITE_VALUES");
    if (onDisk == 0)                      failures.push_back("OUTPUT_UNREADABLE");
    else if (onDisk != fileSize)          failures.push_back("FILE_SIZE_MISMATCH");
    if (vocabPresentInGguf && vocabBytes.empty())
                                             failures.push_back("VOCAB_ENCODE_FAILED");
    if (!vocabPresentInGguf)               failures.push_back("VOCAB_ABSENT_FROM_GGUF");
    // RAWRXD_GGUF_TO_NQB_CONVERTER_AUTHORITY_001 -- the checks whose absence
    // let this tool report VERDICT=PASS while emitting a header that
    // understated the model. Every one of these is a field a reader consumes:
    // a zero in any of them is not "unknown", it is a wrong answer.
    if (headerParamCount == 0)    failures.push_back("HEADER_PARAM_COUNT_ZERO");
    if (headerBpw100 == 0)        failures.push_back("HEADER_BITS_PER_WEIGHT_ZERO");

    // ----------------------------------------------------------------
    // RAWRXD_NQB_CODEC_IDENTITY_001
    //
    // The repository contains a file named
    //     llama3.2-3b-real-q0.nqb
    // whose 255 footers are ALL quantType=0 (DENSE_F32), whose length equals the
    // dense-F32 artifact's to the byte, and whose sampled payload windows are
    // byte-identical to it. It is not a q0 file. The filename carried the codec
    // intent and the footer types carried the truth, and nothing compared the
    // two -- so a codec-fidelity gate run against it would have measured
    // dense-F32 passthrough twice and reported it as q0.
    //
    // A filename is decoration. The census below is what the file IS, taken
    // from the footers the writer actually emitted, and it is now compared
    // against what this run was asked to produce.
    // ----------------------------------------------------------------
    const char* codecNames[Deep2::NQBRAID_COUNT] = {
        "DENSE_F32", "DENSE_BF16", "CODEBOOK_1BIT", "CODEBOOK_2BIT",
        "CODEBOOK_3BIT", "BRAID_115"
    };
    for (uint32_t c = 0; c < Deep2::NQBRAID_COUNT; ++c) {
        std::fprintf(stderr, "CODEC_COUNT_%s=%llu\n", codecNames[c],
                     (unsigned long long)census.codecCount[c]);
    }
    std::fprintf(stderr, "CODEC_ELEMENTS=%llu\n", (unsigned long long)census.paramCount);
    std::fprintf(stderr, "CODEC_PAYLOAD_BYTES=%llu\n", (unsigned long long)census.payloadBytes);
    std::fprintf(stderr, "CODEC_FOOTER_BYTES=%llu\n", (unsigned long long)census.footerBytes);

    // This converter emits dense F32 and nothing else. Asserted rather than
    // assumed: if a codec path is added later and not wired here, the artifact
    // would silently claim a compression it does not contain.
    const bool codecRequestApplied =
        census.tensorCount > 0 &&
        census.codecCount[Deep2::NQBRAID_DENSE_F32] == census.tensorCount;
    std::fprintf(stderr, "REQUESTED_CODEC=DENSE_F32\n");
    std::fprintf(stderr, "RESOLVED_CODEC=%s\n",
                 codecRequestApplied ? "DENSE_F32" : "MIXED_OR_OTHER");
    std::fprintf(stderr, "CODEC_REQUEST_APPLIED=%d\n", codecRequestApplied ? 1 : 0);
    if (!codecRequestApplied) failures.push_back("CODEC_REQUEST_NOT_APPLIED");

    // Compression actually realised. Only meaningful for a LOSSY request: a
    // dense-F32 file is SUPPOSED to come out at 32.00 bits per weight, so
    // asserting "compression not realised" against it would fail every correct
    // dense conversion. The check fires only when the caller asked for a codec
    // that must compress and the bytes say otherwise -- which is the shape the
    // fake q0 artifact had.
    const double physicalBpW =
        census.paramCount ? (static_cast<double>(census.payloadBytes) * 8.0 /
                             static_cast<double>(census.paramCount)) : 0.0;
    const bool lossyRequested = false;   // DENSE_F32 is lossless; nothing to realise
    std::fprintf(stderr, "PHYSICAL_BITS_PER_WEIGHT=%.4f\n", physicalBpW);
    std::fprintf(stderr, "COMPRESSION_EXPECTATION=%s\n",
                 lossyRequested ? "STRICTLY_LESS_THAN_32" : "NONE_LOSSLESS_CODEC");
    if (lossyRequested && physicalBpW >= 32.0)
        failures.push_back("COMPRESSION_NOT_REALISED");

    // The census must also agree with the header the writer backfilled. These
    // are the same numbers written twice on purpose: once inside the writer and
    // once here from an independent read of its result. Agreement is a real
    // cross-check; a mismatch means finalize() did not see what was emitted.
    if (headerNumTensors != convertedCount)
        failures.push_back("CENSUS_TENSOR_COUNT_DISAGREES_WITH_LOOP");
    if (headerParamCount != globalParamCount)
        failures.push_back("CENSUS_PARAM_COUNT_DISAGREES_WITH_LOOP");
    if (headerBpw100 != Deep2::nanof32DeriveBitsPerWeight100(census.payloadBytes,
                                                             census.paramCount))
        failures.push_back("CENSUS_BPW_DISAGREES_WITH_DERIVATION");
    std::fprintf(stderr, "HEADER_NUM_TENSORS=%u\n", headerNumTensors);
    std::fprintf(stderr, "HEADER_PARAM_COUNT=%llu\n", (unsigned long long)headerParamCount);
    std::fprintf(stderr, "HEADER_BITS_FIELD_RAW=%u\n", headerBpw100);
    std::fprintf(stderr, "DATA_START=%llu\n", (unsigned long long)writer.dataStart());
    if (archMeta.vocabSize == 0)         failures.push_back("ARCH_VOCAB_SIZE_ZERO");
    if (archMeta.numLayers == 0)         failures.push_back("ARCH_NUM_LAYERS_ZERO");
    if (archMeta.hiddenDim == 0)         failures.push_back("ARCH_HIDDEN_DIM_ZERO");
    if (archMeta.ropeTheta <= 0.0f)      failures.push_back("ARCH_ROPE_THETA_ZERO");
    // NQB_INVARIANT_TOKEN_DOMAIN_001: the vocabulary must fit the embedding.
    // Asserted at the CONVERTER too, not only in the writer and the loader,
    // so the bridge cannot produce a file that its own format forbids.
    if (hasVocab && vocabSpec.tokens.size() > archMeta.vocabSize)
        failures.push_back("TOKEN_DOMAIN_VIOLATION_VOCAB_GT_EMBED");
    if (measuredEmbedRows == 0)
        failures.push_back("TOKEN_EMBED_NOT_CONVERTED");
    else if (measuredEmbedRows < archMeta.vocabSize)
        failures.push_back("TOKEN_DOMAIN_VIOLATION_EMBED_LT_VOCAB");
    // The metadata key and the tensor shape must agree. When they did not, the
    // header was silently wrong; now it is a named failure.
    if (measuredEmbedRows != 0 && archMeta.vocabSize != 0 &&
        measuredEmbedRows != archMeta.vocabSize)
        failures.push_back("EMBED_ROWS_VOCAB_SIZE_DISAGREE");

    std::fprintf(stderr, "\n=== MEASURED SUMMARY ===\n");
    std::fprintf(stderr, "GGUF_TENSORS=%zu\n",       ggufTensorCount);
    std::fprintf(stderr, "CONVERTED=%zu\n",            convertedCount);
    std::fprintf(stderr, "SKIPPED=%zu\n",              skippedCount);
    std::fprintf(stderr, "ELEMENTS_TOTAL=%zu\n",       globalElements);
    std::fprintf(stderr, "SOURCE_NONFINITE_TENSORS=%zu\n", globalNonFiniteTensors);
    std::fprintf(stderr, "SOURCE_NONFINITE_VALUES=%zu\n",  globalNonFiniteValues);
    std::fprintf(stderr, "QUANT_TYPE=NQBRAID_DENSE_F32\n");
    std::fprintf(stderr, "SYNTHETIC_WEIGHTS=0\n");

    // The production Q2_K kernel has an env-gated alternate scale unpack
    // (RAWRXD_Q2K_SCALE6) kept as a falsification control.  It is NOT the ggml
    // decode.  If it is active, this file would contain weights no llama.cpp
    // build would ever produce, so the artifact is not a faithful copy of the
    // model and the run must not report PASS.  A receipt that cannot name the
    // decoder that produced the bytes is not a receipt.
    const char* scale6 = std::getenv("RAWRXD_Q2K_SCALE6");
    const bool scale6Active = scale6 && scale6[0] && scale6[0] != '0';
    std::fprintf(stderr, "Q2K_SCALE6_FALSIFICATION_CONTROL=%d\n", scale6Active ? 1 : 0);
    if (scale6Active) failures.push_back("Q2K_FALSIFICATION_CONTROL_ACTIVE");
    std::fprintf(stderr, "VOCAB_PRESENT_IN_GGUF=%d VOCAB_ENTRIES=%zu VOCAB_BYTES=%zu\n",
                 vocabPresentInGguf ? 1 : 0, vocabSpec.tokens.size(), vocabBytes.size());
    std::fprintf(stderr, "FILE_SIZE_DECLARED=%llu\n", (unsigned long long)fileSize);
    std::fprintf(stderr, "FILE_SIZE_ONDISK=%llu\n",   (unsigned long long)onDisk);
    // The reader narrows F32 -> BF16. This is the irreducible error the
    // downstream logit oracle inherits; it is measured, not claimed.
    std::fprintf(stderr, "READER_BF16_MAX_ABS_ERR=%.6g\n", globalBf16MaxAbsErr);

    std::fprintf(stderr, "FAILURES=%zu\n", failures.size());
    for (const std::string& f : failures) std::fprintf(stderr, "  FAIL=%s\n", f.c_str());

    if (failures.empty()) {
        // COMMIT. The container becomes visible under its real name only now,
        // after the census and every verdict check above has passed. A converter
        // that dies before this point leaves "<path>.building" and no artifact.
        if (!MoveFileExW(buildingPathW.c_str(), nqbPathW.c_str(),
                         MOVEFILE_REPLACE_EXISTING)) {
            std::fprintf(stderr, "FAIL=promote_rename winerr=%lu\n", GetLastError());
            std::remove(buildingPath.c_str());
            std::fprintf(stderr, "VERDICT=FAIL\n");
            return 2;
        }
        std::fprintf(stderr, "PROMOTED_TO=%s\n", nqbPath);
        std::fprintf(stderr, "TRANSACTIONAL_WRITE=1\n");
        std::fprintf(stderr, "VERDICT=PASS\n");
        return 0;
    }
    std::fprintf(stderr, "VERDICT=FAIL\n");
    std::fprintf(stderr, "ARTIFACT_PROMOTED=0 building_file_retained=%s\n",
                 buildingPath.c_str());
    return 2;   // 2 = "a gate that ran and failed", distinct from 1 = crash
}
