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

// Convenience: append a single tensor to an .nqb file stream.
// Returns the absolute file offset of the tensor's DATA (not the footer).
static uint64_t appendTensor(std::ofstream& out,
                             const Deep2::Nanof32TensorSpec& spec,
                             const std::vector<uint8_t>& payload) {
    uint64_t dataOffset = static_cast<uint64_t>(out.tellp());
    out.write(reinterpret_cast<const char*>(payload.data()),
              static_cast<std::streamsize>(payload.size()));

    Deep2::Nanof32BraidTensorFooter footer{};
    footer.magic       = Deep2::NANO_F32_BRAID_MAGIC;
    footer.quantType = spec.quant;
    footer.scaleMin  = spec.scaleMin;
    footer.scaleMax  = spec.scaleMax;
    footer.rows      = spec.rows;
    footer.cols      = spec.cols;
    footer.dataBytes = payload.size();
    footer.expertIndex = spec.expertIndex;
    std::snprintf(footer.name, sizeof footer.name, "%s", spec.name.c_str());

    out.write(reinterpret_cast<const char*>(&footer), sizeof footer);
    return dataOffset;
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
    // 3. Write .nqb header + arch meta
    // ----------------------------------------------------------------
    std::ofstream out(nqbPath, std::ios::binary);
    if (!out) {
        std::fprintf(stderr, "FAIL=nqb_open_write path=%s\n", nqbPath);
        return 1;
    }

    Deep2::Nanof32BraidHeader hdr{};
    hdr.magic    = Deep2::NANO_F32_BRAID_MAGIC;
    hdr.version  = Deep2::NANO_F32_BRAID_VERSION;
    hdr.numTensors = 0; // measured at finalisation, never declared
    hdr.bitsPerWeight = 0; // dense F32 is not "bits per weight"
    // vocabSectionOffset and vocabSectionBytes filled later if vocab present
    out.write(reinterpret_cast<const char*>(&hdr), sizeof hdr);
    out.write(reinterpret_cast<const char*>(&archMeta), sizeof archMeta);
    // hdr.numTensors is deliberately left 0 here and filled in at finalisation
    // from the number of tensors ACTUALLY written.  Declaring it from the GGUF
    // tensor count would let a skipped tensor leave a header that lies.

    // ----------------------------------------------------------------
    // 4. Vocabulary section (if extracted from GGUF) — placed BEFORE
    //    the first tensor so reverse tensor traversal from EOF works.
    // ----------------------------------------------------------------
    std::vector<uint8_t> vocabBytes;
    if (hasVocab) {
        vocabBytes = Deep2::nanof32EncodeVocabSection(vocabSpec);
        if (!vocabBytes.empty()) {
            uint64_t vocabOffset = static_cast<uint64_t>(out.tellp());
            out.write(reinterpret_cast<const char*>(vocabBytes.data()),
                      static_cast<std::streamsize>(vocabBytes.size()));
            hdr.vocabSectionOffset = vocabOffset;
            hdr.vocabSectionBytes  = vocabBytes.size();
            std::fprintf(stderr, "VOCAB_SECTION=written entries=%zu bytes=%zu\n",
                         vocabSpec.tokens.size(), vocabBytes.size());
        } else {
            std::fprintf(stderr, "WARN=vocab_encode_failed\n");
            hdr.vocabSectionOffset = 0;
            hdr.vocabSectionBytes  = 0;
        }
    } else {
        hdr.vocabSectionOffset = 0;
        hdr.vocabSectionBytes  = 0;
    }

    uint64_t firstTensorOffset = static_cast<uint64_t>(out.tellp());

    // ----------------------------------------------------------------
    // 5. Enumerate all GGUF tensors, dequantise, append as dense F32
    // ----------------------------------------------------------------
    size_t convertedCount = 0;
    size_t skippedCount   = 0;
    std::vector<float>     floatBuf;
    std::vector<uint8_t> payload;
    uint64_t lastDataOffset = 0;

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

        const uint64_t dataOff = appendTensor(out, spec, payload);
        lastDataOffset = dataOff;
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
    // 6. Finalise header with MEASURED tensor count and byte coverage
    // ----------------------------------------------------------------
    uint64_t fileSize = static_cast<uint64_t>(out.tellp());
    hdr.numTensors   = static_cast<uint32_t>(convertedCount);
    hdr.fileSize        = fileSize;
    hdr.tensorDirOffset = fileSize - sizeof(Deep2::Nanof32BraidTensorFooter); // last footer
    // RAWRXD_GGUF_TO_NQB_CONVERTER_AUTHORITY_001 -- header completeness.
    //
    // paramCount and bitsPerWeight were both left at 0. The reader reports
    // both, so a converted real model announced itself as:
    //     [NQBRAID] OPEN: params=0 bitsPerWeight=0.00 tensors=201
    // which is a header that lies about its own contents. paramCount is
    // measured from the tensors actually written (not from the GGUF metadata,
    // so a skip cannot inflate it).
    //
    // RAWRXD_NQB_BITS_PER_WEIGHT_UNIT_001 -- CORRECTION. This previously read:
    //     "the field is documented as 115 == 1.15 bits/weight, so 32 bits is 320"
    // That drops a factor of 100. 115 hundredths == 1.15, therefore 32.00 bits
    // is 3200, not 320. The mistake was made by "fixing" a zero with a number
    // that had never been checked against the unit, and it was invisible to every
    // reader because the reader only prints the field. It was caught by
    // RAWRXD_NQB_PRODUCTION_REOPEN_001, which compares the decoded value
    // against the payload width it measured in the same pass:
    //     EXPECTED_BITS_PER_WEIGHT=32  DECODED_BITS_PER_WEIGHT=3.2
    // The value is derived from sizeof() rather than typed, so the next unit
    // change cannot silently produce another plausible wrong constant.
    hdr.paramCount    = globalParamCount;
    hdr.bitsPerWeight = static_cast<uint32_t>(sizeof(float) * 8 * 100);  // 3200 == 32.00
    (void)lastDataOffset;

    out.seekp(0, std::ios::beg);
    out.write(reinterpret_cast<const char*>(&hdr), sizeof hdr);
    out.close();

    // On-disk size must equal what the header claims, or the reverse reader's
    // backward walk starts at the wrong offset and silently reads garbage.
    uint64_t onDisk = 0;
    {
        std::ifstream probe(nqbPath, std::ios::binary | std::ios::ate);
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
    if (hdr.paramCount == 0)             failures.push_back("HEADER_PARAM_COUNT_ZERO");
    if (hdr.bitsPerWeight == 0)          failures.push_back("HEADER_BITS_PER_WEIGHT_ZERO");
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
        std::fprintf(stderr, "VERDICT=PASS\n");
        return 0;
    }
    std::fprintf(stderr, "VERDICT=FAIL\n");
    return 2;   // 2 = "a gate that ran and failed", distinct from 1 = crash
}
