// deep2_canonical_inference_probe.cpp
// RAWRXD_DEEP2_BATCH5_CANONICAL_INFERENCE_001
//
// Drives the real 940 MB Qwen2/Q6_K model through the production path:
//
//   loadModel -> ModelRegistry::admit -> weight bind -> context
//   -> tokenize -> prefill -> decode -> logits -> sample -> token
//
// No synthetic forward. No fixture architecture. Every field printed is either
// an observed value or a comparison against an observed counter.
//
// The first measured failure is the point of this probe: it names the boundary
// that broke rather than collapsing into a single pass/fail.

#include "Deep2Engine.h"
#include "Deep2ModelRegistry.hpp"

#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

using Deep2::Deep2Engine;

namespace {

const char* statusName(Deep2::GenerationStatus s) {
    switch (s) {
        case Deep2::GenerationStatus::Completed:      return "Completed";
        case Deep2::GenerationStatus::EndOfSequence:  return "EndOfSequence";
        case Deep2::GenerationStatus::Cancelled:      return "Cancelled";
        case Deep2::GenerationStatus::InvalidInput:   return "InvalidInput";
        case Deep2::GenerationStatus::ForwardFailure: return "ForwardFailure";
        case Deep2::GenerationStatus::InternalError:  return "InternalError";
    }
    return "Unknown";
}

// Measures finiteness over the real logits buffer. Reports how many values were
// examined so a PASS cannot be produced by inspecting nothing.
struct LogitsReport {
    std::size_t examined = 0;
    std::size_t nonFinite = 0;
    float min = 0.0f;
    float max = 0.0f;
    bool allFinite() const { return examined > 0 && nonFinite == 0; }
};

LogitsReport measureLogits(const std::vector<float>& v) {
    LogitsReport r;
    if (v.empty()) return r;
    r.examined = v.size();
    float lo = v[0], hi = v[0];
    for (float f : v) {
        if (!std::isfinite(f)) { ++r.nonFinite; continue; }
        if (f < lo) lo = f;
        if (f > hi) hi = f;
    }
    r.min = lo;
    r.max = hi;
    return r;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: deep2_canonical_inference_probe <model.gguf>\n");
        return 2;
    }
    const std::string path = argv[1];
    const std::string prompt = (argc > 2) ? argv[2] : "2+2=";

    // ---- boundary 1: load + admission -------------------------------------
    Deep2Engine engine;
    engine.setVulkanStrictNoCpuFallback(false);

    Deep2::ModelLoadDiag diag;
    const bool loaded = engine.loadModel(path, &diag);
    std::printf("MODEL_LOADED=%d\n", loaded ? 1 : 0);
    std::printf("LOAD_STAGE=%s\n",
                diag.stageName.empty() ? "(none)" : diag.stageName.c_str());
    std::printf("LOAD_MESSAGE=%s\n",
                diag.message.empty() ? "(none)" : diag.message.c_str());

    if (!loaded) {
        std::printf("FAIL_BOUNDARY=LOAD_OR_ADMISSION\n");
        std::printf("CANONICAL_INFERENCE=FAIL\n");
        return 1;
    }

    const std::string arch = engine.modelArchitecture();
    std::printf("ARCH=%s\n", arch.c_str());
    std::printf("HIDDEN_DIM=%zu\n", engine.hiddenDim());
    std::printf("VOCAB_SIZE=%zu\n", engine.vocabSize());
    std::printf("NUM_LAYERS=%zu\n", engine.numLayers());

    // ---- boundary 2: tokenizer --------------------------------------------
    const std::vector<int> promptTokens = engine.tokenize(prompt);
    std::printf("TOKENIZER_READY=%d\n", promptTokens.empty() ? 0 : 1);
    std::printf("PROMPT_TOKEN_COUNT=%zu\n", promptTokens.size());
    if (promptTokens.empty()) {
        std::printf("FAIL_BOUNDARY=TOKENIZER\n");
        std::printf("CANONICAL_INFERENCE=FAIL\n");
        return 1;
    }

    // ---- boundary 3: canonical streaming generation --------------------------
    //
    // ORDERING IS LOAD-BEARING. generateStream owns the full prefill+decode
    // sequence and expects the KV cache at the start position. Driving
    // decodeContinuousOne first advances kvCache->currentLength() past 0, and
    // generateStream's prefill then fails at token 0 with
    // "attention: sequence/KV position mismatch" — which is stale state in the
    // CALLER, not a defect in the engine. So the canonical stream runs first, on
    // a cache the probe has not touched.
    Deep2::GenerationOptions opts;
    opts.maxTokens = 8;
    opts.temperature = 0.0f;   // greedy: deterministic, seed-independent
    opts.topK = 1;

    std::vector<int32_t> emitted;
    std::string text;
    const Deep2::GenerationResult gr = engine.generateStream(
        prompt, opts,
        [&emitted, &text](int32_t tokenId, const std::string& piece) -> bool {
            emitted.push_back(tokenId);
            text += piece;
            return true;   // never cancel early; let the full budget run
        });

    std::printf("STREAM_STATUS=%s\n", statusName(gr.status));
    std::printf("STREAM_COMPLETED=%d\n", gr.completed ? 1 : 0);
    std::printf("STREAM_CANCELLED=%d\n", gr.cancelled ? 1 : 0);
    std::printf("STREAM_FAILURE_DETAIL=%s\n",
                gr.failureDetail.empty() ? "(none)" : gr.failureDetail.c_str());
    std::printf("STREAM_GENERATED_TOKENS=%llu\n",
                static_cast<unsigned long long>(gr.generatedTokens));
    std::printf("STREAM_CALLBACK_TOKENS=%zu\n", emitted.size());
    std::printf("STREAM_TEXT_BYTES=%zu\n", text.size());

    std::size_t outOfRange = 0;
    for (int32_t t : emitted) {
        if (t < 0 || static_cast<std::size_t>(t) >= engine.vocabSize()) ++outOfRange;
    }
    std::printf("STREAM_TOKENS_OUT_OF_VOCAB=%zu\n", outOfRange);

    // Print the decoded text so the receipt shows LANGUAGE, not just a token
    // count. Eight valid token ids could still be noise; coherent output cannot.
    // Non-printable bytes are escaped so the receipt stays line-oriented.
    {
        std::string escaped;
        for (unsigned char ch : text) {
            if (ch == '\n')      escaped += "\\n";
            else if (ch == '\r') escaped += "\\r";
            else if (ch == '\t') escaped += "\\t";
            else if (ch < 0x20 || ch == 0x7f) {
                char buf[8];
                std::snprintf(buf, sizeof buf, "\\x%02X", ch);
                escaped += buf;
            } else {
                escaped.push_back(static_cast<char>(ch));
            }
        }
        std::printf("STREAM_TEXT=[%s]\n", escaped.c_str());
    }

    const bool streamOk =
        (gr.status == Deep2::GenerationStatus::Completed ||
         gr.status == Deep2::GenerationStatus::EndOfSequence) &&
        gr.generatedTokens >= 1 &&
        emitted.size() >= 1 &&
        outOfRange == 0;

    // ---- boundary 4: canonical single-step decode, on a fresh engine --------
    //
    // A second engine instance so the decode measurement cannot inherit KV
    // state from the stream above. forwardSpeculativeBlock is NOT used: it is a
    // speculative-decode primitive requiring kvCache->currentLength() >=
    // basePos+count, so calling it at basePos=0 on a fresh cache always fails.
    // decodeContinuousOne is the primitive Deep2Engine.h names as the only live
    // decode path: embed -> forwardTokenAllLayers -> computeLogits -> sampleToken.
    Deep2Engine engine2;
    engine2.setVulkanStrictNoCpuFallback(false);
    Deep2::ModelLoadDiag diag2;
    const bool loaded2 = engine2.loadModel(path, &diag2);
    std::printf("DECODE_ENGINE_LOADED=%d\n", loaded2 ? 1 : 0);

    bool decode0Ok = false;
    bool logitsOk = false;
    bool tokenValid = false;
    int sampled = -1;

    if (loaded2) {
        Deep2Engine::DecodeCursor cursor;
        const bool cursorOk = engine2.initializeDecodeCursor(cursor);
        std::printf("DECODE_CURSOR_READY=%d\n", cursorOk ? 1 : 0);
        if (cursorOk) {
            cursor.pendingToken = promptTokens.back();
            cursor.pendingForward = true;

            const Deep2Engine::DecodeOneResult d1 =
                engine2.decodeContinuousOne(cursor);
            std::printf("DECODE_0_KIND=%d\n", static_cast<int>(d1.kind));
            std::printf("DECODE_0_TOKEN=%d\n", d1.token);
            std::printf("DECODE_0_ERROR=%s\n",
                        d1.error.empty() ? "(none)" : d1.error.c_str());
            std::printf("DECODE_0_SEQ=%zu\n", cursor.seq);
            std::printf("DECODE_0_ROUTE=%d\n", static_cast<int>(cursor.lockedRoute));

            decode0Ok = (d1.kind != Deep2Engine::DecodeOneResult::Kind::Error);
            std::printf("DECODE_0_OK=%d\n", decode0Ok ? 1 : 0);

            // Finiteness over the engine's OWN logits buffer.
            const LogitsReport lr = measureLogits(cursor.logits);
            std::printf("LOGITS_EXAMINED=%zu\n", lr.examined);
            std::printf("LOGITS_NONFINITE=%zu\n", lr.nonFinite);
            std::printf("LOGITS_MIN=%.6f\n", static_cast<double>(lr.min));
            std::printf("LOGITS_MAX=%.6f\n", static_cast<double>(lr.max));
            logitsOk = lr.allFinite();
            std::printf("LOGITS_FINITE=%d\n", logitsOk ? 1 : 0);

            if (logitsOk) {
                sampled = engine2.sampleCommittedToken(cursor.logits.data());
                tokenValid = (sampled >= 0) &&
                    (static_cast<std::size_t>(sampled) < engine2.vocabSize());
            }
            std::printf("SAMPLED_TOKEN_ID=%d\n", sampled);
            std::printf("TOKEN_ID_VALID=%d\n", tokenValid ? 1 : 0);
        }
    }

    // ---- verdict -----------------------------------------------------------
    const bool allOk = decode0Ok && logitsOk && tokenValid && streamOk;

    std::printf("REAL_GGUF=1\n");
    std::printf("REAL_WEIGHTS=%d\n", (loaded && loaded2) ? 1 : 0);
    std::printf("REAL_FORWARD=%d\n", decode0Ok ? 1 : 0);
    std::printf("GENERATED_TOKEN_COUNT=%llu\n",
                static_cast<unsigned long long>(gr.generatedTokens));
    std::printf("CANONICAL_INFERENCE=%s\n", allOk ? "PASS" : "FAIL");
    return allOk ? 0 : 1;
}