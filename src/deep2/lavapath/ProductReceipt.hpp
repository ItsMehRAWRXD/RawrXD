#pragma once
/* Canonical PRODUCT_RUN receipt — one for all adapters. ≤99 lines.
   PRODUCT_PASS = PromoteReady tetrad; PROMOTE=0 until climb law opens;
   MULTI_FAMILY = next independent gate (≠ TinyLlama R25 ProductOpen). */
#include "Deep2ProductGate.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace rawr::product_run {

struct Result {
    int modelResolved = 0;
    int modelOpen = 0;
    int tokenizerReady = 0;
    int runtimeReady = 0;
    int streamEnter = 0;
    int firstToken = 0;
    int streamFinished = 0;
    uint32_t generatedTokens = 0;
    uint64_t wallNs = 0;
    uint64_t textBytes = 0;
    int productPass = 0;
    const char* failedStage = "NONE";
    const char* failedOwner = "NONE";
    const char* exitReason = "INCOMPLETE";
    std::string text;
    std::string modelPath;
    std::string modelName;
};

inline void EmitReceipt(FILE* f, const Result& r) noexcept {
    if (!f) f = stderr;
    const int commit =
        (r.generatedTokens > 0 && r.streamFinished) ? 1 : 0;
    const int ready = Deep2::product_gate::PromoteReady(
        r.modelOpen, r.streamEnter, (uint64_t)r.generatedTokens, commit);
    std::fprintf(f, "PRODUCT_RUN\n");
    std::fprintf(f, "MODEL_RESOLVED=%d\nMODEL_OPEN=%d\n",
                 r.modelResolved, r.modelOpen);
    std::fprintf(f, "TOKENIZER_READY=%d\nKV_READY=%d\nRUNTIME_READY=%d\n",
                 r.tokenizerReady, r.runtimeReady, r.runtimeReady);
    std::fprintf(f, "STREAM_ENTER=%d\nFIRST_TOKEN=%d\n",
                 r.streamEnter, r.firstToken);
    std::fprintf(f, "GENERATED_TOKENS=%u\nLAST_TOKEN=%u\n",
                 r.generatedTokens, r.generatedTokens);
    std::fprintf(f, "STREAM_FINISHED=%d\nEXIT_REASON=%s\n",
                 r.streamFinished, r.exitReason);
    std::fprintf(f, "PRODUCT_OPEN_PASS=%d\nSESSION_ENTER_PASS=%d\n"
                    "TOKEN_COMMIT_PASS=%d\nPRODUCT_PASS=%d\nPROMOTE=0\n"
                    "FINAL_READY_GATE=PRODUCT_OPEN_PASS&&SESSION_ENTER_PASS&&"
                    "GENERATED_TOKENS>0&&TOKEN_COMMIT_PASS\n"
                    "NEXT_INDEPENDENT_GATE=MULTI_FAMILY\n"
                    "NOTE=TINYLLAMA_R25_PRODUCTOPEN_NE_MULTI_FAMILY\n",
                 r.modelOpen, r.streamEnter, commit, ready);
    if (!ready)
        std::fprintf(f, "FAILED_STAGE=%s\nFAILED_OWNER=%s\n",
                     r.failedStage, r.failedOwner);
    if (!r.modelPath.empty())
        std::fprintf(f, "PATH=%s\n", r.modelPath.c_str());
    if (!r.modelName.empty())
        std::fprintf(f, "MODEL=%s\n", r.modelName.c_str());
    std::fflush(f);
}

inline int FunctionalComplete(const Result& r) noexcept {
    /* COMPLETE only — CANCELLED must not count as product pass. */
    if (!r.exitReason || std::strcmp(r.exitReason, "COMPLETE") != 0) return 0;
    const int commit = (r.generatedTokens > 0 && r.streamFinished) ? 1 : 0;
    return Deep2::product_gate::PromoteReady(r.modelOpen, r.streamEnter,
                                             (uint64_t)r.generatedTokens,
                                             commit);
}

} // namespace rawr::product_run
