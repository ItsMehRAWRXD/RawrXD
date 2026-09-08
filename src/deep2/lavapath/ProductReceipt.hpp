#pragma once
/* Canonical PRODUCT_RUN receipt — one for all adapters. ≤99 lines. */
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
    std::fprintf(f, "PRODUCT_PASS=%d\n", r.productPass);
    if (!r.productPass)
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
    return (r.modelResolved && r.modelOpen && r.runtimeReady && r.streamEnter &&
            r.firstToken && r.generatedTokens > 0 && r.streamFinished &&
            r.exitReason && std::strcmp(r.exitReason, "COMPLETE") == 0)
               ? 1
               : 0;
}

} // namespace rawr::product_run
