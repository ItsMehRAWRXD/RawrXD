// DecodeFeedbackProbe.hpp — SECOND_MODEL decode-boundary instrumentation
#pragma once
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace Deep2 {

struct DecodeFeedbackWitness {
    int enabled = 0;
    int firstTokenId = -1;
    char firstTokenText[64]{};
    int next16Ids[16]{};
    int next16Count = 0;
    char next16Text[256]{};
    int eosId = -1;
    int bosId = -1;
    int unkId = -1;
    char tokenizerModel[64]{};
    int feedbackChecks = 0;
    int feedbackMismatches = 0;
    int feedbackTokenMatch = 1; // 1 until a mismatch
    int pendingFeedToken = -1;  // sampled at N; must equal feed at N+1
    int repeatedTokenId = -1;
    int repeatRunLength = 0;
    int maxRepeatRun = 0;
    int lastSampled = -1;
};

inline DecodeFeedbackWitness& DecodeFeedback() {
    static DecodeFeedbackWitness w;
    return w;
}

inline bool DecodeFeedbackWanted() {
#ifdef _WIN32
    const char* e = std::getenv("RAWRXD_DECODE_FEEDBACK");
#else
    const char* e = getenv("RAWRXD_DECODE_FEEDBACK");
#endif
    return e && e[0] == '1';
}

inline void DecodeFeedbackReset() {
    DecodeFeedback() = DecodeFeedbackWitness{};
    DecodeFeedback().enabled = DecodeFeedbackWanted() ? 1 : 0;
}

inline void DecodeFeedbackNoteSpecials(int eos, int bos, int unk,
                                       const char* tokModel) {
    auto& w = DecodeFeedback();
    if (!w.enabled) return;
    w.eosId = eos;
    w.bosId = bos;
    w.unkId = unk;
    if (tokModel) {
        std::strncpy(w.tokenizerModel, tokModel, sizeof(w.tokenizerModel) - 1);
    }
}

inline void DecodeFeedbackOnFeed(int fedToken) {
    auto& w = DecodeFeedback();
    if (!w.enabled) return;
    if (w.pendingFeedToken < 0) return;
    w.feedbackChecks++;
    if (fedToken != w.pendingFeedToken) {
        w.feedbackMismatches++;
        w.feedbackTokenMatch = 0;
    }
}

inline void DecodeFeedbackOnSample(int tokenId, const std::string& piece) {
    auto& w = DecodeFeedback();
    if (!w.enabled) return;
    w.pendingFeedToken = tokenId;
    if (w.firstTokenId < 0) {
        w.firstTokenId = tokenId;
        std::snprintf(w.firstTokenText, sizeof(w.firstTokenText), "%s",
                      piece.c_str());
    } else if (w.next16Count < 16) {
        w.next16Ids[w.next16Count++] = tokenId;
        if (piece.size() + std::strlen(w.next16Text) < sizeof(w.next16Text) - 1)
            std::strncat(w.next16Text, piece.c_str(),
                         sizeof(w.next16Text) - std::strlen(w.next16Text) - 1);
    }
    if (tokenId == w.lastSampled) {
        w.repeatRunLength++;
        if (w.repeatRunLength > w.maxRepeatRun) {
            w.maxRepeatRun = w.repeatRunLength;
            w.repeatedTokenId = tokenId;
        }
    } else {
        w.repeatRunLength = 1;
        w.lastSampled = tokenId;
    }
}

inline void DecodeFeedbackDump(FILE* out) {
    auto& w = DecodeFeedback();
    if (!out) out = stderr;
    std::fprintf(out, "FIRST_TOKEN_ID=%d\n", w.firstTokenId);
    std::fprintf(out, "FIRST_TOKEN_TEXT=%s\n", w.firstTokenText);
    std::fprintf(out, "NEXT_16_TOKEN_IDS=");
    for (int i = 0; i < w.next16Count; ++i) {
        if (i) std::fputc(',', out);
        std::fprintf(out, "%d", w.next16Ids[i]);
    }
    std::fputc('\n', out);
    std::fprintf(out, "NEXT_16_TOKEN_TEXT=%s\n", w.next16Text);
    std::fprintf(out, "EOS_ID=%d\n", w.eosId);
    std::fprintf(out, "BOS_ID=%d\n", w.bosId);
    std::fprintf(out, "UNK_ID=%d\n", w.unkId);
    std::fprintf(out, "TOKENIZER_MODEL=%s\n", w.tokenizerModel);
    std::fprintf(out, "FEEDBACK_TOKEN_MATCH=%d\n", w.feedbackTokenMatch);
    std::fprintf(out, "FEEDBACK_CHECKS=%d\n", w.feedbackChecks);
    std::fprintf(out, "FEEDBACK_MISMATCHES=%d\n", w.feedbackMismatches);
    std::fprintf(out, "REPEATED_TOKEN_ID=%d\n", w.repeatedTokenId);
    std::fprintf(out, "REPEAT_RUN_LENGTH=%d\n", w.maxRepeatRun);
}

} // namespace Deep2
