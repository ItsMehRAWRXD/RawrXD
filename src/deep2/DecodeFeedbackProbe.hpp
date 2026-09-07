// DecodeFeedbackProbe.hpp — U08 decode-boundary instrumentation
#pragma once
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>

namespace Deep2 {

struct DecodeStepWitness {
    int step = -1;
    int argmax = -1;
    int tokenId = -1;
    int tokenInVocab = 0;
    int logitsFinite = 0;
    float logitMax = 0.f;
    float logitMin = 0.f;
    int visibleBytes = 0;
    uint64_t logitsFnv = 0;
    uint64_t hiddenFnv = 0;
    float hiddenNorm = 0.f;
    int kvLen = -1;
    int pos = -1;
    char pieceText[48]{};
    char pieceHex[96]{};
};

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
    int feedbackTokenMatch = 1;
    int pendingFeedToken = -1;
    int repeatedTokenId = -1;
    int repeatRunLength = 0;
    int maxRepeatRun = 0;
    int lastSampled = -1;
    int vocabSize = 0;
    int specialCount = 0;
    int nonzeroIds = 0;
    int inVocabCount = 0;
    int sampleTotal = 0;
    int emptyPieceCount = 0;
    int argmaxChanged = 0;
    int sampleNeqArgmax = 0;
    int lastArgmax = -1;
    int stepCount = 0;
    DecodeStepWitness steps[32]{};
    // Prefill-first-logit localization (U08)
    uint64_t logitsFnv0 = 0;
    int top5Ids[5]{};
    float top5Logits[5]{};
    int top5Count = 0;
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
                                       const char* tokModel, int vocab = 0) {
    auto& w = DecodeFeedback();
    if (!w.enabled) return;
    w.eosId = eos;
    w.bosId = bos;
    w.unkId = unk;
    w.vocabSize = vocab;
    if (tokModel)
        std::strncpy(w.tokenizerModel, tokModel, sizeof(w.tokenizerModel) - 1);
}

inline void DecodeFeedbackOnFeed(int fedToken) {
    auto& w = DecodeFeedback();
    if (!w.enabled || w.pendingFeedToken < 0) return;
    w.feedbackChecks++;
    if (fedToken != w.pendingFeedToken) {
        w.feedbackMismatches++;
        w.feedbackTokenMatch = 0;
    }
}

inline void DecodeFeedbackOnLogits(int step, const float* logits, size_t nVocab) {
    auto& w = DecodeFeedback();
    if (!w.enabled || step < 0 || step >= 32 || !logits || nVocab == 0) return;
    w.vocabSize = (int)nVocab;
    auto& s = w.steps[step];
    s.step = step;
    s.logitMax = logits[0];
    s.logitMin = logits[0];
    s.argmax = 0;
    s.logitsFinite = 1;
    uint64_t fnv = 14695981039346656037ull;
    for (size_t i = 0; i < nVocab; ++i) {
        float v = logits[i];
        uint32_t bits = 0;
        std::memcpy(&bits, &v, sizeof(bits));
        fnv ^= bits;
        fnv *= 1099511628211ull;
        if (!std::isfinite(v)) s.logitsFinite = 0;
        if (v > s.logitMax) {
            s.logitMax = v;
            s.argmax = (int)i;
        }
        if (v < s.logitMin) s.logitMin = v;
    }
    s.logitsFnv = fnv;
    if (w.lastArgmax >= 0 && s.argmax != w.lastArgmax) w.argmaxChanged++;
    w.lastArgmax = s.argmax;

    // First post-prefill logits fingerprint + top-5 (U08 prefill divergence).
    if (step == 0) {
        uint64_t h = 14695981039346656037ull;
        for (size_t i = 0; i < nVocab; ++i) {
            uint32_t bits = 0;
            std::memcpy(&bits, &logits[i], sizeof(bits));
            h ^= bits;
            h *= 1099511628211ull;
        }
        w.logitsFnv0 = h;
        w.top5Count = 0;
        for (size_t i = 0; i < nVocab; ++i) {
            float v = logits[i];
            if (!std::isfinite(v)) continue;
            int slot = w.top5Count;
            if (slot < 5) {
                w.top5Ids[slot] = (int)i;
                w.top5Logits[slot] = v;
                w.top5Count++;
            } else {
                int worst = 0;
                for (int k = 1; k < 5; ++k)
                    if (w.top5Logits[k] < w.top5Logits[worst]) worst = k;
                if (v > w.top5Logits[worst]) {
                    w.top5Ids[worst] = (int)i;
                    w.top5Logits[worst] = v;
                }
            }
        }
        // Sort top5 descending
        for (int a = 0; a < w.top5Count; ++a)
            for (int b = a + 1; b < w.top5Count; ++b)
                if (w.top5Logits[b] > w.top5Logits[a]) {
                    std::swap(w.top5Logits[a], w.top5Logits[b]);
                    std::swap(w.top5Ids[a], w.top5Ids[b]);
                }
    }
}

inline void DecodeFeedbackFillPiece(DecodeStepWitness& s, const std::string& piece) {
    s.visibleBytes = 0;
    for (unsigned char c : piece)
        if (c >= 32 && c != 127) s.visibleBytes++;
    std::snprintf(s.pieceText, sizeof(s.pieceText), "%s", piece.c_str());
    size_t hx = 0;
    for (unsigned char c : piece) {
        if (hx + 3 >= sizeof(s.pieceHex)) break;
        std::snprintf(s.pieceHex + hx, sizeof(s.pieceHex) - hx, "%02X", c);
        hx += 2;
    }
}

inline void DecodeFeedbackOnSample(int tokenId, const std::string& piece) {
    auto& w = DecodeFeedback();
    if (!w.enabled) return;
    w.pendingFeedToken = tokenId;
    w.sampleTotal++;
    const int step = w.stepCount;
    if (tokenId != 0) w.nonzeroIds++;
    if (w.vocabSize > 0 && tokenId >= 0 && tokenId < w.vocabSize) w.inVocabCount++;
    if (piece.empty()) w.emptyPieceCount++;
    if (tokenId == w.eosId || tokenId == w.bosId || tokenId == w.unkId)
        w.specialCount++;
    if (step < 32) {
        auto& s = w.steps[step];
        s.step = step;
        s.tokenId = tokenId;
        s.tokenInVocab =
            (w.vocabSize > 0 && tokenId >= 0 && tokenId < w.vocabSize) ? 1 : 0;
        DecodeFeedbackFillPiece(s, piece);
        if (s.argmax >= 0 && tokenId != s.argmax) w.sampleNeqArgmax++;
        if (s.argmax < 0) s.argmax = tokenId;
        w.stepCount++;
    }
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

inline void DecodeFeedbackDumpSteps(FILE* out) {
    auto& w = DecodeFeedback();
    if (!out) out = stderr;
    for (int i = 0; i < w.stepCount && i < 32; ++i) {
        auto& s = w.steps[i];
        std::fprintf(out,
                     "STEP=%d ARGMAX=%d TOKEN_ID=%d TOKEN_IN_VOCAB=%d "
                     "LOGITS_FINITE=%d LOGIT_MAX=%.4f LOGIT_MIN=%.4f "
                     "VISIBLE_BYTES=%d TOKEN_PIECE_HEX=%s TOKEN_PIECE_TEXT=[%s]\n",
                     s.step, s.argmax, s.tokenId, s.tokenInVocab, s.logitsFinite,
                     s.logitMax, s.logitMin, s.visibleBytes, s.pieceHex,
                     s.pieceText);
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
    std::fprintf(out, "EOS_ID=%d BOS_ID=%d UNK_ID=%d\n", w.eosId, w.bosId,
                 w.unkId);
    std::fprintf(out, "TOKENIZER_MODEL=%s\n", w.tokenizerModel);
    std::fprintf(out, "FEEDBACK_TOKEN_MATCH=%d\n", w.feedbackTokenMatch);
    std::fprintf(out, "FEEDBACK_CHECKS=%d\n", w.feedbackChecks);
    std::fprintf(out, "REPEATED_TOKEN_ID=%d\n", w.repeatedTokenId);
    std::fprintf(out, "REPEAT_RUN_LENGTH=%d\n", w.maxRepeatRun);
    std::fprintf(out, "ARGMAX_CHANGED=%d\n", w.argmaxChanged);
    std::fprintf(out, "SAMPLE_NEQ_ARGMAX=%d\n", w.sampleNeqArgmax);
    std::fprintf(out, "TOKEN_IDS_NONZERO=%d\n", w.nonzeroIds);
    std::fprintf(out, "TOKEN_IDS_IN_VOCAB=%d\n",
                 w.sampleTotal ? (w.inVocabCount == w.sampleTotal) : 0);
    std::fprintf(out, "SAMPLE_TOTAL=%d\n", w.sampleTotal);
    std::fprintf(out, "EMPTY_PIECE_COUNT=%d\n", w.emptyPieceCount);
    std::fprintf(out, "SPECIAL_TOKEN_COUNT=%d\n", w.specialCount);
    DecodeFeedbackDumpSteps(out);
}

} // namespace Deep2
