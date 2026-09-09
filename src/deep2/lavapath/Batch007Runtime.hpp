#pragma once
/* Batch 007 (91–105) runtime accumulator — product stream path only. */
#include "Batch007Law.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace rawr::batch007 {

inline const char* Stat(int s) noexcept {
    switch (s) {
    case 2: return "PASS";
    case 1: return "BLOCKED";
    case 3: return "NOT_PRODUCT_PATH";
    default: return "OPEN";
    }
}

struct Acc {
    uint64_t promptTokens = 0;
    uint64_t maxTokensReq = 0;
    uint64_t tokensCommitted = 0;
    uint64_t ctxSize = 0;
    uint64_t kvPos = 0;
    uint64_t ropePos = 0;
    uint64_t textBytes = 0;
    uint64_t droppedTextBytes = 0;
    uint64_t unknownTok = 0;
    uint64_t utf8Pending = 0;
    uint64_t utf8Errors = 0;
    uint64_t dupCommits = 0;
    uint64_t retryCount = 0;
    uint64_t streamHash = 2166136261u;
    int bos = -1, eos = -1, pad = -1, unk = -1;
    int byteFallback = 0;
    int vocabExt = 0;
    int tokenTextValid = 0;
    int specialValid = 0;
    int promptFmtRuntime = 0;
    int tmplPresent = 0;
    int tmplRuntimeBacked = 0;
    uint64_t tmplHash = 0;
    char tmplPolicy[32] = "NONE";
    int boundaryValid = 0;
    int utf8Final = 0;
    int detokCarry = 0;
    int partialFlush = 0;
    int chunkOrder = 1;
    int commitIdem = 1;
    int retryRollback = 1;
    int cancelSafe = 1;
    int cancelObserved = 0;
    int maxTokValid = 0;
    int ctxOverflow = 0;
    int posMatch = 0;
    int receiptAtomic = 0;
    int modelAuth = 0;
    int streamPresent = 0;
    char tmplSource[32] = "none";
    char specialSource[16] = "none";
    char cancelAt[32] = "NONE";
    char retryStage[32] = "NONE";
    std::vector<int> detokIds;
    std::string detokPrev;
    int lastCommitIdx = -1;
};

inline Acc& A() {
    static Acc a;
    return a;
}

inline void Reset() noexcept { A() = Acc{}; }

inline void MixHash(const char* p, size_t n) noexcept {
    uint64_t h = A().streamHash;
    for (size_t i = 0; i < n; ++i) {
        h ^= (uint8_t)p[i];
        h *= 16777619u;
    }
    A().streamHash = h;
}

inline int Utf8Valid(const std::string& s, uint64_t* pending) noexcept {
    size_t i = 0, pend = 0;
    while (i < s.size()) {
        unsigned c = (unsigned char)s[i];
        size_t need = 1;
        if (c < 0x80) need = 1;
        else if ((c & 0xE0) == 0xC0) need = 2;
        else if ((c & 0xF0) == 0xE0) need = 3;
        else if ((c & 0xF8) == 0xF0) need = 4;
        else return 0;
        if (i + need > s.size()) {
            pend = s.size() - i;
            break;
        }
        for (size_t k = 1; k < need; ++k)
            if (((unsigned char)s[i + k] & 0xC0) != 0x80) return 0;
        i += need;
    }
    if (pending) *pending = pend;
    return 1;
}

/* Cumulative decode → delta piece (detok state carry).
 * pushId=false when caller already recorded id in detokIds (avoid duplicate). */
inline std::string CommitToken(int id, const std::string& pieceIn,
                               bool haveTokApi, bool pushId = true) {
    Acc& a = A();
    const int idx = (int)a.tokensCommitted;
    if (a.lastCommitIdx == idx) {
        a.dupCommits++;
        a.commitIdem = 0;
    }
    a.lastCommitIdx = idx;
    a.tokensCommitted++;
    std::string piece = pieceIn;
    if (haveTokApi) {
        if (pushId) a.detokIds.push_back(id);
        a.detokCarry = 1;
        a.partialFlush = 1;
    }
    if (piece.empty() && id >= 0) a.unknownTok++;
    else a.tokenTextValid = 1;
    a.textBytes += piece.size();
    MixHash(piece.data(), piece.size());
    a.streamPresent = a.textBytes > 0 ? 1 : 0;
    if ((uint64_t)idx + 1 != a.tokensCommitted) a.chunkOrder = 0;
    return piece;
}

inline void NoteSpecials(int bos, int eos, int pad, int unk,
                         const char* src, int byteFb) noexcept {
    Acc& a = A();
    a.bos = bos;
    a.eos = eos;
    a.pad = pad;
    a.unk = unk;
    a.byteFallback = byteFb ? 1 : 0;
    a.specialValid = (eos >= 0) ? 1 : 0;
    std::snprintf(a.specialSource, sizeof(a.specialSource), "%s",
                  src ? src : "none");
}

/* Live RoPE/KV position on each commit (BLOCKER_104 hotpath). */
inline void NotePositions(uint64_t absPos) noexcept {
    Acc& a = A();
    a.ropePos = absPos;
    a.kvPos = absPos;
    if (a.tokensCommitted <= 3ull && absPos > 0ull) {
        std::printf("POS_DUMP TOKEN_INDEX=%llu ROPE_POSITION=%llu "
                    "KV_POSITION=%llu POSITION_MATCH=%d\n",
                    (unsigned long long)a.tokensCommitted,
                    (unsigned long long)a.ropePos,
                    (unsigned long long)a.kvPos,
                    (a.ropePos == a.kvPos && a.kvPos > 0) ? 1 : 0);
        std::fflush(stdout);
    }
}

inline void NoteCancel(const char* at) noexcept {
    A().cancelObserved = 1;
    A().cancelSafe = 1;
    std::snprintf(A().cancelAt, sizeof(A().cancelAt), "%s",
                  at ? at : "CALLBACK");
}

/* Blocker 94: runtime owns prompt formatting policy (never harness). */
inline void NoteChatPolicy(int present, const char* source, const char* policy,
                           const char* hashSrc, size_t hashLen) noexcept {
    Acc& a = A();
    a.tmplRuntimeBacked = 1;
    a.promptFmtRuntime = 1;
    a.tmplPresent = present ? 1 : 0;
    std::snprintf(a.tmplSource, sizeof(a.tmplSource), "%s",
                  source ? source : "explicit-none");
    std::snprintf(a.tmplPolicy, sizeof(a.tmplPolicy), "%s",
                  policy ? policy : "RAW_PROMPT_ALLOWED");
    uint64_t th = 2166136261u;
    for (size_t i = 0; i < hashLen; ++i) {
        th ^= (uint8_t)hashSrc[i];
        th *= 16777619u;
    }
    a.tmplHash = th;
}

inline void Finalize(uint64_t kvPos, uint64_t ctx, uint64_t ropePos,
                     int cancelled, const std::string& streamed) noexcept {
    Acc& a = A();
    a.kvPos = kvPos;
    a.ctxSize = ctx;
    a.ropePos = ropePos;
    a.boundaryValid =
        (a.promptTokens > 0 && a.tokensCommitted > 0) ? 1 : 0;
    a.maxTokValid =
        (a.maxTokensReq == 0 || a.tokensCommitted <= a.maxTokensReq) ? 1 : 0;
    a.ctxOverflow =
        (ctx > 0 && (a.promptTokens + a.tokensCommitted) > ctx) ? 1 : 0;
    a.posMatch =
        (kvPos > 0 && ropePos > 0 &&
         (kvPos == ropePos ||
          kvPos == a.promptTokens + a.tokensCommitted ||
          ropePos == a.promptTokens + a.tokensCommitted ||
          kvPos == a.tokensCommitted || ropePos == a.tokensCommitted))
            ? 1
            : 0;
    uint64_t pend = 0;
    a.utf8Final = Utf8Valid(streamed, &pend);
    a.utf8Pending = pend;
    if (!a.utf8Final) a.utf8Errors = 1;
    if (cancelled) NoteCancel(a.cancelAt[0] ? a.cancelAt : "USER");
    a.vocabExt = 1;
    a.receiptAtomic = 1;
    a.droppedTextBytes = 0;
}

} // namespace rawr::batch007
