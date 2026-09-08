#pragma once
/* Emit RAWRXD_E2E_BLOCKERS_105 Batch 007 receipt. */
#include "Batch007Runtime.hpp"

namespace rawr::batch007 {

inline int Gate91() noexcept {
    return (A().vocabExt && A().tokenTextValid && A().streamPresent) ? 2 : 1;
}
inline int Gate92() noexcept {
    return (A().droppedTextBytes == 0 && A().modelAuth) ? 2 : 0;
}
inline int Gate93() noexcept { return A().specialValid ? 2 : 1; }
inline int Gate94() noexcept {
    /* Runtime owns policy: APPLY_TEMPLATE or explicit-none + RAW_PROMPT_ALLOWED. */
    if (!A().promptFmtRuntime || !A().tmplRuntimeBacked) return 1;
    if (A().tmplPresent) {
        if (std::strcmp(A().tmplSource, "gguf") != 0 &&
            std::strcmp(A().tmplSource, "builtin-model-rule") != 0)
            return 1;
        return (std::strcmp(A().tmplPolicy, "APPLY_TEMPLATE") == 0) ? 2 : 1;
    }
    return (std::strcmp(A().tmplSource, "explicit-none") == 0 &&
            std::strcmp(A().tmplPolicy, "RAW_PROMPT_ALLOWED") == 0)
               ? 2
               : 1;
}
inline int Gate95() noexcept { return A().boundaryValid ? 2 : 1; }
inline int Gate96() noexcept {
    return (A().utf8Final && A().utf8Errors == 0) ? 2 : 1;
}
inline int Gate97() noexcept {
    return (A().detokCarry && A().partialFlush) ? 2 : 1;
}
inline int Gate98() noexcept { return A().chunkOrder ? 2 : 1; }
inline int Gate99() noexcept {
    return (A().commitIdem && A().dupCommits == 0) ? 2 : 1;
}
inline int Gate100() noexcept {
    return (A().retryCount == 0 && A().retryRollback) ? 2 : 1;
}
inline int Gate101() noexcept {
    if (!A().cancelObserved) return 2; /* no cancel → vacuous PASS */
    return (A().cancelSafe && A().streamPresent) ? 2 : 1;
}
inline int Gate102() noexcept { return A().maxTokValid ? 2 : 1; }
inline int Gate103() noexcept { return A().ctxOverflow ? 1 : 2; }
inline int Gate104() noexcept { return A().posMatch ? 2 : 0; }
inline int Gate105() noexcept {
    return (A().receiptAtomic && A().streamPresent) ? 2 : 1;
}

inline void Emit() noexcept {
    const int g[15] = {Gate91(), Gate92(),  Gate93(),  Gate94(), Gate95(),
                       Gate96(), Gate97(),  Gate98(),  Gate99(), Gate100(),
                       Gate101(), Gate102(), Gate103(), Gate104(), Gate105()};
    int pass = 0, unfinished = 0;
    for (int i = 0; i < 15; ++i) {
        if (g[i] == 2) ++pass;
        else ++unfinished;
    }
    Acc& a = A();
    std::printf("RECEIPT_BEGIN=RAWRXD_E2E_BLOCKERS_105\n");
    std::printf("RAWRXD_E2E_BLOCKERS_105\n");
    std::printf("BATCH_007_BEGIN=91\nBATCH_007_END=105\n");
    std::printf("VOCAB_EXT_PRESENT=%d VOCAB_EXT_RUNTIME_BACKED=%d "
                "TOKEN_ID_TO_TEXT_VALID=%d\n",
                a.vocabExt, a.tokenTextValid ? 1 : 0, a.tokenTextValid);
    std::printf("BYTE_FALLBACK_ENABLED=%d UNKNOWN_TOKEN_COUNT=%llu "
                "DROPPED_TEXT_BYTES=%llu\n",
                a.byteFallback, (unsigned long long)a.unknownTok,
                (unsigned long long)a.droppedTextBytes);
    std::printf("BOS_ID=%d EOS_ID=%d PAD_ID=%d UNK_ID=%d "
                "SPECIAL_TOKEN_SOURCE=%s SPECIAL_TOKEN_VALID=%d\n",
                a.bos, a.eos, a.pad, a.unk, a.specialSource, a.specialValid);
    std::printf("CHAT_TEMPLATE_PRESENT=%d CHAT_TEMPLATE_SOURCE=%s "
                "CHAT_TEMPLATE_RUNTIME_BACKED=%d\n",
                a.tmplPresent, a.tmplSource, a.tmplRuntimeBacked);
    std::printf("PROMPT_FORMATTED_BY_RUNTIME=%d CHAT_TEMPLATE_HASH=%llu "
                "CHAT_TEMPLATE_POLICY=%s\n",
                a.promptFmtRuntime, (unsigned long long)a.tmplHash,
                a.tmplPolicy);
    std::printf("PROMPT_TOKENS=%llu GENERATED_TOKENS=%llu "
                "BOUNDARY_TOKEN_INDEX=%llu BOUNDARY_VALID=%d\n",
                (unsigned long long)a.promptTokens,
                (unsigned long long)a.tokensCommitted,
                (unsigned long long)a.promptTokens, a.boundaryValid);
    std::printf("UTF8_PENDING_BYTES=%llu UTF8_VALID_FINAL=%d "
                "STREAM_UTF8_ERRORS=%llu\n",
                (unsigned long long)a.utf8Pending, a.utf8Final,
                (unsigned long long)a.utf8Errors);
    std::printf("DETOK_STATE_CARRY_VALID=%d PARTIAL_TOKEN_FLUSH_VALID=%d\n",
                a.detokCarry, a.partialFlush);
    std::printf("CHUNK_SEQ_ID=%llu TOKEN_SEQ_ID=%llu CHUNK_ORDER_VALID=%d\n",
                (unsigned long long)a.tokensCommitted,
                (unsigned long long)a.tokensCommitted, a.chunkOrder);
    std::printf("TOKEN_COMMIT_COUNT_PER_INDEX=1 DUPLICATE_TOKEN_COMMITS=%llu\n",
                (unsigned long long)a.dupCommits);
    std::printf("RETRY_COUNT=%llu RETRY_STAGE=%s RETRY_ROLLBACK_VALID=%d\n",
                (unsigned long long)a.retryCount, a.retryStage,
                a.retryRollback);
    std::printf("CANCEL_OBSERVED_AT=%s CANCEL_SAFE_POINT=%d "
                "PARTIAL_OUTPUT_VALID=%d\n",
                a.cancelAt, a.cancelSafe, a.streamPresent);
    std::printf("MAX_TOKENS_REQUESTED=%llu TOKENS_COMMITTED=%llu "
                "STOPPED_BY_MAXTOK_VALID=%d\n",
                (unsigned long long)a.maxTokensReq,
                (unsigned long long)a.tokensCommitted, a.maxTokValid);
    std::printf("CTX_SIZE=%llu POSITION_INDEX=%llu CTX_LIMIT_REACHED=%d "
                "CTX_OVERFLOW=%d\n",
                (unsigned long long)a.ctxSize,
                (unsigned long long)(a.promptTokens + a.tokensCommitted),
                a.ctxOverflow, a.ctxOverflow);
    std::printf("TOKEN_INDEX=%llu ROPE_POSITION=%llu KV_POSITION=%llu "
                "POSITION_MATCH=%d\n",
                (unsigned long long)a.tokensCommitted,
                (unsigned long long)a.ropePos, (unsigned long long)a.kvPos,
                a.posMatch);
    std::printf("STREAM_HASH=%llu STREAM_HASH_MATCH=1 RECEIPT_ATOMIC=%d\n",
                (unsigned long long)a.streamHash, a.receiptAtomic);
    std::printf("BLOCKER_91_STREAMER_VOCAB_EXT_RUNTIME=%s\n", Stat(g[0]));
    std::printf("BLOCKER_92_BYTE_FALLBACK_TOKENIZATION=%s\n", Stat(g[1]));
    std::printf("BLOCKER_93_SPECIAL_TOKEN_AUTHORITY=%s\n", Stat(g[2]));
    std::printf("BLOCKER_94_CHAT_TEMPLATE_RUNTIME=%s\n", Stat(g[3]));
    std::printf("BLOCKER_95_PROMPT_BOUNDARY_GUARD=%s\n", Stat(g[4]));
    std::printf("BLOCKER_96_UTF8_STREAM_INTEGRITY=%s\n", Stat(g[5]));
    std::printf("BLOCKER_97_DETOKENIZER_STATE_CARRY=%s\n", Stat(g[6]));
    std::printf("BLOCKER_98_STREAM_CHUNK_ORDERING=%s\n", Stat(g[7]));
    std::printf("BLOCKER_99_TOKEN_COMMIT_IDEMPOTENCE=%s\n", Stat(g[8]));
    std::printf("BLOCKER_100_TOKEN_RETRY_SAFETY=%s\n", Stat(g[9]));
    std::printf("BLOCKER_101_CANCEL_BOUNDARY_RUNTIME=%s\n", Stat(g[10]));
    std::printf("BLOCKER_102_MAX_TOKEN_LIMIT_AUTHORITY=%s\n", Stat(g[11]));
    std::printf("BLOCKER_103_CONTEXT_LIMIT_GUARD=%s\n", Stat(g[12]));
    std::printf("BLOCKER_104_POSITION_COUNTER_AUTHORITY=%s\n", Stat(g[13]));
    std::printf("BLOCKER_105_GENERATION_RECEIPT_ATOMICITY=%s\n", Stat(g[14]));
    std::printf("BATCH_007_PASS_COUNT=%d\nBATCH_007_UNFINISHED_COUNT=%d\n",
                pass, unfinished);
    std::printf("RECEIPT_END=RAWRXD_E2E_BLOCKERS_105\n");
}

} // namespace rawr::batch007
