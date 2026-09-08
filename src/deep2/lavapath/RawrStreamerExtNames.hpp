#pragma once
#include "RawrStreamerOwnership.hpp"
#include "RawrStreamerExtNames2.hpp"

inline const char* RawrExecutionScopeName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "NONE", "DISCOVER", "INDEX", "VALIDATE", "PLAN", "TUNE", "PREFILL",
        "DECODE", "GENERATE", "STREAM", "TEARDOWN", "END_TO_END"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrOutputClassName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "NONE", "DIAGNOSTIC", "PROGRESS", "RECEIPT", "MEASUREMENT",
        "MODEL_TOKEN", "MODEL_TEXT", "COMPLETION", "BLOCKED", "FAILURE"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrProductionStateName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "NONE", "NOT_ENTERED", "ENTERED", "PREFILL_ACTIVE", "DECODE_ACTIVE",
        "TOKEN_PRODUCED", "STREAM_ACTIVE", "FINISHED"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrCompletionReasonName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "NONE", "EOS", "MAX_TOKENS", "STOP_SEQUENCE",
        "USER_CANCEL_AFTER_OUTPUT", "REQUEST_SATISFIED", "STREAM_CLOSED",
        "TEARDOWN_CLEAN"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrTerminationClassName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "NONE", "COMPLETED", "BLOCKED_BEFORE_EXECUTION",
        "BLOCKED_DURING_EXECUTION", "FAILED_BEFORE_STREAM",
        "FAILED_DURING_STREAM", "ABORTED_DURING_STREAM", "CANCELLED",
        "DEVICE_LOST", "PROCESS_LOST"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrFailureDomainName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "NONE", "INPUT", "MODEL", "FORMAT", "TOKENIZER", "ADDRESS", "MEMORY",
        "RESIDENCY", "DEVICE", "SHADER", "KERNEL", "NUMERIC", "SCHEDULER",
        "QUEUE", "IO", "STREAM", "TEARDOWN", "ENVIRONMENT", "INTERNAL"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrBlockOwnerName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "NONE", "CALLER", "MODEL_RESOLVER", "GGUF", "TOKENIZER", "RMV",
        "RESIDENCY", "CAPABILITY_SOLVER", "KERNEL_SOLVER", "SHADER_PIPELINE",
        "DEVICE", "QKV", "KVA", "O_PROJ", "FFN", "LOGITS", "SAMPLER",
        "STREAMER", "TEARDOWN", "ENVIRONMENT"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrRecoveryActionName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "NONE", "RETRY", "REOPEN", "REINDEX", "REACQUIRE", "REBIND",
        "REBUILD_PIPELINE", "REPLAN", "REDUCE_WORKING_SET", "EVICT",
        "RECLAIM", "SWITCH_LEGAL_VARIANT", "SWITCH_DEVICE", "FALLBACK_HOST",
        "RESUME", "ABORT"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}
