#pragma once
/* Remaining Ext name helpers. */
#include "RawrStreamerOwnership.hpp"

inline const char* RawrRecoveryDispositionName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "NONE", "NOT_APPLICABLE", "AVAILABLE", "IN_PROGRESS", "SUCCEEDED",
        "EXHAUSTED", "FORBIDDEN"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrProgressKindName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "NONE", "HEARTBEAT", "MODEL_INDEX", "TENSOR_ADDRESS", "TENSOR_ACQUIRE",
        "PREFILL_LAYER", "DECODE_LAYER", "DECODE_TOKEN", "TOKEN_EMIT",
        "RELEASE", "TEARDOWN"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrResourceStateName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "NONE", "DESCRIBED", "ADDRESSED", "ACQUIRING", "ACQUIRED", "RESIDENT",
        "IN_USE", "RELEASING", "RELEASED", "INVALID"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrOwnershipStateName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "NONE", "CALLER", "MODEL", "RUNTIME", "DEVICE", "KERNEL", "STREAM",
        "TRANSFER", "RELEASED"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrDataValidityName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "UNKNOWN", "UNINITIALIZED", "INITIALIZED", "FINITE", "NONZERO",
        "NUMERIC_VALID", "PARITY_VALID", "INVALID"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrPerformanceClassName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "UNKNOWN", "UNMEASURED", "MEASURED", "OVER_BUDGET", "WITHIN_BUDGET",
        "WINNER"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrTeardownStateName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "NONE", "ENTERED", "STREAM_STOPPED", "WORK_DRAINED", "QUEUES_IDLE",
        "RESOURCES_RELEASED", "DEVICE_IDLE", "WITNESS", "COMPLETE"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}
