#pragma once
#include "RawrExtScope.hpp"
#include "RawrExtTerm.hpp"
#include "RawrExtRecovery.hpp"

static inline const char* RawrExecutionScopeName(RawrExecutionScope v) {
    switch (v) {
        case RAWR_SCOPE_NONE: return "NONE";
        case RAWR_SCOPE_DISCOVER: return "DISCOVER";
        case RAWR_SCOPE_INDEX: return "INDEX";
        case RAWR_SCOPE_VALIDATE: return "VALIDATE";
        case RAWR_SCOPE_PLAN: return "PLAN";
        case RAWR_SCOPE_TUNE: return "TUNE";
        case RAWR_SCOPE_PREFILL: return "PREFILL";
        case RAWR_SCOPE_DECODE: return "DECODE";
        case RAWR_SCOPE_GENERATE: return "GENERATE";
        case RAWR_SCOPE_STREAM: return "STREAM";
        case RAWR_SCOPE_TEARDOWN: return "TEARDOWN";
        case RAWR_SCOPE_END_TO_END: return "END_TO_END";
        default: return "UNKNOWN";
    }
}

static inline const char* RawrTerminationClassName(RawrTerminationClass v) {
    switch (v) {
        case RAWR_TERM_NONE: return "NONE";
        case RAWR_TERM_COMPLETED: return "COMPLETED";
        case RAWR_TERM_BLOCKED_BEFORE_EXECUTION: return "BLOCKED_BEFORE_EXECUTION";
        case RAWR_TERM_BLOCKED_DURING_EXECUTION: return "BLOCKED_DURING_EXECUTION";
        case RAWR_TERM_FAILED_BEFORE_STREAM: return "FAILED_BEFORE_STREAM";
        case RAWR_TERM_FAILED_DURING_STREAM: return "FAILED_DURING_STREAM";
        case RAWR_TERM_ABORTED_DURING_STREAM: return "ABORTED_DURING_STREAM";
        case RAWR_TERM_CANCELLED: return "CANCELLED";
        case RAWR_TERM_DEVICE_LOST: return "DEVICE_LOST";
        case RAWR_TERM_PROCESS_LOST: return "PROCESS_LOST";
        default: return "UNKNOWN";
    }
}

static inline const char* RawrRecoveryActionName(RawrRecoveryAction v) {
    switch (v) {
        case RAWR_RECOVERY_NONE: return "NONE";
        case RAWR_RECOVERY_RETRY: return "RETRY";
        case RAWR_RECOVERY_REOPEN: return "REOPEN";
        case RAWR_RECOVERY_REINDEX: return "REINDEX";
        case RAWR_RECOVERY_REACQUIRE: return "REACQUIRE";
        case RAWR_RECOVERY_REBIND: return "REBIND";
        case RAWR_RECOVERY_REBUILD_PIPELINE: return "REBUILD_PIPELINE";
        case RAWR_RECOVERY_REPLAN: return "REPLAN";
        case RAWR_RECOVERY_REDUCE_WORKING_SET: return "REDUCE_WORKING_SET";
        case RAWR_RECOVERY_EVICT: return "EVICT";
        case RAWR_RECOVERY_RECLAIM: return "RECLAIM";
        case RAWR_RECOVERY_SWITCH_LEGAL_VARIANT: return "SWITCH_LEGAL_VARIANT";
        case RAWR_RECOVERY_SWITCH_DEVICE: return "SWITCH_DEVICE";
        case RAWR_RECOVERY_FALLBACK_HOST: return "FALLBACK_HOST";
        case RAWR_RECOVERY_RESUME: return "RESUME";
        case RAWR_RECOVERY_ABORT: return "ABORT";
        default: return "UNKNOWN";
    }
}
