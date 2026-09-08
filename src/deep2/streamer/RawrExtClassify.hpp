#pragma once
#include "RawrExtScope.hpp"
#include "RawrExtTerm.hpp"
#include "RawrExtReceipt.hpp"

static inline bool RawrIsProductionCompletion(const RawrCompletionReceipt& r) {
    return r.termination_class == RAWR_TERM_COMPLETED &&
           r.production_state == RAWR_PRODUCTION_FINISHED &&
           r.production_decode_path == 1 &&
           r.model_output_produced == 1 &&
           r.generated_tokens > 0 &&
           r.numeric_valid == 1 &&
           r.output_valid == 1;
}

static inline bool RawrIsBlocked(const RawrCompletionReceipt& r) {
    return r.termination_class == RAWR_TERM_BLOCKED_BEFORE_EXECUTION ||
           r.termination_class == RAWR_TERM_BLOCKED_DURING_EXECUTION;
}

static inline bool RawrIsStreamAbort(const RawrCompletionReceipt& r) {
    return r.termination_class == RAWR_TERM_ABORTED_DURING_STREAM ||
           r.termination_class == RAWR_TERM_FAILED_DURING_STREAM;
}

static inline bool RawrHasCleanTeardown(const RawrCompletionReceipt& r) {
    return r.teardown_witness == 1 &&
           r.teardown_state == RAWR_TEARDOWN_COMPLETE;
}

static inline bool RawrRunsCorrectly(const RawrCompletionReceipt& r) {
    return RawrIsProductionCompletion(r) &&
           r.cpu_f32_expands == 0 &&
           r.host_forward_layer_calls == 0;
}

static inline bool RawrRunsWithinBudget(const RawrCompletionReceipt& r,
                                        RAWR_U64 wall_budget_ns) {
    return RawrRunsCorrectly(r) && r.wall_ns <= wall_budget_ns;
}

static inline const char* RawrTerminalName(const RawrCompletionReceipt& r) {
    switch ((RawrTerminationClass)r.termination_class) {
        case RAWR_TERM_COMPLETED: return "STREAM_COMPLETE";
        case RAWR_TERM_BLOCKED_BEFORE_EXECUTION:
        case RAWR_TERM_BLOCKED_DURING_EXECUTION: return "STREAM_BLOCKED";
        case RAWR_TERM_ABORTED_DURING_STREAM:
        case RAWR_TERM_CANCELLED: return "STREAM_ABORTED";
        case RAWR_TERM_FAILED_BEFORE_STREAM:
        case RAWR_TERM_FAILED_DURING_STREAM:
        case RAWR_TERM_DEVICE_LOST:
        case RAWR_TERM_PROCESS_LOST: return "STREAM_FAILED";
        default: return "STREAM_UNKNOWN";
    }
}
