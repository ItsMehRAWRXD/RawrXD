#pragma once
/* Completion + progress receipts. Event receipts stay in base vocab. */
#include "RawrStreamerOwnership.hpp"

struct RawrCompletionReceipt {
    RAWR_U64 generation;
    RAWR_U32 execution_scope;
    RAWR_U32 termination_class;
    RAWR_U32 completion_reason;
    RAWR_U32 production_state;
    RAWR_U32 status;
    RAWR_U32 blocker;
    RAWR_U32 blocker_owner;
    RAWR_U32 failure_domain;
    RAWR_U32 recovery_action;
    RAWR_U32 recovery_disposition;
    RAWR_U32 teardown_state;
    RAWR_U32 performance_class;
    RAWR_U64 prompt_tokens;
    RAWR_U64 generated_tokens;
    RAWR_U64 prefill_layers_completed;
    RAWR_U64 decode_steps_completed;
    RAWR_U64 wall_ns;
    RAWR_U64 first_token_ns;
    RAWR_U64 decode_ns;
    RAWR_F64 decode_tps;
    RAWR_U32 production_decode_path;
    RAWR_U32 model_output_produced;
    RAWR_U32 cpu_f32_expands;
    RAWR_U32 host_forward_layer_calls;
    RAWR_U32 numeric_valid;
    RAWR_U32 output_valid;
    RAWR_U32 teardown_witness;
};

struct RawrProgressReceipt {
    RAWR_U64 generation;
    RAWR_U64 sequence;
    RAWR_U32 state;
    RAWR_U32 stage;
    RAWR_U32 progress_kind;
    RAWR_U64 completed;
    RAWR_U64 total;
    RAWR_U64 token_position;
    RAWR_U64 layer_position;
    RAWR_U64 timestamp_ns;
    RAWR_U32 work_moved;
    RAWR_U32 heartbeat;
};

inline bool RawrIsProductionCompletion(const RawrCompletionReceipt& r) noexcept {
    return r.termination_class == RAWR_TERM_COMPLETED &&
           r.production_state == RAWR_PRODUCTION_FINISHED &&
           r.production_decode_path == 1 && r.model_output_produced == 1 &&
           r.generated_tokens > 0 && r.numeric_valid == 1 &&
           r.output_valid == 1;
}

inline bool RawrIsBlocked(const RawrCompletionReceipt& r) noexcept {
    return r.termination_class == RAWR_TERM_BLOCKED_BEFORE_EXECUTION ||
           r.termination_class == RAWR_TERM_BLOCKED_DURING_EXECUTION;
}

inline bool RawrIsStreamAbort(const RawrCompletionReceipt& r) noexcept {
    return r.termination_class == RAWR_TERM_ABORTED_DURING_STREAM ||
           r.termination_class == RAWR_TERM_FAILED_DURING_STREAM;
}

inline bool RawrHasCleanTeardown(const RawrCompletionReceipt& r) noexcept {
    return r.teardown_witness == 1 &&
           r.teardown_state == RAWR_TEARDOWN_COMPLETE;
}

inline bool RawrRunsCorrectly(const RawrCompletionReceipt& r) noexcept {
    return RawrIsProductionCompletion(r) && r.cpu_f32_expands == 0 &&
           r.host_forward_layer_calls == 0;
}

inline bool RawrRunsWithinBudget(const RawrCompletionReceipt& r,
                                 RAWR_U64 wall_budget_ns) noexcept {
    return RawrRunsCorrectly(r) && r.wall_ns <= wall_budget_ns;
}

inline const char* RawrTerminalName(const RawrCompletionReceipt& r) noexcept {
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
