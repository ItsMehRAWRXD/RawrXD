#pragma once
#include "RawrStreamerTypes.hpp"

enum RawrDataValidity : RAWR_U32 {
    RAWR_DATA_UNKNOWN = 0,
    RAWR_DATA_UNINITIALIZED,
    RAWR_DATA_INITIALIZED,
    RAWR_DATA_FINITE,
    RAWR_DATA_NONZERO,
    RAWR_DATA_NUMERIC_VALID,
    RAWR_DATA_PARITY_VALID,
    RAWR_DATA_INVALID
};

enum RawrPerformanceClass : RAWR_U32 {
    RAWR_PERF_UNKNOWN = 0,
    RAWR_PERF_UNMEASURED,
    RAWR_PERF_MEASURED,
    RAWR_PERF_OVER_BUDGET,
    RAWR_PERF_WITHIN_BUDGET,
    RAWR_PERF_WINNER
};

enum RawrTeardownState : RAWR_U32 {
    RAWR_TEARDOWN_NONE = 0,
    RAWR_TEARDOWN_ENTERED,
    RAWR_TEARDOWN_STREAM_STOPPED,
    RAWR_TEARDOWN_WORK_DRAINED,
    RAWR_TEARDOWN_QUEUES_IDLE,
    RAWR_TEARDOWN_RESOURCES_RELEASED,
    RAWR_TEARDOWN_DEVICE_IDLE,
    RAWR_TEARDOWN_WITNESS,
    RAWR_TEARDOWN_COMPLETE
};

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
