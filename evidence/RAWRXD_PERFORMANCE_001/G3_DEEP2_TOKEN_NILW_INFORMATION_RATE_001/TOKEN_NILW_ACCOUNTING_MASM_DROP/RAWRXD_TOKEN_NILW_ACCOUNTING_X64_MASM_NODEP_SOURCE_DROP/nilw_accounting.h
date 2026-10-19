#pragma once

typedef unsigned int       nilw_u32;
typedef unsigned long long nilw_u64;

enum NilwStatus {
    NILW_STATUS_OK = 0,
    NILW_STATUS_NULL = 1,
    NILW_STATUS_INVALID = 2
};

enum NilwError {
    NILW_ERROR_NULL_INPUT            = 0x00001,
    NILW_ERROR_TOTAL_WEIGHTS_ZERO    = 0x00002,
    NILW_ERROR_ACTIVE_WEIGHTS_ZERO   = 0x00004,
    NILW_ERROR_ACTIVE_RANGE          = 0x00008,
    NILW_ERROR_CODEC_BITS_ZERO       = 0x00010,
    NILW_ERROR_NEW_GT_CODEC          = 0x00020,
    NILW_ERROR_PAYLOAD_SUM_OVERFLOW  = 0x00040,
    NILW_ERROR_IDENTITY_MISMATCH     = 0x00080,
    NILW_ERROR_TARGET_NILW_ZERO      = 0x00100,
    NILW_ERROR_PAYLOAD_CAP_ZERO      = 0x00200,
    NILW_ERROR_RATE_CAP_ZERO         = 0x00400,
    NILW_ERROR_TARGET_TPS_ZERO       = 0x00800,
    NILW_ERROR_MIN_TOKENS_ZERO       = 0x01000,
    NILW_ERROR_RUN_TOKENS_ZERO       = 0x02000,
    NILW_ERROR_WALL_NS_ZERO          = 0x04000,
    NILW_ERROR_BOOLEAN_RANGE         = 0x08000,
    NILW_ERROR_RUN_PAYLOAD_TOO_SMALL = 0x10000
};

enum NilwGate {
    NILW_GATE_INPUT_VALID             = 0x00001,
    NILW_GATE_IDENTITY                = 0x00002,
    NILW_GATE_NILW_LIMIT              = 0x00004,
    NILW_GATE_TOKEN_PAYLOAD_CAP       = 0x00008,
    NILW_GATE_MEAN_PAYLOAD_CAP        = 0x00010,
    NILW_GATE_INFORMATION_RATE        = 0x00020,
    NILW_GATE_TARGET_TPS              = 0x00040,
    NILW_GATE_MIN_TOKEN_WINDOW        = 0x00080,
    NILW_GATE_NO_FULL_MATERIALIZATION = 0x00100,
    NILW_GATE_NO_REPORTED_OVERFLOW    = 0x00200,
    NILW_GATE_NO_LONGRUN_FAILURES     = 0x00400,
    NILW_GATE_LIVE_WITNESS            = 0x00800,
    NILW_GATE_TOKEN_AUTHORITY         = 0x01000,
    NILW_GATE_DECODE_AUTHORITY        = 0x02000,
    NILW_GATE_NO_SUPERSEDED_FALLBACK  = 0x04000,
    NILW_GATE_SUSTAINABLE             = 0x08000,
    NILW_GATE_RUNTIME_AUTHORIZED      = 0x10000
};

#pragma pack(push, 8)
typedef struct NilwInput {
    nilw_u64 total_logical_weights;
    nilw_u64 active_logical_weights;
    nilw_u64 active_codec_bits;
    nilw_u64 new_codec_bits;
    nilw_u64 overhead_bits;
    nilw_u64 observed_new_payload_bits;
    nilw_u64 run_new_payload_bytes;
    nilw_u64 run_generated_tokens;
    nilw_u64 run_wall_ns;
    nilw_u64 payload_cap_bytes_per_token;
    nilw_u64 information_rate_cap_bps;
    nilw_u64 target_tps;
    nilw_u64 min_generated_tokens;
    nilw_u64 target_nilw_num;
    nilw_u64 target_nilw_den;
    nilw_u64 live_runtime_witness_count;
    nilw_u64 longrun_failures;
    nilw_u32 token_authority_agrees;
    nilw_u32 decode_authority_agrees;
    nilw_u32 superseded_zero_path_used;
    nilw_u32 full_materialization;
    nilw_u32 reported_budget_overflow;
    nilw_u32 reserved0;
} NilwInput;

typedef struct NilwResult {
    nilw_u32 status;
    nilw_u32 reserved0;
    nilw_u64 error_mask;
    nilw_u64 gate_mask;
    nilw_u64 calculated_payload_bits;
    nilw_u64 calculated_reuse_bits;
    nilw_u64 active_codec_bpw_num;
    nilw_u64 active_codec_bpw_den;
    nilw_u64 physicalization_num;
    nilw_u64 physicalization_den;
    nilw_u64 new_information_num;
    nilw_u64 new_information_den;
    nilw_u64 overhead_num;
    nilw_u64 overhead_den;
    nilw_u64 token_nilw_num;
    nilw_u64 token_nilw_den;
    nilw_u64 mean_payload_bytes_num;
    nilw_u64 mean_payload_tokens_den;
    nilw_u64 information_rate_bytes_num;
    nilw_u64 information_rate_wall_ns_den;
    nilw_u64 generation_tps_tokens_num;
    nilw_u64 generation_tps_wall_ns_den;
} NilwResult;
#pragma pack(pop)

#if defined(__cplusplus)
static_assert(sizeof(NilwInput) == 160, "NilwInput ABI drift");
static_assert(sizeof(NilwResult) == 168, "NilwResult ABI drift");
extern "C" {
#endif
nilw_u32 NilwEvaluate(const NilwInput* input, NilwResult* result);
#if defined(__cplusplus)
}
#endif
