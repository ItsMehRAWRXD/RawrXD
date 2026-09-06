#pragma once

// TOKEN_PRESSURE_VALVE_001
// No dependency token-flow controller for RawrXD decode streams.
// It changes token pattern pressure only; it does not change context size,
// temperature, GPU split, model path, or model lifecycle.

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TPV_MAGIC          0x31565054u  /* TPV1 */
#define TPV_VERSION        1u
#define TPV_RING_COUNT     64u
#define TPV_STATE_BYTES    608u
#define TPV_RESULT_BYTES   64u

enum TPV_Mode : uint32_t {
    TPV_MODE_NEEDLE = 0,   /* narrow/direct */
    TPV_MODE_MIST   = 1,   /* softer/wider */
    TPV_MODE_PULSE  = 2,   /* alternating explore/compress */
    TPV_MODE_RINSE  = 3,   /* summarize/compress */
    TPV_MODE_CUTOFF = 4,   /* stop early on loop pressure */
    TPV_MODE_REPAIR = 5    /* favor repair/fix/code after failure */
};

enum TPV_TokenFlag : uint32_t {
    TPV_TOK_NEWLINE     = 1u << 0,
    TPV_TOK_WHITESPACE  = 1u << 1,
    TPV_TOK_FENCE       = 1u << 2,
    TPV_TOK_BRACE_OPEN  = 1u << 3,
    TPV_TOK_BRACE_CLOSE = 1u << 4,
    TPV_TOK_ERROR       = 1u << 5,
    TPV_TOK_EDIT        = 1u << 6,
    TPV_TOK_DESTRUCTIVE = 1u << 7,
    TPV_TOK_FILLER      = 1u << 8,
    TPV_TOK_STOPLIKE    = 1u << 9,
    TPV_TOK_CODE        = 1u << 10,
    TPV_TOK_SENT_END    = 1u << 11
};

enum TPV_Action : uint32_t {
    TPV_ACT_NONE            = 0,
    TPV_ACT_REPEAT_PENALTY  = 1u << 0,
    TPV_ACT_NARROW          = 1u << 1,
    TPV_ACT_WIDEN           = 1u << 2,
    TPV_ACT_CLOSE_STRUCTURE = 1u << 3,
    TPV_ACT_STOP_HINT       = 1u << 4,
    TPV_ACT_COMPRESS        = 1u << 5,
    TPV_ACT_REPAIR_JET      = 1u << 6,
    TPV_ACT_APPROVAL_HOLD   = 1u << 7
};

typedef struct TPV_State {
    uint32_t magic;
    uint32_t version;
    uint32_t mode;
    uint32_t flags;
    uint32_t pos;
    uint32_t count;
    uint32_t repeat_pressure;
    uint32_t run_pressure;
    uint32_t stall_pressure;
    uint32_t structure_pressure;
    uint32_t repair_pressure;
    uint32_t approval_pressure;
    uint32_t last_token;
    uint32_t run_token;
    uint32_t run_length;
    int32_t  brace_depth;
    uint32_t fence_parity;
    uint32_t line_count;
    uint64_t total_tokens;
    uint64_t seal64;
    uint32_t ring[TPV_RING_COUNT];
    uint32_t ring_flags[TPV_RING_COUNT];
    uint32_t reserved[2];
} TPV_State;

typedef struct TPV_Result {
    uint32_t action;
    uint32_t mode;
    uint32_t repeat_pressure;
    uint32_t run_pressure;
    uint32_t stall_pressure;
    uint32_t structure_pressure;
    uint32_t repair_pressure;
    uint32_t approval_pressure;
    uint32_t line_count;
    int32_t  brace_depth;
    uint32_t fence_parity;
    uint32_t reserved0;
    uint64_t total_tokens;
    uint64_t seal64;
} TPV_Result;

#ifdef __cplusplus
static_assert(sizeof(TPV_State) == TPV_STATE_BYTES, "TPV_State ABI size mismatch");
static_assert(sizeof(TPV_Result) == TPV_RESULT_BYTES, "TPV_Result ABI size mismatch");
#endif

uint32_t TPV_InitState(TPV_State* state, uint32_t mode, uint32_t flags);
uint32_t TPV_Reset(TPV_State* state);
uint32_t TPV_SetMode(TPV_State* state, uint32_t mode);
uint32_t TPV_UpdateToken(TPV_State* state, uint32_t token_id, uint32_t token_flags, TPV_Result* out_result);
uint32_t TPV_ProbeWindow(const uint32_t* token_ids, uint32_t token_count, TPV_Result* out_result);
uint64_t TPV_SealState(const TPV_State* state);
void     TPV_SecureZero(void* ptr, uint64_t bytes);

#ifdef __cplusplus
}
#endif
