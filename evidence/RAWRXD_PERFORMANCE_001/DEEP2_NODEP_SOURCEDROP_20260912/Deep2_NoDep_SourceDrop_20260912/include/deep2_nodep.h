#ifndef DEEP2_NODEP_H
#define DEEP2_NODEP_H

#if defined(_MSC_VER)
#define D2CALL __fastcall
#else
#define D2CALL
#endif

typedef unsigned long      d2_u32;
typedef unsigned long long d2_u64;
typedef long               d2_i32;
typedef void*              d2_ptr;

typedef struct D2DecodeCtx {
    d2_u64 magic; d2_u32 version; d2_u32 flags;
    d2_u64 position, target_tokens, generated;
    d2_u32 error, authority;
    d2_u64 exec_generation;
    d2_u64 forward_calls, select_calls, commit_calls, advance_calls;
    d2_u64 full_forward_obs, token_select_obs, token_commit_obs, state_advance_obs;
    d2_ptr user;
    d2_ptr forward_fn, select_fn, commit_fn, advance_fn;
    d2_u64 logits_handle, vocab, selected_token, selected_aux;
    d2_u32 fail_stage, fail_reason;
    d2_u64 block_cursor, blocks_entered, blocks_completed;
    d2_u64 kv_position, expected_position, prompt_tokens;
    d2_u64 plan_generation, ticket_generation;
} D2DecodeCtx;

typedef struct D2DecodeConfig {
    d2_ptr user;
    d2_ptr forward_fn; /* int(user,pos,&opaque_logits,&vocab) */
    d2_ptr select_fn;  /* int(user,opaque_logits,vocab,&token) */
    d2_ptr commit_fn;  /* int(user,token,pos,ctx) */
    d2_ptr advance_fn; /* int(user,new_pos,ctx,0) */
} D2DecodeConfig;

typedef struct D2Range {
    d2_u64 region_id, shard_id, offset, bytes, codec, owner_cookie, generation, state;
} D2Range;

typedef struct D2ExpertRange {
    d2_u64 layer_id, expert_id;
    D2Range *gate, *up, *down;
    d2_u64 residency_generation;
} D2ExpertRange;

#ifdef __cplusplus
extern "C" {
#endif
int D2CALL Deep2DecodeInit(D2DecodeCtx*, const D2DecodeConfig*);
int D2CALL Deep2DecodeSetPosition(D2DecodeCtx*, d2_u64);
int D2CALL Deep2DecodeSeedLiveState(D2DecodeCtx*, d2_u64 kv_pos, d2_u64 prompt_tokens, d2_u64 expected_pos);
int D2CALL Deep2DecodeSetTarget(D2DecodeCtx*, d2_u64);
int D2CALL Deep2DecodeBeginToken(D2DecodeCtx*);
int D2CALL Deep2ObserveForward(D2DecodeCtx*, d2_u64 blocks_entered, d2_u64 blocks_completed, d2_u64 flags);
int D2CALL Deep2RunFullDecode(D2DecodeCtx*);
int D2CALL Deep2AttemptDecodeGrant(D2DecodeCtx*);
int D2CALL Deep2ActivationSwap(d2_ptr* ping, d2_ptr* pong);
int D2CALL Deep2RangeTicketCopy(D2Range* dst, const D2Range* src);
int D2CALL Deep2HotsetLookup(d2_ptr entries, d2_u64 count, d2_u64 region_id, d2_u64 generation);
#ifdef __cplusplus
}
#endif
#endif
