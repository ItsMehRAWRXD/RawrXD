/* ds671_runtime_receipt.h — OBSERVED/DERIVED only; never invent PROMOTE */
#ifndef DS671_RUNTIME_RECEIPT_H
#define DS671_RUNTIME_RECEIPT_H
#include <stdint.h>

typedef struct Ds671RunState {
    /* DECLARED (intent only — never promote alone) */
    uint32_t expected_shards;
    uint32_t expected_tensors;
    uint32_t expected_blocks, expected_experts, expected_used, expected_shared;
    uint32_t expected_emb, expected_vocab;
    uint32_t promote_requested;

    /* OBSERVED */
    uint32_t opened_shards;
    uint64_t total_bytes;
    uint32_t tensor_total, unresolved_tensors;
    uint32_t class_emb, class_out, class_attn, class_mla;
    uint32_t class_dense, class_exp, class_norm, class_other;
    uint32_t meta_blocks, meta_experts, meta_used, meta_shared;
    uint32_t meta_emb, meta_vocab;
    uint32_t router_executed, router_selected_count;
    uint32_t expert_forward_count, shared_expert_executed, dense_layers_executed;
    uint32_t mla_executed, logits_count, generated_tokens, token_commit_count;
    uint32_t fixed_gate_eval_rc;
    uint64_t fixed_gate_pass_mask, fixed_gate_fail_mask;
    uint32_t stream_used, fallback_used, stub_used, synthetic_weight_used;
    uint32_t full_load_no_stream; /* 1 only if session opened all tensors resident without stream */
} Ds671RunState;

typedef struct Ds671Receipt {
    uint32_t manifest_pass, semantic_map_pass, metadata_pass;
    uint32_t decode_pass, policy_pass, no_fake_path;
    uint32_t promote; /* DERIVED ONLY */
} Ds671Receipt;

/* returns 0 iff promote==1; else 1 (fail-closed) */
int ds671_emit_receipt(const Ds671RunState *s, Ds671Receipt *r);
#endif
