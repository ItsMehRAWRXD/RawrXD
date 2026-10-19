/* ds671_runtime_receipt.c — promote is DERIVED from OBSERVED only */
#include "ds671_runtime_receipt.h"
#include <string.h>

int ds671_emit_receipt(const Ds671RunState *s, Ds671Receipt *r)
{
    uint32_t classified, required;
    if (!s || !r) return 1;
    memset(r, 0, sizeof(*r));

    r->manifest_pass =
        (s->opened_shards == s->expected_shards) &&
        (s->expected_shards == 11u) &&
        (s->tensor_total == s->expected_tensors) &&
        (s->expected_tensors == 1025u) &&
        (s->unresolved_tensors == 0u) &&
        (s->total_bytes > 0u) &&
        (s->full_load_no_stream == 1u);

    classified = s->class_emb + s->class_out + s->class_attn + s->class_mla +
                 s->class_dense + s->class_exp + s->class_norm + s->class_other;
    required = (s->class_emb > 0) && (s->class_out > 0) && (s->class_mla > 0) &&
               (s->class_exp > 0) && (s->class_norm > 0); /* norm=0 cannot promote */
    r->semantic_map_pass =
        (classified == s->tensor_total) &&
        (s->unresolved_tensors == 0u) &&
        (s->class_other == 0u) &&
        required;

    r->metadata_pass =
        (s->meta_blocks == s->expected_blocks) &&
        (s->meta_experts == s->expected_experts) &&
        (s->meta_used == s->expected_used) &&
        (s->meta_shared == s->expected_shared) &&
        (s->meta_emb == s->expected_emb) &&
        (s->meta_vocab == s->expected_vocab);

    r->decode_pass =
        (s->router_executed == 1u) &&
        (s->router_selected_count == 8u) &&
        (s->expert_forward_count >= 8u) &&
        (s->shared_expert_executed == 1u) &&
        (s->dense_layers_executed >= 3u) &&
        (s->mla_executed == 1u) &&
        (s->logits_count == s->meta_vocab) &&
        (s->generated_tokens > 0u) &&
        (s->token_commit_count == s->generated_tokens);

    r->policy_pass =
        (s->fixed_gate_eval_rc == 1u) &&
        (s->fixed_gate_pass_mask == 0x1full) &&
        (s->fixed_gate_fail_mask == 0u);

    r->no_fake_path =
        (s->stream_used == 0u) &&
        (s->fallback_used == 0u) &&
        (s->stub_used == 0u) &&
        (s->synthetic_weight_used == 0u);

    /* promote_requested is DECLARED — ignored for authority */
    (void)s->promote_requested;
    r->promote =
        r->manifest_pass && r->semantic_map_pass && r->metadata_pass &&
        r->decode_pass && r->policy_pass && r->no_fake_path;

    return r->promote ? 0 : 1;
}
