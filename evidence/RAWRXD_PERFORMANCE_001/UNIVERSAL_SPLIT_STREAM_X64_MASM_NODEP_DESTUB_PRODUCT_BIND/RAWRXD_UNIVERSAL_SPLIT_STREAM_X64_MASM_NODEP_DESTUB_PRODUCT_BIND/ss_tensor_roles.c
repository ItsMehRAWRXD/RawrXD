/* ss_tensor_roles.c — DeepSeek MLA/MoE name → role; metadata-agnostic */
#include "ss_tensor_roles.h"
#include <string.h>
#include <stdlib.h>
const char *ss_tensor_role_name(SsTensorRole r)
{
    static const char *n[] = {
        "UNKNOWN","TOKEN_EMBD","OUTPUT_NORM","LM_HEAD","ATTN_NORM",
        "Q_A","Q_B","Q_A_NORM","KV_A","KV_B","KV_A_NORM","ATTN_OUT",
        "FFN_NORM","ROUTER","EXPERT_GATE","EXPERT_UP","EXPERT_DOWN",
        "SHARED_GATE","SHARED_UP","SHARED_DOWN","DENSE_GATE","DENSE_UP",
        "DENSE_DOWN","EXP_PROBS_BIAS"
    };
    return (unsigned)r < sizeof n / sizeof n[0] ? n[r] : "UNKNOWN";
}
static int ends(const char *s, const char *suf)
{
    size_t a = strlen(s), b = strlen(suf);
    return a >= b && !strcmp(s + a - b, suf);
}
int ss_tensor_role_parse(const char *name, SsRoleHit *out)
{
    const char *p; char *end = 0; long bi;
    if (!name || !out) return 1;
    memset(out, 0, sizeof *out); out->block = -1; out->role = SS_ROLE_UNKNOWN;
    if (!strcmp(name, "token_embd.weight")) { out->role = SS_ROLE_TOKEN_EMBD; return 0; }
    if (!strcmp(name, "output_norm.weight")) { out->role = SS_ROLE_OUTPUT_NORM; return 0; }
    if (!strcmp(name, "output.weight")) { out->role = SS_ROLE_LM_HEAD; return 0; }
    if (strncmp(name, "blk.", 4)) return 0;
    p = name + 4; bi = strtol(p, &end, 10);
    if (!end || *end != '.' || bi < 0 || bi > 100000) return 0;
    out->block = (int)bi; p = end + 1;
    if (!strcmp(p, "attn_norm.weight")) out->role = SS_ROLE_ATTN_NORM;
    else if (!strcmp(p, "attn_q_a.weight")) out->role = SS_ROLE_Q_A;
    else if (!strcmp(p, "attn_q_b.weight")) out->role = SS_ROLE_Q_B;
    else if (!strcmp(p, "attn_q_a_norm.weight")) out->role = SS_ROLE_Q_A_NORM;
    else if (!strcmp(p, "attn_kv_a_mqa.weight")) out->role = SS_ROLE_KV_A;
    else if (!strcmp(p, "attn_kv_b.weight")) out->role = SS_ROLE_KV_B;
    else if (!strcmp(p, "attn_kv_a_norm.weight")) out->role = SS_ROLE_KV_A_NORM;
    else if (!strcmp(p, "attn_output.weight")) out->role = SS_ROLE_ATTN_OUT;
    else if (!strcmp(p, "ffn_norm.weight")) out->role = SS_ROLE_FFN_NORM;
    else if (!strcmp(p, "ffn_gate_inp.weight")) out->role = SS_ROLE_ROUTER;
    else if (!strcmp(p, "ffn_gate_exps.weight")) out->role = SS_ROLE_EXPERT_GATE;
    else if (!strcmp(p, "ffn_up_exps.weight")) out->role = SS_ROLE_EXPERT_UP;
    else if (!strcmp(p, "ffn_down_exps.weight")) out->role = SS_ROLE_EXPERT_DOWN;
    else if (!strcmp(p, "ffn_gate_shexp.weight")) out->role = SS_ROLE_SHARED_GATE;
    else if (!strcmp(p, "ffn_up_shexp.weight")) out->role = SS_ROLE_SHARED_UP;
    else if (!strcmp(p, "ffn_down_shexp.weight")) out->role = SS_ROLE_SHARED_DOWN;
    else if (!strcmp(p, "ffn_gate.weight")) out->role = SS_ROLE_DENSE_GATE;
    else if (!strcmp(p, "ffn_up.weight")) out->role = SS_ROLE_DENSE_UP;
    else if (!strcmp(p, "ffn_down.weight")) out->role = SS_ROLE_DENSE_DOWN;
    else if (ends(p, "exp_probs_b.bias")) out->role = SS_ROLE_EXP_PROBS_BIAS;
    return 0;
}
