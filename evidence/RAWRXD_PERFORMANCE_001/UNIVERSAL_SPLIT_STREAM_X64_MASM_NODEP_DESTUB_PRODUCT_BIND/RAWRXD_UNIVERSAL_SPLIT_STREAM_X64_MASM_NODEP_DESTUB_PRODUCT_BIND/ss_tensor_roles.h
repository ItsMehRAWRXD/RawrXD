/* ss_tensor_roles.h — raw GGUF name → runtime tensor role */
#ifndef SS_TENSOR_ROLES_H
#define SS_TENSOR_ROLES_H
#include <stdint.h>
typedef enum SsTensorRole {
    SS_ROLE_UNKNOWN = 0,
    SS_ROLE_TOKEN_EMBD,
    SS_ROLE_OUTPUT_NORM,
    SS_ROLE_LM_HEAD,
    SS_ROLE_ATTN_NORM,
    SS_ROLE_Q_A,
    SS_ROLE_Q_B,
    SS_ROLE_Q_A_NORM,
    SS_ROLE_KV_A,
    SS_ROLE_KV_B,
    SS_ROLE_KV_A_NORM,
    SS_ROLE_ATTN_OUT,
    SS_ROLE_FFN_NORM,
    SS_ROLE_ROUTER,
    SS_ROLE_EXPERT_GATE,
    SS_ROLE_EXPERT_UP,
    SS_ROLE_EXPERT_DOWN,
    SS_ROLE_SHARED_GATE,
    SS_ROLE_SHARED_UP,
    SS_ROLE_SHARED_DOWN,
    SS_ROLE_DENSE_GATE,
    SS_ROLE_DENSE_UP,
    SS_ROLE_DENSE_DOWN,
    SS_ROLE_EXP_PROBS_BIAS
} SsTensorRole;
typedef struct SsRoleHit {
    SsTensorRole role;
    int block; /* -1 = global */
} SsRoleHit;
int ss_tensor_role_parse(const char *name, SsRoleHit *out);
const char *ss_tensor_role_name(SsTensorRole r);
#endif
