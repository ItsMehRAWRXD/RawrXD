/* Production scaffold only — descriptors, not wired into product PASS path.
 * VERIFIER must not be imported here; production must not call blind_oracle. */
#ifndef DEEP2_PROD_SCAFFOLD_H
#define DEEP2_PROD_SCAFFOLD_H
#include <stdint.h>

#define PRODUCTION_GEOMETRY_PRESENT 1
#define PRODUCTION_DISPATCHER_PRESENT 0 /* scaffold only */
#define PRODUCTION_KERNEL_REGISTRY_PRESENT 0
#define PRODUCTION_AUTHORITY_DERIVATION_PRESENT 0
#define VERIFIER_USED_FOR_DISPATCH 0
#define VERIFIER_USED_FOR_GEOMETRY 0
#define VERIFIER_USED_FOR_AUTHORITY 0
#define VERIFIER_USED_FOR_KERNEL_SELECTION 0

typedef enum {
    D2_OP_EMBEDDING = 1,
    D2_OP_RMSNORM = 2,
    D2_OP_Q_PROJ = 3,
    D2_OP_LM_HEAD = 8
} Deep2Op;

typedef struct {
    uint32_t codec;
    uint32_t input_elements, output_elements, rows, cols;
    uint32_t block_elements, block_bytes;
    uint64_t blocks_per_row, row_bytes, expected_tensor_bytes;
    uint32_t workgroup_x;
    int exact;
} RuntimeGeometry;

typedef enum {
    A_NONE = 0,
    A_PROVIDER_RANGE = 1ull << 0,
    A_WARM = 1ull << 1,
    A_HOT = 1ull << 3,
    A_CONSUMER_IMPORTED = 1ull << 4,
    A_MODEL_OP_RAN = 1ull << 5,
    A_BLOCK_OP_RAN = 1ull << 6,
    A_OUTPUT_NORM_RAN = 1ull << 7,
    A_LOGITS_RAN = 1ull << 8
} Deep2Authority;

/* Q6_K lm-head geometry target (DeepSeek shard-1 output.weight):
 * CODEC=14 INPUT=7168 OUTPUT=129280 TENSOR_BYTES=760166400 */
#endif
