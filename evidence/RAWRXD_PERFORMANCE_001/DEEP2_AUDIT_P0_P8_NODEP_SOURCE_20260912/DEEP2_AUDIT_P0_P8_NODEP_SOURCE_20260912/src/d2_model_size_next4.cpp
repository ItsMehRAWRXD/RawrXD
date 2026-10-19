#include "deep2_audit_nodep.h"
extern "C" int d2_next4_ready(const D2Next4State* s) {
    if (!s) return 0;
    if (!s->residency_solver || !s->packed_execution || !s->predictive_expert_cache || !s->adaptive_kv) return 0;
    if (s->materialized_weight_bytes != 0) return 0;
    if (s->critical_path_nvme_reads_per_token != 0) return 0;
    return 1;
}
