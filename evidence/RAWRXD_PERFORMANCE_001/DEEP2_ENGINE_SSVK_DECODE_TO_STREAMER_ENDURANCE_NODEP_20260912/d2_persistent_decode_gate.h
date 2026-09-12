#ifndef D2_PERSISTENT_DECODE_GATE_H
#define D2_PERSISTENT_DECODE_GATE_H

#include "d2_engine_ssvk_decode_bind.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct D2PersistentGate {
    D2DecodeBind* bind;
    uint64_t window_target;
    uint64_t pass_tokens;
    uint64_t bad_tokens;
    uint64_t command_rebuilds;
    uint64_t kv_host_roundtrips;
    uint64_t nvme_reads;
    uint64_t external_runtime_calls;
    uint64_t host_forward_calls;
    uint64_t host_materializations;
} D2PersistentGate;

void d2_persistent_gate_init(
    D2PersistentGate* g, D2DecodeBind* bind, uint64_t window_target);

int d2_persistent_gate_run(D2PersistentGate* g);
int d2_persistent_gate_pass(const D2PersistentGate* g);

#ifdef __cplusplus
}
#endif
#endif
