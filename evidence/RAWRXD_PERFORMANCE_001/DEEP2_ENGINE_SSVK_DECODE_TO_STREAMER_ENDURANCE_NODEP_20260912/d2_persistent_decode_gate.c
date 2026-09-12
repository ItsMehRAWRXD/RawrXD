#include "d2_persistent_decode_gate.h"
#include <string.h>

void d2_persistent_gate_init(
    D2PersistentGate* g, D2DecodeBind* bind, uint64_t window_target)
{
    if (!g) return;
    memset(g, 0, sizeof(*g));
    g->bind = bind;
    g->window_target = window_target ? window_target : 16;
}

int d2_persistent_gate_run(D2PersistentGate* g) {
    uint64_t i;
    if (!g || !g->bind) return D2X_EINVAL;

    for (i = 0; i < g->window_target; ++i) {
        uint32_t tok = 0;
        D2DecodeReceipt r;
        int rc = d2_decode_bind_one(g->bind, &tok, 0, 0, &r);
        (void)tok;

        g->command_rebuilds += r.command_rebuilds_this_token;
        g->kv_host_roundtrips += r.kv_host_roundtrips;
        g->nvme_reads += r.critical_path_nvme_reads;
        g->external_runtime_calls += r.external_runtime_calls;
        g->host_forward_calls += r.host_forward_layer_calls;
        g->host_materializations += r.host_materializations;

        if (rc == D2X_OK) g->pass_tokens++;
        else {
            g->bad_tokens++;
            return rc;
        }
    }
    return d2_persistent_gate_pass(g) ? D2X_OK : D2X_EAUTH;
}

int d2_persistent_gate_pass(const D2PersistentGate* g) {
    if (!g || !g->bind) return 0;
    return
        g->pass_tokens == g->window_target &&
        g->bad_tokens == 0 &&
        g->bind->persistent_prepares == 1 &&
        g->command_rebuilds == 0 &&
        g->kv_host_roundtrips == 0 &&
        g->nvme_reads == 0 &&
        g->external_runtime_calls == 0 &&
        g->host_forward_calls == 0 &&
        g->host_materializations == 0;
}
