#include "deep2_nodep_missing15.h"

static d2_i32 ok_wait(void *p) { (void)p; return 0; }
static d2_i32 ok_submit(void *p) { (void)p; return 0; }

static d2_i32 run_smoke(void) {
    D2SurvivalOps ops;
    D2SurvivalResult sr;
    D2ArenaPlan ap;
    D2Token2Witness w;

    ops.ctx = 0;
    ops.wait_queue_idle = ok_wait;
    ops.submit_noop = ok_submit;
    ops.submit_embd = ok_submit;
    if (d2_post_forward_survival(&ops, &sr) != D2_OK) return 10;
    if (!sr.post_forward_device_alive || sr.promote) return 11;

    ap.gpu_budget = 32ull << 30;
    ap.driver_reserve = 2ull << 30;
    ap.weights = 20ull << 30;
    ap.kv = 2ull << 30;
    ap.persistent = 1ull << 30;
    ap.scratch = 1ull << 30;
    ap.activation_a = 512ull << 20;
    ap.activation_b = 512ull << 20;
    ap.command_descriptor_reserve = 256ull << 20;
    if (d2_arena_plan_finalize(&ap) != D2_OK || !ap.full_gpu_resident) return 20;

    w.target_tokens = 2;
    w.forward_calls = 2;
    w.full_block_forward_calls = 2;
    w.sealed_logits_reuse_token1 = 0;
    w.embd_calls_after_advance = 1;
    w.position0 = 0;
    w.position1 = 1;
    w.commit_calls = 2;
    w.advance_calls = 2;
    w.generated = 2;
    w.device_lost = 0;
    w.auth_autoregressive_commit_granted = 1;
    w.full_model_tps_authority = 0;
    w.promote = 0;
    if (d2_target2_authority_check(&w) != D2_OK) return 30;

    return 0;
}

#ifdef _MSC_VER
__declspec(dllimport) void __stdcall ExitProcess(unsigned int code);
void mainCRTStartup(void) {
    ExitProcess((unsigned int)run_smoke());
}
#else
int main(void) { return (int)run_smoke(); }
#endif
