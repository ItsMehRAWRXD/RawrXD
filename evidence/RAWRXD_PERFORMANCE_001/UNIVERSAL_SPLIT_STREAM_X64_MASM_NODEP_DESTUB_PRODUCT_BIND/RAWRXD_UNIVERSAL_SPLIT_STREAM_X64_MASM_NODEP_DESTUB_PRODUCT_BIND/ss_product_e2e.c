/* ss_product_e2e.c — deep2_benchmark --phase split-stream → MASM destub phase */
#include "ss_phase_abi.h"
#include "duo_ticket.h"
#include "duo_emit.h"
#include "enterprise_abi.h"
#include "ss_evidence.h"
#include "ss_model_plan.h"
#include <stdio.h>
#include <string.h>
int ss_product_e2e(const char *model_path, const char *prompt)
{
    SSGpuBackend be; SSPhaseArgs a; SSPhaseResult r;
    static SsModelPlan plan;
    const char *stop; int math_obs, model_op, block_op, onorm_op, logits_op, token_op;
    (void)prompt;
    memset(&be, 0, sizeof be); memset(&a, 0, sizeof a); memset(&r, 0, sizeof r);
    memset(&plan, 0, sizeof plan);
    ss_barrier_reset(); ss_copy_reset();
    printf("PRODUCT_BINARY=deep2_benchmark.exe\nPHASE=split-stream\n");
    printf("MODEL=%s\n", model_path ? model_path : "");
    printf("FULL_MODEL_INIT_BYPASSED=1 UNIVERSAL_SPLIT_STREAM_DESTUB=1\n");
    if (!model_path) { printf("TOKEN_COMMIT=NOT_RUN PROMOTE=0\n"); return 20; }
    /* Phase-0: observe model plan only — never mints FULL_MODEL_FORWARD. */
    if (ss_model_plan_build_split(model_path, &plan) == 0) {
        ss_model_plan_print(&plan);
        ss_model_plan_print_inventory(&plan);
    } else {
        printf("MODEL_PLAN_REAL=0 MULTI_SHARD_INVENTORY_PASS=0 FULL_MODEL_FORWARD=0\n");
        if (plan.metaReal) ss_model_plan_print(&plan);
    }
    if (ss_d3d12_backend_init()) {
        printf("D3D12_HOT=NOT_RUN PHASE_RC=BACKEND TOKEN_COMMIT=NOT_RUN PROMOTE=0\n");
        return 28;
    }
    ss_geo_indep_output_weight(model_path);
    ss_q6k_row_oracle(model_path);
    be.promote_fn = ss_d3d12_promote;
    be.release_fn = ss_d3d12_release;
    be.consume_fn = ss_d3d12_consume;
    ss_d3d12_set_shard(model_path);
    ss_d3d12_set_plan(&plan);
    a.shard1_path = model_path;
    a.model_id = 1; a.model_generation = 1; a.op_ticket = 1; a.owner_cookie = 1;
    a.host_budget = 8ull << 30; a.gpu_budget = 8ull << 30; a.gpu_backend = &be;
    ss_product_split_phase(&a, &r);
    model_op = r.deep2_consume_status >= SS_DEEP2_MODEL_OP;
    block_op = r.deep2_consume_status >= SS_DEEP2_BLOCK_OP;
    onorm_op = r.deep2_consume_status >= SS_DEEP2_OUTPUT_NORM;
    logits_op = r.deep2_consume_status >= SS_DEEP2_LOGITS;
    token_op = r.deep2_consume_status >= SS_DEEP2_TOKEN;
    math_obs = model_op ? 1 : 0;
    printf("ANCHOR_FOUND=%llu WHICH=%llu PROVIDER_RANGE off=%llu len=%llu\n",
           (unsigned long long)r.gguf_anchor_found, (unsigned long long)r.anchor_which,
           (unsigned long long)r.file_offset, (unsigned long long)r.region_bytes);
    printf("WARM=%llu HOT=%llu GPU=%llu PCI=0x%llX PARITY=%llu MG_LOADS=%llu HOT_HITS=%llu\n",
           (unsigned long long)r.warm_pass, (unsigned long long)r.hot_pass,
           (unsigned long long)r.gpu, (unsigned long long)r.pci_device,
           (unsigned long long)r.readback_parity, (unsigned long long)r.mg_loads,
           (unsigned long long)r.hot_hits);
    printf("DEEP2_CONSUME_D3D12_HOT=%s DEEP2_IMPORTED_MODEL_OP=%s DEEP2_IMPORTED_BLOCK_OP=%s\n",
           r.deep2_consume_status >= SS_DEEP2_CONSUMED ? "PASS" : "NOT_RUN",
           model_op ? "PASS" : "NOT_RUN", block_op ? "PASS" : "NOT_RUN");
    printf("DEEP2_OUTPUT_NORM=%s DEEP2_LOGITS=%s DEEP2_TOKEN=%s PHASE_RC=%llu\n",
           onorm_op ? "PASS" : "NOT_RUN", logits_op ? "PASS" : "NOT_RUN",
           token_op ? "PASS" : "NOT_RUN", (unsigned long long)r.phase_rc);
    printf("TOKEN_COMMIT=%s\n",
           r.token_commit_status == SS_TOKEN_COMMIT_OK ? "PASS" : "NOT_RUN");
    {
        DuoTicket dt;
        duo_ingest_split_stream(&dt, r.file_offset, 1, r.file_offset, r.region_bytes,
                                (int)r.gguf_anchor_found, r.warm_pass, r.mg_loads,
                                r.hot_pass, 1, (int)r.readback_parity, (int)r.gpu,
                                a.owner_cookie, 0);
        if (r.deep2_consume_status >= SS_DEEP2_IMPORTED)
            duo_observe_interop(&dt, r.file_offset, 1, 1);
        if (r.deep2_consume_status >= SS_DEEP2_CONSUMED)
            duo_observe_consumer_ran(&dt, r.file_offset, 1);
        if (logits_op) duo_observe_logits(&dt, r.file_offset, 1);
        if (token_op) duo_observe_token(&dt, r.file_offset, 1);
        if (token_op) stop = "ABBREVIATED_DECODE_HOLD";
        else if (logits_op) stop = "TOKEN_NOT_RUN";
        else if (onorm_op) stop = "LM_HEAD_NOT_RUN";
        else if (block_op) stop = "OUTPUT_NORM_NOT_RUN";
        else if (model_op) stop = "LM_HEAD_NOT_RUN";
        else if (r.deep2_consume_status == SS_DEEP2_CONSUMED) stop = "LOGITS_NOT_RUN";
        else if (r.deep2_consume_status == SS_DEEP2_IMPORTED) stop = "DEEP2_PRIMITIVE_NOT_RUN";
        else stop = "D3D12_VULKAN_INTEROP_NOT_ESTABLISHED";
        duo_print_disposition(&dt, stop);
        ent_print_split_stream(r.region_bytes && r.gguf_anchor_found, r.phase_rc, math_obs);
        ss_gate_reconcile(r.deep2_consume_status, r.phase_rc, model_op, block_op, math_obs);
    }
    printf("DECODE_KIND=ABBREVIATED_SPLIT_STREAM FULL_MODEL_FORWARD=0 TPS_SCOPE=PRODUCT_CHAIN_ONLY\n");
    printf("MULTIMODEL_SPLIT_STREAM_PRODUCT_E2E_001=OPEN MG_REDEFINED=0 PROMOTE=0\n");
    ss_d3d12_backend_shutdown();
    return (int)r.phase_rc;
}
