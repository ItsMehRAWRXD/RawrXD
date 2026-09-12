/* ss_product.c — REAL file → plan → MG/WARM → D3D12 HOT → Q4_K primitive */
#include "ss_product.h"
#include "ss_gguf_find.h"
#include "ur_plan.h"
#include <stdio.h>
#include <string.h>
#include <math.h>
int ss_q4k_block(const uint8_t *b, float *y);

int ss_product_e2e(const char *model_path, const char *prompt)
{
    UrFileProvider fp; UrProviderVTable pvt; UrGpuDevice gd; UrDeviceVTable dvt;
    UrRuntime rt; UrRegionDesc desc; UrOpPlan plan; UrRegionId id; UrTicket tk;
    SsTensorHit hit; const uint8_t *p = 0; uint64_t n = 0, row_b;
    UrGeneration g = 0; UrResidencyState st; float y[256]; int i, finite = 0, gpu = 0;
    const char *name = "token_embd.weight";

    (void)prompt;
    printf("PRODUCT_BINARY=deep2_benchmark.exe\nPHASE=split-stream\n");
    printf("MODEL=%s\n", model_path ? model_path : "");
    if (!model_path || ss_gguf_find(model_path, name, &hit) || !hit.found) {
        printf("ADAPTER_TENSOR=FAIL NAME=%s\nTOKEN_COMMIT=NOT_RUN\nPROMOTE=0\n", name);
        return 2;
    }
    if (hit.type != 12 || hit.dims[0] < 256) {
        printf("ADAPTER_TENSOR=WRONG_TYPE type=%u d0=%llu\nPROMOTE=0\n",
               hit.type, (unsigned long long)hit.dims[0]);
        return 3;
    }
    row_b = (hit.dims[0] / 256ull) * 144ull;
    printf("ADAPTER_TENSOR=PASS NAME=%s TYPE=Q4_K FILE_OFF=%llu ROW_BYTES=%llu\n",
           name, (unsigned long long)hit.file_off, (unsigned long long)row_b);

    if (ur_file_open(&fp, model_path)) return 4;
    ur_file_as_vtable(&fp, &pvt);
    ur_runtime_init(&rt, pvt, 0xD2671u);
    memset(&desc, 0, sizeof desc);
    desc.model = 1; desc.model_gen = 1; desc.provider = 1;
    desc.offset = hit.file_off; desc.length = row_b;
    id = ur_region_id_from_desc(&desc);
    if (ur_index_put(&rt.index, id, &desc) || ur_op_begin(&rt.auth, rt.owner, &tk)
        || ur_plan_begin(&plan, 1, 1, 1, tk) || ur_plan_add(&plan, id, UR_LANE_SHARED)
        || ur_plan_require(&rt, &plan)) {
        printf("PLAN_REQUIRE=FAIL\nPROMOTE=0\n"); ur_runtime_shutdown(&rt); ur_file_close(&fp); return 5;
    }
    printf("CURRENT_OP_REGION_PLAN=1 MG_LOADS=%llu WARM=1\n",
           (unsigned long long)rt.tel.mg_loads);

    if (ur_gpudev_init(&gd) == 0 && gd.discrete && !gd.uma) {
        ur_gpudev_as_vtable(&gd, &dvt); ur_runtime_set_device(&rt, dvt);
        if (ur_promote_hot_at(&rt, id, 0) == 0 && ur_region_state(&rt, id, &st) == 0
            && st == UR_HOT && gd.byte_parity) {
            gpu = 1;
            printf("D3D12_HOT=1 PCI=0x%04X UMA=0 PARITY=1 COPY=%llu\n",
                   gd.pci, (unsigned long long)gd.gpu_copy_bytes);
        }
    }
    if (!gpu) printf("D3D12_HOT=NOT_RUN\n");

    if (usr_require(&rt, id, tk, &p, &n) || !p || n < 144 || ss_q4k_block(p, y)) {
        printf("TENSOR_PRIMITIVE=FAIL\nTOKEN_COMMIT=NOT_RUN\nPROMOTE=0\n");
        ur_runtime_shutdown(&rt); ur_file_close(&fp); if (gd.dev) ur_gpudev_shutdown(&gd);
        return 6;
    }
    for (i = 0; i < 256; i++) if (y[i] == y[i]) finite++;
    printf("TENSOR_PRIMITIVE=Q4_K_DEQUANT FINITE=%d\n", finite);
    printf("DEEP2_FORWARD=NOT_RUN LOGITS=NOT_RUN TOKEN_COMMIT=NOT_RUN\n");
    printf("MULTIMODEL_SPLIT_STREAM_PRODUCT_E2E_001=OPEN\n");
    {
        int bind_ok = (rt.tel.mg_loads == 1 && finite == 256);
        printf("SPLIT_STREAM_PRODUCT_BIND_001=%s MG_REDEFINED=0 PROMOTE=0\n",
               bind_ok ? "PASS" : "FAIL");
        ur_op_end(&rt.auth, rt.owner, tk, 1);
        ur_runtime_shutdown(&rt); ur_file_close(&fp);
        if (gd.dev) ur_gpudev_shutdown(&gd);
        return bind_ok ? 0 : 7;
    }
}
