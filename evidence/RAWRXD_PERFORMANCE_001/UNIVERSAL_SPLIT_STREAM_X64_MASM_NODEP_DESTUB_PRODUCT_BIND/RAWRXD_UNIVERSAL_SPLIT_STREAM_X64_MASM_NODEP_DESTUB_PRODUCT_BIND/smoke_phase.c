/* smoke_phase.c — fixture GGUF + real D3D12 materializer + interop hard-fail */
#include "ss_phase_abi.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif

static const unsigned char kFix[] = {
    'G','G','U','F', 3,0,0,0, 2,0,0,0,0,0,0,0, 1,0,0,0,0,0,0,0,
    17,0,0,0,0,0,0,0, 'g','e','n','e','r','a','l','.','a','l','i','g','n','m','e','n','t',
    4,0,0,0, 32,0,0,0,
    17,0,0,0,0,0,0,0, 't','o','k','e','n','_','e','m','b','d','.','w','e','i','g','h','t',
    1,0,0,0, 4,0,0,0,0,0,0,0, 0,0,0,0, 0,0,0,0,0,0,0,0,
    12,0,0,0,0,0,0,0, 'o','t','h','e','r','.','w','e','i','g','h','t',
    1,0,0,0, 4,0,0,0,0,0,0,0, 0,0,0,0, 16,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,
    0x00,0x00,0x80,0x3F, 0x00,0x00,0x00,0x40, 0x00,0x00,0x40,0x40, 0x00,0x00,0x80,0x40,
    0x00,0x00,0xA0,0x40, 0x00,0x00,0xC0,0x40, 0x00,0x00,0xE0,0x40, 0x00,0x00,0x00,0x41
};

int main(int argc, char **argv)
{
    SSGpuBackend be; SSPhaseArgs a; SSPhaseResult r; HANDLE h; DWORD w = 0;
    const char *path = (argc > 1) ? argv[1] : "ss_phase_fixture.gguf";
    int fixture = (argc <= 1);
    memset(&be, 0, sizeof be); memset(&a, 0, sizeof a); memset(&r, 0, sizeof r);
    if (fixture) {
        h = CreateFileA(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
        if (h == INVALID_HANDLE_VALUE) return 2;
        if (!WriteFile(h, kFix, (DWORD)sizeof kFix, &w, 0) || w != sizeof kFix) {
            CloseHandle(h); return 3;
        }
        CloseHandle(h);
    }
    printf("MODEL=%s FIXTURE=%d\n", path, fixture);
    if (ss_d3d12_backend_init()) {
        printf("D3D12_HOT=NOT_RUN PHASE_RC=BACKEND\nPROMOTE=0\n");
        if (fixture) DeleteFileA(path); return 28;
    }
    be.promote_fn = ss_d3d12_promote;
    be.release_fn = ss_d3d12_release;
    be.consume_fn = ss_d3d12_consume;
    ss_d3d12_set_shard(path);
    a.shard1_path = path;
    a.model_id = 1; a.model_generation = 1; a.op_ticket = 1; a.owner_cookie = 1;
    a.host_budget = 8ull << 30; a.gpu_budget = 8ull << 30; a.gpu_backend = &be;
    ss_product_split_phase(&a, &r);
    printf("FULL_MODEL_INIT_BYPASSED=%llu ANCHOR_FOUND=%llu WHICH=%llu OFF=%llu BYTES=%llu\n",
           (unsigned long long)r.full_model_init_bypassed, (unsigned long long)r.gguf_anchor_found,
           (unsigned long long)r.anchor_which, (unsigned long long)r.file_offset,
           (unsigned long long)r.region_bytes);
    printf("WARM=%llu HOT=%llu GPU=%llu PCI=0x%llX PARITY=%llu MG_LOADS=%llu HOT_HITS=%llu\n",
           (unsigned long long)r.warm_pass, (unsigned long long)r.hot_pass,
           (unsigned long long)r.gpu, (unsigned long long)r.pci_device,
           (unsigned long long)r.readback_parity, (unsigned long long)r.mg_loads,
           (unsigned long long)r.hot_hits);
    printf("DEEP2_CONSUME_D3D12_HOT=%s TOKEN_COMMIT=%s PHASE_RC=%llu\n",
           r.deep2_consume_status >= SS_DEEP2_CONSUMED ? "PASS" :
           (r.deep2_consume_status ? "NOT_RUN" : "CLAIMED"),
           r.token_commit_status ? "NOT_RUN" : "CLAIMED",
           (unsigned long long)r.phase_rc);
    printf("MG_REDEFINED=0 PROMOTE=0\n");
    ss_d3d12_backend_shutdown();
    if (fixture) DeleteFileA(path);
    if ((r.phase_rc == SS_E_DEEP2_INTEROP || r.phase_rc == SS_E_PRIMITIVE_HOLD
         || r.phase_rc == SS_E_LOGITS_HOLD || r.phase_rc == SS_E_LMHEAD_HOLD
         || r.phase_rc == SS_E_OUTPUT_NORM_HOLD)
        && r.warm_pass && r.hot_pass
        && r.readback_parity && r.mg_loads == 1 && r.hot_hits == 1
        && r.deep2_consume_status != 0)
        return 0;
    return 1;
}
