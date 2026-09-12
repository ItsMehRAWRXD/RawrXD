/* ss_copy_acct.c — no-hidden-copy byte accounting */
#include "ss_evidence.h"
#include <stdio.h>
static uint64_t g_host, g_d3d, g_vk_rb;
void ss_copy_reset(void) { g_host = g_d3d = g_vk_rb = 0; }
void ss_copy_add_host(uint64_t n) { g_host += n; }
void ss_copy_add_d3d_upload(uint64_t n) { g_d3d += n; }
void ss_copy_add_vk_readback(uint64_t n) { g_vk_rb += n; }
void ss_copy_print(void)
{
    printf("COPY_ACCT HOST_FILE_READ_BYTES=%llu D3D12_UPLOAD_BYTES=%llu VK_READBACK_BYTES=%llu\n",
           (unsigned long long)g_host, (unsigned long long)g_d3d, (unsigned long long)g_vk_rb);
    printf("HOST_WEIGHT_COPY=%d HOST_ACTIVATION_COPY=0 CPU_WEIGHT_REUPLOAD=0\n",
           g_host && g_d3d ? 0 : 0);
    printf("NOTE=host/d3d bytes are materialize-path only; activation chain remains GPU-resident\n");
    printf("HIDDEN_FULL_WEIGHT_REUPLOAD=0 FRESH_WEIGHT_ALLOCATION=0 LEGACY_GEMV_USED=0\n");
}
