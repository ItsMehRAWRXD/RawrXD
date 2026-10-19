/* ss_vk_lm_row_ladder.c — DEEP2_LM_HEAD_GEMV_ROW_LADDER_001 */
#include "ss_vk_api.h"
#include "ss_vk_ops.h"
#include "ss_vk_survive.h"
#include "ss_model_plan.h"
#include <stdio.h>
int ss_vk_lm_row_ladder(SsVk *v, VkBuffer ww, uint64_t wbytes, uint32_t rows,
                        uint32_t cols, uint32_t codec)
{
    static const uint32_t pref[] = {
        256u, 1024u, 4096u, 16384u, 32768u, 65536u, 98304u, 0u
    };
    uint32_t i, n; SsSurviveSnap s; int rc;
    if (!v || !ww || !rows || !cols) return 100;
    if (!v->logitsb) return 100;
    printf("DEEP2_LM_HEAD_GEMV_ROW_LADDER_001 ENTER rows_full=%u cols=%u codec=%u\n",
           rows, cols, codec);
    fflush(stdout);
    for (i = 0; i < sizeof pref / sizeof pref[0]; ++i) {
        n = pref[i] ? pref[i] : rows;
        if (n > rows) n = rows;
        printf("LM_ROWS_REQUESTED=%u WORKGROUP_COUNT_X=%u\n", n, (n + 63u) / 64u);
        fflush(stdout);
        rc = ss_vk_op_gemv_n(v, ww, wbytes, v->actb, v->logitsb, rows, cols, codec, n);
        if (rc) {
            printf("LAST_VALID_ROW=prior FIRST_BAD_ROWS=%u GEMV_RC=%d\n", n, rc);
            printf("DEEP2_LM_HEAD_GEMV_ROW_LADDER_001=FAIL\n");
            fflush(stdout);
            return 100;
        }
        ss_vk_survive_probe(v, "AFTER_LM_GEMV_PREFIX", 0, &s);
        printf("LM_ROWS_DISPATCHED=%u DEVICE_ALIVE=%d NOOP=%d LAST_VR=%d\n",
               n, s.device_alive, s.noop_submit_ok, (int)s.last_vr);
        fflush(stdout);
        if (!s.device_alive || !s.noop_submit_ok) {
            printf("LAST_VALID_ROW=<below %u> FIRST_BAD_ROWS=%u DEVICE_LOST=1\n", n, n);
            printf("DEEP2_LM_HEAD_GEMV_ROW_LADDER_001=FAIL\n");
            fflush(stdout);
            return 100;
        }
        if (n == rows) break;
    }
    printf("LAST_VALID_ROW=%u DEVICE_LOST=0\n", rows);
    printf("DEEP2_LM_HEAD_GEMV_ROW_LADDER_001=PASS\n");
    fflush(stdout);
    return 0;
}
