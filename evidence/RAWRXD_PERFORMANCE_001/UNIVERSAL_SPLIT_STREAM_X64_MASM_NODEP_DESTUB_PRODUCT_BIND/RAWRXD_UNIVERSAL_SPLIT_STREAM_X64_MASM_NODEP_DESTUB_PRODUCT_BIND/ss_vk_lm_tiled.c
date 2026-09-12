/* ss_vk_lm_tiled.c — full vocab via ≤32768-row GEMV tiles (post ladder) */
#include "ss_vk_api.h"
#include "ss_vk_ops.h"
#include "ss_vk_survive.h"
#include <stdio.h>
int ss_vk_lm_tiled_gemv(SsVk *v, VkBuffer ww, uint64_t wbytes, uint32_t rows,
                        uint32_t cols, uint32_t codec, uint32_t tile)
{
    uint32_t base, n, stride; uint64_t w_off, y_off, tile_w;
    int rc; SsSurviveSnap s;
    if (!v || !ww || !rows || !cols || !tile || !v->logitsb) return 100;
    if (codec == 14) stride = ((cols + 255u) / 256u) * 210u;
    else if (codec == 12) stride = ((cols + 255u) / 256u) * 144u;
    else stride = cols * 4u;
    printf("LM_HEAD_TILED tile=%u rows=%u stride=%u codec=%u\n",
           tile, rows, stride, codec);
    fflush(stdout);
    for (base = 0; base < rows; base += tile) {
        n = rows - base; if (n > tile) n = tile;
        w_off = (uint64_t)base * (uint64_t)stride;
        y_off = (uint64_t)base * 4ull;
        tile_w = (uint64_t)n * (uint64_t)stride;
        if (w_off + tile_w > wbytes) return 100;
        rc = ss_vk_op_gemv_tile(v, ww, w_off, tile_w, v->actb, v->logitsb, y_off,
                                n, cols, codec);
        if (rc) {
            printf("LM_TILE_FAIL base=%u n=%u rc=%d\n", base, n, rc);
            return 100;
        }
        if (((base / tile) & 3u) == 0u) {
            ss_vk_survive_probe(v, "AFTER_LM_TILE", 0, &s);
            if (!s.device_alive || !s.noop_submit_ok) {
                printf("LM_TILE_DEVICE_LOST base=%u LAST_VR=%d\n",
                       base, (int)s.last_vr);
                return 100;
            }
        }
    }
    ss_vk_survive_probe(v, "AFTER_LM_TILED_FULL", 0, &s);
    printf("LM_HEAD_TILED_FULL DEVICE_ALIVE=%d NOOP=%d\n",
           s.device_alive, s.noop_submit_ok);
    fflush(stdout);
    return (s.device_alive && s.noop_submit_ok) ? 0 : 100;
}
