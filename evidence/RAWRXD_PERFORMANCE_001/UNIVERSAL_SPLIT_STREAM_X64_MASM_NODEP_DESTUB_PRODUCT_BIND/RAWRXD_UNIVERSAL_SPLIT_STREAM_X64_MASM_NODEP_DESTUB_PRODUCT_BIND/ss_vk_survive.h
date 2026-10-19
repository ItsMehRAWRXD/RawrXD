/* ss_vk_survive.h — post-forward device survival; no authority mint */
#ifndef SS_VK_SURVIVE_H
#define SS_VK_SURVIVE_H
#include <stdint.h>
struct SsVk;
typedef struct SsSurviveSnap {
    int device_alive;
    int noop_submit_ok;
    int embd_submit_ok;
    int qidle_ok;
    int32_t last_vr;
    uint64_t heap0_budget;
    uint64_t heap0_usage;
    uint64_t heap1_budget;
    uint64_t heap1_usage;
    const char *when;
} SsSurviveSnap;
void ss_vk_survive_print(const SsSurviveSnap *s);
int ss_vk_survive_budget(struct SsVk *v, SsSurviveSnap *s);
int ss_vk_survive_noop(struct SsVk *v, SsSurviveSnap *s);
int ss_vk_survive_probe(struct SsVk *v, const char *when, int try_embd,
                        SsSurviveSnap *s);
#endif
