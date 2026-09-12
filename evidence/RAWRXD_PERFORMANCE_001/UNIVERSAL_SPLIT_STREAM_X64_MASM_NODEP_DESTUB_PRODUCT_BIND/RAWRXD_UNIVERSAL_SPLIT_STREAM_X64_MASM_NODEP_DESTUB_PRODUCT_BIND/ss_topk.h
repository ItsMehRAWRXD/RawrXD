/* ss_topk.h */
#ifndef SS_TOPK_H
#define SS_TOPK_H
#include <stdint.h>
int ss_topk_softmax(const float *logits, uint32_t n, uint32_t k,
                    uint32_t *ids, float *wts, float *sum_out);
#endif
