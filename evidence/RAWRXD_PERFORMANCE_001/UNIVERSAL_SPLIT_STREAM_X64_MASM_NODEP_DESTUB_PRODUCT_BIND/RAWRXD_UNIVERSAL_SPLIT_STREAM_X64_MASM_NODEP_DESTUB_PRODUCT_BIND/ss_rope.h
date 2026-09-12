/* ss_rope.h */
#ifndef SS_ROPE_H
#define SS_ROPE_H
#include <stdint.h>
void ss_rope_apply(float *x, uint32_t heads, uint32_t head_dim, uint32_t rope_dim,
                   uint32_t pos, float freq_base);
int ss_rope_changed(const float *a, const float *b, uint32_t n);
#endif
