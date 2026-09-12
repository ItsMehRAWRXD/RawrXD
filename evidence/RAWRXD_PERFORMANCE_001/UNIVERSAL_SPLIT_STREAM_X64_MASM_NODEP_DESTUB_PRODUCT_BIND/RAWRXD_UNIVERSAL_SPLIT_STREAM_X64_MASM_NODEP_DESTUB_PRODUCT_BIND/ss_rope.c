/* ss_rope.c — rotary on last rope_dim of each head */
#include <math.h>
#include <stdint.h>
void ss_rope_apply(float *x, uint32_t heads, uint32_t head_dim, uint32_t rope_dim,
                   uint32_t pos, float freq_base)
{
    uint32_t h, i; float *p; double ang, c, s, x0, x1, inv;
    if (!x || !heads || !head_dim || !rope_dim || rope_dim > head_dim || rope_dim % 2u) return;
    if (freq_base <= 0.f) freq_base = 10000.f;
    inv = 1.0 / (double)rope_dim;
    for (h = 0; h < heads; ++h) {
        p = x + h * head_dim + (head_dim - rope_dim);
        for (i = 0; i < rope_dim; i += 2u) {
            ang = (double)pos / pow((double)freq_base, (double)i * inv);
            c = cos(ang); s = sin(ang);
            x0 = p[i]; x1 = p[i + 1u];
            p[i] = (float)(x0 * c - x1 * s);
            p[i + 1u] = (float)(x0 * s + x1 * c);
        }
    }
}
int ss_rope_changed(const float *a, const float *b, uint32_t n)
{
    uint32_t i;
    if (!a || !b || !n) return 0;
    for (i = 0; i < n; ++i) if (a[i] != b[i]) return 1;
    return 0;
}
