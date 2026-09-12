/* ss_silu_host.c — SiLU(gate)*up in-place into out */
#include <math.h>
#include <stdint.h>
void ss_silu_mul(const float *g, const float *u, float *out, uint32_t n)
{
    uint32_t i; float x, s;
    for (i = 0; i < n; ++i) {
        x = g[i];
        s = x / (1.f + expf(-x));
        out[i] = s * u[i];
    }
}
