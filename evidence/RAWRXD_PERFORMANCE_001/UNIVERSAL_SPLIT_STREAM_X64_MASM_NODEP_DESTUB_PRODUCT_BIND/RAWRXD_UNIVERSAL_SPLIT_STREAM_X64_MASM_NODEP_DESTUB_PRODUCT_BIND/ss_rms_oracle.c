/* ss_rms_oracle.c — CPU RMSNorm reference vs GPU buffer (numeric oracle) */
#include "ss_evidence.h"
#include "ss_vk_api.h"
#include <stdio.h>
#include <math.h>
#include <stdint.h>
static int finf(float x) { return x == x && x <= 1e30f && x >= -1e30f; }
int ss_rms_oracle(const float *x, const float *w, const float *y_gpu, uint32_t n, float eps)
{
    double acc = 0.0, max_abs = 0.0; uint32_t i, bad = 0; float inv;
    if (!x || !w || !y_gpu || !n) return 1;
    for (i = 0; i < n; ++i) acc += (double)x[i] * (double)x[i];
    inv = (float)(1.0 / sqrt(acc / (double)n + (double)eps));
    for (i = 0; i < n; ++i) {
        float ref = x[i] * inv * w[i], d;
        if (!finf(y_gpu[i]) || !finf(ref)) { bad = i + 1; break; }
        d = y_gpu[i] - ref; if (d < 0) d = -d;
        if (d > max_abs) max_abs = d;
        if (d > 1e-3f) { bad = i + 1; break; }
    }
    printf("RMS_ORACLE n=%u max_abs_err=%.9g first_bad=%u %s\n",
           n, max_abs, bad, bad ? "FAIL" : "PASS");
    printf("RMS_ORACLE_SOURCE=CPU_SCALAR_VS_GPU_BUFFER TOL=1e-3\n");
    return bad ? 1 : 0;
}
