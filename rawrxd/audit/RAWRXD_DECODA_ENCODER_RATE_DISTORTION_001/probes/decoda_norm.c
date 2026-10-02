/* decoda_norm.c -- is the harness's 2-bit level set a mis-normalization?
 *
 * decoda.cpp:377  q <<= (residual_bits_ - planes)   -> q in {0,1024,2048,3072}
 * decoda.cpp:405  v = residual_scale_[row] * (q / qmax), qmax = 4095
 *
 * => levels {0, 1/4, 1/2, 3/4} * scale.  Only 75% of range reachable.
 * => normalized would be      {0, 1/3, 2/3, 1.0} * scale
 * => max-reachable would be   {0, 1/4, 1/2, 3/4} normalized by 3/4 = same as
 *    normalized, i.e. {0, 1/3, 2/3, 1.0}
 *
 * Three level sets, same rate, same metric:
 *   HARNESS  q/qmax          = {0, .2500, .5000, .7500}
 *   NORMAL   (q<<s)/((qmax>>s)) = {0, .3333, .6667, 1.0000}
 *   OPTIMAL  Lloyd-Max on the inlier residual, 2^planes levels
 *
 * Build: cl /O2 decoda_norm.c /Fe:decoda_norm.exe
 */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>


#define COLS 2048
#define MAXROWS 4096
#define MAXN (MAXROWS * COLS)

static float g_w[MAXN];
static double g_den;

typedef struct { float *hat; double num; } R;

static int g_n, g_rows;
static double measure(const float *hat)
{
    double num = 0;
    for (int i = 0; i < g_n; i++) {
        double d = (double)g_w[i] - hat[i];
        num += d * d;
    }
    return sqrt(num / g_den);
}

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : "blk_9_ffn_gate_exps_weight.f32";
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return 1; }
    if (fseek(f,0,SEEK_END)==0) { long z=ftell(f); fseek(f,0,SEEK_SET); g_n=(int)(z/4); } if (g_n<=0||g_n>MAXN) { fprintf(stderr,"bad n\n"); return 1; } g_rows=g_n/COLS; if (fread(g_w, 4, g_n, f) != (size_t)g_n) { fprintf(stderr, "short read\n"); return 1; }
    fclose(f);
    g_den = 0;
    for (int i = 0; i < g_n; i++) g_den += (double)g_w[i] * g_w[i];

    printf("RAWRXD_DECODA_NORM_001\n");
    printf("source: %s  elements=%d  rows=%d\n\n", path, g_n, g_rows);
    printf("level sets at p planes (fraction of per-row scale):\n");
    printf("  p=1  harness {.5}      normalized {1}       lloyd {per-block}\n");
    printf("  p=2  harness {.25,.5,.75}  normalized {1/3,2/3,1}  lloyd {per-block}\n\n");

    float *hat = (float *)malloc((size_t)g_n * sizeof(float));
    float *lev = (float *)malloc((size_t)g_rows * 4096 * sizeof(float));
    if (!hat || !lev) { fprintf(stderr, "oom\n"); return 1; }

    printf("%3s %14s %14s %14s %10s\n",
           "p", "harness", "normalized", "lloyd_row", "norm_gain%");

    for (int p = 1; p <= 6; p++) {
        const int RB = 12;
        const unsigned qmax = (1u << RB) - 1u;

        /* --- build the same tensor state the harness builds --- */
        float *resid = (float *)malloc((size_t)g_n * sizeof(float));
        /* ternary base, span 64, per decoda.cpp:139-179 */
        {
            const int span = 64;
            int nb = g_n / span;
            double *alpha = (double *)malloc(nb * sizeof(double));
            for (int b = 0; b < nb; b++) {
                int begin = b * span, end = begin + span;
                double ma = 0;
                for (int i = begin; i < end; i++) ma += fabs((double)g_w[i]);
                double a = ma / span; if (!(a > 0)) a = 0;
                for (int pass = 0; pass < 2 && a > 0; pass++) {
                    double th = 0.5 * a, s = 0; int nz = 0;
                    for (int i = begin; i < end; i++)
                        if (fabs((double)g_w[i]) >= th) { s += fabs((double)g_w[i]); nz++; }
                    if (nz) a = s / nz;
                }
                alpha[b] = a; double th = 0.5 * a;
                for (int i = begin; i < end; i++) {
                    double q = 0;
                    if (a > 0 && (double)g_w[i] >=  th) q =  a;
                    if (a > 0 && (double)g_w[i] <= -th) q = -a;
                    resid[i] = g_w[i] - (float)q;
                }
            }
            free(alpha);
        }
        /* outliers: 3 * per-row rms(residual); outliers carried EXACT */
        unsigned char *is_out = (unsigned char *)calloc((size_t)g_n,1);
        for (int r = 0; r < g_rows; r++) {
            size_t s = (size_t)r*COLS, e = (size_t)(r+1)*COLS;
            double sq = 0; for (size_t i = s; i < e; i++) sq += (double)resid[i] * resid[i];
            double rms = sqrt(sq / COLS), th = 3.0 * rms;
            for (size_t i = s; i < e; i++)
                if (rms > 0 && fabs((double)resid[i]) > th) is_out[i] = 1;
        }
        /* residual scale per row, outliers zeroed: decoda.cpp:212-221 */
        float *rs = (float *)malloc((size_t)g_rows * sizeof(float));
        float *rem = (float *)malloc((size_t)g_n * sizeof(float));
        for (int i = 0; i < g_n; i++) rem[i] = is_out[i] ? 0.0f : resid[i];
        for (int r = 0; r < g_rows; r++) {
            size_t s = (size_t)r*COLS, e = (size_t)(r+1)*COLS;
            float mx = 0;
            for (size_t i = s; i < e; i++) { float a = fabsf(rem[i]); if (a > mx) mx = a; }
            rs[r] = mx;
        }
        /* 12-bit magnitude code, decoda.cpp:228-241 */
        unsigned *q12 = (unsigned *)malloc((size_t)g_n * sizeof(unsigned));
        for (int r = 0; r < g_rows; r++) {
            size_t s = (size_t)r*COLS, e = (size_t)(r+1)*COLS;
            float sc = rs[r];
            for (size_t i = s; i < e; i++) {
                unsigned q = 0;
                if (sc > 0) {
                    double z = fabs((double)rem[i]) / sc;
                    q = (unsigned)llround(z * qmax);
                    if (q > qmax) q = qmax;
                }
                q12[i] = q;
            }
        }

        /* --- HARNESS: prefix << then /qmax --- */
        /* reconstructed = base + (outlier ? exact resid : quantized rem)
           base = w - resid, and rem == resid for non-outliers            */
        for (int r = 0; r < g_rows; r++) {
            size_t s = (size_t)r*COLS, e = (size_t)(r+1)*COLS;
            for (size_t i = s; i < e; i++) {
                float base = g_w[i] - resid[i];
                if (is_out[i]) { hat[i] = base + resid[i]; continue; }
                unsigned qp = (q12[i] >> (RB - p)) << (RB - p);
                float v = rs[r] * ((float)qp / (float)qmax);
                hat[i] = base + (rem[i] < 0 ? -v : v);
            }
        }
        double eh = measure(hat);

        /* --- NORMALIZED: same prefix, divide by (qmax>>(RB-p)) --- */
        unsigned den_n = ((1u << p) - 1u) << (RB - p);
        if (den_n == 0) den_n = 1;
        for (int r = 0; r < g_rows; r++) {
            size_t s = (size_t)r*COLS, e = (size_t)(r+1)*COLS;
            for (size_t i = s; i < e; i++) {
                float base = g_w[i] - resid[i];
                if (is_out[i]) { hat[i] = base + resid[i]; continue; }
                unsigned qp = (q12[i] >> (RB - p)) << (RB - p);
                float v = rs[r] * ((float)qp / (float)den_n);
                hat[i] = base + (rem[i] < 0 ? -v : v);
            }
        }
        double en = measure(hat);

        /* --- LLOYD, per row, on the inlier residual, 2^p levels --- */
        {
            unsigned L = 1u << p;
            for (int r = 0; r < g_rows; r++) {
                size_t s = (size_t)r*COLS, e = (size_t)(r+1)*COLS;
                float *lv = lev + (size_t)r * L;
                double *acc = (double *)calloc(L, sizeof(double));
                unsigned *cnt = (unsigned *)calloc(L, sizeof(unsigned));
                for (unsigned k = 0; k < L; k++) lv[k] = ((float)k + 0.5f) / (float)L;
                float sc = rs[r] > 0 ? rs[r] : 1.0f;
                for (int it = 0; it < 12; it++) {
                    for (unsigned k = 0; k < L; k++) { acc[k] = 0; cnt[k] = 0; }
                    for (size_t i = s; i < e; i++) {
                        if (is_out[i]) continue;
                        double z = fabs((double)rem[i]) / sc;
                        unsigned k = (unsigned)(z * L); if (k >= L) k = L - 1;
                        acc[k] += z; cnt[k]++;
                    }
                    for (unsigned k = 0; k < L; k++) if (cnt[k]) lv[k] = (float)(acc[k] / cnt[k]);
                }
                for (size_t i = s; i < e; i++) {
                    float base = g_w[i] - resid[i];
                    if (is_out[i]) { hat[i] = base + resid[i]; continue; }
                    double z = fabs((double)rem[i]) / sc;
                    unsigned k = (unsigned)(z * L); if (k >= L) k = L - 1;
                    float v = lv[k] * sc;
                    hat[i] = base + (rem[i] < 0 ? -v : v);
                }
                free(acc); free(cnt);
            }
        }
        double el = measure(hat);

        printf("%3d %14.6f %14.6f %14.6f %9.2f%%\n",
               p, eh, en, el, 100.0 * (eh - en) / eh);

        free(resid); free(is_out); free(rs); free(rem); free(q12);
    }

    free(hat); free(lev);
    return 0;
}

