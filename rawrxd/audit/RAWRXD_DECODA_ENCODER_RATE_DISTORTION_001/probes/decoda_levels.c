/* decoda_levels.c -- can ONE level table serve every plane count?
 *
 * Per-row Lloyd at plane count p fits 2^p levels. That is p-dependent, so it
 * breaks progressive decoding unless a single table serves all p.
 *
 * Four level sources, identical distortion metric:
 *   harness  prefix/qmax                       decoda.cpp:405 as-is, 0 extra bits
 *   per_p    exact Lloyd fit for this p         2^p levels/row  (p-dependent table)
 *   subsamp  Lloyd at K_MAX, every 2^(K-p)th    1 table, K_MAX levels/row
 *   interp   Lloyd at K_MAX, linear interp      1 table, K_MAX levels/row
 *
 * Table cost is reported so the gain can be charged against it.
 * Build: cl /O2 decoda_levels.c /Fe:decoda_levels.exe
 */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define COLS   2048
#define MAXROWS 4096
#define MAXN   (MAXROWS * COLS)
#define KMAX   8
#define RB     12
#define QMAX   ((1u << RB) - 1u)

static float g_w[MAXN];
static int   g_n, g_rows;
static double g_den;
static float  *g_rem, *g_rs;
static unsigned char *g_out;
static unsigned *g_q12;

static void prep(void)
{
    int nb = g_n / 64;
    double *alpha = (double *)malloc(nb * sizeof(double));
    float *resid = (float *)malloc((size_t)g_n * sizeof(float));
    for (int b = 0; b < nb; b++) {
        int begin = b * 64, end = begin + 64;
        double ma = 0;
        for (int i = begin; i < end; i++) ma += fabs((double)g_w[i]);
        double a = ma / 64; if (!(a > 0)) a = 0;
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

    g_out = (unsigned char *)calloc((size_t)g_n, 1);
    for (int r = 0; r < g_rows; r++) {
        size_t s = (size_t)r * COLS, e = (size_t)(r + 1) * COLS;
        double sq = 0; for (size_t i = s; i < e; i++) sq += (double)resid[i] * resid[i];
        double rms = sqrt(sq / COLS), th = 3.0 * rms;
        for (size_t i = s; i < e; i++)
            if (rms > 0 && fabs((double)resid[i]) > th) g_out[i] = 1;
    }
    g_rem = (float *)malloc((size_t)g_n * sizeof(float));
    g_rs = (float *)malloc((size_t)g_rows * sizeof(float));
    for (int i = 0; i < g_n; i++) g_rem[i] = g_out[i] ? 0.0f : resid[i];
    for (int r = 0; r < g_rows; r++) {
        size_t s = (size_t)r * COLS, e = (size_t)(r + 1) * COLS;
        float mx = 0;
        for (size_t i = s; i < e; i++) { float a = fabsf(g_rem[i]); if (a > mx) mx = a; }
        g_rs[r] = mx;
    }
    g_q12 = (unsigned *)malloc((size_t)g_n * sizeof(unsigned));
    for (int r = 0; r < g_rows; r++)
        for (int i = r * COLS; i < (r + 1) * COLS; i++) {
            unsigned q = 0;
            if (g_rs[r] > 0) {
                double z = fabs((double)g_rem[i]) / g_rs[r];
                q = (unsigned)llround(z * QMAX); if (q > QMAX) q = QMAX;
            }
            g_q12[i] = q;
        }
    free(resid);
}

static void fit(int r, int L, float *lv)
{
    int s = r * COLS, e = s + COLS;
    double *acc = (double *)calloc(L, sizeof(double));
    unsigned *cnt = (unsigned *)calloc(L, sizeof(unsigned));
    float sc = g_rs[r] > 0 ? g_rs[r] : 1.0f;
    for (int k = 0; k < L; k++) lv[k] = ((float)k + 0.5f) / (float)L;
    for (int it = 0; it < 16; it++) {
        for (int k = 0; k < L; k++) { acc[k] = 0; cnt[k] = 0; }
        for (int i = s; i < e; i++) {
            if (g_out[i]) continue;
            double z = fabs((double)g_rem[i]) / sc;
            int k = (int)(z * L); if (k >= L) k = L - 1;
            acc[k] += z; cnt[k]++;
        }
        for (int k = 0; k < L; k++) if (cnt[k]) lv[k] = (float)(acc[k] / cnt[k]);
    }
    free(acc); free(cnt);
}

/* sum of squared residual error, given a level-lookup for the p-bit prefix */
static double eval(int p, const float *tab, int mode)
{
    double num = 0;
    int L = 1 << p;
    for (int r = 0; r < g_rows; r++) {
        const float *lvK = tab + (size_t)r * (1 << KMAX);
        float sc = g_rs[r];
        for (int i = r * COLS; i < (r + 1) * COLS; i++) {
            if (g_out[i]) continue;
            unsigned idx = g_q12[i] >> (RB - p);
            double frac;
            if (mode == 0) {                       /* harness: prefix / QMAX */
                unsigned qp = idx << (RB - p);
                frac = (double)qp / (double)QMAX;
            } else if (mode == 1) {                /* per_p: direct index */
                frac = lvK[idx];
            } else if (mode == 2) {                /* subsample */
                int step = 1 << (KMAX - p);
                int k = idx * step; if (k >= (1 << KMAX)) k = (1 << KMAX) - 1;
                frac = lvK[k];
            } else {                               /* interp */
                float pos = (float)idx * (float)(1 << KMAX) / (float)L;
                int k0 = (int)pos;
                if (k0 > (1 << KMAX) - 2) k0 = (1 << KMAX) - 2;
                float t = pos - k0;
                frac = lvK[k0] * (1.0f - t) + lvK[k0 + 1] * t;
            }
            double v = frac * sc;
            double d = (double)g_rem[i] - (g_rem[i] < 0 ? -v : v);
            num += d * d;
        }
    }
    return num;
}

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : "blk_9_ffn_gate_exps_weight.f32";
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return 1; }
    fseek(f, 0, SEEK_END); long z = ftell(f); fseek(f, 0, SEEK_SET);
    g_n = (int)(z / 4); if (g_n <= 0 || g_n > MAXN) { fprintf(stderr, "bad n\n"); return 1; }
    g_rows = g_n / COLS;
    if (fread(g_w, 4, g_n, f) != (size_t)g_n) { fprintf(stderr, "short read\n"); return 1; }
    fclose(f);
    g_den = 0;
    for (int i = 0; i < g_n; i++) g_den += (double)g_w[i] * g_w[i];
    prep();

    float *tabK = (float *)malloc((size_t)g_rows * (1 << KMAX) * sizeof(float));
    if (!tabK) { fprintf(stderr, "oom\n"); return 1; }
    for (int r = 0; r < g_rows; r++) fit(r, 1 << KMAX, tabK + (size_t)r * (1 << KMAX));

    double tc = (double)((1 << KMAX) * 2 * g_rows) * 8.0 / g_n;
    printf("RAWRXD_DECODA_LEVELS_001\n");
    printf("source: %s  elements=%d  rows=%d\n", path, g_n, g_rows);
    printf("K_MAX=%d shared table cost = %.4f b/w (fp16, %d levels/row)\n\n",
           KMAX, tc, 1 << KMAX);
    printf("%3s %12s %12s %12s %12s %12s\n",
           "p", "harness", "per_p", "subsamp", "interp", "tbl_cost");
    for (int p = 1; p <= 8; p++) {
        float *tabp = (float *)malloc((size_t)g_rows * (1 << KMAX) * sizeof(float));
        if (!tabp) { fprintf(stderr, "oom\n"); return 1; }
        for (int r = 0; r < g_rows; r++)
            fit(r, 1 << p, tabp + (size_t)r * (1 << KMAX));
        double eh = sqrt(eval(p, NULL, 0) / g_den);
        double ep = sqrt(eval(p, tabp, 1) / g_den);
        double es = sqrt(eval(p, tabK, 2) / g_den);
        double ei = sqrt(eval(p, tabK, 3) / g_den);
        double tpc = (double)((1 << p) * 2 * g_rows) * 8.0 / g_n;
        printf("%3d %12.6f %12.6f %12.6f %12.6f %12.4f\n",
               p, eh, ep, es, ei, tpc);
        free(tabp);
    }
    printf("\nper_p needs its own 2^p table: %.4f b/w at p=4, %.4f b/w at p=8\n",
           (double)((1 << 4) * 2 * g_rows) * 8.0 / g_n,
           (double)((1 << 8) * 2 * g_rows) * 8.0 / g_n);
    free(tabK);
    return 0;
}