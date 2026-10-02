/* decoda_d1_floor.c -- what rate does each architecture actually need for rel_L2 < 5%?
 *
 * D1 asks for <5% additional rel_L2 below Q4_K's 4.5 b/w. That target is
 * unreachable by every configuration measured here. This reports the MINIMUM
 * RATE at which each architecture reaches <5%, which is the answerable form.
 *
 * Architectures, all with the verified encoder path:
 *   A  harness as built        ternary + sign + per-ROW scale + outliers, /qmax
 *   B  A + normalization        one divisor, zero bytes
 *   C  reversed                sign + per-BLOCK scale, no ternary, no outliers
 *   D  C + outliers exact      outlier stream kept, ternary dropped
 *   E  D + per-block Lloyd     levels fit at this plane count
 *   F  C + per-block Lloyd
 *
 * Build: cl /O2 decoda_d1_floor.c /Fe:decoda_d1_floor.exe
 */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define COLS   2048
#define MAXROWS 4096
#define MAXN   (MAXROWS * COLS)
#define RB     12
#define QMAX   ((1u << RB) - 1u)
#define THRESH 0.05

static float g_w[MAXN];
static int   g_n, g_rows;
static double g_den;

/* ternary base, span 64 */
static float *g_resid;
static void build_ternary(void)
{
    int nb = g_n / 64;
    double *alpha = (double *)malloc(nb * sizeof(double));
    g_resid = (float *)malloc((size_t)g_n * sizeof(float));
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
            g_resid[i] = g_w[i] - (float)q;
        }
    }
    free(alpha);
}

static void mark_outliers(const float *resid, unsigned char *is_out)
{
    for (int r = 0; r < g_rows; r++) {
        size_t s = (size_t)r * COLS, e = (size_t)(r + 1) * COLS;
        double sq = 0; for (size_t i = s; i < e; i++) sq += (double)resid[i] * resid[i];
        double rms = sqrt(sq / COLS), th = 3.0 * rms;
        for (size_t i = s; i < e; i++)
            if (rms > 0 && fabs((double)resid[i]) > th) is_out[i] = 1;
    }
}

static void fit_lloyd(const float *mag, const unsigned char *is_out,
                      int lo, int hi, int L, float sc, float *lv)
{
    double *acc = (double *)calloc(L, sizeof(double));
    unsigned *cnt = (unsigned *)calloc(L, sizeof(unsigned));
    for (int k = 0; k < L; k++) lv[k] = ((float)k + 0.5f) / (float)L;
    for (int it = 0; it < 16; it++) {
        for (int k = 0; k < L; k++) { acc[k] = 0; cnt[k] = 0; }
        for (int i = lo; i < hi; i++) {
            if (is_out && is_out[i]) continue;   /* tail must not shape the fit */
            double z = sc > 0 ? fabs((double)mag[i]) / sc : 0.0;   /* MAGNITUDE */
            int k = (int)(z * L); if (k >= L) k = L - 1; if (k < 0) k = 0;
            acc[k] += z; cnt[k]++;
        }
        for (int k = 0; k < L; k++) if (cnt[k]) lv[k] = (float)(acc[k] / cnt[k]);
    }
    free(acc); free(cnt);
}

/* src: 0=w 1=resid ; per_row_scale ; use_out ; normalize ; lloyd */
static double eval_cfg(int src, int per_row_scale, int use_out, int normalize,
                       int lloyd, int planes, double *bw_out)
{
    int nout = 0, sspan = per_row_scale ? COLS : 64;
    int nscale = g_n / sspan;
    float *sig = (float *)malloc((size_t)g_n * sizeof(float));
    unsigned char *is_out = (unsigned char *)calloc((size_t)g_n, 1);
    unsigned *q12 = (unsigned *)malloc((size_t)g_n * sizeof(unsigned));

    for (int i = 0; i < g_n; i++) sig[i] = src ? g_resid[i] : g_w[i];
    if (use_out) { mark_outliers(sig, is_out); for (int i = 0; i < g_n; i++) if (is_out[i]) nout++; }

    float *scale = (float *)malloc((size_t)nscale * sizeof(float));
    for (int s = 0; s < nscale; s++) {
        int b = s * sspan, e = b + sspan;
        float mx = 0;
        for (int i = b; i < e; i++) {
            if (is_out[i]) continue;
            float a = fabsf(sig[i]); if (a > mx) mx = a;
        }
        scale[s] = mx;
    }
    for (int i = 0; i < g_n; i++) {
        float sc = scale[i / sspan];
        unsigned q = 0;
        if (!is_out[i] && sc > 0) {
            double z = fabs((double)sig[i]) / sc;
            q = (unsigned)llround(z * QMAX); if (q > QMAX) q = QMAX;
        }
        q12[i] = q;
    }

    double num = 0;
    for (int s = 0; s < nscale; s++) {
        int b = s * sspan, e = b + sspan;
        float sc = scale[s];
        float *lv = NULL;
        if (lloyd && planes > 0) {
            lv = (float *)malloc((size_t)(1 << planes) * sizeof(float));
            fit_lloyd(sig, use_out ? is_out : NULL, b, e, 1 << planes, sc > 0 ? sc : 1.0f, lv);
        }
        for (int i = b; i < e; i++) {
            float base = src ? (g_w[i] - g_resid[i]) : 0.0f;
            if (is_out[i]) {
                double rec = base + (src ? (double)g_resid[i] : (double)sig[i]);
                double d = rec - (double)g_w[i];
                num += d * d; continue;
            }
            double frac;
            if (planes == 0) frac = 0;
            else {
                unsigned idx = q12[i] >> (RB - planes);
                if (lloyd) frac = lv[idx];
                else if (normalize) {
                    unsigned den = ((1u << planes) - 1u) << (RB - planes);
                    unsigned qp = idx << (RB - planes);
                    frac = (double)qp / (double)(den ? den : 1u);
                } else {
                    unsigned qp = idx << (RB - planes);
                    frac = (double)qp / (double)QMAX;
                }
            }
            double v = frac * sc;
            double rec = base + (sig[i] < 0 ? -v : v);
            double d = rec - (double)g_w[i];
            num += d * d;
        }
        free(lv);
    }

    double PBY = (double)((g_n + 7) / 8);
    double bytes = PBY + (double)nscale * 4 + PBY * planes;
if (src) {
        bytes += (double)((g_n + 4) / 5);       /* trits */
        bytes += (double)(g_n / 64) * 4;        /* alphas */
        if (use_out) bytes += nout * 6;
    }
    /* charge the per-p Lloyd level table: 2^planes fp16 levels per scale block */
    if (lloyd && planes > 0)
        bytes += (double)((1u << planes) * 2 * nscale);
    *bw_out = bytes * 8.0 / g_n;

    free(sig); free(is_out); free(q12); free(scale);
    return sqrt(num / g_den);
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
    build_ternary();

    printf("RAWRXD_DECODA_D1_FLOOR_001\n");
    printf("source: %s  elements=%d  rows=%d\n", path, g_n, g_rows);
    printf("threshold rel_L2 < %.2f ; Q4_K target = 4.5000 b/w\n\n", THRESH);

    struct { const char *name; int src, prs, uo, nz, ly; } cfg[] = {
        { "A  harness as built",              1, 1, 1, 0, 0 },
        { "B  A + normalization",            1, 1, 1, 1, 0 },
        { "C  reversed (no ternary/outlier)", 0, 0, 0, 0, 0 },
        { "D  C + outliers exact",            0, 0, 1, 0, 0 },
        { "E  D + per-block Lloyd",           0, 0, 1, 0, 1 },
        { "F  C + per-block Lloyd",           0, 0, 0, 0, 1 },
    };

    printf("%-34s %10s %12s %10s\n", "architecture", "min b/w", "rel_L2 there", "vs 4.5");
    for (unsigned c = 0; c < sizeof cfg / sizeof cfg[0]; c++) {
        double bestbw = 0, beste = 0;
        int found = 0;
        for (int p = 0; p <= 12 && !found; p++) {
            double bw; double e = eval_cfg(cfg[c].src, cfg[c].prs, cfg[c].uo,
                                           cfg[c].nz, cfg[c].ly, p, &bw);
            if (e < THRESH) { bestbw = bw; beste = e; found = 1; }
        }
        if (found)
            printf("%-34s %10.4f %12.6f %9.2fx\n", cfg[c].name, bestbw, beste, bestbw / 4.5);
        else
            printf("%-34s %10s %12s %10s\n", cfg[c].name, "UNREACHED", "-", "-");
    }

    printf("\nfull curve for B (harness + normalization) and F (reversed + Lloyd):\n");
    printf("%3s %10s %12s %10s %12s\n", "p", "B b/w", "B rel_L2", "F b/w", "F rel_L2");
    for (int p = 0; p <= 8; p++) {
        double bwb, bwf;
        double eb = eval_cfg(1, 1, 1, 1, 0, p, &bwb);
        double ef = eval_cfg(0, 0, 0, 0, 1, p, &bwf);
        printf("%3d %10.4f %12.6f %10.4f %12.6f\n", p, bwb, eb, bwf, ef);
    }
    free(g_resid);
    return 0;
}

