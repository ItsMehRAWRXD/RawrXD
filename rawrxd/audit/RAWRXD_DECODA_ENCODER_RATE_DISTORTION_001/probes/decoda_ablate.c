/* decoda_ablate.c -- decompose the "reversal" gain into its three causes.
 *
 * All rows: same tensor, same error metric sqrt(sum(d^2)/sum(w^2)), same plane
 * count and same reported rate. Only the named component changes.
 *
 *   A  harness-faithful : ternary(span) + sign + per-ROW scale + outliers
 *   B  A, outliers off                       -> isolates outlier stream
 *   C  B, per-BLOCK scale                   -> isolates scale granularity
 *   D  C, ternary off                      -> isolates ternary base  == "reversal"
 *   E  D, outliers back on                  -> do outliers earn their rate?
 *
 * Rate accounting for each row is exact for its own stream.
 * Build: cl /O2 decoda_ablate.c /Fe:decoda_ablate.exe
 */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define NN   524288
#define ROWS 256
#define COLS 2048
#define TPB  5                     /* trits per byte */

static float g_w[NN];
static double g_den;

static double rel_l2(const float *hat)
{
    double num = 0;
    for (size_t i = 0; i < NN; i++) {
        double d = (double)g_w[i] - hat[i];
        num += d * d;
    }
    return sqrt(num / g_den);
}

/* ---- ternary base: decoda.cpp:139-179, alpha per span, 2 Lloyd passes ---- */
static void ternary_base(int span, float *base, float *resid, double *bytes_alpha)
{
    int nb = NN / span;
    double *alpha = (double *)malloc(nb * sizeof(double));
    for (int b = 0; b < nb; b++) {
        int begin = b * span, end = begin + span;
        double ma = 0;
        for (int i = begin; i < end; i++) ma += fabs((double)g_w[i]);
        double a = ma / span;
        if (!(a > 0)) a = 0;
        for (int pass = 0; pass < 2 && a > 0; pass++) {
            double th = 0.5 * a, s = 0; int nz = 0;
            for (int i = begin; i < end; i++)
                if (fabs((double)g_w[i]) >= th) { s += fabs((double)g_w[i]); nz++; }
            if (nz) a = s / nz;
        }
        alpha[b] = a;
        double th = 0.5 * a;
        for (int i = begin; i < end; i++) {
            double q = 0;
            if (a > 0 && (double)g_w[i] >=  th) q =  a;
            if (a > 0 && (double)g_w[i] <= -th) q = -a;
            base[i] = (float)q;
            resid[i] = g_w[i] - (float)q;
        }
    }
    *bytes_alpha = nb * 4.0;
    free(alpha);
}

/* outliers: decoda.cpp:194, threshold = 3.0 * per-ROW rms(residual) */
static int mark_outliers(const float *resid, unsigned char *is_out)
{
    int nout = 0;
    for (int r = 0; r < ROWS; r++) {
        size_t s = (size_t)r * COLS, e = s + COLS;
        double sq = 0;
        for (size_t i = s; i < e; i++) sq += (double)resid[i] * resid[i];
        double rms = sqrt(sq / COLS), th = 3.0 * rms;
        for (size_t i = s; i < e; i++)
            if (rms > 0 && fabs((double)resid[i]) > th) { is_out[i] = 1; nout++; }
    }
    return nout;
}

/* ---- one row of the ablation -------------------------------------------- */
typedef struct {
    const char *label;
    int use_ternary;
    int use_outliers;
    int scale_per_row;
    int span;
} Cfg;

static double run(Cfg c, int planes)
{
    int nb = NN / c.span;
    float *base = (float *)calloc(NN, sizeof(float));
    float *resid = (float *)calloc(NN, sizeof(float));
    float *rem = (float *)calloc(NN, sizeof(float));
    unsigned char *is_out = (unsigned char *)calloc(NN, 1);
    double bytes_alpha = 0;
    int nout = 0;

    if (c.use_ternary) {
        ternary_base(c.span, base, resid, &bytes_alpha);
    } else {
        for (size_t i = 0; i < NN; i++) resid[i] = g_w[i];
    }

    if (c.use_ternary && c.use_outliers) nout = mark_outliers(resid, is_out);

    if (c.use_outliers) {
        for (size_t i = 0; i < NN; i++) rem[i] = is_out[i] ? 0.0f : resid[i];
    } else {
        for (size_t i = 0; i < NN; i++) rem[i] = resid[i];
    }

    /* scale: per-row(2048) or per-block(span) */
    int scale_span = c.scale_per_row ? COLS : c.span;
    int nscale = NN / scale_span;
    float *sc = (float *)malloc(nscale * sizeof(float));
    for (int s = 0; s < nscale; s++) {
        int b = s * scale_span, e = b + scale_span;
        float mx = 0;
        for (int i = b; i < e; i++) { float a = fabsf(rem[i]); if (a > mx) mx = a; }
        sc[s] = mx;
    }

    /* reconstruct */
    unsigned qm = (1u << planes) - 1u;
    float *hat = (float *)malloc(NN * sizeof(float));
    for (size_t i = 0; i < NN; i++) {
        float s = sc[i / scale_span];
        float sg = (g_w[i] < 0) ? -1.f : 1.f;
        double v = resid[i];                     /* outliers exact via resid */
        if (!is_out[i] && s > 0) {
            double z = fabs(v) / s;
            double q = (double)qm * z, qi = floor(q + 0.5);
            if (qi > qm) qi = qm;
            v = (qi / qm) * s * sg;
        }
        hat[i] = base[i] + (float)v;
    }
    double e = rel_l2(hat);

    /* exact rate for THIS configuration */
    double PBY = (double)((NN + 7) / 8);
    double bytes = 0;
    if (c.use_ternary) bytes += (double)((NN + TPB - 1) / TPB);   /* trits */
    if (c.use_ternary) bytes += bytes_alpha;                     /* alphas */
    bytes += PBY;                                                 /* sign     */
    bytes += (double)nscale * 4;                                 /* scales   */
    bytes += PBY * planes;                                       /* planes   */
    if (c.use_outliers) bytes += nout * 6;                       /* idx+val  */

    printf("  %-46s %8.4f %12.6f\n", c.label, bytes * 8.0 / NN, e);
    free(base); free(resid); free(rem); free(is_out); free(sc); free(hat);
    return e;
}

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : "blk_9_ffn_gate_exps_weight.f32";
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return 1; }
    if (fread(g_w, 4, NN, f) != NN) { fprintf(stderr, "short read\n"); return 1; }
    fclose(f);
    g_den = 0;
    for (size_t i = 0; i < NN; i++) g_den += (double)g_w[i] * g_w[i];

    printf("RAWRXD_DECODA_ABLATE_001\n");
    printf("source: %s  elements=%d  span=64 (harness block_size)\n", path, NN);
    printf("metric: sqrt(sum(d^2)/sum(w^2)), identical for every row\n\n");

    for (int planes = 2; planes <= 4; planes += 2) {
        printf("=== %d magnitude planes ===\n", planes);
        printf("  %-46s %8s %12s\n", "configuration", "b/w", "rel_L2");
        printf("  A harness-faithful  tern+sign+rowscale+out    ");
        run((Cfg){ "A  ternary + sign + per-ROW scale + outliers",
                   1, 1, 1, 64 }, planes);
        printf("  B A minus outliers                          ");
        run((Cfg){ "B  A, outliers off", 1, 0, 1, 64 }, planes);
        printf("  C B with per-BLOCK scale                    ");
        run((Cfg){ "C  B, per-BLOCK scale", 1, 0, 0, 64 }, planes);
        printf("  D C minus ternary  (the 'reversal')         ");
        run((Cfg){ "D  sign + per-BLOCK scale, no ternary", 0, 0, 0, 64 }, planes);
        printf("  E D plus outliers back on                   ");
        run((Cfg){ "E  D + outliers", 0, 1, 0, 64 }, planes);
        printf("\n");
    }
    return 0;
}