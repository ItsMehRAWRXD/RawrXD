/* decoda_span.c -- does allocation gain depend on block span?
 *
 * The harness uses block_size=64 (8192 blocks). My prior run used 256 (2048
 * blocks). Dispersion drives the achievable allocation gain, and dispersion
 * grows as span shrinks. This sweeps span and reports, per span:
 *   energy max/min, scale max/min, predicted spread log4(E), observed spread,
 *   and the measured gain vs uniform at a FIXED rate.
 *
 * Build: cl /O2 decoda_span.c /Fe:decoda_span.exe
 */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define NN   524288
#define CEIL 12

static float g_w[NN];
static double g_den;

static double run_span(int span)
{
    int nb = NN / span;
    float *sc = (float *)malloc(nb * sizeof(float));
    double (*E)[CEIL + 1] = malloc(nb * sizeof *E);
    if (!sc || !E) { fprintf(stderr, "oom\n"); exit(1); }

    for (int b = 0; b < nb; b++) {
        float mx = 0;
        for (int i = b * span; i < (b + 1) * span; i++) {
            float a = fabsf(g_w[i]); if (a > mx) mx = a;
        }
        sc[b] = mx;
    }
    for (int b = 0; b < nb; b++)
        for (int k = 0; k <= CEIL; k++) {
            double se = 0;
            for (int i = b * span; i < (b + 1) * span; i++) {
                if (k == 0) { double d = g_w[i]; se += d * d; continue; }
                unsigned qm = (1u << k) - 1u;
                float s = sc[b], sg = (g_w[i] < 0) ? -1.f : 1.f;
                double z = s > 0 ? fabs((double)g_w[i]) / s : 0.0;
                double q = (double)qm * z, qi = floor(q + 0.5);
                if (qi > qm) qi = qm;
                double d = (double)g_w[i] - (qi / qm) * s * sg;
                se += d * d;
            }
            E[b][k] = se;
        }

    double emin = 1e300, emax = 0, smin = 1e300, smax = 0;
    for (int b = 0; b < nb; b++) {
        if (E[b][0] < emin) emin = E[b][0];
        if (E[b][0] > emax) emax = E[b][0];
        if (sc[b] < smin) smin = sc[b];
        if (sc[b] > smax) smax = sc[b];
    }
    printf("\n--- span=%d  blocks=%d ---\n", span, nb);
    printf("  energy max/min = %8.3f   scale max/min = %8.3f\n", emax / emin, smax / smin);
    printf("  log4(E max/min) = %8.3f planes (predicted depth spread)\n",
           log(emax / emin) / log(4.0));

    const double PC = (double)span / NN;
    const double BASE = (double)(((NN + 7) / 8) + nb * 4) * 8.0 / NN;
    printf("%3s %10s %12s %12s %9s %10s %14s\n",
           "K", "budget", "uniform", "adaptive", "gain%", "mean K_j", "K range");
    double best_gain = 0;
    for (int K = 2; K <= 6; K++) {
        int ceil_ = K + 4; if (ceil_ > CEIL) ceil_ = CEIL;
        double budget = BASE + (double)((NN + 7) / 8) * K * 8.0 / NN;
        double slots = (budget - BASE) / PC;
        int *depth = (int *)calloc(nb, sizeof(int));
        for (int b = 0; b < nb; b++) depth[b] = 1;
        double used = nb;
        while (1) {
            int bb = -1; double bv = 0;
            for (int b = 0; b < nb; b++)
                for (int k = depth[b]; k < ceil_; k++) {
                    double dd = E[b][k] - E[b][k + 1];
                    if (dd > bv) { bv = dd; bb = b * 1000 + k; }
                }
            if (bb < 0) break;
            if (used + 1.0 > slots) break;
            int b = bb / 1000, k = bb % 1000;
            depth[b] = k + 1; used += 1.0;
        }
        double tu = 0, ta = 0;
        int mn = 99, mx = 0;
        for (int b = 0; b < nb; b++) {
            tu += E[b][K]; ta += E[b][depth[b]];
            if (depth[b] < mn) mn = depth[b];
            if (depth[b] > mx) mx = depth[b];
        }
        double eu = sqrt(tu / g_den), ea = sqrt(ta / g_den);
        double g = 100.0 * (eu - ea) / eu;
        if (g > best_gain) best_gain = g;
        printf("%3d %10.4f %12.6f %12.6f %8.2f%% %10.3f %6d..%d\n",
               K, budget, eu, ea, g, used / nb, mn, mx);
        free(depth);
    }
    printf("  BEST_GAIN_AT_THIS_SPAN = %.2f%%\n", best_gain);
    free(sc); free(E);
    return best_gain;
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

    printf("RAWRXD_DECODA_SPAN_001\n");
    printf("source: %s  elements=%d  sum_w2=%.4f\n\n", path, NN, g_den);

    int spans[] = {64, 128, 256, 512};
    double g[4];
    for (int i = 0; i < 4; i++) g[i] = run_span(spans[i]);

    printf("\n=== gain vs span ===\n");
    printf("%8s %12s\n", "span", "best_gain%");
    for (int i = 0; i < 4; i++) printf("%8d %11.2f%%\n", spans[i], g[i]);
    return 0;
}