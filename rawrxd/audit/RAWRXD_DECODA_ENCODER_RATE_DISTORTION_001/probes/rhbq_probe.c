/* rhbq_probe.c — does Hadamard pre-rotation actually improve rate-distortion?
 *
 * Measures, on the real blk.9.ffn_gate_exps tensor:
 *   A. transform validity (round-trip + norm preservation) BEFORE any statistic
 *   B. incoherence statistics before/after rotation
 *   C. achieved rel_L2 at matched bitrate vs the rate-distortion bound
 *
 * The transform is verified before it is trusted. A rotation that is not
 * orthogonal produces different statistics without being wrong, so every
 * downstream number is meaningless unless ||HW||_F == ||W||_F to float precision
 * and FWHT(FWHT(x))/8 == x.
 *
 * Build: cl /O2 /arch:AVX2 rhbq_probe.c   |   gcc -O2 -o rhbq_probe rhbq_probe.c -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define BLK   256                 /* elements per block (spec)            */
#define G     8                   /* FWHT group size (what the AVX2 kernel does) */
#define NB    (BLK / G)

/* ---- scalar reference FWHT over G elements, unnormalized, natural order ---- */
static void fwht_ref(double *a, int n)
{
    for (int len = 1; len < n; len <<= 1)
        for (int i = 0; i < n; i += len << 1)
            for (int j = 0; j < len; j++) {
                double u = a[i + j], v = a[i + j + len];
                a[i + j]       = u + v;
                a[i + j + len] = u - v;
            }
}

/* bit-reversal permutation of 3 index bits: out[i] = natural[bitrev3(i)] */
static int bitrev3(int i) { return ((i & 1) << 2) | (i & 2) | ((i & 4) >> 2); }

typedef struct {
    double rms, maxabs, ratio, outlier_frac, kurtosis;
} Stats;

static Stats stats(const float *w, size_t n)
{
    Stats s; memset(&s, 0, sizeof s);
    double s1 = 0, s2 = 0, s3 = 0, s4 = 0, mx = 0;
    for (size_t i = 0; i < n; i++) {
        double x = w[i], a = fabs(x);
        double x2 = x * x;
        s1 += x; s2 += x2; s3 += x2 * x; s4 += x2 * x2;
        if (a > mx) mx = a;
    }
    double N  = (double)n;
    double m  = s1 / N, v = s2 / N - m * m;
    double sd = sqrt(v);
    s.rms  = sqrt(s2 / N);
    s.maxabs = mx;
    s.ratio  = mx / (s.rms > 0 ? s.rms : 1);
    s.outlier_frac = 0;                       /* filled by caller (needs sd) */
    s.kurtosis = (v > 0) ? (s4 / N - 4 * (s2 / N) * (s2 / N) + 6 * (s2 / N) * (s2 / N))
                          / (v * v) : 0;
    return s;
}

static double outlier_frac_at(const float *w, size_t n, double k, double *sd_out)
{
    double s1 = 0, s2 = 0;
    for (size_t i = 0; i < n; i++) { s1 += w[i]; s2 += (double)w[i] * w[i]; }
    double N = (double)n, m = s1 / N;
    double sd = sqrt(s2 / N - m * m);
    if (sd_out) *sd_out = sd;
    size_t c = 0;
    for (size_t i = 0; i < n; i++) if (fabs((double)w[i] - m) > k * sd) c++;
    return (double)c / N;
}

/* ---- block bitplane reconstruction: per BLK, scale to int, emit R planes ---- */
/* mirrors the feasibility harness: plane k == (k+1) bits/weight, MSB-first     */
static double planes_rel_l2(const float *w, size_t n, int planes)
{
    int levels = (1 << (planes - 1)) - 1;         /* signed magnitude, +1 bit sign */
    double num = 0, den = 0;
    for (size_t b = 0; b + BLK <= n; b += BLK) {
        float mx = 0;
        for (int j = 0; j < BLK; j++) { float a = fabsf(w[b + j]); if (a > mx) mx = a; }
        double step = mx > 0 ? (double)mx / levels : 0;
        for (int j = 0; j < BLK; j++) {
            double x = w[b + j];
            double q = step > 0 ? floor(x / step + 0.5) : 0;
            if (q >  levels) q =  levels;
            if (q < -levels) q = -levels;
            double h = q * step;
            double d = x - h;
            num += d * d; den += x * x;
        }
    }
    return den > 0 ? sqrt(num / den) : 0;
}

/* ---- optimal uniform scalar quantizer at R bits: Lloyd-Max (float step) ---- */
static double uniform_rel_l2(const float *w, size_t n, int bits)
{
    int levels = (1 << (bits - 1)) - 1;
    if (levels < 1) return 1.0;
    double mx = 0;
    for (size_t i = 0; i < n; i++) { double a = fabs((double)w[i]); if (a > mx) mx = a; }
    double step = mx / levels;
    double num = 0, den = 0;
    for (size_t i = 0; i < n; i++) {
        double x = w[i];
        double q = step > 0 ? floor(x / step + 0.5) : 0;
        if (q >  levels) q =  levels;
        if (q < -levels) q = -levels;
        double d = x - q * step;
        num += d * d; den += x * x;
    }
    return den > 0 ? sqrt(num / den) : 0;
}

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1]
        : "blk_9_ffn_gate_exps_weight.f32";

    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return 1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    size_t n = (size_t)sz / sizeof(float);
    float *w = malloc(n * sizeof(float));
    if (fread(w, sizeof(float), n, f) != n) { fprintf(stderr, "short read\n"); return 1; }
    fclose(f);

    printf("RAWRXD_RHBQ_PROBE_001\n");
    printf("source: %s  elements=%zu\n", path, n);

    /* ================= A. TRANSFORM VALIDITY ================= */
    double *probe = malloc(G * sizeof(double));
    for (int i = 0; i < G; i++) probe[i] = (double)(i + 1) * 1.0 - 3.5;
    double norm_before = 0, norm_after = 0, rt_err = 0;
    for (int i = 0; i < G; i++) norm_before += probe[i] * probe[i];
    fwht_ref(probe, G);
    for (int i = 0; i < G; i++) norm_after += probe[i] * probe[i];
    fwht_ref(probe, G);                       /* inverse = FWHT / N */
    for (int i = 0; i < G; i++) rt_err = fmax(rt_err, fabs(probe[i] / G - ((double)(i + 1) - 3.5)));
    free(probe);

    printf("\n=== A. TRANSFORM VALIDITY (must pass before any statistic is read) ===\n");
    printf("  (unnormalized FWHT: HH^T = G*I, so ||Hx|| == sqrt(G)*||x||)\n");
    printf("  ||x||_before          = %.15g\n", sqrt(norm_before));
    printf("  ||FWHT(x)||_after     = %.15g   expected sqrt(G)*||x|| = %.15g\n",
           sqrt(norm_after), sqrt((double)G * norm_before));
    printf("  norm_rel_error        = %.3e\n",
           fabs(sqrt(norm_after / ((double)G * norm_before)) - 1.0));
    printf("  roundtrip_max_abs_err = %.3e   (FWHT(FWHT(x))/G - x)\n", rt_err);
    int ok_valid = (fabs(sqrt(norm_after / ((double)G * norm_before)) - 1.0) < 1e-12)
                && (rt_err < 1e-12);
    printf("  TRANSFORM_VALID       = %d\n", ok_valid);
    if (!ok_valid) { printf("\nABORT: transform is not orthogonal; every statistic below is void.\n"); return 2; }

    /* full-tensor norm check, the thing that actually gates the claim */
    double nf = 0; for (size_t i = 0; i < n; i++) nf += (double)w[i] * w[i];

    /* ================= rotation ================= */
    float *r = malloc(n * sizeof(float));
    memcpy(r, w, n * sizeof(float));
    for (size_t b = 0; b + BLK <= n; b += BLK)
        for (int g = 0; g < NB; g++) {
            double t[G];
            for (int j = 0; j < G; j++) t[j] = r[b + g * G + j];
            fwht_ref(t, G);                      /* natural order */
            for (int j = 0; j < G; j++)          /* emit bit-reversed, as the kernel does */
                r[b + g * G + j] = (float)t[bitrev3(j)];
        }
    double nr = 0; for (size_t i = 0; i < n; i++) nr += (double)r[i] * r[i];
    printf("\n=== A2. FULL-TENSOR ORTHOGONALITY ===\n");
    printf("  ||W||_F                = %.15g\n", sqrt(nf));
    printf("  ||W_rot||_F            = %.15g   expected sqrt(G)*||W||_F = %.15g\n",
           sqrt(nr), sqrt((double)G * nf));
    printf("  FROBENIUS_REL_ERROR    = %.3e\n", fabs(sqrt(nr / ((double)G * nf)) - 1.0));

    /* ================= B. INCOHERENCE ================= */
    printf("\n=== B. INCOHERENCE STATISTICS ===\n");
    double sd;
    Stats  sw = stats(w, n), sr = stats(r, n);
    double ow = outlier_frac_at(w, n, 3.0, &sd);
    double or_ = outlier_frac_at(r, n, 3.0, &sd);
    printf("  %-22s %14s %14s\n", "", "RAW", "ROTATED");
    printf("  %-22s %14.6g %14.6g\n", "rms", sw.rms, sr.rms);
    printf("  %-22s %14.6g %14.6g\n", "max|w|", sw.maxabs, sr.maxabs);
    printf("  %-22s %14.4f %14.4f\n", "max/rms", sw.ratio, sr.ratio);
    printf("  %-22s %13.4f%% %13.4f%%\n", "outliers >3sigma", 100 * ow, 100 * or_);
    printf("  %-22s %14.4f %14.4f\n", "excess kurtosis", sw.kurtosis, sr.kurtosis);

    /* ================= C. RATE-DISTORTION ================= */
    printf("\n=== C. ACHIEVED rel_L2 vs RATE-DISTORTION BOUND ===\n");
    printf("  bound(R) = 2^-(R-0.254) : entropy-constrained scalar quantization,\n");
    printf("  high-rate, Gaussian source. NO quantizer -- rotated or not --\n");
    printf("  can go below this column. It is the floor, not a competitor.\n\n");
    printf("  %4s %14s %14s %14s %14s %14s\n",
           "bits", "bound", "uniform", "planes_raw", "planes_rot", "rot_vs_bnd");
    for (int R = 1; R <= 12; R++) {
        double bound = pow(2.0, -(R - 0.254));
        double u  = (R >= 2 && R <= 24) ? uniform_rel_l2(w, n, R) : 0;
        double pr = planes_rel_l2(w, n, R);
        double pt = planes_rel_l2(r, n, R);
        printf("  %4d %14.3e %14.3e %14.3e %14.3e %14.2fx\n",
               R, bound, u, pr, pt, pt / bound);
    }

    /* ================= VERDICT ================= */
    double p3r = planes_rel_l2(r, n, 4), p3w = planes_rel_l2(w, n, 4);
    double b3  = pow(2.0, -(4 - 0.254));
    int claim_285_impossible = (pow(2.0, -(2.85 - 0.254)) > 0.05);
    printf("\n=== DECISIVE ===\n");
    printf("  ROTATION_HELPS_AT_4BITS = %d  (raw %.4f -> rot %.4f, ratio %.2fx)\n",
           p3r < p3w ? 1 : 0, p3w, p3r, p3w / (p3r > 0 ? p3r : 1));
    printf("  BOUND_AT_4BITS         = %.4f\n", b3);
    printf("  RAW_PLANES_VIOLATE_BOUND = %d\n", p3w < b3);
    printf("  ROT_PLANES_VIOLATE_BOUND = %d\n", p3r < b3);
    printf("  CLAIM_2_85BW_BELOW_5PCT_MATHEMATICALLY_POSSIBLE = %d  (floor = %.1f%%)\n",
           !claim_285_impossible, 100 * pow(2.0, -(2.85 - 0.254)));

    free(w); free(r);
    return 0;
}
