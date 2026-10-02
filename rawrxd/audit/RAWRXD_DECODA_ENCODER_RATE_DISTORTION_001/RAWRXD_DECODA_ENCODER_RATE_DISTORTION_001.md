RAWRXD_DECODA_ENCODER_RATE_DISTORTION_001
=============================================
STATUS = MEASURED_AND_CROSS_VALIDATED
DATE   = 2026-10-02
SCOPE  = Decoda encoder rate-distortion on real DeepSeek-V2-Lite-Chat blk.9 weights

This receipt supersedes and retracts every numeric claim made about this
workload outside of a reproducible measurement. Retractions are enumerated
in section R.


0. SOURCE IDENTITY
-----------------
The encoder was modified during this work. Both states are retained.

  decoda.cpp PATCHED    SHA256 DC3B07E035C18C720E9C1311A526159EF2F995C3C16E50D11B257F439B9330F7
  decoda.cpp PRISTINE   SHA256 459B19C9D7AAF80E6C8DDE71016EDDD19720C2F463533CA2AB6C40EACBE27A3C
                        (retained as decoda.cpp.bak)

  decoda.hpp            SHA256 9F445C900A35B09B581180173293D1F72A4521BF2667104CAC6A2271C29E7F1E
                        UNCHANGED before and after. No header change.

The tree is outside the git repository, so the .bak copy is the only
rollback path. Both files are required to reproduce any number below.

The patch is one divisor in Tensor::progressiveResidual, decoda.cpp:405:

    -  float v = residual_scale_[row] * (float(q) / float(qmax));
    +  const std::uint32_t shift = residual_bits_ - planes;
    +  const std::uint32_t pmax = (((1u << planes) - 1u) << shift);
    +  const std::uint32_t denom = pmax ? pmax : qmax;
    +  float v = residual_scale_[row] * (float(q) / float(denom));

magnitudePrefix() zero-fills unknown low bits, so at plane count p the
largest representable prefix is (2^p - 1) << (residual_bits - p). Dividing
by qmax made every plane count reach only (2^p-1)/(2^residual_bits-1) of
the block range: 0.75 at p=2. The alphabet was mis-scaled.

No serialization change. Byte counts are byte-identical before and after.


1. INSTRUMENT VALIDATION (must pass before any number is admissible)
-------------------------------------------------------------------
INSTRUMENT_REPRODUCES_REFERENCE_BINARY   = 1
  feasibility.exe was rebuilt from feasibility.cpp + decoda.cpp and its
  output matched the shipped binary to every printed digit on all three
  tensors, all 13 plane rows. This is the gate that made every other
  number in this receipt trustworthy; it was reached only after four
  earlier instruments produced confident wrong output.

MEASUREMENT_DID_NOT_LIE                  = 1
  Baseline rebuilt from pristine source reproduced 0.328657 / 0.170473 /
  0.0884503 / 0.045075 / 0.0226333 / 0.0113139 on ffn_gate_exps. These are
  the same values reported by the shipped feasibility.exe.

PATCH_MATCHES_INDEPENDENT_MODEL          = 1
  The patched binary's curve (0.339205, 0.148584, 0.0705402, 0.0342133,
  0.0167737, 0.00830663) equals the standalone probe decoda_norm.exe to
  all printed digits on all three tensors, at identical byte counts.


2. DATASET
----------
ffn_gate_exps   524288 elems  256x2048  Q4_K-decoded  rms 0.0332024  outliers 1.2508%
ffn_up_exps     524288 elems  256x2048  Q4_K-decoded  rms 0.0319298  outliers 1.2609%
ffn_gate_inp    131072 elems   64x2048  native F32   rms 0.0188928  outliers 1.2794%

Metric: rel_L2 = sqrt(sum((w - w_hat)^2) / sum(w^2)), identical in every row.
Denominator is sum of w^2, NOT the element count.


3. LEVEL NORMALIZATION -- ACCEPTED
---------------------------------
Zero bytes added. Byte column identical at every plane count.

  planes  b/w      before        after        ratio
      0  3.9319    0.388937     0.388937     1.00
      1  4.9319    0.328657     0.339205     0.97
      2  5.9319    0.170473     0.148584     1.15
      3  6.9319    0.0884503    0.0705402    1.25
      4  7.9319    0.045075     0.0342133    1.32
      5  8.9319    0.0226333    0.0167737    1.35
      6  9.9319    0.0113139    0.00830663   1.36
      7 10.9319    0.00559834   0.00409879   1.37
      8 11.9319    0.00273531   0.00201086   1.36

DIRECTION_CONSISTENT_ACROSS_TENSORS = 1
  Regresses at p=1 on all three (-3.21%, -3.19%, -2.14%), improves at p>=2
  on all three (up to +26.58%, +26.58%, +19.09%).

NORMALIZATION_MOVES_D1_FLOOR = 0
  Same plane count crosses the 5% threshold before and after. Normalization
  buys fidelity at fixed rate, NOT rate at fixed fidelity. Stated explicitly
  because an earlier framing in this thread conflated the two.


4. ACHIEVABLE FLOOR -- THE ANSWERABLE FORM OF D1
------------------------------------------------
Minimum rate at which each architecture reaches rel_L2 < 0.05.

  architecture                      gate_exps  up_exps  gate_inp
  A  harness as built                 7.7160  7.7209    8.7298
  B  A + normalization                7.7160  7.7209    8.7298
  C  reversed (no ternary/outlier)    6.5000  6.5000    7.5000
  D  C + outliers exact               6.5000  6.5000    6.5000
  E  D + per-p Lloyd                  9.5000  9.5000    9.5000
  F  C + per-p Lloyd                  9.5000  9.5000   14.5000

Q4_K rate = 4.5000 b/w.

  ACHIEVABLE_FLOOR_BW          = 6.5000
  FLOOR_OVER_Q4K              = 1.4444x
  FLOOR_CONSISTENT_ALL_TENSORS = 1

D1 SUB-Q4K TARGET REACHABLE_BY_ANY_MEASURED_CONFIG = 0
  The gate's premise -- a sub-4.5 b/w tier with <5% additional rel_L2 --
  is false for this source. The gap is rate-distortion, not encoder quality.

D1 CANNOT BE MOVED BY RESIDUAL IMPROVEMENT = 1
  The sub-4.5 b/w tier contains exactly one point: plane 0. At plane 0
  progressiveResidual returns 0.0f at its planes==0 guard, so the residual
  contributes nothing and the reconstruction is entirely ternary + sign +
  scales + outliers. Any improvement operating on magnitude planes is
  structurally incapable of moving D1.

D1 AND D2 ARE THE SAME TEST = 1
  feasibility.cpp:155 evaluates best_under < 0.05; feasibility.cpp:157
  evaluates best_under < best_over. With best_under sourced from the single
  plane-0 point, both reduce to comparing plane 0 against plane 12.


5. PER-BLOCK DEPTH ALLOCATION -- ACCEPTED, BOUNDED
---------------------------------------------------
Gain is bounded by log4(energy dispersion) because the marginal distortion
gain matrix is rank-1: gain_b(k) = E_b * c * 4^-k.

   span  blocks  energy max/min  log4(max/min)  best gain
     64    8192            13.302          1.867     4.96%
    128    4096             9.441          1.619     2.86%
    256    2048             7.855          1.487     2.21%
    512    1024             7.361          1.440     2.18%

PREDICTED_SPREAD_MATCHES_OBSERVED = 1
  Observed K range at every budget is exactly 2 planes centred on the mean,
  matching log4(prediction) to two decimals at all four spans.

CLAIMED_GAIN_15_TO_25_PERCENT = RETRACTED
  Measured best is 4.96% at the most favourable span.


6. ENHANCEMENTS REJECTED ON MEASUREMENT
----------------------------------------
GAMMA_CLOSED_FORM_DIVERGES = 1
  gamma_K min over blocks by plane count 1..10:
    0.4889, -1.415, -8.306, -34.43, -136.1, -536.9, -2129, -8473,
    -3.38e4, -1.35e5
  Claimed range is (0, 0.5). Divergent. An earlier clamp to [0,0.5] turned
  this divergence into a silent "no effect" and was itself a defect.

HIERARCHICAL_MASK_SAVING_BW = 0.00556 per plane
  At density d, active 32-element subgroups = 1-(1-d)^32. At d=0.13232
  that is 0.990, so essentially nothing is skipped. Claimed "<0.12 b/w for
  MSB" is refuted by an order of magnitude.

PER_P_LLOYD_RATE_JUSTIFIED = 0
  Distortion gain is real: 1.84x-2.05x across all three tensors at p=1..6.
  A shared K_MAX=8 table recovers only 1-18% of it (subsampled and
  interpolated agree to six digits and both track the harness), because the
  gain lives in fitting AT each resolution, not in Lloyd placement.
  Charged cost = 2^p * 2 B * nscale, which moves the floor 6.5 -> 9.5 b/w.

LLOYD_FIT_MUST_EXCLUDE_OUTLIERS = 1
  Fitting levels with the 1.28% tail included pushed config E to
  UNREACHED; excluding it gave 0.030136. Same mechanism that made the
  per-row residual scale waste dynamic range.

HESSIAN_TRAVERSAL = UNTESTED
  Requires calibration activations. Not present on disk.


7. FINAL DISPOSITION
---------------------
ACCEPT level normalization          IMPLEMENTED in decoda.cpp, one divisor
ACCEPT outlier stream               free at C+D; crosses a plane earlier on F32
ACCEPT ternary base AT PLANE 0 ONLY  it is the entire reconstruction when
                                    residual is off; removing it costs a
                                    full plane above p=0
REJECT per-p Lloyd tables           6.5 -> 9.5 b/w
REJECT Lagrangian allocation        +4.96% and the floor is already 6.5
REJECT hierarchical masking         0.0056 b/w/plane
REJECT gamma closed form            divergent
REJECT binary-plane 1 bit/weight    bounded by N-2*PopCount; RD floor at
                                    2.85 b/w is 16.5%, not <5%
REJECT Hadamard pre-rotation        excess kurtosis 5.4190 -> 5.3579;
                                    rel_L2 0.1286 -> 0.1265 (1.02x)
REJECT ternary+sign as an
     alternative to sign+planes     1.78x worse at 79% of the rate

D1_VERDICT_UNCHANGED = FAIL
  Honest outcome. The gate fails because its threshold is unreachable,
  not because the encoder is weak. Promoting it by restating the threshold
  against the measured floor would be goalpost movement and is NOT done
  here. A new gate testing the floor is the legitimate route.


8. INSTRUMENT DEFECTS FOUND AND FIXED (13)
-------------------------------------------
 #  defect                                        caught by
 1  FWHT orthogonality asserted for unnormalized  the gate itself, run 1
 2  Lloyd levels double-scaled by sc              constant-column giveaway
 3  MSB density predicate identical for all k     identical columns
 4  MSB density predicate repeated                identical columns
 5  plane cost charged 1/NN not BLK/NN            budget never bound
 6  error printed sqrt(tot/NN), not sqrt(tot/s2)  30x gap vs base
 7  qmax>>(RB-p) used as prefix divisor           magnitudes ~649
 8  outlier gate conditioned on use_ternary       E identical to D
 9  static NN heap overflow on 131072-elem file  0xC0000005
10  static NN heap overflow, third geometry      ASan-free crash
11  signed values passed as magnitudes            ASan, build 1
12  outliers included in the Lloyd fit            UNREACHED anomaly
13  gamma clamp converted divergence to pass      silent no-op rows

Twelve of thirteen produced plausible, confident, wrong numbers. None was
found by reading the code. Each was caught by an invariant: orthogonality,
monotonicity, conservation, exact agreement with a reference binary, or
behaviour across a different tensor geometry.


9. RETRACTIONS (R)
------------------
R1  "Decoda is 3.0x / 3.4x worse than optimal at 3.9 b/w"
    RETRACTED. Compared a 1.6 b/w effective magnitude rate against a 4 b/w
    quantizer. Rate mismatch, not encoder defect. This was made twice.

R2  "Lloyd per-row is the largest gain and is free"
    RETRACTED as stated. The 1.84-2.05x is real but costs 2^p*2B*nscale
    bytes; at p>=4 it is a net rate regression. Only p<=2 pays.

R3  "Adaptive allocation delivers 7.11% / 15-25% at fixed rate"
    RETRACTED. The instrument that produced it violated monotonicity
    (uniform-4 0.2578 -> uniform-8 0.3674), returned identical error for
    different rate, and reported 18.7160 b/w against a 13.0625 b/w format
    ceiling. Measured best is 4.96%.

R4  "Plane 0 entropy 0.334 proves planes 0-1 carry outlier flags"
    RETRACTED. Marginal bit entropy of an already-quantized stream is ~1
    bit/plane by construction and cannot distinguish signal from noise.
    Plane 0's 6.17% is the geometric consequence of it being the top bit of
    a Gaussian-quantized value, not an outlier flag.

R5  "Hadamard rotation flattens outliers and reaches 4.12% at plane 0"
    RETRACTED. Excess kurtosis moves 5.4190 -> 5.3579. rel_L2 0.1286 ->
    0.1265. Also arithmetically impossible: the RD floor at 2.85 b/w is
    16.5%, so no quantizer reaches <5% there.

R6  "A trivial quantizer beats Decoda everywhere below 11 b/w"
    RETRACTED as a rate-blind comparison. A per-256-block quantizer beats
    it by ~2.8x at MATCHED rate (0.3602 global-scale vs 0.1286
    block-scale at 4 b/w); the harness's plane 0 is 3.93 b/w carrying only
    ~1.6 b/w of magnitude.

R7  "Per-block emission would recover the loss"
    RETRACTED. residual_planes_ is already plane-major and the scale is
    looked up per element. There is no cross-block mixing to eliminate.


10. REPRODUCTION
----------------
  build_feasn.bat   builds feasibility_norm.exe (patched)
  build_feas.bat    builds feasibility_base.exe (baseline)
  build_d1a.bat     builds decoda_d1_asan.exe under AddressSanitizer

  decoda_norm.exe     level normalization, three tensors
  decoda_levels.exe   shared-table vs per-p level sharing
  decoda_span.exe     allocation gain vs block span
  decoda_d1_asan.exe  achievable-floor table, three tensors

  All probes read blk_9_*.f32 from C:\Users\Garrett\AppData\Local\Temp\kilo\
  decoda_real\ and are EPHEMERAL. This receipt is the durable record; the
  probes must be re-created from it to reproduce.
