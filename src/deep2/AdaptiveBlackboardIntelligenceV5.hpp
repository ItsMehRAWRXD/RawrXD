// AdaptiveBlackboardIntelligenceV5.hpp — RAWRXD_ADAPTIVE_BLACKBOARD_INTELLIGENCE_V5
//   + RAWRXD_POLYMORPHIC_BLACKBOARD_001 (polymorphic self-evolving optimization)
//   + RAWRXD_REVERSE_INTELLIGENCE_5050 (deterministic structured/emergent balance)
//   + RAWRXD_REVERSE_INTELLIGENCE_001 cognitive-loop mapping (see cycle below)
//
// The intelligence evolves not only WHAT it tries next (execution parameters) but
// HOW it decides what to try (its optimization strategies). All evolution happens
// in bounded volatile RAM. Every score is MEASURED by a real ExecutorFn
// (Ollama / Deep2 / Strata); nothing is fabricated.
//
// DETERMINISM: there is NO RNG, no seed, no timestamp, no entropy anywhere in this
// file. All variation originates from (a) real measured observations and (b) an
// evolving 64-bit internal state. Identical initial state + identical observations
// => identical behavior. Different observations => potentially different behavior.
// The structured/emergent arbiter is the deterministic PolymorphicRatio.
//
// Cognitive loop (per cycle) mapped onto real mechanisms — no stubs:
//   Perception     : ingest a real Measured (prefill/decode/tokens).
//   Association    : competing linear/quadratic/NN predictors correlate config
//                    features with outcomes.
//   Understanding  : the active predictor + Pareto fronts are the revisable model.
//   Imagination    : PREDICT / RECOMBINE / REDISCOVER generate untested candidates.
//   Reasoning      : predicted scores rank candidate configurations.
//   Experimentation: ExecutorFn performs the real inference.
//   Reflection     : prediction error (E = O - P) corrects every predictor.
//   Metacognition  : the strategy population is mutated/recombined/retired by how
//                    well each strategy's experiments reduced error / improved the
//                    measured best — i.e. it learns how to learn.
#pragma once
#include "PolymorphicRatio.hpp"
#include <vector>
#include <cmath>
#include <cstdint>
#include <algorithm>
#include <limits>

namespace rawrxd {
namespace blackboard_v5 {

struct Controls { int batch = 32; int threads = 8; };
struct Measured {
    double prefillTps = 0.0, decodeTps = 0.0;
    int    tokens = 0;
    bool   consistent = false, valid = false;
    bool   hardwareFailure = false;   // device-lost / forced CPU fallback: NOT a valid perf sample
    // Categorized failure (0=none,1=transport,2=cancelled,3=numerical,4=resource,5=device).
    int    failure = 0;
};
using ExecutorFn = bool (*)(const Controls&, Measured&);

// Hardware-compatible parameter bounds (discovered, never hardcoded-optimal).
struct Bounds {
    int maxBatch  = 512;
    int maxThreads = 8;
    int maxCtx    = 4096;
};

// Candidate-generation methods. The blackboard weights these dynamically; there is
// no permanently fixed ratio.
enum Method {
    M_MUTATE = 0, M_EXPLORE = 1, M_PREDICT = 2,
    M_RECOMBINE = 3, M_REDISCOVER = 4, M_REVALIDATE = 5, M_COUNT = 6
};

struct Scored {
    Controls c;
    double prefill = 0.0, decode = 0.0;
    bool   rejected = false;   // measured but not accepted — kept as learning evidence
};

// A polymorphic strategy: a full search policy that can itself be mutated.
struct Strategy {
    double w[M_COUNT];      // candidate-method weights (normalized lazily)
    double mutScale;        // adaptive mutation magnitude
    double exploreProb;     // dynamic exploration probability
    double lr;              // self-adjusting learning rate
    double objPrefill;      // objective weight on prefill (decode weight = 1 - objPrefill)
    double reward = 0.0;    // EMA fitness (how well this strategy learns/improves)
    double useCount = 0.0;
    int    id = 0;
};

// Per-cycle telemetry (optional out-param; never persisted).
struct CycleInfo {
    int    method = -1;
    int    strategyId = -1;
    Controls cand;
    double predicted = 0.0, measured = 0.0, prefill = 0.0;
    bool   ran = false, accepted = false, wasRepeat = false;
    double activeErr = 0.0, exploreProb = 0.0, mutScale = 0.0, temperature = 1.0;
    int    activePredictor = 0;
};

// Deterministic 64-bit mixer (splitmix64 finalizer) — the sole source of variation.
static inline uint64_t Mix64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

struct V5Blackboard {
    // Observation matrix (bounded) — all MEASURED.
    std::vector<Scored> obs;
    // Three fully separated evidence categories.
    std::vector<Scored> frontModeled;    // predicted prefill AND predicted decode
    std::vector<Scored> frontObserved;   // measured prefill AND measured decode
    std::vector<Scored> frontValidated;  // measured, repeat-validated best
    std::vector<Scored> rejected;        // measured-but-rejected (learning evidence)
    std::vector<Scored> hwFailures;      // hardware-failure observations (diagnostic only, never learned)
    uint64_t failKind[6] = {0,0,0,0,0,0}; // per-category failure counters (transport/cancel/num/resource/device)

    Bounds bounds;

    // Independently retained, repeat-validated best (never degrades on exploration).
    Controls best;     double bestDecode = 0.0, bestPrefill = 0.0; int bestRepeats = 0; bool haveBest = false;

    // Working "current" configuration (may explore and get worse).
    Controls current;  double curDecode = 0.0, curPrefill = 0.0;

    // Robust repeat aggregation buffer for the pending candidate.
    Controls pending;  std::vector<double> pendingSamples; double pendingDecode = 0.0;
    int pendingRepeats = 0; bool havePending = false;

    // Competing predictors (3): 0=linear, 1=quadratic, 2=nearest-neighbour.
    double w[3][5];       // decode weights
    double pw[3][5];      // prefill weights
    double err[3];        // decode error EMA per predictor
    double perr[3];       // prefill error EMA per predictor
    double lr[3];         // per-predictor self-adjusting learning rate
    double residualVar = 1.0;

    // Polymorphic strategy population (bounded).
    std::vector<Strategy> strategies;
    int  activeStrategy = 0;
    double temperature = 1.0;
    double lastImprovementIter = 0.0;
    bool   stagnated = false;

    // Changeable structured/emergent balance (default 50/50), DETERMINISTIC.
    PolymorphicRatio ratio;
    double structReward = 0.0, emergReward = 0.0;   // feedback for ratio adaptation

    // Universal peak-percentage objective (backend-independent). The requested
    // percentage is a TARGET only; it never fabricates achieved throughput. The
    // four evidence categories stay strictly separate:
    //   requested  = requestedPercent (objective, may exceed 100%)
    //   modeled    = predictions (frontModeled)
    //   measured   = observedPeak (max single measured decode)
    //   validated  = validatedPeak (repeat-validated bestDecode)
    struct PeakObjective {
        double requestedPercent = 100.0;
        double observedPeak = 0.0;
        double validatedPeak = 0.0;
        bool   parityCertified = false;
    } objective;

    // Dynamically discovered backend capabilities (which controls actually apply).
    struct BackendCapabilities {
        bool batch = true, threads = true, prefill = true, decode = true, context = true;
        bool gpu = false, residency = false, expertPaging = false, dualGpu = false;
    } caps;

    // Evolving deterministic internal state (no RNG). Variation comes from here,
    // which is itself driven only by real observations.
    uint64_t state = 0x9E3779B97F4A7C15ULL;

    uint64_t iterations = 0, accepts = 0, rejects = 0, failures = 0;
    size_t cap = 256;
    static constexpr int STRAT_CAP = 8;
    static constexpr int PENDING_CAP = 5;
    static constexpr int REJECT_CAP = 64;
    static constexpr int HW_FAIL_CAP = 32;
    static constexpr int FRONT_CAP = 64;

    V5Blackboard() {
        for (int p = 0; p < 3; ++p) {
            for (int k = 0; k < 5; ++k) { w[p][k] = 0.0; pw[p][k] = 0.0; }
            // Every competing predictor starts from the SAME weak prior intercept so
            // none begins near zero (which would make a zero-weight estimator win the
            // active-predictor contest and collapse predictions early in a run).
            w[p][0] = 200.0; pw[p][0] = 600.0;
            err[p] = 1.0; perr[p] = 1.0; lr[p] = 0.05;
        }
        SeedStrategies();
    }

    // Deterministic variation primitives (advance internal state).
    uint64_t NextU64() { state = Mix64(state); return state; }
    double   NextU01() { return (double)(NextU64() >> 11) * (1.0 / 9007199254740992.0); }
    int      NextInt(int n) { return n > 0 ? (int)(NextU64() % (uint64_t)n) : 0; }
    double   NextGauss() {
        double u1 = NextU01(); if (u1 < 1e-12) u1 = 1e-12;
        const double u2 = NextU01();
        return std::sqrt(-2.0 * std::log(u1)) * std::cos(6.283185307179586 * u2);
    }
    void ObserveState(uint64_t obs) { state = Mix64(state ^ obs); }

    void SeedStrategies() {
        strategies.clear();
        for (int i = 0; i < 5; ++i) {
            Strategy s;
            for (int m = 0; m < M_COUNT; ++m) s.w[m] = NextU01() + 0.05;
            s.mutScale = 0.2 + 0.3 * NextU01();
            s.exploreProb = 0.1 + 0.4 * NextU01();
            s.lr = 0.02 + 0.06 * NextU01();
            s.objPrefill = 0.05 + 0.15 * NextU01();
            s.reward = 0.0; s.useCount = 0.0; s.id = i;
            strategies.push_back(s);
        }
        activeStrategy = 0;
    }
};

// ---- feature maps for the competing predictors -------------------------------
static inline void Feat(int id, const Controls& c, double* phi, int& n) {
    const double nb = c.batch / 512.0, nt = c.threads / 32.0;
    if (id == 0)      { phi[0]=1; phi[1]=nb; phi[2]=nt; n=3; }
    else if (id == 1) { phi[0]=1; phi[1]=nb; phi[2]=nt; phi[3]=nb*nt; n=4; }
    else              { phi[0]=1; phi[1]=nb; phi[2]=nt; phi[3]=nb*nb; phi[4]=nt*nt; n=5; }
}
static inline double Dot(const double* w, const double* phi, int n) {
    double s = 0.0; for (int i = 0; i < n; ++i) s += w[i]*phi[i]; return s;
}

// Nearest-neighbour prediction over the measured observation matrix.
static inline double NNPredict(const V5Blackboard& bb, const Controls& c, double& outDist) {
    if (bb.obs.empty()) { outDist = 1e9; return bb.w[0][0]; }
    const double qb = c.batch/512.0, qt = c.threads/32.0;
    double best = 1e18, acc = 0.0, wsum = 0.0;
    for (const auto& o : bb.obs) {
        const double db = o.c.batch/512.0 - qb, dt = o.c.threads/32.0 - qt;
        const double d = db*db + dt*dt + 1e-6;
        const double ww = 1.0 / d;
        acc += ww * o.decode; wsum += ww;
        if (d < best) best = d;
    }
    outDist = std::sqrt(best);
    return wsum > 0 ? acc / wsum : bb.w[0][0];
}

static inline double PredictId(const V5Blackboard& bb, int id, const Controls& c) {
    if (id == 2) { double d; return NNPredict(bb, c, d); }
    double phi[5]; int n; Feat(id, c, phi, n);
    return Dot(bb.w[id], phi, n);
}
static inline double PredictPrefillId(const V5Blackboard& bb, int id, const Controls& c) {
    double phi[5]; int n; Feat(id, c, phi, n);
    return Dot(bb.pw[id], phi, n);
}

// Active predictor = lowest decode error EMA (they compete).
static inline int ActivePredictor(const V5Blackboard& bb) {
    int best = 0; for (int p = 1; p < 3; ++p) if (bb.err[p] < bb.err[best]) best = p;
    return best;
}
static inline double Predict(const V5Blackboard& bb, const Controls& c) {
    return PredictId(bb, ActivePredictor(bb), c);
}
static inline double Uncertainty(const V5Blackboard& bb) {
    return std::sqrt(bb.residualVar > 0 ? bb.residualVar : 1.0);
}

// Reflection: correct every predictor with the real measurement (E = O - P).
static inline void Correct(V5Blackboard& bb, const Controls& c, double actual, double actualPrefill) {
    for (int p = 0; p < 3; ++p) {
        double pred;
        if (p == 2) { double d; pred = NNPredict(bb, c, d); }
        else { double phi[5]; int n; Feat(p, c, phi, n); pred = Dot(bb.w[p], phi, n); }
        const double e = actual - pred;
        bb.err[p] = 0.9 * bb.err[p] + 0.1 * e * e;
        if (p != 2) {
            double phi[5]; int n; Feat(p, c, phi, n);
            const double l = bb.lr[p];
            for (int i = 0; i < n; ++i) bb.w[p][i] += l * e * phi[i];
        }
        double pphi[5]; int pn; Feat(p, c, pphi, pn);
        const double pp = Dot(bb.pw[p], pphi, pn);
        const double pe = actualPrefill - pp;
        bb.perr[p] = 0.9 * bb.perr[p] + 0.1 * pe * pe;
        const double pl = bb.lr[p];
        for (int i = 0; i < pn; ++i) bb.pw[p][i] += pl * pe * pphi[i];
    }
    const double ap = Predict(bb, c);
    bb.residualVar = 0.98 * bb.residualVar + 0.02 * (actual - ap) * (actual - ap);
    // Self-adjusting learning rates: faster when wrong, slower when accurate.
    const double e = std::sqrt(bb.err[ActivePredictor(bb)]);
    for (int p = 0; p < 3; ++p)
        bb.lr[p] = std::min(0.5, std::max(0.005, 0.02 / (0.3 + e)));
}

// Genuine Pareto: a dominates b if >= in both and > in one.
static inline bool Dominates(const Scored& x, const Scored& y) {
    return x.prefill >= y.prefill && x.decode >= y.decode &&
           (x.prefill > y.prefill || x.decode > y.decode);
}
static inline void ParetoAdd(std::vector<Scored>& f, const Scored& s) {
    for (const auto& e : f) if (Dominates(e, s)) return;
    f.erase(std::remove_if(f.begin(), f.end(),
        [&](const Scored& e){ return Dominates(s, e); }), f.end());
    if (f.size() >= V5Blackboard::FRONT_CAP) f.erase(f.begin());
    f.push_back(s);
}

static inline int ClampBatch(const V5Blackboard& bb, int b) {
    if (!bb.caps.batch) b = 32;                       // backend does not support batch control
    return std::max(1, std::min(bb.bounds.maxBatch, b));
}
static inline int ClampThreads(const V5Blackboard& bb, int t) {
    if (!bb.caps.threads) t = 1;                      // backend does not support thread control
    return std::max(1, std::min(bb.bounds.maxThreads, t));
}

// Adaptive mutation around a base config (deterministic, observation-driven).
static inline Controls Mutate(V5Blackboard& bb, Controls base, double scale) {
    const double u = Uncertainty(bb);
    const double s = scale * (0.5 + u / (u + 1.0));
    const double g1 = bb.NextGauss(), g2 = bb.NextGauss();
    base.batch   = ClampBatch(bb, (int)std::lround(base.batch * std::exp(g1 * s)));
    base.threads = ClampThreads(bb, base.threads + (int)std::lround(g2 * (1.0 + s)));
    return base;
}

static inline Controls RandomConfig(V5Blackboard& bb) {
    Controls c;
    c.batch   = ClampBatch(bb, 1 + bb.NextInt(bb.bounds.maxBatch));
    c.threads = ClampThreads(bb, 1 + bb.NextInt(bb.bounds.maxThreads));
    return c;
}

// Softmax sample an index from weights (deterministic).
static inline int SampleWeighted(V5Blackboard& bb, const double* w, int n, double temp) {
    double mx = -1e18; for (int i = 0; i < n; ++i) mx = std::max(mx, w[i]/temp);
    double sum = 0; std::vector<double> p(n);
    for (int i = 0; i < n; ++i) { p[i] = std::exp(w[i]/temp - mx); sum += p[i]; }
    double r = bb.NextU01() * sum, acc = 0;
    for (int i = 0; i < n; ++i) { acc += p[i]; if (r <= acc) return i; }
    return n-1;
}

// Deliberately revisit a previously rejected configuration (skepticism / rediscovery).
static inline Controls Rediscover(V5Blackboard& bb) {
    if (!bb.rejected.empty()) {
        Controls c = bb.rejected[bb.NextInt((int)bb.rejected.size())].c;
        return Mutate(bb, c, 0.1);   // small perturbation => genuine re-test
    }
    return RandomConfig(bb);
}

// Recombination of two measured configurations.
static inline Controls Recombine(V5Blackboard& bb) {
    if (bb.obs.size() < 2) return Mutate(bb, bb.current, 0.3);
    Controls a = bb.obs[bb.NextInt((int)bb.obs.size())].c;
    Controls b = bb.obs[bb.NextInt((int)bb.obs.size())].c;
    Controls c;
    c.batch   = ClampBatch(bb, (a.batch + b.batch) / 2);
    c.threads = ClampThreads(bb, (bb.NextU64() & 1) ? a.threads : b.threads);
    return c;
}

// Predictive selection: sample candidates and pick the best by the active
// predictor, biased toward the requested peak-percentage objective. The target is
// requestedPercent% of the best known peak (observed or validated). Candidates
// predicted to reach the target are preferred; if none reach it, the highest
// predicted candidate is chosen (approach the objective). Never fabricates.
static inline Controls PredictiveSelect(V5Blackboard& bb, int activeP) {
    const double basePeak = std::max({bb.objective.observedPeak, bb.objective.validatedPeak, 1.0});
    const double target = (bb.objective.requestedPercent / 100.0) * basePeak;
    Controls bestC = bb.current; double bestScore = -1e30;
    const int K = 8;
    for (int i = 0; i < K; ++i) {
        Controls c = (i % 2 == 0) ? Mutate(bb, bb.current, 0.3) : RandomConfig(bb);
        const double p = PredictId(bb, activeP, c);
        double score = -std::fabs(p - target);
        if (p >= target) score += 1000.0;          // prefer reaching the objective
        if (score > bestScore) { bestScore = score; bestC = c; }
    }
    return bestC;
}

// ---- strategy evolution (metacognition) --------------------------------------
static inline void NormalizeStrategy(Strategy& s) {
    double sum = 0; for (int m = 0; m < M_COUNT; ++m) { if (s.w[m] < 0) s.w[m] = 0; sum += s.w[m]; }
    if (sum <= 0) { for (int m = 0; m < M_COUNT; ++m) s.w[m] = 1.0 / (double)M_COUNT; return; }
    for (int m = 0; m < M_COUNT; ++m) s.w[m] /= sum;
}
static inline void EvolveStrategies(V5Blackboard& bb) {
    // Mutate the active strategy's policy (deterministic).
    Strategy& s = bb.strategies[bb.activeStrategy];
    for (int m = 0; m < M_COUNT; ++m) s.w[m] = std::max(0.0, s.w[m] * std::exp(bb.NextGauss() * 0.25));
    s.mutScale   = std::min(1.5, std::max(0.02, s.mutScale * std::exp(bb.NextGauss() * 0.2)));
    s.exploreProb= std::min(0.9, std::max(0.0, s.exploreProb + 0.05 * bb.NextGauss()));
    s.lr         = std::min(0.5, std::max(0.005, s.lr * std::exp(bb.NextGauss() * 0.2)));
    s.objPrefill = std::min(0.6, std::max(0.0, s.objPrefill + 0.02 * bb.NextGauss()));
    NormalizeStrategy(s);
    // Recombine two strategies occasionally.
    if (bb.strategies.size() >= 2 && bb.NextU01() < 0.5) {
        Strategy& a = bb.strategies[bb.NextInt((int)bb.strategies.size())];
        Strategy& b = bb.strategies[bb.NextInt((int)bb.strategies.size())];
        if (&a != &b) {
            const double t = 0.5;
            for (int m = 0; m < M_COUNT; ++m) a.w[m] = t*a.w[m] + (1-t)*b.w[m];
            a.mutScale = t*a.mutScale + (1-t)*b.mutScale;
            NormalizeStrategy(a);
        }
    }
    // Retire the worst strategy if clearly ineffective, replace with fresh.
    if (bb.strategies.size() > 3) {
        int worst = 0; for (size_t i = 1; i < bb.strategies.size(); ++i)
            if (bb.strategies[i].reward < bb.strategies[worst].reward) worst = (int)i;
        if (bb.strategies[worst].reward < -0.2 && bb.strategies[worst].useCount > 3) {
            Strategy fresh;
            for (int m = 0; m < M_COUNT; ++m) fresh.w[m] = bb.NextU01() + 0.05;
            fresh.mutScale = 0.2 + 0.3*bb.NextU01(); fresh.exploreProb = 0.1 + 0.4*bb.NextU01();
            fresh.lr = 0.02 + 0.06*bb.NextU01(); fresh.objPrefill = 0.05 + 0.15*bb.NextU01();
            fresh.id = bb.strategies[worst].id + 1000;
            bb.strategies[worst] = fresh; NormalizeStrategy(fresh);
        }
    }
}

// Bounded observation retention that prioritizes informative experiments.
static inline void ObsAdd(V5Blackboard& bb, const Scored& s) {
    if (bb.obs.size() >= bb.cap) {
        size_t ev = 0; double worstNovelty = 1e18;
        for (size_t i = 0; i < bb.obs.size(); ++i) {
            double nearest = 1e18;
            for (size_t j = 0; j < bb.obs.size(); ++j) if (i != j) {
                const double db = bb.obs[i].c.batch/512.0 - bb.obs[j].c.batch/512.0;
                const double dt = bb.obs[i].c.threads/32.0 - bb.obs[j].c.threads/32.0;
                nearest = std::min(nearest, db*db + dt*dt);
            }
            if (nearest < worstNovelty) { worstNovelty = nearest; ev = i; }
        }
        bb.obs.erase(bb.obs.begin() + ev);
    }
    bb.obs.push_back(s);
}

static inline void RejectAdd(V5Blackboard& bb, const Scored& s) {
    if (bb.rejected.size() >= V5Blackboard::REJECT_CAP) bb.rejected.erase(bb.rejected.begin());
    bb.rejected.push_back(s);
}

// Robust aggregation (median) of repeated measurements + consistency test.
static inline double RobustMedian(std::vector<double> v) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const size_t n = v.size();
    return (n % 2) ? v[n/2] : 0.5*(v[n/2-1] + v[n/2]);
}
static inline bool SamplesConsistent(const std::vector<double>& v) {
    if (v.size() < 2) return true;
    double mn = v[0], mx = v[0];
    for (double x : v) { mn = std::min(mn, x); mx = std::max(mx, x); }
    const double med = RobustMedian(v);
    if (med <= 0) return false;
    return (mx - mn) / med < 0.15;    // within 15% spread => consistent
}

static inline const char* MethodName(int m) {
    switch (m) {
        case M_MUTATE: return "MUTATE"; case M_EXPLORE: return "EXPLORE";
        case M_PREDICT: return "PREDICT"; case M_RECOMBINE: return "RECOMBINE";
        case M_REDISCOVER: return "REDISCOVER"; case M_REVALIDATE: return "REVALIDATE";
        default: return "?";
    }
}

// One deterministic polymorphic empirical cycle. Accounts every attempt.
static inline void ExploreCycleV5(V5Blackboard& bb, ExecutorFn exec, CycleInfo* info = nullptr) {
    ++bb.iterations;
    if (info) *info = CycleInfo{};
    const double u = Uncertainty(bb);
    const int ap = ActivePredictor(bb);

    // Stagnation detection & recovery (observation-driven).
    bb.stagnated = bb.haveBest &&
        (bb.iterations - bb.lastImprovementIter > 8.0) &&
        (bb.iterations > 12.0);

    // Temperature responds to stagnation and uncertainty (NO predetermined decay).
    double t = 0.1 + 0.5 * u / (u + 1.0) + (bb.stagnated ? 0.6 : 0.0);
    t += 0.15 * ((bb.state >> 8) & 0xFFFF) / 65535.0;   // deterministic state term
    bb.temperature = std::min(1.5, std::max(0.05, t));

    // Select a strategy (learns which optimization methods work) — deterministic.
    if (bb.strategies.empty()) bb.SeedStrategies();
    {
        std::vector<double> rw(bb.strategies.size());
        for (size_t i = 0; i < bb.strategies.size(); ++i)
            rw[i] = bb.strategies[i].reward + 0.05 * std::log1p(bb.strategies[i].useCount + 1.0);
        bb.activeStrategy = SampleWeighted(bb, rw.data(), (int)rw.size(), 0.5 + bb.temperature);
    }
    Strategy& strat = bb.strategies[bb.activeStrategy];

    // Choose a method. First the changeable, DETERMINISTIC structured/emergent
    // balance decides the group (default 50/50, no fixed ratio); then the
    // strategy's dynamic weights pick a method WITHIN that group.
    static const int STRUCT[] = { M_MUTATE, M_PREDICT, M_REVALIDATE, M_REDISCOVER };
    static const int EMERG[]  = { M_EXPLORE, M_RECOMBINE };
    auto sampleGroup = [&](const int* grp, int gn) {
        double w[M_COUNT]; double mx = -1e18;
        for (int i = 0; i < gn; ++i) { w[i] = strat.w[grp[i]]; mx = std::max(mx, w[i]); }
        double sum = 0; for (int i = 0; i < gn; ++i) { w[i] = std::exp(w[i] - mx); sum += w[i]; }
        double r = bb.NextU01() * sum, acc = 0;
        for (int i = 0; i < gn; ++i) { acc += w[i]; if (r <= acc) return grp[i]; }
        return grp[gn - 1];
    };
    const bool emergent = (bb.ratio.Select() == 1u);
    int method = emergent ? sampleGroup(EMERG, 2) : sampleGroup(STRUCT, 4);
    // Stagnation forces recovery via exploration / rediscovery / recombination.
    if (bb.stagnated) {
        const int roll = bb.NextInt(100);
        if (roll < 40) method = M_EXPLORE;
        else if (roll < 70) method = M_REDISCOVER;
        else if (roll < 85) method = M_RECOMBINE;
    }

    Controls cand;
    bool wasRepeat = false;
    switch (method) {
        case M_MUTATE:    cand = Mutate(bb, bb.current, strat.mutScale); break;
        case M_EXPLORE:   cand = RandomConfig(bb); break;
        case M_PREDICT:   cand = PredictiveSelect(bb, ap); break;
        case M_RECOMBINE: cand = Recombine(bb); break;
        case M_REDISCOVER:cand = Rediscover(bb); break;
        case M_REVALIDATE:
            wasRepeat = true;
            cand = bb.havePending ? bb.pending : (bb.haveBest ? bb.best : bb.current);
            break;
        default:          cand = Mutate(bb, bb.current, strat.mutScale); break;
    }

    const double pred = PredictId(bb, ap, cand);
    const double predPf = PredictPrefillId(bb, ap, cand);
    const double curDecodeBefore = bb.curDecode;

    Measured m;
    const bool ran = exec(cand, m);
    if (info) {
        info->method = method; info->strategyId = strat.id; info->cand = cand;
        info->predicted = pred; info->activeErr = std::sqrt(bb.err[ap]);
        info->exploreProb = strat.exploreProb; info->mutScale = strat.mutScale;
        info->temperature = bb.temperature; info->activePredictor = ap;
        info->wasRepeat = wasRepeat;
    }
    if (!ran || !m.valid || m.decodeTps <= 0 || m.hardwareFailure) {
        // Classify the failure so the engine can respond per category. Transport,
        // cancellation, numerical, resource and device failures are counted
        // separately; device/numerical/resource samples are preserved for
        // diagnostics. NONE of them reach the predictors, obs or acceptance.
        int kind = m.failure;
        if (kind == 0) kind = m.hardwareFailure ? 5 : (!ran ? 1 : 3);
        if (kind < 0 || kind > 5) kind = 3;
        ++bb.failKind[kind];
        ++bb.failures; ++bb.rejects;
        if (kind == 3 || kind == 4 || kind == 5) {
            if (bb.hwFailures.size() >= V5Blackboard::HW_FAIL_CAP) bb.hwFailures.erase(bb.hwFailures.begin());
            bb.hwFailures.push_back(Scored{cand, m.prefillTps, m.decodeTps, true});
        }
        strat.reward = 0.9 * strat.reward + 0.1 * (-0.5);
        strat.useCount += 1.0;
        return;
    }

    // Perception: ingest the real observation into internal state.
    bb.ObserveState(((uint64_t)(int64_t)(m.decodeTps * 1000.0)) ^
                    ((uint64_t)(uint32_t)m.tokens << 20) ^
                    ((uint64_t)(uint32_t)cand.batch << 2) ^
                    (uint64_t)(uint32_t)cand.threads);

    // Reflection: correct predictors with the real observation.
    Correct(bb, cand, m.decodeTps, m.prefillTps);

    // Evidence separation: modeled vs observed.
    ParetoAdd(bb.frontObserved, Scored{cand, m.prefillTps, m.decodeTps, false});
    ParetoAdd(bb.frontModeled,  Scored{cand, predPf, pred, false});   // fully modeled
    ObsAdd(bb, Scored{cand, m.prefillTps, m.decodeTps, false});
    // Measured peak (single-shot) — kept separate from the validated peak.
    bb.objective.observedPeak = std::max(bb.objective.observedPeak, m.decodeTps);

    // Measured-vs-measured acceptance. Inconsistent candidates may NOT become current.
    bool accept = m.consistent && (m.decodeTps >= bb.curDecode);
    if (!accept && m.consistent && bb.temperature > 0) {
        const double scale = (bb.curDecode > 0 ? bb.curDecode : 1.0);
        accept = (bb.NextU01()) < std::exp((m.decodeTps - bb.curDecode) / (bb.temperature * scale));
    }
    if (accept) {
        bb.current = cand; bb.curDecode = m.decodeTps; bb.curPrefill = m.prefillTps; ++bb.accepts;
    } else {
        ++bb.rejects;
        RejectAdd(bb, Scored{cand, m.prefillTps, m.decodeTps, true});
    }

    // Deliberate repeat measurement + robust aggregation for the pending candidate.
    const bool sameAsPending = bb.havePending && cand.batch == bb.pending.batch && cand.threads == bb.pending.threads;
    if (m.consistent && (sameAsPending || method == M_REVALIDATE || wasRepeat)) {
        if (!sameAsPending) { bb.pending = cand; bb.pendingSamples.clear(); bb.pendingRepeats = 0; bb.havePending = true; }
        if (bb.pendingSamples.size() < V5Blackboard::PENDING_CAP) bb.pendingSamples.push_back(m.decodeTps);
        bb.pendingRepeats = (int)bb.pendingSamples.size();
        bb.pendingDecode = RobustMedian(bb.pendingSamples);
        if (bb.pendingRepeats >= 2 && SamplesConsistent(bb.pendingSamples) &&
            (!bb.haveBest || bb.pendingDecode > bb.bestDecode)) {
            bb.best = bb.pending; bb.bestDecode = bb.pendingDecode; bb.bestPrefill = m.prefillTps;
            bb.bestRepeats = bb.pendingRepeats; bb.haveBest = true;
            bb.lastImprovementIter = (double)bb.iterations;
            ParetoAdd(bb.frontValidated, Scored{bb.best, m.prefillTps, bb.bestDecode, false});
        }
    }

    // Strategy reward (metacognition): did this strategy reduce error / improve best?
    const double improve = (bb.curDecode - curDecodeBefore) / (curDecodeBefore > 0 ? curDecodeBefore : 1.0);
    const double eNorm = std::sqrt(bb.err[ap]);
    const double reward = 0.5 * improve + 0.5 * (-eNorm / (1.0 + eNorm));
    strat.reward = 0.9 * strat.reward + 0.1 * reward;
    strat.useCount += 1.0;

    // Feed the DETERMINISTIC ratio arbiter with real reward.
    if (emergent) bb.emergReward = 0.9 * bb.emergReward + 0.1 * reward;
    else          bb.structReward = 0.9 * bb.structReward + 0.1 * reward;
    if (bb.iterations % 5 == 0) {
        int pct = (int)bb.ratio.First();
        if (bb.structReward > bb.emergReward + 1e-9)      pct += 2;
        else if (bb.emergReward > bb.structReward + 1e-9) pct -= 2;
        pct = std::max(20, std::min(80, pct));
        bb.ratio.Set((uint32_t)pct, (uint32_t)(100 - pct));
    }

    // Evolve the strategy population occasionally (policy-level learning).
    if (bb.NextInt(3) == 0) EvolveStrategies(bb);

    // Validated peak mirrors the independently repeat-validated best only.
    bb.objective.validatedPeak = bb.bestDecode;

    if (info) {
        info->ran = true; info->measured = m.decodeTps; info->prefill = m.prefillTps;
        info->accepted = accept;
    }
}

} // namespace blackboard_v5
} // namespace rawrxd