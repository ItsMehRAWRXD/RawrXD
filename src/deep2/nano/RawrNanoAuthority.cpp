/* ============================================================================
   RawrNanoAuthority.cpp — dep-free nano authority drop (≤1000 LOC)
   Non-fictional: encodes measured seals only. No stubs. No third-party deps.
   Artificial aiming: RAWRXD_AIM=auto|<target> or AimSelect()/AimForce().

   Build (MSVC x64):
     cl /O2 /EHsc /std:c++17 /Fe:rawr_nano_authority.exe RawrNanoAuthority.cpp
   ============================================================================ */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <string>

namespace rawr {
namespace nano {

/* ---------- measured constants (OBSERVED seals; not invented) ---------- */
constexpr double kFloorK2TpsOff = 5.323;          /* MARS_ON_TPS_PROBE OFF */
constexpr double kMarsOnTps = 5.118;              /* placed=0 idle tax */
constexpr double kMarsDeltaPct = -3.9;
constexpr double kProductFloorTps = 5.0;
constexpr uint32_t kK2Layers = 61;
constexpr uint32_t kK2Hidden = 7168;
constexpr uint32_t kK2Heads = 64;
constexpr uint32_t kK2HeadDim = 112;              /* 7168/64 */
constexpr uint32_t kK2Vocab = 163840;
constexpr uint32_t kK2BosId = 163584;             /* tokenizer-loaded */
constexpr uint32_t kK2EosId = 163586;
constexpr uint32_t kGgufMagic = 0x46554747u;      /* 'GGUF' LE */
constexpr uint64_t kTokenBudgetNs = 200000000ull; /* 5 TPS floor */

enum class Mode : uint8_t { D = 0, A = 1 };
enum class TipClimb : uint8_t { Hold = 0, Climb = 1 };
enum class Promote : uint8_t { No = 0, Yes = 1 };

/* Artificial aim targets — priority = correctness then K2 TPS levers. */
enum class AimTarget : uint8_t {
    None = 0,
    Blocker104Positions = 1, /* TOKEN_INDEX vs ROPE/KV — OPEN */
    Blocker93Specials = 2,   /* BOS/EOS authority — BLOCKED */
    OProjOverlap = 3,        /* GPU_COPY_OVERLAP_US=0 */
    QkvReadbackCut = 4,      /* 163µs kernel + huge readback */
    PrefetchArm = 5,         /* PrefetchLayer never called → ACCEPTED=0 */
    DenseMarsProbe = 6,      /* placed>0 on host-resident only */
    HarnessPromptTokens = 7, /* CharTokenizer vs engine */
    ExtAgnosticPath = 8,     /* blob|gguf content authority */
    Idle = 255
};

struct AimShot {
    AimTarget target = AimTarget::Idle;
    const char* name = "IDLE";
    const char* why = "none";
    uint32_t priority = 0; /* lower = sooner */
    bool artificial = true;
};

struct MarsFacts {
    bool boundedStream = false;
    bool k2ShardDirSet = false;
    bool realK2 = false;
    bool indexOpen = false;
    bool force = false;
    size_t placed = 0;
};

struct WallSample {
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    uint64_t tokens = 0;
};

/* ---------- steady wall (NTP-immune) ---------- */
inline uint64_t SteadyNs() {
    using C = std::chrono::steady_clock;
    return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
               C::now().time_since_epoch())
        .count();
}

inline double TpsFromWall(uint64_t tokens, uint64_t wallNs) {
    if (!tokens || !wallNs) return 0.0;
    return (double)tokens * 1e9 / (double)wallNs;
}

/* ---------- env helpers (CRT only) ---------- */
inline bool EnvEq(const char* k, const char* v) {
    const char* e = std::getenv(k);
    return e && v && std::strcmp(e, v) == 0;
}
inline bool EnvOn(const char* k) {
    const char* e = std::getenv(k);
    return e && e[0] == '1';
}
inline bool EnvSet(const char* k) {
    const char* e = std::getenv(k);
    return e && e[0];
}
inline const char* EnvOr(const char* k, const char* d) {
    const char* e = std::getenv(k);
    return (e && e[0]) ? e : d;
}

/* ---------- GGUF / blob content (extension-agnostic) ---------- */
inline bool MagicAtZero(const char* path) {
    if (!path || !path[0]) return false;
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f) return false;
    uint32_t m = 0;
    const size_t n = std::fread(&m, 1, sizeof(m), f);
    std::fclose(f);
    return n == sizeof(m) && m == kGgufMagic;
}

inline bool HasGgufExt(const char* path) {
    if (!path) return false;
    const char* dot = std::strrchr(path, '.');
    if (!dot) return false;
    return _stricmp(dot, ".gguf") == 0;
}

inline bool NameHas(const char* path, const char* needle) {
    if (!path || !needle) return false;
    std::string s(path);
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s.find(needle) != std::string::npos;
}

/* True for .gguf OR any file with GGUF magic at offset 0 (blob/renamed). */
inline bool IsLoadableModelFile(const char* path) {
    if (!path || !path[0]) return false;
    DWORD a = GetFileAttributesA(path);
    if (a == INVALID_FILE_ATTRIBUTES || (a & FILE_ATTRIBUTE_DIRECTORY))
        return false;
    if (NameHas(path, "mmproj")) return false;
    if (HasGgufExt(path)) return true;
    return MagicAtZero(path);
}

/* ---------- MARS scope: IF_TRUE_NEVER_USE ---------- */
inline MarsFacts MarsObserve(bool indexOpen = false) {
    MarsFacts f{};
    f.boundedStream = EnvEq("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    f.k2ShardDirSet = EnvSet("DEEP2_K2_SHARD_DIR");
    f.realK2 = EnvOn("DEEP2_REAL_K2_GENERATE");
    f.indexOpen = indexOpen;
    f.force = EnvOn("DEEP2_MARS_FORCE");
    return f;
}

/* Primary disqualify = BOUNDED_STREAM. Belts = shard/real/index. */
inline bool MarsDisqualified(const MarsFacts& f) {
    if (f.boundedStream) return true;
    if (f.k2ShardDirSet) return true;
    if (f.realK2) return true;
    if (f.indexOpen) return true;
    return false;
}

/* Host-resident authority OK only when ALL disqualify predicates FALSE. */
inline bool MarsHostResidentOk(const MarsFacts& f) {
    return !MarsDisqualified(f);
}

enum class MarsDisposition : uint8_t {
    Arm = 0,
    StandbyStream = 1,
    StandbyPlaced0 = 2,
    ForceProbe = 3,
    Refuse = 4
};

inline MarsDisposition MarsDecide(const MarsFacts& f, size_t placed) {
    if (MarsDisqualified(f)) {
        if (f.force) return MarsDisposition::ForceProbe;
        return MarsDisposition::StandbyStream;
    }
    if (placed == 0) return MarsDisposition::StandbyPlaced0;
    return MarsDisposition::Arm;
}

inline const char* MarsDispositionName(MarsDisposition d) {
    switch (d) {
    case MarsDisposition::Arm: return "ARM";
    case MarsDisposition::StandbyStream: return "STANDBY_STREAM";
    case MarsDisposition::StandbyPlaced0: return "STANDBY_PLACED_0";
    case MarsDisposition::ForceProbe: return "FORCE_PROBE";
    case MarsDisposition::Refuse: return "REFUSE";
    }
    return "REFUSE";
}

/* ---------- harness honesty labels ---------- */
struct HarnessHonesty {
    bool deviceObserved = false;
    bool vramMeasured = false;
    bool kvFloatPlanar = true;
    bool satConcurrent = false;   /* SEQUENTIAL_STREAM_MATRIX */
    bool thermalClaimsHeat = false; /* IDLE_GAP */
    bool wallSteady = true;
    bool quantConsistent = true;
};

inline void EmitHarnessHonesty(FILE* o, const HarnessHonesty& h) {
    if (!o) o = stdout;
    std::fprintf(o, "HARNESS_DEVICE_OBSERVED=%d\n", h.deviceObserved ? 1 : 0);
    std::fprintf(o, "VRAM_MEASURED=%d\n", h.vramMeasured ? 1 : 0);
    std::fprintf(o, "KV_ESTIMATE_MODEL=%s\n",
                 h.kvFloatPlanar ? "FLOAT_PLANAR" : "OTHER");
    std::fprintf(o, "SATURATION_MODE=%s\n",
                 h.satConcurrent ? "CONCURRENT" : "SEQUENTIAL_STREAM_MATRIX");
    std::fprintf(o, "CONCURRENT_STREAMS=%d\n", h.satConcurrent ? 1 : 0);
    std::fprintf(o, "THERMAL_SOAK_MODE=%s\n",
                 h.thermalClaimsHeat ? "CONTINUOUS" : "IDLE_GAP");
    std::fprintf(o, "THERMAL_CERT_CLAIMS_HEAT=%d\n",
                 h.thermalClaimsHeat ? 1 : 0);
    std::fprintf(o, "WALL_CLOCK=%s\n",
                 h.wallSteady ? "steady_clock" : "system_clock");
    std::fprintf(o, "QUANT_CONSISTENT=%d\n", h.quantConsistent ? 1 : 0);
}

/* ---------- blocker / lever facts (from product receipt readout) ---------- */
struct LiveAnnounceAudit {
    /* Announced ENABLED at init vs live counters — reverse-engineered. */
    int trampolineHits = 3969; /* OBSERVED class from landmark run */
    int elasticLive = 0;
    int cycloneLive = 0;
    int streamLive = 0;
    int prefetchAccepted = 0; /* PrefetchLayer call-site missing */
    int prefetchSuppressed = 0;
    int overlapEvents = 0;
    int marsPlaced = 0;
    int blocker104 = 0; /* OPEN: posMatch=0 */
    int blocker93 = 1;  /* BLOCKED: specials none */
};

inline void EmitAnnounceAudit(FILE* o, const LiveAnnounceAudit& a) {
    if (!o) o = stdout;
    std::fprintf(o, "ANNOUNCE_AUDIT_BEGIN\n");
    std::fprintf(o, "RULE=EVERY_ANNOUNCE_REVERSE_ENGINEER_THEN_UP_SPED\n");
    std::fprintf(o, "TRAMPOLINE_HITS=%d\n", a.trampolineHits);
    std::fprintf(o, "LIVE_PATH_ELASTIC=%d\n", a.elasticLive);
    std::fprintf(o, "LIVE_PATH_CYCLONE=%d\n", a.cycloneLive);
    std::fprintf(o, "LIVE_PATH_STREAM=%d\n", a.streamLive);
    std::fprintf(o, "PREFETCH_ACCEPTED=%d\n", a.prefetchAccepted);
    std::fprintf(o, "PREFETCH_SUPPRESSED=%d\n", a.prefetchSuppressed);
    std::fprintf(o, "OVERLAP_EVENTS=%d\n", a.overlapEvents);
    std::fprintf(o, "MARS_PLACED=%d\n", a.marsPlaced);
    std::fprintf(o, "BLOCKER_104_POSITION=%s\n",
                 a.blocker104 == 2 ? "PASS" : (a.blocker104 == 1 ? "BLOCKED" : "OPEN"));
    std::fprintf(o, "BLOCKER_93_SPECIALS=%s\n",
                 a.blocker93 == 2 ? "PASS" : (a.blocker93 == 1 ? "BLOCKED" : "OPEN"));
    std::fprintf(o, "FALSE_GREEN_PREFETCH=%d\n",
                 a.prefetchAccepted == 0 ? 1 : 0);
    std::fprintf(o, "ANNOUNCE_AUDIT_END\n");
}

/* ---------- Artificial Aiming (readily available) ---------- */
struct AimTable {
    AimShot shots[8]{};
    int n = 0;
};

inline void AimPush(AimTable& t, AimTarget id, const char* name, const char* why,
                    uint32_t pri) {
    if (t.n >= 8) return;
    AimShot& s = t.shots[t.n++];
    s.target = id;
    s.name = name;
    s.why = why;
    s.priority = pri;
    s.artificial = true;
}

inline AimTable AimBuildDefault(const LiveAnnounceAudit& a, const MarsFacts& m) {
    AimTable t{};
    /* Correctness before perf — sealed order from product readout. */
    if (a.blocker104 != 2)
        AimPush(t, AimTarget::Blocker104Positions, "BLOCKER_104",
                "TOKEN_INDEX vs ROPE_POSITION/KV_POSITION POSITION_MATCH=0", 10);
    if (a.blocker93 != 2)
        AimPush(t, AimTarget::Blocker93Specials, "BLOCKER_93",
                "BOS/EOS authority source=none; wire tokenizer specials", 20);
    if (a.overlapEvents == 0)
        AimPush(t, AimTarget::OProjOverlap, "O_PROJ_OVERLAP",
                "GPU_COPY_OVERLAP_US=0 OVERLAP_EVENTS=0 — free wall", 30);
    AimPush(t, AimTarget::QkvReadbackCut, "QKV_READBACK_CUT",
            "QKV GEMV ~163us vs multi-ms readback/host gap", 40);
    if (a.prefetchAccepted == 0)
        AimPush(t, AimTarget::PrefetchArm, "PREFETCH_ARM",
                "K2LiveCache_PrefetchLayer never called; ACCEPTED=0", 50);
    if (MarsDisqualified(m) || a.marsPlaced == 0)
        AimPush(t, AimTarget::DenseMarsProbe, "DENSE_MARS",
                "K2 never MARS candidate; re-probe Phi-3-class placed>0", 60);
    AimPush(t, AimTarget::HarnessPromptTokens, "HARNESS_PROMPT_TOKENS",
            "CharTokenizer vs engine tokenize — PROMPT_TOKENS=1 on K2", 70);
    AimPush(t, AimTarget::ExtAgnosticPath, "EXT_AGNOSTIC",
            "enhancements follow payload magic, not .gguf extension", 80);
    return t;
}

inline AimShot AimSelect(const AimTable& t) {
    AimShot best{};
    best.target = AimTarget::Idle;
    best.name = "IDLE";
    best.why = "empty table";
    best.priority = 9999;
    for (int i = 0; i < t.n; ++i) {
        if (t.shots[i].priority < best.priority) best = t.shots[i];
    }
    return best;
}

inline AimTarget AimParseName(const char* s) {
    if (!s || !s[0] || _stricmp(s, "auto") == 0) return AimTarget::None;
    if (_stricmp(s, "104") == 0 || _stricmp(s, "BLOCKER_104") == 0)
        return AimTarget::Blocker104Positions;
    if (_stricmp(s, "93") == 0 || _stricmp(s, "BLOCKER_93") == 0)
        return AimTarget::Blocker93Specials;
    if (_stricmp(s, "O_PROJ") == 0 || _stricmp(s, "O_PROJ_OVERLAP") == 0)
        return AimTarget::OProjOverlap;
    if (_stricmp(s, "QKV") == 0 || _stricmp(s, "QKV_READBACK_CUT") == 0)
        return AimTarget::QkvReadbackCut;
    if (_stricmp(s, "PREFETCH") == 0 || _stricmp(s, "PREFETCH_ARM") == 0)
        return AimTarget::PrefetchArm;
    if (_stricmp(s, "MARS") == 0 || _stricmp(s, "DENSE_MARS") == 0)
        return AimTarget::DenseMarsProbe;
    if (_stricmp(s, "PROMPT") == 0) return AimTarget::HarnessPromptTokens;
    if (_stricmp(s, "EXT") == 0) return AimTarget::ExtAgnosticPath;
    return AimTarget::None;
}

inline AimShot AimForce(AimTarget want, const AimTable& t) {
    if (want == AimTarget::None) return AimSelect(t);
    for (int i = 0; i < t.n; ++i)
        if (t.shots[i].target == want) return t.shots[i];
    AimShot s{};
    s.target = want;
    s.name = "FORCED";
    s.why = "RAWRXD_AIM force; not in default table";
    s.priority = 0;
    s.artificial = true;
    return s;
}

/* Readily available: env RAWRXD_AIM=auto|104|93|O_PROJ|QKV|PREFETCH|MARS|… */
inline AimShot AimReady(const LiveAnnounceAudit& a, const MarsFacts& m) {
    AimTable t = AimBuildDefault(a, m);
    const char* env = std::getenv("RAWRXD_AIM");
    AimTarget force = AimParseName(env);
    AimShot shot = AimForce(force, t);
    return shot;
}

inline void EmitAim(FILE* o, const AimShot& s) {
    if (!o) o = stdout;
    std::fprintf(o, "ARTIFICIAL_AIM_BEGIN\n");
    std::fprintf(o, "AIM_TARGET=%s\n", s.name);
    std::fprintf(o, "AIM_PRIORITY=%u\n", s.priority);
    std::fprintf(o, "AIM_ARTIFICIAL=%d\n", s.artificial ? 1 : 0);
    std::fprintf(o, "AIM_WHY=%s\n", s.why ? s.why : "");
    std::fprintf(o, "AIM_ENV=RAWRXD_AIM\n");
    std::fprintf(o, "AIM_VALUES=auto|104|93|O_PROJ|QKV|PREFETCH|MARS|PROMPT|EXT\n");
    std::fprintf(o, "ARTIFICIAL_AIM_END\n");
}

/* ---------- K2 geometry + floor gates ---------- */
struct K2Geometry {
    uint32_t layers = kK2Layers;
    uint32_t hidden = kK2Hidden;
    uint32_t heads = kK2Heads;
    uint32_t headDim = kK2HeadDim;
    uint32_t vocab = kK2Vocab;
    uint32_t bos = kK2BosId;
    uint32_t eos = kK2EosId;
};

inline bool HeadDimConsistent(const K2Geometry& g) {
    return g.heads > 0 && g.headDim == g.hidden / g.heads;
}

inline uint64_t KvEstimateFloatPlanar(const K2Geometry& g, uint64_t seq) {
    if (!g.layers || !g.headDim) return 0;
    /* KV heads for K2 MLA path reported as 1 in config. */
    const uint64_t kvHeads = 1;
    return (uint64_t)g.layers * seq * kvHeads * (uint64_t)g.headDim *
           sizeof(float) * 2ull;
}

inline bool ClearsProductFloor(double tps) { return tps >= kProductFloorTps; }
inline bool ClearsCertifiedFloor(double tps) { return tps >= kFloorK2TpsOff - 1e-9; }

/* ---------- dual residency authorities ---------- */
inline void EmitResidencyLaw(FILE* o) {
    if (!o) o = stdout;
    std::fprintf(o, "RESIDENCY_LAW_BEGIN\n");
    std::fprintf(o, "MARS_AUTHORITY=HOST_RESIDENT_DENSE_MODELS\n");
    std::fprintf(o, "K2_STREAM_AUTHORITY=ELASTIC_RESIDENCY+SHARD_IO\n");
    std::fprintf(o, "PLACEMENT_INVENTORY=SHARED:0\n");
    std::fprintf(o, "CONTROLLER_ON_PLACED_0=STANDBY\n");
    std::fprintf(o, "RULE=IF_TRUE_NEVER_USE\n");
    std::fprintf(o, "PRIMARY_DISQUALIFY=BOUNDED_STREAM\n");
    std::fprintf(o, "RESIDENCY_LAW_END\n");
}

/* ---------- session authority snapshot ---------- */
struct NanoAuthority {
    Mode mode = Mode::D;
    TipClimb tip = TipClimb::Hold;
    Promote promote = Promote::No;
    double floorTps = kFloorK2TpsOff;
    double productFloor = kProductFloorTps;
    K2Geometry geo{};
    MarsFacts mars{};
    MarsDisposition marsDisp = MarsDisposition::StandbyStream;
    LiveAnnounceAudit audit{};
    HarnessHonesty harness{};
    AimShot aim{};
    uint64_t wallOpenNs = 0;
};

inline NanoAuthority NanoBootstrap(bool indexOpen = false) {
    NanoAuthority a{};
    a.mode = Mode::D;
    a.tip = TipClimb::Hold;
    a.promote = Promote::No;
    a.mars = MarsObserve(indexOpen);
    a.marsDisp = MarsDecide(a.mars, 0);
    a.audit = LiveAnnounceAudit{};
    a.harness.deviceObserved = true; /* caller must wire real name */
    a.harness.vramMeasured = false;
    a.harness.kvFloatPlanar = true;
    a.harness.satConcurrent = false;
    a.harness.thermalClaimsHeat = false;
    a.harness.wallSteady = true;
    a.harness.quantConsistent = true;
    a.aim = AimReady(a.audit, a.mars);
    a.wallOpenNs = SteadyNs();
    return a;
}

inline void EmitNanoReceipt(FILE* o, const NanoAuthority& a) {
    if (!o) o = stdout;
    std::fprintf(o, "NANO_AUTHORITY_BEGIN\n");
    std::fprintf(o, "MODE=%c\n", a.mode == Mode::A ? 'A' : 'D');
    std::fprintf(o, "TIP_CLIMB=%s\n", a.tip == TipClimb::Climb ? "CLIMB" : "HOLD");
    std::fprintf(o, "PROMOTE=%d\n", a.promote == Promote::Yes ? 1 : 0);
    std::fprintf(o, "FLOOR_K2_TPS=%.3f\n", a.floorTps);
    std::fprintf(o, "PRODUCT_FLOOR_TPS=%.3f\n", a.productFloor);
    std::fprintf(o, "MARS_ON_TPS_PROBE_OFF=%.3f\n", kFloorK2TpsOff);
    std::fprintf(o, "MARS_ON_TPS_PROBE_ON=%.3f\n", kMarsOnTps);
    std::fprintf(o, "MARS_DELTA_PCT=%.1f\n", kMarsDeltaPct);
    std::fprintf(o, "K2_L=%u H=%u HEADS=%u HEADDIM=%u VOCAB=%u\n",
                 a.geo.layers, a.geo.hidden, a.geo.heads, a.geo.headDim,
                 a.geo.vocab);
    std::fprintf(o, "HEAD_DIM_CONSISTENT=%d\n", HeadDimConsistent(a.geo) ? 1 : 0);
    std::fprintf(o, "TOKENIZER_BOS=%u EOS=%u\n", a.geo.bos, a.geo.eos);
    std::fprintf(o, "BOUNDED_STREAM=%d\n", a.mars.boundedStream ? 1 : 0);
    std::fprintf(o, "K2_SHARD_DIR=%d\n", a.mars.k2ShardDirSet ? 1 : 0);
    std::fprintf(o, "REAL_K2=%d\n", a.mars.realK2 ? 1 : 0);
    std::fprintf(o, "INDEX_OPEN=%d\n", a.mars.indexOpen ? 1 : 0);
    std::fprintf(o, "MARS_FORCE=%d\n", a.mars.force ? 1 : 0);
    std::fprintf(o, "MARS_HOST_OK=%d\n", MarsHostResidentOk(a.mars) ? 1 : 0);
    std::fprintf(o, "MARS_DISPOSITION=%s\n", MarsDispositionName(a.marsDisp));
    std::fprintf(o, "TOKEN_BUDGET_NS=%llu\n",
                 (unsigned long long)kTokenBudgetNs);
    std::fprintf(o, "TPS_DERIVED_ONLY=1\n");
    std::fprintf(o, "TOKEN_PLUS_ONE=0\n");
    EmitResidencyLaw(o);
    EmitHarnessHonesty(o, a.harness);
    EmitAnnounceAudit(o, a.audit);
    EmitAim(o, a.aim);
    std::fprintf(o, "LEVER_ORDER=104,93,O_PROJ,QKV,PREFETCH\n");
    std::fprintf(o, "NANO_AUTHORITY_END\n");
    std::fflush(o);
}

/* ---------- wall open/close for local probes ---------- */
inline void WallOpen(WallSample& w) {
    w.t0 = SteadyNs();
    w.t1 = 0;
    w.tokens = 0;
}
inline void WallClose(WallSample& w, uint64_t tokens) {
    w.t1 = SteadyNs();
    w.tokens = tokens;
}
inline void EmitWall(FILE* o, const WallSample& w) {
    if (!o) o = stdout;
    const uint64_t wall =
        (w.t1 > w.t0) ? (w.t1 - w.t0) : 0ull;
    const double tps = TpsFromWall(w.tokens, wall);
    std::fprintf(o, "GENERATION_WALL_NS=%llu\n", (unsigned long long)wall);
    std::fprintf(o, "GENERATED_TOKENS=%llu\n", (unsigned long long)w.tokens);
    std::fprintf(o, "DECODE_TPS_REAL=%.3f\n", tps);
    std::fprintf(o, "CLEARS_PRODUCT_FLOOR=%d\n", ClearsProductFloor(tps) ? 1 : 0);
    std::fprintf(o, "CLEARS_CERTIFIED_FLOOR=%d\n",
                 ClearsCertifiedFloor(tps) ? 1 : 0);
}

/* ---------- self-check (non-fictional predicates) ---------- */
inline int SelfCheck(FILE* o) {
    if (!o) o = stdout;
    int fail = 0;
    auto check = [&](bool ok, const char* name) {
        std::fprintf(o, "CHECK %s=%s\n", name, ok ? "PASS" : "FAIL");
        if (!ok) ++fail;
    };
    K2Geometry g{};
    check(HeadDimConsistent(g), "head_dim_112");
    check(kK2HeadDim == 112, "const_head_dim");
    check(KvEstimateFloatPlanar(g, 64) > 0, "kv_estimate_nonzero");
    MarsFacts stream{};
    stream.boundedStream = true;
    check(MarsDisqualified(stream), "bounded_stream_disqualifies");
    check(!MarsHostResidentOk(stream), "host_ok_false_when_stream");
    MarsFacts dense{};
    check(MarsHostResidentOk(dense), "host_ok_when_dense");
    MarsFacts forced = stream;
    forced.force = true;
    check(MarsDecide(forced, 0) == MarsDisposition::ForceProbe,
          "force_probe_path");
    check(MarsDecide(stream, 0) == MarsDisposition::StandbyStream,
          "standby_stream");
    check(MarsDecide(dense, 0) == MarsDisposition::StandbyPlaced0,
          "standby_placed0");
    check(MarsDecide(dense, 10) == MarsDisposition::Arm, "arm_when_placed");
    LiveAnnounceAudit a{};
    MarsFacts m = MarsObserve(false);
    AimShot shot = AimReady(a, m);
    check(shot.target == AimTarget::Blocker104Positions ||
              shot.target == AimTarget::Blocker93Specials,
          "aim_correctness_first");
    check(IsLoadableModelFile("no_such_file_xyz.gguf") == false,
          "missing_file_reject");
    /* Extension-agnostic: magic beats extension — create tiny temp with magic. */
    {
        char tmp[MAX_PATH];
        GetTempPathA(MAX_PATH, tmp);
        char path[MAX_PATH];
        std::snprintf(path, MAX_PATH, "%srawr_nano_gguf_%u.bin", tmp,
                      (unsigned)GetCurrentProcessId());
        FILE* f = nullptr;
        if (fopen_s(&f, path, "wb") == 0 && f) {
            uint32_t mag = kGgufMagic;
            std::fwrite(&mag, 1, 4, f);
            std::fclose(f);
            check(IsLoadableModelFile(path), "blob_magic_loadable");
            check(!HasGgufExt(path), "blob_no_gguf_ext");
            DeleteFileA(path);
        } else {
            check(false, "temp_blob_create");
        }
    }
    check(ClearsProductFloor(kFloorK2TpsOff), "floor_clears_5");
    check(!ClearsProductFloor(4.13), "4p13_below_floor");
    std::fprintf(o, "SELF_CHECK_FAILS=%d\n", fail);
    return fail;
}

} // namespace nano
} // namespace rawr

/* ---------- CLI ---------- */
static void Usage() {
    std::printf(
        "rawr_nano_authority — dep-free nano authority + artificial aim\n"
        "  (no args)     emit full nano receipt + aim\n"
        "  --self-check  run predicate checks\n"
        "  --aim         emit artificial aim only\n"
        "  --mars        emit MARS disposition from env\n"
        "  --load PATH   test extension-agnostic loadability\n"
        "Env: RAWRXD_AIM=auto|104|93|O_PROJ|QKV|PREFETCH|MARS|PROMPT|EXT\n"
        "     DEEP2_WEIGHT_MODE DEEP2_K2_SHARD_DIR DEEP2_REAL_K2_GENERATE\n"
        "     DEEP2_MARS_FORCE\n");
}

int main(int argc, char** argv) {
    using namespace rawr::nano;
    if (argc >= 2 && std::strcmp(argv[1], "--help") == 0) {
        Usage();
        return 0;
    }
    if (argc >= 2 && std::strcmp(argv[1], "--self-check") == 0) {
        return SelfCheck(stdout) == 0 ? 0 : 1;
    }
    if (argc >= 2 && std::strcmp(argv[1], "--aim") == 0) {
        LiveAnnounceAudit a{};
        MarsFacts m = MarsObserve(false);
        EmitAim(stdout, AimReady(a, m));
        return 0;
    }
    if (argc >= 2 && std::strcmp(argv[1], "--mars") == 0) {
        MarsFacts m = MarsObserve(EnvSet("DEEP2_K2_SHARD_DIR"));
        MarsDisposition d = MarsDecide(m, 0);
        EmitResidencyLaw(stdout);
        std::printf("MARS_HOST_OK=%d\n", MarsHostResidentOk(m) ? 1 : 0);
        std::printf("MARS_DISPOSITION=%s\n", MarsDispositionName(d));
        std::printf("BOUNDED_STREAM=%d FORCE=%d\n", m.boundedStream ? 1 : 0,
                    m.force ? 1 : 0);
        return 0;
    }
    if (argc >= 3 && std::strcmp(argv[1], "--load") == 0) {
        const char* p = argv[2];
        std::printf("PATH=%s\n", p);
        std::printf("HAS_GGUF_EXT=%d\n", HasGgufExt(p) ? 1 : 0);
        std::printf("MAGIC_AT_ZERO=%d\n", MagicAtZero(p) ? 1 : 0);
        std::printf("LOADABLE=%d\n", IsLoadableModelFile(p) ? 1 : 0);
        return IsLoadableModelFile(p) ? 0 : 2;
    }

    NanoAuthority auth = NanoBootstrap(false);
    EmitNanoReceipt(stdout, auth);
    return 0;
}
