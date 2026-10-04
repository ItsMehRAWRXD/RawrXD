// ============================================================================
// KernelLoomGenerator.cpp
//
// RAWRXD_SPACELESS_EXECUTION_VIEW_GEMV_002
// RAWRXD_UNLIMITED_LOOM_STUB_GRAMMAR_GENERATOR_001
//
// An unbounded kernel-vacancy generator.
//
// WHAT THIS IS NOT
//   It is not a kernel catalog, and it does not implement anything. It emits
//   DECLARATIONS -- semantic vacancies that a later tracer, compiler and
//   verifier may materialize, execute, measure, reject or braid.
//
// THE SEED
//   NanoQuant's binary-basis factorisation is used as one ANCESTRAL GRAMMAR,
//   not as a format:
//
//       W  ~=  sum_i  alpha_i * B_i
//       y  ~=  sum_i  alpha_i * GEMV(B_i, x)
//
//   where B_i is itself factorisable (B_i = U_i V_i) so the GEMV can run off
//   the bases WITHOUT materialising W. That is the "spaceless" property:
//
//       DEQUANT_BUFFER               = 0
//       RECONSTRUCTED_WEIGHT_BUFFER  = 0
//       PERMANENT_DERIVED_WEIGHT     = 0
//       SOURCE_WEIGHT_MUTATION       = 0
//
// THE SIGNED SCALE DOMAIN
//   "1.5-bit" is not a thing: bit width is a storage property and cannot be
//   negative. The sign belongs to the BASIS COEFFICIENT, so the domain is:
//
//       SEED_SCALE_MIN  = -1.5x
//       SEED_SCALE_MAX  = +1.5x
//       SCALE_DOMAIN    = SIGNED_DYNAMIC
//       FIXED_MAX       = NONE
//
//   The positive envelope widens across generations, but NOT for its own sake.
//   --residual-gate makes widening conditional on a measured reconstruction
//   improvement, so the envelope grows only while it buys accuracy. Without
//   that flag the envelope is open (the user's "-*.*x max"); with it, growth
//   must be earned.
//
// WEIGHT-OWNERSHIP CORRECTION (baked in, not documented after the fact)
//   Calling LinearW() does not mean LinearW() performs the arithmetic. It is a
//   dispatcher: on a GPU-eligible route it hands the tensor to
//   tryVulkanHostGEMV and RETURNS. So a route that merely contains
//   LinearW(weight, ...) is CONDITIONAL, not OWNED:
//
//       BYPASS     = compute never enters LinearW
//       DELEGATED  = enters LinearW, LinearW hands off, returns
//       OWNED      = enters LinearW and reaches its local GEMV kernel
//       CONDITIONAL= source can be DELEGATED or OWNED by runtime route
//
//   Getting this wrong is how "we hooked LinearW" turns into false coverage.
//
// NO BOUNDARY vs HARD BOUNDARY
//   Free to cross: kernel names, layer decomposition, CPU/GPU assignment,
//                  fusion seams, quant representation, residency strategy.
//   Never free:  memory validity, declared observable semantics, finite
//                output, hardware capability.
//   GENERATION_SPACE=OPEN and SAFETY_BOUNDARY=ABSOLUTE coexist deliberately.
//
// BUILD
//   C++17, standard library only.
//   cl /std:c++17 /EHsc /O2 kernel_loom_gen.cpp
//   ./kernel_loom_gen.exe --seed 1337 --count 64 --out loom.hpp
//   ./kernel_loom_gen.exe --seed 1337 --count 0            (streams forever)
// ============================================================================

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace rawrxd::loom {

// ---------------------------------------------------------------------------
struct Options {
    std::uint64_t seed    = 0x52415752584C4F4DULL; // "RAWRXDLOM"
    std::uint64_t count   = 256;      // 0 = stream until interrupted
    double  scale_min     = -1.5;     // SEED_SCALE_MIN
    double  scale_seed_max=  1.5;     // SEED_SCALE_MAX
    double  scale_growth  =  1.125;   // envelope multiplier per epoch
    std::uint32_t epoch   = 64;
    // When set, the envelope only widens if the modelled residual improves.
    // This is what turns "unlimited" from "arbitrary" into "earned".
    bool    residual_gate = false;
    std::uint32_t basis_seed = 4;
    std::uint32_t rank_seed = 8;
    std::string out;
};

struct Atom { std::string_view token; std::uint32_t id; };

// Grammar dimensions. These are ANCESTRY HINTS, not the identity: the
// identity of a genome is its fingerprint, and nothing downstream may treat a
// semantic tag as the thing that is actually being executed.
static constexpr std::array<Atom, 13> kSemantic {{
    {"Unknown",0},{"Linear",1},{"Norm",2},{"Attention",3},{"Expert",4},
    {"StateSpace",5},{"Convolution",6},{"Reduction",7},{"Transform",8},
    {"Embedding",9},{"Projection",10},{"MemoryMotion",11},{"Composite",12}
}};
static constexpr std::array<Atom, 10> kRepresentation {{
    {"Native",0},{"BinaryBasis",1},{"SignedBasis",2},{"SparseBasis",3},
    {"ResidualBasis",4},{"MixedRank",5},{"QuantBlock",6},{"F16",7},
    {"F32View",8},{"Generated",9}
}};
static constexpr std::array<Atom, 10> kDevice {{
    {"Cpu",0},{"Gpu0",1},{"Gpu1",2},{"GpuRows",3},{"GpuCols",4},
    {"CpuGpu",5},{"GpuAsymmetric",6},{"MultiDevice",7},
    {"RuntimeSelected",8},{"Generated",9}
}};
static constexpr std::array<Atom, 11> kResidency {{
    {"Direct",0},{"Ephemeral",1},{"Streamed",2},{"Pinned",3},
    {"PersistentTile",4},{"Prefetch",5},{"ResidentView",6},
    {"NoReconstruct",7},{"TransientRealize",8},{"Generated",9},{"Spaceless",10}
}};
static constexpr std::array<Atom, 11> kMutation {{
    {"Identity",0},{"Fuse",1},{"Split",2},{"Reorder",3},{"Tile",4},
    {"Vectorize",5},{"RankFold",6},{"BasisExpand",7},{"DeviceBraid",8},
    {"ResidencyInvert",9},{"UnknownMutation",10}
}};
static constexpr std::array<Atom, 8> kProof {{
    {"Finite",0},{"Bounds",1},{"Parity",2},{"Differential",3},
    {"ErrorBound",4},{"Receipt",5},{"Semantic",6},{"Generated",7}
}};

// How a weight tensor's arithmetic is actually OWNED. See the header.
static constexpr std::array<Atom, 5> kOwnership {{
    {"Bypass",0},          // never enters LinearW
    {"Delegated",1},       // enters LinearW, which hands off and returns
    {"Owned",2},           // reaches LinearW's local GEMV kernel
    {"Conditional",3},     // runtime route decides Delegated vs Owned
    {"Unknown",4}
}};

template <std::size_t N>
const Atom& pick(const std::array<Atom, N>& a, std::mt19937_64& rng) {
    std::uniform_int_distribution<std::size_t> d(0, N - 1);
    return a[d(rng)];
}

static std::uint32_t pick_u32(std::mt19937_64& rng,
                              std::initializer_list<std::uint32_t> v) {
    std::vector<std::uint32_t> t(v);
    std::uniform_int_distribution<std::size_t> d(0, t.size() - 1);
    return t[d(rng)];
}

// FNV-1a. Not cryptographic: this is a receipt key for generated identity, and
// two genomes colliding here would be a generator defect worth knowing about,
// not a security event.
static std::uint64_t mix(std::uint64_t h, std::uint64_t x) {
    h ^= x; h *= 1099511628211ULL; return h;
}

struct Genome {
    std::uint64_t ordinal{}, fingerprint{};
    Atom semantic{}, representation{}, device{}, residency{},
         mutation{}, proof{}, ownership{};
    std::uint32_t rank{}, tile_rows{}, tile_cols{}, vector_width{},
                  batch_width{}, prefetch_distance{}, arity{};
    std::int32_t  basis_count{};
    std::int32_t  scale_min_milli{}, scale_max_milli{};
    double        scale_max{};
    // Whether this generation's envelope actually widened. Recorded so
    // "unlimited" can be audited instead of merely claimed.
    bool          envelope_widened{};
    double        modelled_residual{};
    std::vector<std::uint64_t> parents;
};

// The measured stand-in for "does a wider envelope buy accuracy".
//
// This is a MODEL of residual behaviour, not a measurement of a real GEMV, and
// it says so: it models error as the sum of a per-basis term and a per-rank
// term. It exists so the WIDENING GATE is exercised and can be falsified --
// not so a receipt can claim numerical success. A real implementation must
// replace this with a measured reconstruction error; the gate logic around it
// is the part that transfers.
static double modelResidual(double scaleMax,
                            std::uint32_t rank,
                            std::uint32_t basisCount) {
    if (basisCount == 0 || rank == 0) return 1e9;
    const double coverage = (1.0 - std::pow(0.5, static_cast<double>(rank)));
    const double spread   = std::log2(std::max(1.0, std::abs(scaleMax)));
    const double bases    = 1.0 - std::pow(0.5, static_cast<double>(basisCount));
    return std::max(0.0, spread) * (1.0 - coverage) * (1.0 - bases);
}

static double scaleMaxFor(std::uint64_t ordinal, std::mt19937_64& rng,
                          const Options& o, bool* widened) {
    std::uniform_real_distribution<double> jitter(1.0, 1.75);
    const std::uint64_t ep = o.epoch ? ordinal / o.epoch : ordinal;
    const double candidate =
        o.scale_seed_max * std::pow(o.scale_growth, static_cast<double>(ep))
                           * jitter(rng);
    *widened = candidate > o.scale_seed_max;
    return candidate;
}

static Genome generate(std::uint64_t ordinal, std::mt19937_64& rng,
                       const Options& o) {
    Genome g{};
    g.ordinal = ordinal;
    g.semantic        = pick(kSemantic, rng);
    g.representation  = pick(kRepresentation, rng);
    g.device          = pick(kDevice, rng);
    g.residency       = pick(kResidency, rng);
    g.mutation        = pick(kMutation, rng);
    g.proof           = pick(kProof, rng);
    g.ownership       = pick(kOwnership, rng);

    g.rank             = pick_u32(rng, {1,2,3,4,6,8,12,16,24,32,48,64,96,128});
    g.tile_rows        = pick_u32(rng, {1,8,16,32,64,128,256,512});
    g.tile_cols        = pick_u32(rng, {1,8,16,32,64,128,256,512});
    g.vector_width     = pick_u32(rng, {1,2,4,8,16,32});
    g.batch_width      = pick_u32(rng, {1,2,4,8,16});
    g.prefetch_distance= pick_u32(rng, {0,1,2,3,4,6,8,12,16,24,32});
    g.basis_count      = static_cast<std::int32_t>(
                             o.basis_seed + pick_u32(rng, {0,1,2,4,8,16}));

    // Arity has no architectural ceiling; the reachable maximum expands
    // logarithmically with population age.
    const std::uint32_t dyn = 1u + static_cast<std::uint32_t>(
        std::min<std::uint64_t>(63, std::log2(static_cast<double>(ordinal + 2))));
    std::uniform_int_distribution<std::uint32_t> ad(1, dyn);
    g.arity = ad(rng);

    bool widened = false;
    g.scale_max = scaleMaxFor(ordinal, rng, o, &widened);

    // ---- the widening gate ------------------------------------------------
    // Without the gate the envelope is open-ended, which is what was asked for.
    // With it, a generation only keeps a wider envelope when the modelled
    // residual actually improves. Recording which path was taken keeps both
    // behaviours auditable instead of one silently replacing the other.
    if (o.residual_gate) {
        const double atSeed = modelResidual(o.scale_seed_max, g.rank, g.basis_count);
        const double atWide = modelResidual(g.scale_max,  g.rank, g.basis_count);
        if (!(atWide < atSeed)) {
            g.scale_max = o.scale_seed_max;
            widened = false;
        }
        g.modelled_residual = modelResidual(g.scale_max, g.rank, g.basis_count);
    } else {
        g.modelled_residual = 0.0;   // not modelled in open mode
    }
    g.envelope_widened = widened;
    g.scale_min_milli = static_cast<std::int32_t>(std::llround(o.scale_min * 1000.0));
    g.scale_max_milli = static_cast<std::int32_t>(std::llround(g.scale_max * 1000.0));

    if (ordinal) {
        const std::uint32_t n = std::min<std::uint32_t>(
            g.arity, static_cast<std::uint32_t>(ordinal));
        std::uniform_int_distribution<std::uint64_t> pd(0, ordinal - 1);
        for (std::uint32_t i = 0; i < n; ++i) g.parents.push_back(pd(rng));
    }

    std::uint64_t h = 1469598103934665603ULL;
    h = mix(h, ordinal);
    for (const Atom* a : {&g.semantic,&g.representation,&g.device,
                           &g.residency,&g.mutation,&g.proof,&g.ownership})
        h = mix(h, a->id);
    h = mix(h, g.rank); h = mix(h, g.tile_rows); h = mix(h, g.tile_cols);
    h = mix(h, g.vector_width); h = mix(h, g.batch_width);
    h = mix(h, g.prefetch_distance);
    h = mix(h, static_cast<std::uint64_t>(g.basis_count));
    h = mix(h, static_cast<std::uint64_t>(g.scale_max_milli));
    for (auto p : g.parents) h = mix(h, p);
    g.fingerprint = h;
    return g;
}

static std::string hex64(std::uint64_t v) {
    std::ostringstream s; s << std::hex << std::uppercase << v; return s.str();
}

// --- emission ---------------------------------------------------------------

static void emit_preamble(std::ostream& os, const Options& o) {
    os <<
R"(#pragma once
// GENERATED FILE -- declarations only, zero implementations.
// Produced by the RawrXD Kernel Loom. Do not hand-edit.

#include <cstddef>
#include <cstdint>
#include <utility>

namespace rawrxd::deep2::loom {

// How the arithmetic is actually OWNED. Calling LinearW() proves entry, not
// ownership: it dispatches to tryVulkanHostGEMV and returns on a GPU-eligible
// route. Coverage claims that ignore this overstate themselves.
enum class Ownership : std::uint8_t {
    Bypass,       // compute never enters LinearW
    Delegated,    // enters LinearW, which hands off and returns
    Owned,        // reaches LinearW's local GEMV kernel
    Conditional,  // runtime route decides Delegated vs Owned
    Unknown
};

// The semantic tag is an ANCESTRY HINT. Identity is the fingerprint.
enum class Semantic : std::uint8_t {
    Unknown, Linear, Norm, Attention, Expert, StateSpace, Convolution,
    Reduction, Transform, Embedding, Projection, MemoryMotion, Composite
};
enum class Representation : std::uint8_t {
    Native, BinaryBasis, SignedBasis, SparseBasis, ResidualBasis,
    MixedRank, QuantBlock, F16, F32View, Generated
};
enum class Device : std::uint8_t {
    Cpu, Gpu0, Gpu1, GpuRows, GpuCols, CpuGpu, GpuAsymmetric,
    MultiDevice, RuntimeSelected, Generated
};
enum class Residency : std::uint8_t {
    Direct, Ephemeral, Streamed, Pinned, PersistentTile, Prefetch,
    ResidentView, NoReconstruct, TransientRealize, Generated, Spaceless
};
enum class Mutation : std::uint8_t {
    Identity, Fuse, Split, Reorder, Tile, Vectorize, RankFold,
    BasisExpand, DeviceBraid, ResidencyInvert, UnknownMutation
};
enum class Proof : std::uint8_t {
    Finite, Bounds, Parity, Differential, ErrorBound, Receipt,
    Semantic, Generated
};

// Generated semantic identity: distinct per fingerprint, so two genomes never
// collide on a shared enum even when their ancestry hints agree.
template <std::uint64_t Fingerprint>
struct GeneratedSemanticTag { static constexpr std::uint64_t value = Fingerprint; };

// The spaceless execution view. Holds enough information to compute y ~= sum
// alpha_i * GEMV(B_i, x) WITHOUT materialising W.
struct SpacelessGemvView {
    const void* source;            // released native tensor, never mutated
    std::uint64_t sourceBytes;
    const void* bases;             // binary/signed basis set
    std::uint32_t basisCount;
    const float*  signedScale;     // alpha_i, signed
    std::uint32_t rank;
    std::uint32_t tileRows;
    std::uint32_t tileCols;
    std::uint32_t groupSize;
    std::uint64_t fingerprint;
};

// Invariants every materialization must hold. NOT enforced here -- declared so
// a future tracer/verifier has something concrete to check against.
namespace Invariants {
inline constexpr bool DequantBufferZero()          noexcept { return true; }
inline constexpr bool ReconstructedWeightZero()     noexcept { return true; }
inline constexpr bool PermanentDerivedWeightZero() noexcept { return true; }
inline constexpr bool SourceWeightUnmutated()       noexcept { return true; }
inline constexpr bool ExecutionViewEphemeral()      noexcept { return true; }
// Generation space is open; the safety boundary is not.
inline constexpr bool GenerationSpaceOpen()         noexcept { return true; }
inline constexpr bool SafetyBoundaryAbsolute()      noexcept { return true; }
inline constexpr bool BootWithoutExecution()        noexcept { return true; }
inline constexpr bool ComputeWithoutExecution()     noexcept { return true; }
} // namespace Invariants

template<
    Semantic Sem, Ownership Own, Representation Rep, Device Dev,
    Residency Res, Mutation Mut, Proof Prf,
    std::uint32_t BasisCount, std::uint32_t Rank,
    std::uint32_t TileRows, std::uint32_t TileCols,
    std::uint32_t VectorWidth, std::uint32_t BatchWidth,
    std::uint32_t PrefetchDistance,
    std::int32_t ScaleMinMilli, std::int32_t ScaleMaxMilli,
    std::uint64_t Fingerprint, class... Parents>
struct LoomGrammar {
    static constexpr Semantic     semantic = Sem;
    static constexpr Ownership    ownership = Own;
    static constexpr Representation representation = Rep;
    static constexpr Device       device = Dev;
    static constexpr Residency    residency = Res;
    static constexpr Mutation     mutation = Mut;
    static constexpr Proof        proof = Prf;
    static constexpr std::uint32_t basis_count = BasisCount;
    static constexpr std::uint32_t rank = Rank;
    static constexpr std::uint32_t tile_rows = TileRows;
    static constexpr std::uint32_t tile_cols = TileCols;
    static constexpr std::uint32_t vector_width = VectorWidth;
    static constexpr std::uint32_t batch_width = BatchWidth;
    static constexpr std::uint32_t prefetch_distance = PrefetchDistance;
    static constexpr std::int32_t  scale_min_milli = ScaleMinMilli;
    static constexpr std::int32_t  scale_max_milli = ScaleMaxMilli;
    static constexpr std::uint64_t fingerprint = Fingerprint;
    static constexpr std::size_t   parent_count = sizeof...(Parents);
    using GeneratedTag = GeneratedSemanticTag<Fingerprint>;
};

struct LoomReceipt {
    std::uint64_t fingerprint;
    bool executed;          // a materializer ran it
    bool finite;            // output was finite
    bool withinBounds;
    bool semanticsMatched;  // met the declared contract
};

// Universal vacancy: any operation shape, no architectural boundary.
template <class Grammar, class Runtime, class... Views>
LoomReceipt loom_vacancy(Runtime& runtime, Views&&... views);

// Universal braid: neighbouring vacancies combined without naming a seam.
template <class Grammar, class Runtime, class... Vacancies>
LoomReceipt loom_braid(Runtime& runtime, Vacancies&&... vacancies);

// Mutation whose result type is deferred to a policy.
template <class Grammar, class MutationPolicy, class Runtime>
auto loom_mutate(Runtime& runtime)
    -> typename MutationPolicy::template result<Grammar>;

)";
    os << "// GENERATOR_SEED="   << o.seed          << "\n";
    os << "// SCALE_SEED_MIN="   << o.scale_min      << "x\n";
    os << "// SCALE_SEED_MAX="   << o.scale_seed_max << "x\n";
    os << "// SCALE_GROWTH="     << o.scale_growth   << "\n";
    os << "// RESIDUAL_GATE="    << (o.residual_gate ? "ON" : "OFF") << "\n";
    os << "// FIXED_SCALE_MAX="  << "NONE"          << "\n";
    os << "// COUNT_0_MEANS="    << "STREAM_UNTIL_INTERRUPTED" << "\n";
    os << "// IMPLEMENTATIONS="  << "0"             << "\n\n";
}

static void emit_one(std::ostream& os, const Genome& g) {
    os << "// --------------------------------------------------------------\n";
    os << "// LOOM_GEN=" << g.ordinal
       << " FP=0x" << hex64(g.fingerprint)
       << " OWNERSHIP=" << g.ownership.token
       << " ANCESTRY=" << g.semantic.token << "/" << g.representation.token
       << " BASIS=" << g.basis_count << " RANK=" << g.rank
       << " SCALE=[" << std::fixed << std::setprecision(3)
       << (g.scale_min_milli / 1000.0) << "x,"
       << (g.scale_max_milli / 1000.0) << "x]"
       << " ENVELOPE=" << (g.envelope_widened ? "WIDENED" : "SEED");
    if (g.modelled_residual > 0.0)
        os << " MODELLED_RESIDUAL=" << std::scientific << g.modelled_residual;
    os << std::defaultfloat << "\n";

    os << "using Grammar_" << g.ordinal << " = LoomGrammar<\n";
    os << "    Semantic::"     << g.semantic.token       << ",\n";
    os << "    Ownership::"    << g.ownership.token      << ",\n";
    os << "    Representation::" << g.representation.token << ",\n";
    os << "    Device::"       << g.device.token         << ",\n";
    os << "    Residency::"    << g.residency.token      << ",\n";
    os << "    Mutation::"     << g.mutation.token       << ",\n";
    os << "    Proof::"        << g.proof.token          << ",\n";
    os << "    " << g.basis_count << ", " << g.rank << ", "
       << g.tile_rows << ", " << g.tile_cols << ", "
       << g.vector_width << ", " << g.batch_width << ", "
       << g.prefetch_distance << ",\n";
    os << "    " << g.scale_min_milli << ", " << g.scale_max_milli
       << ", 0x" << hex64(g.fingerprint) << "ULL";
    for (auto p : g.parents) os << ",\n    Grammar_" << p;
    os << ">;\n\n";

    os << "template <class Runtime, class... Views>\n"
       << "LoomReceipt loom_stub_" << g.ordinal
       << "(Runtime& runtime, Views&&... views);\n\n";
    os << "template <class Runtime, class... Vacancies>\n"
       << "LoomReceipt loom_braid_stub_" << g.ordinal
       << "(Runtime& runtime, Vacancies&&... vacancies);\n\n";
    os << "template <class Runtime, class MutationPolicy>\n"
       << "auto loom_mutate_stub_" << g.ordinal
       << "(Runtime& runtime)\n"
       << "    -> typename MutationPolicy::template result<Grammar_"
       << g.ordinal << ">;\n\n";
}

static void emit_summary(std::ostream& os, const std::vector<Genome>& gs) {
    std::array<std::uint64_t, 5> own{};
    std::size_t widened = 0;
    std::int32_t widest = 0;
    for (const auto& g : gs) {
        ++own[g.ownership.id];
        if (g.envelope_widened) ++widened;
        widest = std::max(widest, g.scale_max_milli);
    }
    os << "// ============================================================\n";
    os << "// LOOM_SUMMARY genomes=" << gs.size() << "\n";
    os << "// UNIQUE_FINGERPRINTS="
       << [&]{ std::vector<std::uint64_t> f; f.reserve(gs.size());
               for (auto& g : gs) f.push_back(g.fingerprint);
               std::sort(f.begin(), f.end());
               f.erase(std::unique(f.begin(), f.end()), f.end());
               return f.size(); }() << "\n";
    os << "// OWNERSHIP_BYPASS="      << own[0] << "\n";
    os << "// OWNERSHIP_DELEGATED="   << own[1] << "\n";
    os << "// OWNERSHIP_OWNED="       << own[2] << "\n";
    os << "// OWNERSHIP_CONDITIONAL=" << own[3] << "\n";
    os << "// OWNERSHIP_UNKNOWN="     << own[4] << "\n";
    os << "// ENVELOPE_WIDENED="      << widened << "\n";
    os << "// WIDEST_SCALE_MILLI="    << widest << "\n";
    os << "// IMPLEMENTATIONS="       << 0 << "\n";
    os << "// MATERIALIZATIONS="      << 0 << "\n";
    os << "// EXECUTED="             << 0 << "\n";
    os << "// VERDICT=UNPROVEN_DECLARATIONS_ONLY\n";
}

static void emit_epilogue(std::ostream& os) { os << "} // namespace rawrxd::deep2::loom\n"; }

// --- args ------------------------------------------------------------------

static std::uint64_t pu64(std::string_view s, const char* what) {
    std::uint64_t v{};
    const auto r = std::from_chars(s.data(), s.data()+s.size(), v);
    if (r.ec != std::errc{} || r.ptr != s.data()+s.size())
        throw std::runtime_error(std::string("invalid ") + what);
    return v;
}
static double pf64(std::string_view s, const char* what) {
    const std::string t(s); char* e = nullptr;
    const double v = std::strtod(t.c_str(), &e);
    if (!e || *e != '\0') throw std::runtime_error(std::string("invalid ") + what);
    return v;
}

static Options parse(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        const std::string_view a(argv[i]);
        auto need = [&](const char* n) -> std::string_view {
            if (++i >= argc) throw std::runtime_error(std::string("missing ") + n);
            return argv[i];
        };
        if      (a == "--seed")            o.seed = pu64(need("--seed"), "seed");
        else if (a == "--count")           o.count = pu64(need("--count"), "count");
        else if (a == "--scale-min")       o.scale_min = pf64(need("--scale-min"), "scale-min");
        else if (a == "--scale-seed-max")  o.scale_seed_max = pf64(need("--scale-seed-max"), "scale-seed-max");
        else if (a == "--scale-growth")    o.scale_growth = pf64(need("--scale-growth"), "scale-growth");
        else if (a == "--growth-epoch")    o.epoch = static_cast<std::uint32_t>(pu64(need("--growth-epoch"), "epoch"));
        else if (a == "--basis-seed")      o.basis_seed = static_cast<std::uint32_t>(pu64(need("--basis-seed"), "basis-seed"));
        else if (a == "--rank-seed")       o.rank_seed  = static_cast<std::uint32_t>(pu64(need("--rank-seed"), "rank-seed"));
        else if (a == "--residual-gate")   o.residual_gate = true;
        else if (a == "--out")             o.out = std::string(need("--out"));
        else if (a == "--help" || a == "-h") {
            std::cout <<
              "RawrXD Kernel Loom generator\n"
              "  --seed N            reproducible\n"
              "  --count N           0 = stream forever (default 256)\n"
              "  --scale-min X       default -1.5\n"
              "  --scale-seed-max X  default +1.5\n"
              "  --scale-growth X    default 1.125\n"
              "  --growth-epoch N    default 64\n"
              "  --basis-seed N      default 4\n"
              "  --rank-seed N       default 8\n"
              "  --residual-gate     widen the envelope only when the\n"
              "                      modelled residual improves\n"
              "  --out FILE          stdout if omitted\n";
            std::exit(0);
        } else throw std::runtime_error("unknown argument: " + std::string(a));
    }
    if (!(o.scale_min < o.scale_seed_max))
        throw std::runtime_error("scale-min must be below scale-seed-max");
    if (!(o.scale_growth >= 1.0))
        throw std::runtime_error("scale-growth must be >= 1.0");
    return o;
}

int run(int argc, char** argv) {
    const Options o = parse(argc, argv);
    std::mt19937_64 rng(o.seed);

    std::ofstream file;
    std::ostream* out = &std::cout;
    if (!o.out.empty()) {
        file.open(o.out, std::ios::binary | std::ios::trunc);
        if (!file) throw std::runtime_error("cannot open output");
        out = &file;
    }

    emit_preamble(*out, o);

    if (o.count == 0) {
        // Open-ended. Never emits a summary, because "unlimited" has no end
        // to summarise.
        for (std::uint64_t i = 0;; ++i) {
            emit_one(*out, generate(i, rng, o));
            if ((i & 63ULL) == 63ULL) out->flush();
        }
    }

    std::vector<Genome> gs;
    gs.reserve(o.count);
    for (std::uint64_t i = 0; i < o.count; ++i) {
        gs.push_back(generate(i, rng, o));
        emit_one(*out, gs.back());
    }
    emit_summary(*out, gs);
    emit_epilogue(*out);
    return 0;
}

} // namespace rawrxd::loom

int main(int argc, char** argv) {
    try { return rawrxd::loom::run(argc, argv); }
    catch (const std::exception& e) {
        std::cerr << "RAWRXD_KERNEL_LOOM ERROR: " << e.what() << '\n';
        return 2;
    }
}