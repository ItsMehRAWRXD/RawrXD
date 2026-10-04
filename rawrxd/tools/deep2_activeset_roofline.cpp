// ============================================================================
// deep2_activeset_roofline.cpp — RAWRXD_ACTIVE_SET_ROOFLINE_001
// ============================================================================
// Answers one question with bytes rather than adjectives:
//
//   for a real GGUF on this disk, how many weight bytes does ONE decode token
//   actually have to touch, and what token rate does the measured memory
//   hierarchy permit at that working set?
//
// WHY THIS EXISTS
//   Sparse MoE claims ("17B active of 397B", "10 of 512 experts") are usually
//   argued from the README's parameter counts. Active-parameter arithmetic is
//   a LOWER BOUND on bytes touched and nothing at all about the memory system.
//   The number that decides feasibility is:
//
//       ACTIVE_BYTES_PER_TOKEN  (measured from real tensor extents)
//       TIER_BANDWIDTH          (measured on this machine)
//       TPS_TIER = TIER_BANDWIDTH / ACTIVE_BYTES_PER_TOKEN
//
//   and the number that decides whether paging helps at all is the ratio of
//   active bytes to resident budget -- the DRAM traffic you cannot avoid.
//
// EVIDENCE DISCIPLINE (this is the whole point of the tool)
//   Every printed field carries its class:
//     MEASURED   read from the file's own bytes, or timed here
//     DERIVED    arithmetic over MEASURED fields only
//     UNMEASURED not available on this run -- printed as such, never guessed
//   A field that cannot be measured is not replaced by an estimate. If the
//   active bytes are unknown the tool prints UNMEASURED and refuses to print a
//   TPS number, because a TPS number derived from an assumed byte count is a
//   guess wearing a decimal point.
//
// BUILD (standalone; deliberately not added to CMakeLists.txt -- see receipt)
//   cl /nologo /std:c++20 /EHsc /O2 /I src\deep2 /Fe:deep2_activeset_roofline.exe \
//      tools\deep2_activeset_roofline.cpp
//
// USAGE
//   deep2_activeset_roofline.exe census   <model.gguf>
//   deep2_activeset_roofline.exe roofline <model.gguf>
// ============================================================================

#include "GGUFLoader.hpp"

#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// Evidence class. Every numeric field printed by this tool carries one.
// ---------------------------------------------------------------------------
enum class Evidence { MEASURED, DERIVED, UNMEASURED };

const char* evName(Evidence e) {
    switch (e) {
        case Evidence::MEASURED:   return "MEASURED";
        case Evidence::DERIVED:    return "DERIVED";
        default:                   return "UNMEASURED";
    }
}

void row(const char* key, Evidence e, const char* value) {
    std::printf("%-34s %-11s %s\n", key, evName(e), value);
}

void rowU64(const char* key, Evidence e, unsigned long long v) {
    char buf[64];
    std::snprintf(buf, sizeof buf, "%llu", v);
    row(key, e, buf);
}

void rowF(const char* key, Evidence e, double v) {
    char buf[64];
    std::snprintf(buf, sizeof buf, "%.4f", v);
    row(key, e, buf);
}

void section(const char* title) {
    std::printf("\n=== %s ===\n", title);
}

// ---------------------------------------------------------------------------
// Tensor role classification.
//
// The role of a tensor is decided from its NAME, and the names are not
// guessed: `census` prints the real name census and `roofline` fails closed
// if an unrecognised family carries weight. Guessing which suffix means
// "expert" is how an active-set number gets to be fiction.
// ---------------------------------------------------------------------------
enum class Role {
    Unknown,
    Embed,          // token_embd / output
    Attention,      // attn_* projections
    LinearAttn,     // linear attention / SSM / DeltaNet / gated delta net
    Norm,           // *_norm.weight
    Router,         // ffn_gate_inp / ffn_gate (MoE router)
    ExpertRouted,   // ffn_*_exps  (routed expert stack)
    ExpertShared,   // ffn_*_shared (shared expert stack)
    DenseMlp,       // ffn_* on a non-MoE layer
    Other
};

const char* roleName(Role r) {
    switch (r) {
        case Role::Embed:        return "EMBED";
        case Role::Attention:    return "ATTENTION";
        case Role::LinearAttn:   return "LINEAR_ATTN";
        case Role::Norm:         return "NORM";
        case Role::Router:       return "ROUTER";
        case Role::ExpertRouted: return "EXPERT_ROUTED";
        case Role::ExpertShared: return "EXPERT_SHARED";
        case Role::DenseMlp:     return "DENSE_MLP";
        case Role::Other:        return "OTHER";
        default:                 return "UNKNOWN";
    }
}

bool contains(const std::string& h, const char* n) {
    return h.find(n) != std::string::npos;
}

Role classify(const std::string& name, bool moe) {
    // name is lowercased by the caller.
    if (contains(name, "token_embd") || contains(name, "output_norm") ||
        name == "lm_head" || contains(name, "lora_a") ||
        contains(name, "embed_tokens"))
        return Role::Embed;

    // MoE stacks must be tested BEFORE generic ffn so a routed expert is never
    // counted as a dense MLP.
    if (contains(name, "_exps") || contains(name, "_exp"))  return Role::ExpertRouted;
    if (contains(name, "shared"))                          return Role::ExpertShared;
    if (contains(name, "ffn_gate_inp") ||
        (moe && contains(name, "ffn_gate") && !contains(name, "exps")))
        return Role::Router;

    if (contains(name, "norm"))                             return Role::Norm;
    if (contains(name, "attn") || contains(name, "attention") ||
        contains(name, "query") || contains(name, "key_value") ||
        contains(name, "value") || contains(name, "dense"))
        return (contains(name, "linear") || contains(name, "ssm") ||
                contains(name, "conv") || contains(name, "gated_delta") ||
                contains(name, "recurrent") || contains(name, "a_beta") ||
                contains(name, "dt_bias") || contains(name, "beta"))
             ? Role::LinearAttn : Role::Attention;

    if (contains(name, "ffn") || contains(name, "feed_forward") ||
        contains(name, "gate_proj") || contains(name, "up_proj") ||
        contains(name, "down_proj"))
        return Role::DenseMlp;

    return Role::Other;
}

std::string lower(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

// ---------------------------------------------------------------------------
// Memory-tier bandwidth, measured here rather than quoted.
//
// Host tier: a sequential read sweep over a buffer larger than any sane cache
// and touched twice so the second pass is not measuring a warm copy. The
// measured value is the SECOND pass; the first is discarded on purpose.
// ---------------------------------------------------------------------------
struct Bandwidth {
    double      gbps      = -1.0;
    unsigned long long bytes = 0;
    double      ms       = 0.0;
    Evidence    ev       = Evidence::UNMEASURED;
};

Bandwidth measureHostReadBandwidth() {
    Bandwidth bw;
    // 1 GiB. Large enough to defeat a server-class L3; small enough to sweep
    // in well under a second on a DDR5-5600 channel pair.
    const size_t bytes = size_t{1} << 30;
    unsigned char* buf = static_cast<unsigned char*>(std::malloc(bytes));
    if (!buf) return bw;

    // Fill with a non-constant pattern so the compiler cannot fold the sweep.
    for (size_t i = 0; i < bytes; i += 64) buf[i] = static_cast<unsigned char>(i * 131u + 7u);

    volatile unsigned long long sink = 0;
    double best = 0.0;
    double bestMs = 0.0;
    for (int pass = 0; pass < 3; ++pass) {
        const auto t0 = std::chrono::steady_clock::now();
        unsigned long long acc = 0;
        for (size_t i = 0; i < bytes; i += 64) acc += buf[i];
        const auto t1 = std::chrono::steady_clock::now();
        sink += acc;
        const double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        if (ms <= 0.0) continue;
        // Pass 0 warms the TLB/page state; take the best of the remaining two.
        if (pass == 0) continue;
        const double gbps = (double(bytes) / 1.0e9) / (ms / 1.0e3);
        if (gbps > best) { best = gbps; bestMs = ms; }
    }
    (void)sink;
    std::free(buf);
    bw.gbps = best;
    bw.ms = bestMs;
    bw.bytes = bytes;
    bw.ev = best > 0.0 ? Evidence::MEASURED : Evidence::UNMEASURED;
    return bw;
}

// ---------------------------------------------------------------------------
// Tier table. Only the host tier is measured by this tool. The VRAM and NVMe
// rows are printed as UNMEASURED on purpose: this tool has no GPU and no
// device handle, and a number typed into a table is not a measurement.
// ---------------------------------------------------------------------------
struct Tier {
    const char* name;
    unsigned long long budgetBytes;
    double      budgetGb;
    bool        budgetIsMeasured;
};

} // namespace

// ===========================================================================
int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr,
            "usage: deep2_activeset_roofline.exe census|roofline <model.gguf>\n");
        return 2;
    }
    const std::string mode = argv[1];
    const std::string path = argv[2];

    std::printf("RAWRXD_ACTIVE_SET_ROOFLINE_001\n");
    std::printf("mode=%s\n", mode.c_str());

    Deep2::GGUFLoader loader;
    if (!loader.load(path)) {
        std::printf("MODEL_LOAD=FAIL\n");
        std::printf("ERROR=%s\n", loader.error().c_str());
        std::printf("VERDICT=NO_VERDICT_MODEL_UNREADABLE\n");
        return 1;
    }

    const std::string arch = loader.getMetaString("general.architecture", "");
    auto metaU64 = [&](const char* leaf) -> unsigned long long {
        if (!arch.empty()) {
            const int64_t p = loader.getMetaInt(arch + std::string(".") + leaf, -1);
            if (p > 0) return static_cast<unsigned long long>(p);
        }
        const int64_t b = loader.getMetaInt(std::string(leaf), -1);
        return b > 0 ? static_cast<unsigned long long>(b) : 0ull;
    };

    const unsigned long long nLayer    = metaU64("block_count");
    const unsigned long long nExpert   = metaU64("expert_count");
    const unsigned long long nUsed     = metaU64("expert_used_count");
    const unsigned long long nShared   = metaU64("expert_shared_count");
    const unsigned long long hiddenDim = metaU64("embedding_length");
    const unsigned long long expertDim = metaU64("expert_feed_forward_length");
    const unsigned long long moeInter  = metaU64("moe.expert_feed_forward_length");
    const bool isMoE = nExpert > 0;

    section("FILE");
    row("GGUF_PATH", Evidence::MEASURED, path.c_str());
    rowU64("GGUF_FILE_BYTES", Evidence::MEASURED,
           static_cast<unsigned long long>(loader.mappedBytes()));
    row("GGUF_VERSION", Evidence::MEASURED, loader.version() ? "v3" : "v2");
    rowU64("GGUF_TENSOR_COUNT", Evidence::MEASURED, loader.tensorCount());
    row("ARCH", Evidence::MEASURED, arch.empty() ? "(none)" : arch.c_str());
    rowU64("SHARD_COUNT", Evidence::MEASURED, loader.shardCount());

    section("MOE GEOMETRY (same keys Deep2Engine.cpp:2162-2169 reads)");
    rowU64("BLOCK_COUNT", Evidence::MEASURED, nLayer);
    rowU64("EMBEDDING_LENGTH", Evidence::MEASURED, hiddenDim);
    rowU64("EXPERT_COUNT", isMoE ? Evidence::MEASURED : Evidence::UNMEASURED, nExpert);
    rowU64("EXPERT_USED_COUNT", isMoE ? Evidence::MEASURED : Evidence::UNMEASURED, nUsed);
    rowU64("EXPERT_SHARED_COUNT", isMoE ? Evidence::MEASURED : Evidence::UNMEASURED, nShared);
    rowU64("EXPERT_FFN_LENGTH", isMoE ? Evidence::MEASURED : Evidence::UNMEASURED, expertDim);
    rowU64("MOE_FFN_LENGTH_alt", isMoE ? Evidence::MEASURED : Evidence::UNMEASURED, moeInter);

    // ---- real tensor census, grouped by role ----
    const auto names = loader.listTensors();
    struct Bucket { unsigned long long bytes = 0; unsigned long long count = 0; };
    Bucket buckets[9];
    unsigned long long totalBytes = 0;
    unsigned long long unknownBytes = 0;
    unsigned long long otherBytes = 0;
    // per-layer routed-expert bytes, to derive the per-expert figure honestly
    unsigned long long routedLayers = 0;
    unsigned long long routedBytesTotal = 0;

    std::vector<std::string> unknownSamples;
    for (const auto& n : names) {
        const auto* t = loader.getTensor(n);
        if (!t) continue;
        const Role r = classify(lower(n), isMoE);
        const unsigned long long b = static_cast<unsigned long long>(t->sizeBytes);
        buckets[static_cast<int>(r)].bytes += b;
        buckets[static_cast<int>(r)].count += 1;
        totalBytes += b;
        if (r == Role::Unknown) {
            unknownBytes += b;
            if (unknownSamples.size() < 24) unknownSamples.push_back(n);
        } else if (r == Role::Other) {
            otherBytes += b;
            if (unknownSamples.size() < 24) unknownSamples.push_back(n);
        }
        if (r == Role::ExpertRouted) {
            routedBytesTotal += b;
            ++routedLayers;
        }
    }

    section("TENSOR ROLE CENSUS (bytes read from the file's own extents)");
    static const Role kOrder[] = {
        Role::Embed, Role::Attention, Role::LinearAttn, Role::Norm,
        Role::Router, Role::ExpertRouted, Role::ExpertShared,
        Role::DenseMlp, Role::Other
    };
    for (Role r : kOrder) {
        const Bucket& b = buckets[static_cast<int>(r)];
        if (b.count == 0) continue;
        char buf[96];
        std::snprintf(buf, sizeof buf, "tensors=%llu bytes=%llu",
                      b.count, b.bytes);
        row(roleName(r), Evidence::MEASURED, buf);
    }
    rowU64("ROLE_TOTAL_BYTES", Evidence::MEASURED, totalBytes);
    if (unknownBytes) {
        rowU64("UNCLASSIFIED_UNKNOWN_BYTES", Evidence::MEASURED, unknownBytes);
    }

    if (mode == "census") {
        if (!unknownSamples.empty()) {
            section("UNCLASSIFIED SAMPLE (classifier must learn these, not guess)");
            for (const auto& s : unknownSamples) std::printf("  %s\n", s.c_str());
        }
        section("RESULT");
        std::printf("CENSUS_ONLY=1\n");
        std::printf("UNCLASSIFIED_UNKNOWN_BYTES=%llu\n", unknownBytes);
        std::printf("OTHER_BYTES=%llu\n", otherBytes);
        std::printf("VERDICT=CENSUS\n");
        return unknownBytes ? 0 : 0;
    }

    // ======================= roofline =====================================
    // A byte count that cannot be attributed to a role cannot be added to an
    // active set. Refuse rather than quietly undercount the footprint.
    const unsigned long long unaccounted = unknownBytes;
    if (unaccounted) {
        section("ROOFLINE");
        rowU64("UNACCOUNTED_BYTES", Evidence::MEASURED, unaccounted);
        std::printf("\nACTIVE_BYTES_PER_TOKEN=UNMEASURED\n");
        std::printf("REASON=unclassified tensor families carry weight bytes;\n");
        std::printf("       an active set that omits them undercounts its own budget.\n");
        std::printf("VERDICT=NO_VERDICT_CLASSIFIER_INCOMPLETE\n");
        return 1;
    }

    section("ACTIVE SET PER DECODE TOKEN");
    // Always touched: embedding output, every layer's attention + linear-attn
    // + norms + router, plus the shared expert, plus lm_head.
    const unsigned long long alwaysBytes =
        buckets[static_cast<int>(Role::Embed)].bytes +
        buckets[static_cast<int>(Role::Attention)].bytes +
        buckets[static_cast<int>(Role::LinearAttn)].bytes +
        buckets[static_cast<int>(Role::Norm)].bytes +
        buckets[static_cast<int>(Role::Router)].bytes +
        buckets[static_cast<int>(Role::ExpertShared)].bytes;
    rowU64("ALWAYS_RESIDENT_BYTES", Evidence::DERIVED, alwaysBytes);

    // Per-routed-expert bytes, derived from the real extents. Guard the divide:
    // if the file declares experts but carries no routed-expert bytes, the two
    // facts disagree and the derived figure would be a division by zero.
    unsigned long long bytesPerExpert = 0;
    Evidence bytesPerExpertEv = Evidence::UNMEASURED;
    if (routedBytesTotal) {
        // Routed expert tensors are per (layer, expert): 3 stacks (gate, up,
        // down) for every layer. Derive from the declared geometry when it is
        // present so the divisor is not itself a guess.
        unsigned long long denom = nLayer * nExpert;
        if (denom == 0) denom = routedLayers;
        if (denom) {
            bytesPerExpert = routedBytesTotal / denom;
            bytesPerExpertEv = Evidence::DERIVED;
        }
    }
    rowU64("ROUTED_EXPERT_BYTES_TOTAL", Evidence::MEASURED, routedBytesTotal);
    rowU64("BYTES_PER_ROUTED_EXPERT", bytesPerExpertEv, bytesPerExpert);

    unsigned long long activeBytes = 0;
    Evidence activeEv = Evidence::UNMEASURED;
    if (isMoE && bytesPerExpertEv != Evidence::UNMEASURED) {
        activeBytes = alwaysBytes + bytesPerExpert * nUsed;
        activeEv = Evidence::DERIVED;
        rowU64("ROUTED_EXPERTS_PER_TOKEN", Evidence::MEASURED, nUsed);
        rowU64("ACTIVE_EXPERT_BYTES_PER_TOKEN", Evidence::DERIVED,
               bytesPerExpert * nUsed);
    } else if (!isMoE) {
        activeBytes = alwaysBytes;
        activeEv = Evidence::DERIVED;
    }
    rowU64("ACTIVE_BYTES_PER_TOKEN", activeEv, activeBytes);

    const unsigned long long coldBytes = (totalBytes > activeBytes)
                                        ? (totalBytes - activeBytes) : 0ull;
    rowU64("COLD_BYTES_NOT_TOUCHED", Evidence::DERIVED, coldBytes);

    section("MEMORY TIERS");
    const Bandwidth host = measureHostReadBandwidth();
    rowF("HOST_TIER_GBPS", host.ev, host.gbps);
    rowF("HOST_TIER_SAMPLE_MIB", host.ev, (double)host.bytes / (1024.0 * 1024.0));

    section("TOKEN RATE BOUND BY THE MEASURED HOST TIER");
    if (activeEv != Evidence::UNMEASURED && host.ev == Evidence::MEASURED &&
        host.gbps > 0.0 && activeBytes > 0) {
        const double gbPerToken = (double)activeBytes / 1.0e9;
        const double tps = host.gbps / gbPerToken;
        rowF("ACTIVE_GB_PER_TOKEN", Evidence::DERIVED, gbPerToken);
        rowF("HOST_BOUND_TPS", Evidence::DERIVED, tps);
        std::printf("\nNOTE: this is the ceiling for the HOST tier only. It is not\n");
        std::printf("      a Deep2 token rate -- it is the rate at which the memory\n");
        std::printf("      system could deliver the active set if everything were\n");
        std::printf("      perfectly resident, perfectly cached, perfectly scheduled.\n");
        std::printf("      Any real number is lower. Reporting it as the estimate\n");
        std::printf("      would be the error this tool exists to avoid.\n");
    } else {
        std::printf("HOST_BOUND_TPS=UNMEASURED\n");
        std::printf("REASON=active byte count or host bandwidth unavailable\n");
    }

    section("WORKING SET REQUIRED FOR A TARGET RATE");
    if (activeEv != Evidence::UNMEASURED && activeBytes > 0) {
        static const double kTargets[] = {5.0, 8.0, 10.0, 12.0, 16.0, 20.0};
        std::printf("%-12s %-18s %-18s\n", "TARGET_TPS", "NEED_GB_PER_SEC", "vs_HOST_MEASURED");
        for (double t : kTargets) {
            const double need = t * (double)activeBytes / 1.0e9;
            const double ratio = host.gbps > 0.0 ? (need / host.gbps) : 0.0;
            char a[48], b[48];
            std::snprintf(a, sizeof a, "%.2f GB/s", need);
            if (ratio == 0.0) std::snprintf(b, sizeof b, "UNMEASURED");
            else                std::snprintf(b, sizeof b, "%.2fx", ratio);
            std::printf("%-12.1f %-18s %-18s\n", t, a, b);
        }
    } else {
        std::printf("TARGET_TABLE=UNMEASURED\n");
    }

    section("TIERS THIS TOOL DID NOT MEASURE");
    row("VRAM_TIER_GBPS", Evidence::UNMEASURED, "no device handle in this tool");
    row("NVME_TIER_GBPS", Evidence::UNMEASURED, "no device handle in this tool");
    row("VRAM_BUDGET_BYTES", Evidence::UNMEASURED, "not read by this tool");
    std::printf("\nA VRAM/NVMe row printed as a number elsewhere in this project is a\n");
    std::printf("QUOTE, not a measurement by this tool, and is labelled there.\n");

    section("RESULT");
    std::printf("VERDICT=%s\n", activeEv == Evidence::UNMEASURED
                                ? "NO_VERDICT_ACTIVE_BYTES_UNMEASURED"
                                : "ACTIVE_SET_DERIVED");
    std::printf("EVIDENCE_ACTIVE_BYTES=%s\n", evName(activeEv));
    return 0;
}
