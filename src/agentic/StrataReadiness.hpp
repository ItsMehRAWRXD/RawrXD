// StrataReadiness.hpp -- real Strata expert-residency readiness probe.
//
// Critical rule (do not weaken): a GGUF file existing on disk does NOT prove
// that expert residency is supported, initialized or operational. Strata is a
// Deep2 *expert* residency mode; it is only applicable to a Mixture-of-Experts
// model. A dense model (e.g. TinyLlama) is fine for routing and session
// lifecycle tests but can never certify expert residency.
//
// This header answers exactly one question without loading weights:
//   "Is this model MoE (does it declare experts), so Strata residency applies?"
//
// It reads only the GGUF header + metadata KV pairs (and, as a fallback, the
// tensor-name table) -- never the multi-gigabyte tensor data -- so it is cheap
// enough to run from `rawr backend status`. It is header-only and depends only
// on InferenceRouter.hpp (for ResidencyReadiness) and the standard library, so
// it can be unit-tested against real model files in isolation.

#pragma once

#include "InferenceRouter.hpp"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>

namespace rawrxd {

// Detailed result of the on-disk MoE probe.
struct GgufResidencyProbe {
    bool        parseOk = false;      // header + metadata parsed without error
    bool        moe = false;          // model declares experts (expert_count > 0)
    uint32_t    numExperts = 0;       // max expert_count seen (0 when dense)
    std::string architecture;         // general.architecture (may be empty)
    std::string error;                // populated when !parseOk
};

namespace detail {

struct GgufReader {
    std::ifstream in;
    std::string   err;
    bool          ok = true;

    explicit GgufReader(const std::string& path) { in.open(path, std::ios::binary); }

    bool read(void* dst, std::size_t n) {
        if (!in) { ok = false; return false; }
        in.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(n));
        if (in.gcount() != static_cast<std::streamsize>(n)) { ok = false; return false; }
        return true;
    }
    template <class T> bool readT(T& v) { return read(&v, sizeof(T)); }

    // Reads a GGUF string (uint64 length + bytes). `maxBytes` bounds a corrupt
    // length so a bad file cannot force a huge allocation.
    bool readString(std::string& out, std::uint64_t maxBytes = 1u << 20) {
        std::uint64_t len = 0;
        if (!readT(len)) return false;
        if (len > maxBytes) { ok = false; return false; }
        out.resize(static_cast<std::size_t>(len));
        if (len && !read(out.data(), static_cast<std::size_t>(len))) return false;
        return true;
    }

    // Skips one metadata value of `type`. Returns the integer value when the
    // type is an integer (via `intOut`/`hasInt`), used for expert_count.
    bool skipValue(std::uint32_t type, std::int64_t& intOut, bool& hasInt) {
        hasInt = false;
        switch (type) {
            case 0: { std::uint8_t  v; if (!readT(v)) return false; intOut = v; hasInt = true; return true; }
            case 1: { std::int8_t   v; if (!readT(v)) return false; intOut = v; hasInt = true; return true; }
            case 2: { std::uint16_t v; if (!readT(v)) return false; intOut = v; hasInt = true; return true; }
            case 3: { std::int16_t  v; if (!readT(v)) return false; intOut = v; hasInt = true; return true; }
            case 4: { std::uint32_t v; if (!readT(v)) return false; intOut = v; hasInt = true; return true; }
            case 5: { std::int32_t  v; if (!readT(v)) return false; intOut = v; hasInt = true; return true; }
            case 6: { float v;         if (!readT(v)) return false; return true; }
            case 7: { std::uint8_t  v; if (!readT(v)) return false; intOut = v; hasInt = true; return true; }
            case 8: { std::string s;   return readString(s); }
            case 10: { std::uint64_t v; if (!readT(v)) return false; intOut = static_cast<std::int64_t>(v); hasInt = true; return true; }
            case 11: { std::int64_t  v; if (!readT(v)) return false; intOut = v; hasInt = true; return true; }
            case 12: { double v;        if (!readT(v)) return false; return true; }
            case 9: {  // ARRAY: uint32 elem_type, uint64 count, then elements
                std::uint32_t et = 0;
                std::uint64_t count = 0;
                if (!readT(et) || !readT(count)) return false;
                if (count > (std::uint64_t)1 << 32) { ok = false; return false; }
                for (std::uint64_t i = 0; i < count; ++i) {
                    std::int64_t dummy = 0; bool h = false;
                    if (!skipValue(et, dummy, h)) return false;
                }
                return true;
            }
            default: ok = false; return false;
        }
    }
};

}  // namespace detail

// Probe a GGUF file for MoE capability by reading header + metadata only.
inline GgufResidencyProbe ProbeGgufMoE(const std::string& path) {
    GgufResidencyProbe r;
    detail::GgufReader rd(path);
    if (!rd.in) { r.error = "cannot open: " + path; return r; }

    std::uint32_t magic = 0;
    std::uint32_t version = 0;
    std::uint64_t tensorCount = 0;
    std::uint64_t kvCount = 0;
    if (!rd.readT(magic) || magic != 0x46554747u) { r.error = "bad GGUF magic"; return r; }
    if (!rd.readT(version) || !rd.readT(tensorCount) || !rd.readT(kvCount)) {
        r.error = "truncated GGUF header"; return r;
    }

    std::int64_t bestExpertCount = 0;
    for (std::uint64_t i = 0; i < kvCount && rd.ok; ++i) {
        std::string key;
        std::uint32_t type = 0;
        if (!rd.readString(key) || !rd.readT(type)) { rd.ok = false; break; }

        if (key == "general.architecture" && type == 8) {
            std::string s;
            if (!rd.readString(s)) { rd.ok = false; break; }
            r.architecture = s;
            continue;
        }
        // expert_count may appear as `<arch>.expert_count`, `*.expert_count`,
        // or (DeepSeek) `*.expert_count`. Match the suffix to stay arch-agnostic.
        const bool isExpertCount =
            key.size() >= 12 && key.compare(key.size() - 12, 12, "expert_count") == 0;
        std::int64_t iv = 0; bool hasInt = false;
        if (!rd.skipValue(type, iv, hasInt)) { rd.ok = false; break; }
        if (isExpertCount && hasInt && iv > bestExpertCount) bestExpertCount = iv;
    }

    if (!rd.ok) { r.error = rd.err.empty() ? "metadata parse error" : rd.err; return r; }

    r.parseOk = true;
    r.numExperts = static_cast<std::uint32_t>(bestExpertCount > 0 ? bestExpertCount : 0);
    r.moe = r.numExperts > 0;
    return r;
}

// The four distinct Strata states. They must never be conflated:
//   Dense              -- not a MoE model; Strata is inapplicable.
//   ModelMoeEligible   -- MODEL_MOE_ELIGIBLE: metadata declares experts.
//   RuntimeReady       -- STRATA_RUNTIME_READY: executor + residency manager
//                         initialized (session opened).
//   ResidencyActive    -- STRATA_RESIDENCY_ACTIVE: expert placement / cache
//                         activity actually observed in the ledger.
//   Certified          -- STRATA_CERTIFIED: inference + numerical correctness +
//                         stability proven.
// The static probe can only reach Dense or ModelMoeEligible; the runtime levels
// are set when a StrataChatSession actually runs.
enum class StrataLevel { Dense, ModelMoeEligible, RuntimeReady, ResidencyActive, Certified };

inline const char* StrataLevelName(StrataLevel l) {
    switch (l) {
        case StrataLevel::Dense: return "DENSE";
        case StrataLevel::ModelMoeEligible: return "MODEL_MOE_ELIGIBLE";
        case StrataLevel::RuntimeReady: return "STRATA_RUNTIME_READY";
        case StrataLevel::ResidencyActive: return "STRATA_RESIDENCY_ACTIVE";
        case StrataLevel::Certified: return "STRATA_CERTIFIED";
    }
    return "DENSE";
}

struct StrataReadiness {
    StrataLevel level = StrataLevel::Dense;
    bool        eligible = false;   // MODEL_MOE_ELIGIBLE (metadata only)
    uint32_t    numExperts = 0;
    std::string architecture;
    std::string detail;
};

// Static classification from model metadata. Never claims runtime readiness.
inline StrataReadiness ClassifyStrataReadiness(const std::string& modelPath) {
    StrataReadiness c;
    if (modelPath.empty()) {
        c.detail = "no model configured";
        return c;
    }
    const GgufResidencyProbe p = ProbeGgufMoE(modelPath);
    if (!p.parseOk) {
        c.detail = "GGUF probe failed: " + p.error;
        return c;
    }
    c.numExperts = p.numExperts;
    c.architecture = p.architecture;
    if (!p.moe) {
        c.level = StrataLevel::Dense;
        c.detail = "model '" + p.architecture + "' is dense (no experts); "
                   "Strata expert residency is not applicable";
        return c;
    }
    c.level = StrataLevel::ModelMoeEligible;
    c.eligible = true;
    c.detail = "MoE model '" + p.architecture + "' with " +
               std::to_string(p.numExperts) + " experts (MODEL_MOE_ELIGIBLE)";
    return c;
}

// Build the authoritative residency readiness from a model path. Ready iff the
// model is genuinely MoE (MODEL_MOE_ELIGIBLE). Dense models and missing /
// unparseable files are NOT ready, with a precise reason -- GGUF presence alone
// never establishes this, and eligibility is not runtime readiness.
inline ResidencyReadiness ProbeStrataReadiness(const std::string& modelPath) {
    const StrataReadiness c = ClassifyStrataReadiness(modelPath);
    ResidencyReadiness rr;
    rr.ready = c.eligible;
    rr.detail = c.detail;
    return rr;
}

}  // namespace rawrxd