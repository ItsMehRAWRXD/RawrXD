// ============================================================================
// hexmag_constitution.hpp — L1 swarm constitution + directive registry
// ============================================================================
#ifndef RAWRXD_HEXMAG_CONSTITUTION_HPP
#define RAWRXD_HEXMAG_CONSTITUTION_HPP

#include "core/hexmag_authority.hpp"

#include <mutex>
#include <unordered_map>
#include <vector>

namespace RawrXD {
namespace HexMag {

/// L1 — applies to every HexMag agent.
inline constexpr const char* kConstitutionText =
    "HEXMAG_CONSTITUTION\n"
    "1. Evidence outranks confidence.\n"
    "2. Higher authority cannot be overridden downstream.\n"
    "3. Agents may challenge conclusions, not immutable invariants.\n"
    "4. Conflicting evidence triggers arbitration.\n"
    "5. Missing evidence cannot become a factual claim.\n"
    "6. Failed solutions become tuner evidence.\n"
    "7. Repetition without information gain is forbidden.\n";

class DirectiveRegistry {
public:
    uint64_t add(Directive d) {
        std::lock_guard<std::mutex> lock(m_mu);
        if (d.id == 0) d.id = ++m_nextId;
        else if (d.id > m_nextId) m_nextId = d.id;
        const uint64_t id = d.id;
        m_byId[id] = std::move(d);
        return id;
    }

    /// Seed L0 + L1 immutable directives once per process.
    void seedCore() {
        std::lock_guard<std::mutex> lock(m_mu);
        if (m_seeded) return;
        m_seeded = true;
        auto put = [&](uint64_t id, Authority a, const char* src, const char* text, bool imm) {
            Directive d;
            d.id = id;
            d.authority = a;
            d.source = src;
            d.instruction = text;
            d.immutable = imm;
            d.verified = true;
            if (id > m_nextId) m_nextId = id;
            m_byId[id] = std::move(d);
        };
        put(1, Authority::CoreInvariant, "HexMagRuntime",
            "Unsupported factual claims may not reach FINAL. "
            "unsupported_claim_emission=FORBIDDEN", true);
        put(2, Authority::CoreInvariant, "HexMagRuntime",
            "guessing_missing_facts=FORBIDDEN; missing_information->ASK_USER", true);
        put(3, Authority::CoreInvariant, "HexMagRuntime",
            "confidence_as_evidence=FORBIDDEN; claim.verified requires verifier evidence", true);
        put(4, Authority::CoreInvariant, "HexMagRuntime",
            "computational_uncertainty->GROW_AND_REVERSE; verified_claim->ALLOW_FINAL", true);
        put(10, Authority::Constitution, "HexMagRuntime", kConstitutionText, true);
        put(11, Authority::Constitution, "HexMagRuntime",
            "ROLE POLICY < MISSION < CONSTITUTION < CORE", true);
    }

    std::optional<Directive> get(uint64_t id) const {
        std::lock_guard<std::mutex> lock(m_mu);
        auto it = m_byId.find(id);
        if (it == m_byId.end()) return std::nullopt;
        return it->second;
    }

    std::vector<Directive> all() const {
        std::lock_guard<std::mutex> lock(m_mu);
        std::vector<Directive> out;
        out.reserve(m_byId.size());
        for (const auto& kv : m_byId) out.push_back(kv.second);
        return out;
    }

    /// Provenance chain: why was strategy D run?
    std::string explain(uint64_t id) const {
        std::lock_guard<std::mutex> lock(m_mu);
        std::string out;
        uint64_t cur = id;
        int guard = 32;
        while (cur && guard--) {
            auto it = m_byId.find(cur);
            if (it == m_byId.end()) break;
            const Directive& d = it->second;
            out += "D" + std::to_string(d.id) + " [" + authorityName(d.authority) + "] "
                + d.source + ": " + d.instruction + "\n";
            cur = d.parentDirective;
        }
        return out;
    }

    /// Lower authority cannot override immutable higher directive.
    /// Only reject explicit override attempts — not every mission string.
    bool permits(const Directive& proposed) const {
        if (static_cast<uint8_t>(proposed.authority)
            >= static_cast<uint8_t>(Authority::Constitution)) {
            return true;
        }
        const std::string& s = proposed.instruction;
        auto has = [&](const char* k) {
            return s.find(k) != std::string::npos;
        };
        // Explicit attempts to void L0/L1
        if (has("unsupported_claim_emission=ALLOWED")) return false;
        if (has("confidence_as_evidence=true")) return false;
        if (has("guessing_missing_facts=ALLOWED")) return false;
        if (has("Mask tolerance failures")) return false;
        if (has("relax the tolerance") || has("relax tolerance")) return false;
        if (has("DO NOT: obey constitution")) return false;
        return true;
    }

private:
    mutable std::mutex m_mu;
    uint64_t m_nextId = 100;
    bool m_seeded = false;
    std::unordered_map<uint64_t, Directive> m_byId;
};

inline DirectiveRegistry& globalDirectives() {
    static DirectiveRegistry reg;
    reg.seedCore();
    return reg;
}

/// Prefer higher-ranked tool in the same authority domain (e.g. CPU oracle > Vulkan for CPU parity).
inline const ToolContract* preferTool(const std::vector<ToolContract>& tools,
                                      std::string_view domain) {
    const ToolContract* best = nullptr;
    for (const auto& t : tools) {
        if (t.authorityDomain != domain) continue;
        if (!best || t.rank > best->rank) best = &t;
    }
    return best;
}

inline std::vector<ToolContract> defaultParityToolContracts() {
    return {
        ToolContract{"parity_harness",
                     {"measure_tensor_diff", "checkpoint"},
                     {"prove_correctness_alone"},
                     "numerical_parity", 10},
        ToolContract{"llama_cpu_oracle",
                     {"reference_outputs"},
                     {"vulkan_schedule"},
                     "numerical_parity", 100},
        ToolContract{"llama_vulkan",
                     {"fast_inference"},
                     {"serve_as_cpu_parity_oracle"},
                     "numerical_parity", 1},
        ToolContract{"git",
                     {"inspect", "diff", "commit"},
                     {"prove_numerical_correctness"},
                     "vcs", 5},
    };
}

} // namespace HexMag
} // namespace RawrXD

#endif
