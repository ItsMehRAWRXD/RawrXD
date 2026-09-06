// ============================================================================
// W0EvidenceLedger.hpp / W0RepairMemory — evidence + positive/negative cases
// ============================================================================
#ifndef RAWRXD_DEEP2W0_W0_EVIDENCE_LEDGER_HPP
#define RAWRXD_DEEP2W0_W0_EVIDENCE_LEDGER_HPP

#include "deep2w0/W0UniversalIR.hpp"

#include <string>
#include <vector>

namespace RawrXD {
namespace W0 {

class EvidenceLedger {
public:
    void add(EvidenceEntry e) { m_entries.push_back(std::move(e)); }
    const std::vector<EvidenceEntry>& all() const { return m_entries; }
    bool allVerified() const {
        if (m_entries.empty()) return false;
        for (const auto& e : m_entries) {
            if (!e.verified) return false;
        }
        return true;
    }
    void clear() { m_entries.clear(); }

private:
    std::vector<EvidenceEntry> m_entries;
};

class RepairMemory {
public:
    void remember(RepairCase c) { m_cases.push_back(std::move(c)); }

    const RepairCase* bestMatch(const std::string& problemFp) const {
        const RepairCase* best = nullptr;
        for (const auto& c : m_cases) {
            if (c.forbidden) continue;
            if (c.problemFingerprint != problemFp) continue;
            if (!best || c.successCount > best->successCount) best = &c;
        }
        return best;
    }

    bool isForbidden(const std::string& transformOp) const {
        for (const auto& c : m_cases) {
            if (c.forbidden && c.transformOp == transformOp) return true;
        }
        return false;
    }

    const std::vector<RepairCase>& cases() const { return m_cases; }

private:
    std::vector<RepairCase> m_cases;
};

} // namespace W0
} // namespace RawrXD

#endif
