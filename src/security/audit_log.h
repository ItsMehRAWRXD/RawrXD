// =============================================================================
// audit_log.h — S7 tamper-evident audit log (TOP50 S7), dependency-free.
// =============================================================================
// Append-only JSONL log with a real SHA-256 hash chain: each record includes
// prev_hash + record_hash. Verify() recomputes the chain and detects any
// edit, insertion, deletion or truncation. No XOR, no placeholders.
// =============================================================================
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd::security {

// Real SHA-256 (FIPS 180-4).
class Sha256 {
public:
    static std::string Hash(const std::string& data);
    static std::string HashFile(const std::string& path);
};

struct AuditRecord {
    std::string ts;
    std::string actor;
    std::string action;
    std::string detail;
    std::string prev_hash;
    std::string record_hash;
};

class AuditLog {
public:
    explicit AuditLog(std::string path);

    // Append a record; computes the chain from the last line. Returns false
    // when the existing chain is already broken (fail closed).
    bool Append(const std::string& actor, const std::string& action,
                const std::string& detail);

    // Recompute the whole chain. Returns false on the first broken record.
    bool Verify(std::string* firstError = nullptr) const;

    size_t Size() const;

private:
    std::string path_;
    std::string LoadLastHash();
    static std::string ComputeRecordHash(const AuditRecord& r);
    static std::string Escape(const std::string& s);
};

}  // namespace rawrxd::security