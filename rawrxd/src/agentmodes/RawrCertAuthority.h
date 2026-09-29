// RawrCertAuthority.h — RAWRXD_RAWRCERT_AUTHORITY_001
// Final certification only. It reads existing receipts, fixes nothing, skips
// nothing, and cannot pass a partial chain. Its own verdict is computed from
// the receipts it read.
#pragma once
#include <string>
#include <vector>

namespace rawrxd { namespace cert {

struct GateInput {
    std::string gateName;
    std::string receiptPath;
};

struct CertResult {
    std::string              exePath;
    std::string              exeSha256;
    int                      gatesRequired = 0;
    int                      gatesPass = 0;
    int                      gatesFail = 0;
    int                      falsePassRetracted = 0;
    std::vector<std::string> failedGates;
    std::string              verdict;
    std::string              rationale;
};

// SHA-256 of a file, lowercase hex. Empty string when unreadable.
std::string sha256File(const std::string& path);

// Known-answer self-test for the SHA-256 implementation above.
// SHA-256("abc") == ba7816bf...15ad. Returns true on match. This is a stable
// vector, unlike the hash of a binary that legitimately gets rebuilt.
bool sha256SelfTest(std::string* detail = nullptr);

// Certify `exe` against `gates`. PASS requires the hash to be readable, every
// required gate present, and zero failures.
CertResult certify(const std::string& exePath, const std::vector<GateInput>& gates);

// Write RAWRXD_RAWRCERT_AUTHORITY_001 from a measured result.
void writeCertReceipt(const std::string& path, const CertResult& r);

}} // namespace rawrxd::cert
