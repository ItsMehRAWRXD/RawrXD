// ============================================================================
// CertificationCore.cpp — Handwritten certification pipeline implementation
// ============================================================================
#include "CertificationCore.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace rawrxd::certification {

std::string CertificationCore::makeId(const std::string& prefix) {
    int n = receiptCounter_.fetch_add(1, std::memory_order_relaxed);
    std::ostringstream oss;
    oss << prefix << "-" << std::hex << n;
    return oss.str();
}

std::string CertificationCore::computeFingerprint(const std::string& content) {
    // FNV-1a hash (deterministic, content-addressable)
    uint64_t hash = 14695981039346656037ULL;
    for (char c : content) {
        hash ^= static_cast<uint8_t>(c);
        hash *= 1099511628211ULL;
    }
    std::ostringstream oss;
    oss << std::hex << hash;
    return oss.str();
}

Subject CertificationCore::importSubject(const std::string& content,
                                          const std::string& generationReceiptId) {
    Subject subject;
    subject.id = makeId("subject");
    subject.content = content;
    subject.sourceReceiptId = generationReceiptId;
    subject.frozen = false;
    return subject;
}

bool CertificationCore::freezeSubject(Subject& subject) {
    if (subject.content.empty()) return false;
    subject.fingerprint = computeFingerprint(subject.content);
    subject.frozen = true;
    return true;
}

TruthResult CertificationCore::runOracle(const Subject& subject,
                                          const std::string& oracleExpectedContent) {
    TruthResult result;
    result.oracleId = makeId("oracle");

    if (!subject.frozen) {
        result.difference = "Subject not frozen — cannot run oracle";
        return result;
    }

    // Structural match: same length
    result.structuralMatch = (subject.content.length() == oracleExpectedContent.length());

    // Numerical match: exact content comparison
    result.numericalMatch = (subject.content == oracleExpectedContent);

    // Determinism match: same fingerprint
    std::string oracleFingerprint = computeFingerprint(oracleExpectedContent);
    result.determinismMatch = (subject.fingerprint == oracleFingerprint);

    if (!result.numericalMatch) {
        result.difference = "Content mismatch: subject fingerprint=" + subject.fingerprint +
                           " vs oracle fingerprint=" + oracleFingerprint;
    }

    return result;
}

std::vector<Evidence> CertificationCore::collectEvidence(
    const Subject& subject, const TruthResult& truth) {

    std::vector<Evidence> evidence;

    // Structural evidence
    Evidence structural;
    structural.type = "structural";
    structural.description = "Content length comparison";
    structural.pass = truth.structuralMatch;
    structural.detail = "subject_len=" + std::to_string(subject.content.length());
    evidence.push_back(structural);

    // Numerical evidence
    Evidence numerical;
    numerical.type = "numerical";
    numerical.description = "Exact content match against oracle";
    numerical.pass = truth.numericalMatch;
    numerical.detail = truth.numericalMatch ? "exact match" : "mismatch detected";
    evidence.push_back(numerical);

    // Determinism evidence
    Evidence determinism;
    determinism.type = "determinism";
    determinism.description = "Fingerprint comparison (FNV-1a)";
    determinism.pass = truth.determinismMatch;
    determinism.detail = "subject=" + subject.fingerprint + " oracle=" + truth.oracleId;
    evidence.push_back(determinism);

    return evidence;
}

Verdict CertificationCore::issueVerdict(const TruthResult& truth,
                                         const std::vector<Evidence>& evidence) {
    Verdict verdict;
    verdict.truth = truth;
    verdict.evidence = evidence;

    // Fail-closed: all three checks must pass
    bool allPass = truth.structuralMatch && truth.numericalMatch && truth.determinismMatch;
    bool anyPass = truth.structuralMatch || truth.numericalMatch || truth.determinismMatch;

    if (allPass) {
        verdict.type = VerdictType::Pass;
        verdict.reason = "All oracle checks passed (structural + numerical + determinism)";
    } else if (!anyPass) {
        verdict.type = VerdictType::Fail;
        verdict.reason = "All oracle checks failed";
    } else {
        // Partial match = Hold (uncertain)
        verdict.type = VerdictType::Hold;
        verdict.reason = "Partial oracle match — uncertain, fail-closed HOLD";
    }

    return verdict;
}

CertificationReceipt CertificationCore::sealReceipt(
    const Subject& subject, const Verdict& verdict,
    const std::string& generationReceiptId) {

    CertificationReceipt receipt;
    receipt.receiptId = makeId("cert-receipt");
    receipt.subjectId = subject.id;
    receipt.subjectFingerprint = subject.fingerprint;
    receipt.verdict = verdict.type;
    receipt.verdictReason = verdict.reason;
    receipt.evidence = verdict.evidence;
    receipt.truth = verdict.truth;
    receipt.generationReceiptId = generationReceiptId;
    receipt.oracleId = verdict.truth.oracleId;
    receipt.sealed = true;

    auto t = std::chrono::system_clock::now();
    auto t_time = std::chrono::system_clock::to_time_t(t);
    std::ostringstream ts;
    ts << std::put_time(std::gmtime(&t_time), "%Y-%m-%dT%H:%M:%SZ");
    receipt.timestamp = ts.str();

    return receipt;
}

CertificationReceipt CertificationCore::certify(
    const std::string& content,
    const std::string& generationReceiptId,
    const std::string& oracleExpectedContent) {

    totalCert_.fetch_add(1, std::memory_order_relaxed);

    auto subject = importSubject(content, generationReceiptId);
    freezeSubject(subject);
    auto truth = runOracle(subject, oracleExpectedContent);
    auto evidence = collectEvidence(subject, truth);
    auto verdict = issueVerdict(truth, evidence);
    auto receipt = sealReceipt(subject, verdict, generationReceiptId);

    switch (verdict.type) {
        case VerdictType::Pass: passCount_.fetch_add(1, std::memory_order_relaxed); break;
        case VerdictType::Fail: failCount_.fetch_add(1, std::memory_order_relaxed); break;
        case VerdictType::Hold: holdCount_.fetch_add(1, std::memory_order_relaxed); break;
        default: break;
    }

    return receipt;
}

} // namespace rawrxd::certification