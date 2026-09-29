// RawrAuditAuthority.h — RAWRXD_RAWRAUDIT_AUTHORITY_001
// Finds hidden stubs, hardcoded PASS, simulated counters, exclusions and
// dead code. This mode is the one that would have caught the
// RAWRXD_RAWR_DUMP_AUTHORITY_001 false PASS before it reached a receipt.
//
// The scanner is a real file walker with real rules. It reports file:line for
// every finding and derives its verdict from the findings, never from a
// constant.
#pragma once
#include <string>
#include <vector>

namespace rawrxd { namespace audit {

enum class Severity { Blocking, Advisory };

struct Finding {
    std::string file;      // path relative to the scan root
    int         line = 0;  // 1-based
    std::string rule;      // e.g. "HARDCODED_VERDICT"
    Severity    severity = Severity::Advisory;
    std::string evidence;  // trimmed source line
};

struct ScanOptions {
    std::string root;                 // directory to walk
    std::vector<std::string> extensions = { ".cpp", ".h", ".hpp", ".cc" };
    bool        blockingOnly = false; // report only blocking findings
    int         maxFiles  = 0;        // 0 == unlimited
    // Substrings naming files to skip. Exemptions are never silent: every one
    // applied is counted and written to the receipt, so a reader can tell a
    // clean scan from a narrowed one.
    std::vector<std::string> exemptions;
};

struct ScanResult {
    int                      filesScanned = 0;
    std::vector<Finding>     findings;
    int                      blockingCount = 0;
    int                      advisoryCount = 0;
    int                      hardcodedPass = 0;
    int                      simulatedCounters = 0;
    int                      exclusions = 0;
    int                      filesExempted = 0;
    bool                     rootExisted = false;
};

// Walk `opts.root` and apply every rule. Real filesystem traversal; a missing
// root yields filesScanned == 0 and rootExisted == false rather than an error.
ScanResult scanSourceTree(const ScanOptions& opts);

// Apply the line rules to a single already-read buffer. Exposed so a single
// file can be audited without a full tree walk.
void scanBuffer(const std::string& fileLabel, const std::string& text,
                ScanResult& out);

// Read and audit one file by path, including function-body rules. Used by the
// gate verifier, which scopes its check to the files backing a single gate.
bool auditFile(const std::string& path, ScanResult& out);

// Classify a function body: true when it performs no computation and only
// emits output. This is the signature of a print-only stub.
bool isPrintOnlyBody(const std::string& body);

// Write RAWRXD_RAWRAUDIT_AUTHORITY_001 to `path` from measured results.
void writeAuditReceipt(const std::string& path, const ScanResult& result,
                       const std::string& scanRoot);

// Convenience: scan a root and write the receipt in one call.
int runAudit(const std::string& scanRoot, const std::string& receiptPath);

}} // namespace rawrxd::audit
