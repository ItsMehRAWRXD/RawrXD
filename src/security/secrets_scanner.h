// =============================================================================
// secrets_scanner.h — S2 secrets scanner (TOP50 S2), dependency-free.
// =============================================================================
// Detects API keys, tokens, private keys and high-entropy strings in source
// trees. Findings feed the Problems panel (I3) and the CLI (tools/secrets_scan).
// =============================================================================
#pragma once
#include <string>
#include <vector>

namespace rawrxd::security {

struct SecretFinding {
    std::string rule_id;     // "AWS_KEY", "GITHUB_TOKEN", "PRIVATE_KEY", ...
    std::string file;
    int line = 0;
    int column = 0;
    std::string match;       // redacted preview (first 4 + last 2 chars)
    std::string message;
};

class SecretsScanner {
public:
    // Scan one file or a directory tree (bounded, skips binaries by extension).
    std::vector<SecretFinding> ScanPath(const std::string& path,
                                        int max_file_bytes = 2 * 1024 * 1024) const;

    static std::string ToJson(const std::vector<SecretFinding>& findings);
};

// Shannon entropy in bits/char.
double ShannonEntropy(const std::string& s);

}  // namespace rawrxd::security