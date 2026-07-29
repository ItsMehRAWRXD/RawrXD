// ============================================================================
// SecretRedaction.hpp - Secret Scanning & Redaction
// ============================================================================

#pragma once
#include <string>
#include <vector>
#include <regex>
#include <memory>

namespace Sovereign {

struct SecretPattern {
    std::string name;
    std::regex pattern;
    std::string redactionTemplate;
    bool enabled;
};

class SecretRedaction {
public:
    SecretRedaction();
    ~SecretRedaction();

    void Initialize();
    void AddPattern(const SecretPattern& pattern);
    std::string Redact(const std::string& text) const;
    std::vector<std::pair<std::string, size_t>> Scan(const std::string& text) const;
    bool ContainsSecrets(const std::string& text) const;

private:
    std::vector<SecretPattern> patterns_;
    mutable std::mutex mutex_;
    void AddDefaultPatterns();
};

} // namespace Sovereign
