// ============================================================================
// SecretRedaction.cpp - Secret Scanning & Redaction Implementation
// ============================================================================

#include "SecretRedaction.hpp"
#include <fstream>
#include <iostream>

namespace Sovereign {

SecretRedaction::SecretRedaction() = default;
SecretRedaction::~SecretRedaction() = default;

void SecretRedaction::Initialize() {
    AddDefaultPatterns();
}

void SecretRedaction::AddDefaultPatterns() {
    AddPattern({"API Key", std::regex(R"((?:api[_-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"])", std::regex::icase), "API_KEY_REDACTED", true});
    AddPattern({"AWS Key", std::regex(R"(AKIA[0-9A-Z]{16})"), "AWS_KEY_REDACTED", true});
    AddPattern({"GitHub Token", std::regex(R"(gh[pousr]_[A-Za-z0-9_]{36,})"), "GITHUB_TOKEN_REDACTED", true});
    AddPattern({"Bearer Token", std::regex(R"(Bearer\s+[A-Za-z0-9\-._~+/]{20,})", std::regex::icase), "BEARER_TOKEN_REDACTED", true});
    AddPattern({"JWT", std::regex(R"(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)"), "JWT_REDACTED", true});
    AddPattern({"Private Key", std::regex(R"(-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----)"), "PRIVATE_KEY_REDACTED", true});
    AddPattern({"Password", std::regex(R"(password\s*[:=]\s*['\"][^'\"]+['\"])", std::regex::icase), "PASSWORD_REDACTED", true});
    AddPattern({"Connection String", std::regex(R"(mongodb(?:\+srv)?://[^\s]+|postgresql://[^\s]+|mysql://[^\s]+)"), "CONNECTION_STRING_REDACTED", true});
}

void SecretRedaction::AddPattern(const SecretPattern& pattern) {
    std::lock_guard<std::mutex> lock(mutex_);
    patterns_.push_back(pattern);
}

std::string SecretRedaction::Redact(const std::string& text) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string result = text;
    for (const auto& p : patterns_) {
        if (p.enabled) {
            result = std::regex_replace(result, p.pattern, p.redactionTemplate);
        }
    }
    return result;
}

std::vector<std::pair<std::string, size_t>> SecretRedaction::Scan(const std::string& text) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::pair<std::string, size_t>> findings;
    for (const auto& p : patterns_) {
        if (!p.enabled) continue;
        std::sregex_iterator iter(text.begin(), text.end(), p.pattern);
        std::sregex_iterator end;
        for (; iter != end; ++iter) {
            findings.push_back({p.name, iter->position()});
        }
    }
    return findings;
}

bool SecretRedaction::ContainsSecrets(const std::string& text) const {
    return !Scan(text).empty();
}

} // namespace Sovereign
