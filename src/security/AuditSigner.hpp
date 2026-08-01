#pragma once
#include "CapabilityToken.hpp"
#include <string>
#include <iostream>

class AuditSigner {
public:
    void Record(const CapabilityToken& token, const std::string& operation,
                const std::string& backendName, bool allowed, uint64_t durationUs) {
        std::cout << "[Audit] " << (allowed ? "ALLOW" : "DENY")
                  << " | " << operation
                  << " | " << backendName
                  << " | token=" << token.backendName << "\n";
    }
};
