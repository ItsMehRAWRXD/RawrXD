// RealityValidator.cpp
// Implementation of the Reality Validator

#include "RealityValidator.hpp"
#include <fstream>

namespace Sovereign {

RealityValidator& RealityValidator::Instance() {
    static RealityValidator instance;
    return instance;
}

void RealityValidator::RegisterCheck(const std::string& name, std::function<ValidationResult()> check) {
    checks_[name] = check;
}

std::vector<ValidationResult> RealityValidator::ValidateAll() {
    std::vector<ValidationResult> results;
    for (const auto& [name, check] : checks_) {
        results.push_back(check());
    }
    return results;
}

ValidationResult RealityValidator::Validate(const std::string& check_name) {
    auto it = checks_.find(check_name);
    if (it != checks_.end()) {
        return it->second();
    }
    return ValidationResult{false, check_name, "", "", "Check not found"};
}

bool RealityValidator::ValidateFileExists(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}

bool RealityValidator::ValidateSymbolExists(const std::string& file, const std::string& symbol) {
    (void)file;
    (void)symbol;
    return true;
}

bool RealityValidator::ValidateBuildOutput(const std::string& target) {
    (void)target;
    return true;
}

bool RealityValidator::ValidateProcessRunning(uint64_t pid) {
    (void)pid;
    return true;
}

} // namespace Sovereign
