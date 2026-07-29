// RealityValidator.hpp
// Coordination Primitive #8: Reality Validator
// Verify that expected state matches actual state

#pragma once
#include <string>
#include <vector>
#include <functional>
#include <map>

namespace Sovereign {

// Validation result
struct ValidationResult {
    bool passed;
    std::string check_name;
    std::string expected;
    std::string actual;
    std::string message;
};

// Reality validator
class RealityValidator {
public:
    static RealityValidator& Instance();
    
    // Register validation checks
    void RegisterCheck(const std::string& name, std::function<ValidationResult()> check);
    
    // Run validations
    std::vector<ValidationResult> ValidateAll();
    ValidationResult Validate(const std::string& check_name);
    
    // Common checks
    bool ValidateFileExists(const std::string& path);
    bool ValidateSymbolExists(const std::string& file, const std::string& symbol);
    bool ValidateBuildOutput(const std::string& target);
    bool ValidateProcessRunning(uint64_t pid);

private:
    RealityValidator() = default;
    std::map<std::string, std::function<ValidationResult()>> checks_;
};

} // namespace Sovereign
