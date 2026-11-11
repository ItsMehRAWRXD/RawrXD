#pragma once

#include "rawrxd/compatibility/ArchitectureDetector.hpp"
#include "rawrxd/compatibility/ModelAdapter.hpp"
#include "rawrxd/compatibility/ModelCapabilities.hpp"
#include <vector>
#include <functional>

namespace rawrxd {
namespace compatibility {

// Validation result for a single test
struct ValidationResult {
    std::string testName;
    bool passed = false;
    std::string errorMessage;
    float executionTimeMs = 0.0f;
    std::unordered_map<std::string, std::string> metadata;
};

// Architecture validation suite
struct ArchitectureValidationSuite {
    ModelArchitecture arch;
    std::string archName;
    std::vector<ValidationResult> results;
    bool allPassed = false;
    float totalTimeMs = 0.0f;
};

// Comprehensive compatibility validator
class CompatibilityValidator {
public:
    CompatibilityValidator();
    ~CompatibilityValidator() = default;

    // Validate a single model file
    std::vector<ValidationResult> ValidateModel(const std::string& ggufPath);
    
    // Validate specific architecture
    ArchitectureValidationSuite ValidateArchitecture(ModelArchitecture arch);
    
    // Run full validation suite for all supported architectures
    std::vector<ArchitectureValidationSuite> RunFullValidationSuite();
    
    // Run regression tests
    bool RunRegressionTests();
    
    // Generate validation report
    std::string GenerateReport(const std::vector<ArchitectureValidationSuite>& suites) const;
    std::string GenerateReport(const std::vector<ValidationResult>& results) const;
    
    // Export results to JSON
    std::string ExportToJSON(const std::vector<ArchitectureValidationSuite>& suites) const;
    
    // Set known-good reference models for validation
    void SetReferenceModel(ModelArchitecture arch, const std::string& ggufPath);
    
    // Get validation summary
    struct Summary {
        int totalTests = 0;
        int passedTests = 0;
        int failedTests = 0;
        float passRate = 0.0f;
        float totalTimeMs = 0.0f;
    };
    Summary GetSummary(const std::vector<ArchitectureValidationSuite>& suites) const;

private:
    std::unordered_map<ModelArchitecture, std::string> referenceModels_;
    
    // Individual validation tests
    ValidationResult TestArchitectureDetection(const std::string& ggufPath);
    ValidationResult TestMetadataParsing(const std::string& ggufPath);
    ValidationResult TestTensorValidation(const std::string& ggufPath);
    ValidationResult TestContextConfiguration(const std::string& ggufPath);
    ValidationResult TestRoPEInitialization(const std::string& ggufPath);
    ValidationResult TestALiBiInitialization(const std::string& ggufPath);
    ValidationResult TestInference(const std::string& ggufPath);
    ValidationResult TestCapabilitiesExtraction(const std::string& ggufPath);
    ValidationResult TestKernelSelection(const std::string& ggufPath);
    ValidationResult TestSpecialTokens(const std::string& ggufPath);
    
    // Helper methods
    ValidationResult RunTest(const std::string& testName, 
                              std::function<bool()> testFunc);
    bool FileExists(const std::string& path);
};

// Quick validation checker for CI/CD
class QuickCompatibilityCheck {
public:
    static bool Check(const std::string& ggufPath);
    static std::string GetQuickReport(const std::string& ggufPath);
};

} // namespace compatibility
} // namespace rawrxd
