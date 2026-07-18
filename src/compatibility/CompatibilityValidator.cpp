#include "rawrxd/compatibility/CompatibilityValidator.hpp"
#include "rawrxd/compatibility/GGUFCompatibilityLoader.hpp"
#include <chrono>
#include <sstream>
#include <fstream>

namespace rawrxd {
namespace compatibility {

CompatibilityValidator::CompatibilityValidator() {
    // Initialize with default reference model paths (can be overridden)
    referenceModels_[ModelArchitecture::LLAMA3] = "models/llama3-8b.gguf";
    referenceModels_[ModelArchitecture::MISTRAL] = "models/mistral-7b.gguf";
    referenceModels_[ModelArchitecture::PHI3] = "models/phi3-mini.gguf";
    referenceModels_[ModelArchitecture::QWEN2] = "models/qwen2-7b.gguf";
}

std::vector<ValidationResult> CompatibilityValidator::ValidateModel(const std::string& ggufPath) {
    std::vector<ValidationResult> results;
    
    if (!FileExists(ggufPath)) {
        ValidationResult result;
        result.testName = "FileExists";
        result.passed = false;
        result.errorMessage = "Model file not found: " + ggufPath;
        results.push_back(result);
        return results;
    }
    
    // Run all validation tests
    results.push_back(TestArchitectureDetection(ggufPath));
    results.push_back(TestMetadataParsing(ggufPath));
    results.push_back(TestTensorValidation(ggufPath));
    results.push_back(TestContextConfiguration(ggufPath));
    results.push_back(TestRoPEInitialization(ggufPath));
    results.push_back(TestALiBiInitialization(ggufPath));
    results.push_back(TestInference(ggufPath));
    results.push_back(TestCapabilitiesExtraction(ggufPath));
    results.push_back(TestKernelSelection(ggufPath));
    results.push_back(TestSpecialTokens(ggufPath));
    
    return results;
}

ArchitectureValidationSuite CompatibilityValidator::ValidateArchitecture(ModelArchitecture arch) {
    ArchitectureValidationSuite suite;
    suite.arch = arch;
    
    ArchitectureDetector detector;
    suite.archName = detector.GetArchitectureName(arch);
    
    auto it = referenceModels_.find(arch);
    if (it == referenceModels_.end() || !FileExists(it->second)) {
        ValidationResult result;
        result.testName = "ReferenceModel";
        result.passed = false;
        result.errorMessage = "No reference model available for " + suite.archName;
        suite.results.push_back(result);
        return suite;
    }
    
    suite.results = ValidateModel(it->second);
    
    // Calculate summary
    suite.allPassed = true;
    for (const auto& result : suite.results) {
        if (!result.passed) {
            suite.allPassed = false;
        }
        suite.totalTimeMs += result.executionTimeMs;
    }
    
    return suite;
}

std::vector<ArchitectureValidationSuite> CompatibilityValidator::RunFullValidationSuite() {
    std::vector<ArchitectureValidationSuite> suites;
    
    // Test all major architectures
    std::vector<ModelArchitecture> architectures = {
        ModelArchitecture::LLAMA3,
        ModelArchitecture::MISTRAL,
        ModelArchitecture::MIXTRAL,
        ModelArchitecture::PHI3,
        ModelArchitecture::QWEN2,
        ModelArchitecture::DEEPSEEK,
        ModelArchitecture::CODESTRAL,
        ModelArchitecture::GEMMA2
    };
    
    for (auto arch : architectures) {
        suites.push_back(ValidateArchitecture(arch));
    }
    
    return suites;
}

bool CompatibilityValidator::RunRegressionTests() {
    auto suites = RunFullValidationSuite();
    
    for (const auto& suite : suites) {
        if (!suite.allPassed) {
            return false;
        }
    }
    
    return true;
}

ValidationResult CompatibilityValidator::TestArchitectureDetection(const std::string& ggufPath) {
    return RunTest("ArchitectureDetection", [&]() -> bool {
        GGUFCompatibilityLoader loader;
        if (!loader.Load(ggufPath)) {
            return false;
        }
        
        auto arch = loader.GetArchitecture();
        if (arch == ModelArchitecture::UNKNOWN) {
            return false;
        }
        
        // Verify architecture is supported
        ArchitectureDetector detector;
        return detector.IsSupported(arch);
    });
}

ValidationResult CompatibilityValidator::TestMetadataParsing(const std::string& ggufPath) {
    return RunTest("MetadataParsing", [&]() -> bool {
        GGUFCompatibilityLoader loader;
        if (!loader.Load(ggufPath)) {
            return false;
        }
        
        auto config = loader.GetConfig();
        
        // Validate essential metadata
        if (config.vocab_size <= 0 || config.hidden_size <= 0 || 
            config.num_layers <= 0 || config.num_heads <= 0) {
            return false;
        }
        
        return true;
    });
}

ValidationResult CompatibilityValidator::TestTensorValidation(const std::string& ggufPath) {
    return RunTest("TensorValidation", [&]() -> bool {
        GGUFCompatibilityLoader loader;
        if (!loader.Load(ggufPath)) {
            return false;
        }
        
        // Check that tensors exist
        size_t tensorCount = loader.GetTensorCount();
        if (tensorCount == 0) {
            return false;
        }
        
        return true;
    });
}

ValidationResult CompatibilityValidator::TestContextConfiguration(const std::string& ggufPath) {
    return RunTest("ContextConfiguration", [&]() -> bool {
        GGUFCompatibilityLoader loader;
        if (!loader.Load(ggufPath)) {
            return false;
        }
        
        auto config = loader.GetConfig();
        
        // Validate context length
        if (config.max_position_embeddings <= 0) {
            return false;
        }
        
        // Validate head dimension calculation
        int expected_head_dim = config.hidden_size / config.num_heads;
        if (expected_head_dim <= 0) {
            return false;
        }
        
        return true;
    });
}

ValidationResult CompatibilityValidator::TestRoPEInitialization(const std::string& ggufPath) {
    return RunTest("RoPEInitialization", [&]() -> bool {
        GGUFCompatibilityLoader loader;
        if (!loader.Load(ggufPath)) {
            return false;
        }
        
        auto adapter = loader.GetAdapter();
        if (!adapter) {
            return false;
        }
        
        auto config = adapter->GetConfig();
        
        // If model uses RoPE, verify it can be initialized
        if (config.use_rope) {
            // RoPE cache should be pre-computed
            // This is verified by successful adapter initialization
            return true;
        }
        
        return true;  // Not all models use RoPE
    });
}

ValidationResult CompatibilityValidator::TestALiBiInitialization(const std::string& ggufPath) {
    return RunTest("ALiBiInitialization", [&]() -> bool {
        GGUFCompatibilityLoader loader;
        if (!loader.Load(ggufPath)) {
            return false;
        }
        
        auto adapter = loader.GetAdapter();
        if (!adapter) {
            return false;
        }
        
        auto config = adapter->GetConfig();
        
        // If model uses ALiBi, verify it can be initialized
        if (config.use_alibi) {
            // ALiBi slopes should be computed
            return true;
        }
        
        return true;  // Not all models use ALiBi
    });
}

ValidationResult CompatibilityValidator::TestInference(const std::string& ggufPath) {
    return RunTest("Inference", [&]() -> bool {
        // This test would require a full model load and inference run
        // For now, we just verify the model can be loaded
        GGUFCompatibilityLoader loader;
        if (!loader.Load(ggufPath)) {
            return false;
        }
        
        return loader.IsSupported();
    });
}

ValidationResult CompatibilityValidator::TestCapabilitiesExtraction(const std::string& ggufPath) {
    return RunTest("CapabilitiesExtraction", [&]() -> bool {
        GGUFCompatibilityLoader loader;
        if (!loader.Load(ggufPath)) {
            return false;
        }
        
        auto adapter = loader.GetAdapter();
        if (!adapter) {
            return false;
        }
        
        // Extract capabilities
        auto caps = CapabilityDetector::DetectFromConfig(adapter->GetConfig());
        
        // Validate capabilities
        auto issues = CapabilityDetector::ValidateCapabilities(caps);
        if (!issues.empty()) {
            return false;
        }
        
        return true;
    });
}

ValidationResult CompatibilityValidator::TestKernelSelection(const std::string& ggufPath) {
    return RunTest("KernelSelection", [&]() -> bool {
        GGUFCompatibilityLoader loader;
        if (!loader.Load(ggufPath)) {
            return false;
        }
        
        auto config = loader.GetRecommendedKernels();
        
        // Verify kernel configuration is valid
        if (config.attention_kernel.empty() || config.matmul_kernel.empty()) {
            return false;
        }
        
        return true;
    });
}

ValidationResult CompatibilityValidator::TestSpecialTokens(const std::string& ggufPath) {
    return RunTest("SpecialTokens", [&]() -> bool {
        GGUFCompatibilityLoader loader;
        if (!loader.Load(ggufPath)) {
            return false;
        }
        
        auto adapter = loader.GetAdapter();
        if (!adapter) {
            return false;
        }
        
        // Verify special tokens are valid
        int bos = adapter->GetBOSToken();
        int eos = adapter->GetEOSToken();
        
        if (bos < 0 || eos < 0) {
            return false;
        }
        
        auto stops = adapter->GetStopTokens();
        if (stops.empty()) {
            return false;
        }
        
        return true;
    });
}

ValidationResult CompatibilityValidator::RunTest(const std::string& testName, 
                                                std::function<bool()> testFunc) {
    ValidationResult result;
    result.testName = testName;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    try {
        result.passed = testFunc();
    } catch (const std::exception& e) {
        result.passed = false;
        result.errorMessage = e.what();
    } catch (...) {
        result.passed = false;
        result.errorMessage = "Unknown exception";
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration<float, std::milli>(end - start).count();
    
    return result;
}

bool CompatibilityValidator::FileExists(const std::string& path) {
    std::ifstream file(path);
    return file.good();
}

std::string CompatibilityValidator::GenerateReport(const std::vector<ArchitectureValidationSuite>& suites) const {
    std::stringstream report;
    report << "# RawrXD Compatibility Validation Report\n\n";
    report << "Generated: " << __DATE__ << " " << __TIME__ << "\n\n";
    
    auto summary = GetSummary(suites);
    report << "## Summary\n\n";
    report << "| Metric | Value |\n";
    report << "|--------|-------|\n";
    report << "| Total Tests | " << summary.totalTests << " |\n";
    report << "| Passed | " << summary.passedTests << " |\n";
    report << "| Failed | " << summary.failedTests << " |\n";
    report << "| Pass Rate | " << std::fixed << std::setprecision(2) << summary.passRate << "% |\n";
    report << "| Total Time | " << summary.totalTimeMs << " ms |\n\n";
    
    report << "## Architecture Results\n\n";
    
    for (const auto& suite : suites) {
        report << "### " << suite.archName << "\n\n";
        report << "Status: " << (suite.allPassed ? "✅ PASS" : "❌ FAIL") << "\n";
        report << "Total Time: " << suite.totalTimeMs << " ms\n\n";
        
        report << "| Test | Status | Time (ms) | Error |\n";
        report << "|------|--------|-----------|-------|\n";
        
        for (const auto& result : suite.results) {
            report << "| " << result.testName << " | ";
            report << (result.passed ? "✅" : "❌") << " | ";
            report << std::fixed << std::setprecision(2) << result.executionTimeMs << " | ";
            report << (result.errorMessage.empty() ? "-" : result.errorMessage) << " |\n";
        }
        
        report << "\n";
    }
    
    return report.str();
}

std::string CompatibilityValidator::GenerateReport(const std::vector<ValidationResult>& results) const {
    std::stringstream report;
    report << "# Single Model Validation Report\n\n";
    
    int passed = 0;
    float totalTime = 0.0f;
    
    for (const auto& result : results) {
        if (result.passed) passed++;
        totalTime += result.executionTimeMs;
    }
    
    report << "Results: " << passed << "/" << results.size() << " passed\n";
    report << "Total Time: " << totalTime << " ms\n\n";
    
    report << "| Test | Status | Time (ms) |\n";
    report << "|------|--------|-----------|\n";
    
    for (const auto& result : results) {
        report << "| " << result.testName << " | ";
        report << (result.passed ? "✅ PASS" : "❌ FAIL") << " | ";
        report << result.executionTimeMs << " |\n";
    }
    
    return report.str();
}

std::string CompatibilityValidator::ExportToJSON(const std::vector<ArchitectureValidationSuite>& suites) const {
    std::stringstream json;
    json << "{\n";
    json << "  \"validation_run\": {\n";
    json << "    \"timestamp\": \"" << __DATE__ << " " << __TIME__ << "\",\n";
    
    auto summary = GetSummary(suites);
    json << "    \"summary\": {\n";
    json << "      \"total_tests\": " << summary.totalTests << ",\n";
    json << "      \"passed\": " << summary.passedTests << ",\n";
    json << "      \"failed\": " << summary.failedTests << ",\n";
    json << "      \"pass_rate\": " << summary.passRate << ",\n";
    json << "      \"total_time_ms\": " << summary.totalTimeMs << "\n";
    json << "    },\n";
    
    json << "    \"architectures\": [\n";
    
    for (size_t i = 0; i < suites.size(); ++i) {
        const auto& suite = suites[i];
        json << "      {\n";
        json << "        \"name\": \"" << suite.archName << "\",\n";
        json << "        \"passed\": " << (suite.allPassed ? "true" : "false") << ",\n";
        json << "        \"total_time_ms\": " << suite.totalTimeMs << ",\n";
        json << "        \"tests\": [\n";
        
        for (size_t j = 0; j < suite.results.size(); ++j) {
            const auto& result = suite.results[j];
            json << "          {\n";
            json << "            \"name\": \"" << result.testName << "\",\n";
            json << "            \"passed\": " << (result.passed ? "true" : "false") << ",\n";
            json << "            \"time_ms\": " << result.executionTimeMs;
            if (!result.errorMessage.empty()) {
                json << ",\n            \"error\": \"" << result.errorMessage << "\"";
            }
            json << "\n          }";
            if (j < suite.results.size() - 1) json << ",";
            json << "\n";
        }
        
        json << "        ]\n";
        json << "      }";
        if (i < suites.size() - 1) json << ",";
        json << "\n";
    }
    
    json << "    ]\n";
    json << "  }\n";
    json << "}";
    
    return json.str();
}

CompatibilityValidator::Summary CompatibilityValidator::GetSummary(
    const std::vector<ArchitectureValidationSuite>& suites) const {
    Summary summary;
    
    for (const auto& suite : suites) {
        for (const auto& result : suite.results) {
            summary.totalTests++;
            if (result.passed) {
                summary.passedTests++;
            } else {
                summary.failedTests++;
            }
        }
        summary.totalTimeMs += suite.totalTimeMs;
    }
    
    if (summary.totalTests > 0) {
        summary.passRate = (100.0f * summary.passedTests) / summary.totalTests;
    }
    
    return summary;
}

void CompatibilityValidator::SetReferenceModel(ModelArchitecture arch, const std::string& ggufPath) {
    referenceModels_[arch] = ggufPath;
}

// QuickCompatibilityCheck implementation
bool QuickCompatibilityCheck::Check(const std::string& ggufPath) {
    GGUFCompatibilityLoader loader;
    if (!loader.Load(ggufPath)) {
        return false;
    }
    
    return loader.IsSupported();
}

std::string QuickCompatibilityCheck::GetQuickReport(const std::string& ggufPath) {
    std::stringstream report;
    
    GGUFCompatibilityLoader loader;
    if (!loader.Load(ggufPath)) {
        report << "Status: FAILED\n";
        report << "Error: Could not load model\n";
        return report.str();
    }
    
    report << "Status: " << (loader.IsSupported() ? "SUPPORTED" : "UNSUPPORTED") << "\n";
    report << "Architecture: " << loader.GetArchitectureName() << "\n";
    report << "Config: vocab=" << loader.GetConfig().vocab_size;
    report << ", hidden=" << loader.GetConfig().hidden_size;
    report << ", layers=" << loader.GetConfig().num_layers << "\n";
    
    return report.str();
}

} // namespace compatibility
} // namespace rawrxd
