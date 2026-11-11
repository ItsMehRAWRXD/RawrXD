/*===========================================================================
 * hardening_gates.hpp
 *
 * VAL-030.1 Runtime Hardening Gates
 *
 * Extended validation beyond basic self-test:
 *   - Dependency sovereignty (no hidden runtime assumptions)
 *   - Portable execution (USB drive, any path)
 *   - POST-style integrity checks
 *   - Kernel dispatch validation
 *   - Memory fabric readiness
 *
 * Usage:
 *   RawrXD_Runtime.exe --hardening-test
 *===========================================================================*/

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>

namespace RawrXD {
namespace Runtime {

// Hardening test severity
enum class TestSeverity {
    INFO,       // Informational only
    WARNING,    // Non-fatal issue
    CRITICAL    // Must pass for operation
};

// Individual hardening test result
struct HardeningResult {
    std::string category;
    std::string testName;
    bool passed;
    TestSeverity severity;
    std::string message;
    double durationMs;
    
    HardeningResult(const std::string& cat, const std::string& name, 
                    bool pass, TestSeverity sev, const std::string& msg, double dur = 0.0)
        : category(cat), testName(name), passed(pass), severity(sev), message(msg), durationMs(dur) {}
};

// Complete hardening report
struct HardeningReport {
    std::string timestamp;
    std::string executablePath;
    std::string runtimeRoot;
    
    std::vector<HardeningResult> results;
    
    uint32_t totalTests = 0;
    uint32_t passedTests = 0;
    uint32_t warningTests = 0;
    uint32_t failedCritical = 0;
    
    bool dependencySovereignty = false;
    bool portableExecution = false;
    bool selfTestIntegrity = false;
    bool kernelDispatch = false;
    bool memoryFabricReady = false;
    
    void GenerateSummary();
    void PrintDetailed();
    bool IsRuntimeReady() const { return failedCritical == 0; }
};

// Hardening gate categories
class HardeningGates {
public:
    HardeningGates();
    ~HardeningGates();
    
    // Run all hardening tests
    HardeningReport RunAllTests();
    
    // Individual gate categories
    std::vector<HardeningResult> TestDependencySovereignty();
    std::vector<HardeningResult> TestPortableExecution();
    std::vector<HardeningResult> TestSelfTestIntegrity();
    std::vector<HardeningResult> TestKernelDispatch();
    std::vector<HardeningResult> TestMemoryFabricReadiness();
    
    // Specific tests
    HardeningResult TestNoPythonDependency();
    HardeningResult TestNoOllamaDependency();
    HardeningResult TestNoCUDARuntime();
    HardeningResult TestNoDotNET();
    HardeningResult TestNoRegistryDependencies();
    HardeningResult TestNoEnvVarDependencies();
    
    HardeningResult TestPathRelocation();
    HardeningResult TestModelDiscovery();
    HardeningResult TestKernelLoading();
    HardeningResult TestConfigRelocation();
    
    HardeningResult TestCPUFeatureScan();
    HardeningResult TestMemoryAllocator();
    HardeningResult TestGGUFIntegrity();
    HardeningResult TestTensorChecksum();
    HardeningResult TestIOCPAvailability();
    
    HardeningResult TestMatmulKernel();
    HardeningResult TestRMSNormKernel();
    HardeningResult TestRoPEKernel();
    HardeningResult TestFlashAttentionKernel();
    
    HardeningResult TestResidencyManager();
    HardeningResult TestAddressTranslation();
    HardeningResult TestCacheHierarchy();
    
private:
    // Helper functions
    bool CheckProcessModules(const std::vector<std::string>& forbiddenModules);
    bool CheckRegistryKeys(const std::vector<std::string>& forbiddenKeys);
    bool CheckEnvironmentVars(const std::vector<std::string>& forbiddenVars);
    bool TestRelocation(const std::string& newPath);
    bool ValidateKernelBinary(const std::string& kernelName);
    uint64_t ComputeTensorChecksum(const float* data, size_t count);
};

// C API exports
extern "C" {
    __declspec(dllexport) int RawrXD_RunHardeningTests();
    __declspec(dllexport) int RawrXD_RunPortableTest(const char* testPath);
    __declspec(dllexport) int RawrXD_ValidateDependencySovereignty();
}

} // namespace Runtime
} // namespace RawrXD
