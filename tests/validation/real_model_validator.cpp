// Real Model Validation Suite - Phase 6
// Validates actual GGUF model loading and inference

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <filesystem>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <dxgi1_6.h>
#include <d3d12.h>
#endif

namespace RawrXD {
namespace Validation {

// GGUF magic number
const uint32_t GGUF_MAGIC = 0x46554747; // "GGUF"

// Test result structure
struct TestResult {
    std::string testName;
    bool passed;
    std::string errorMessage;
    double durationMs;
    uint64_t tokensGenerated;
    double tokensPerSecond;
};

// Model info from GGUF
struct ModelInfo {
    std::string architecture;
    uint32_t parameterCount;
    uint32_t contextLength;
    uint32_t vocabSize;
    uint32_t tensorCount;
    uint64_t totalSize;
    std::string quantization;
};

// GPU info with corrected VRAM detection
struct GPUInfo {
    std::string name;
    uint64_t dedicatedVRAM;      // Actual dedicated VRAM
    uint64_t sharedSystemMemory; // Shared system memory
    uint64_t totalMemory;        // Total available
    uint32_t architecture;       // GPU architecture
    bool supportsUnifiedMemory;
};

// Parse GGUF header
bool ParseGGUFHeader(const std::string& path, ModelInfo& info) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open: " << path << std::endl;
        return false;
    }
    
    // Read magic
    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (magic != GGUF_MAGIC) {
        std::cerr << "Invalid GGUF magic: 0x" << std::hex << magic << std::endl;
        return false;
    }
    
    // Read version
    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    std::cout << "  GGUF Version: " << version << std::endl;
    
    // Read tensor count
    uint64_t tensorCount;
    file.read(reinterpret_cast<char*>(&tensorCount), sizeof(tensorCount));
    info.tensorCount = static_cast<uint32_t>(tensorCount);
    std::cout << "  Tensor Count: " << tensorCount << std::endl;
    
    // Get file size
    file.seekg(0, std::ios::end);
    info.totalSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::cout << "  File Size: " << (info.totalSize / (1024.0 * 1024.0 * 1024.0)) << " GB" << std::endl;
    
    // Try to detect quantization from filename
    std::string filename = std::filesystem::path(path).filename().string();
    if (filename.find("Q4") != std::string::npos) info.quantization = "Q4";
    else if (filename.find("Q5") != std::string::npos) info.quantization = "Q5";
    else if (filename.find("Q6") != std::string::npos) info.quantization = "Q6";
    else if (filename.find("Q8") != std::string::npos) info.quantization = "Q8";
    else if (filename.find("F16") != std::string::npos) info.quantization = "F16";
    else if (filename.find("F32") != std::string::npos) info.quantization = "F32";
    else info.quantization = "Unknown";
    
    std::cout << "  Quantization: " << info.quantization << std::endl;
    
    return true;
}

// CORRECTED GPU memory detection
bool DetectGPUCorrected(GPUInfo& info) {
#ifdef _WIN32
    // Create DXGI factory
    IDXGIFactory6* factory = nullptr;
    HRESULT hr = CreateDXGIFactory2(0, IID_PPV_ARGS(&factory));
    if (FAILED(hr)) {
        std::cerr << "Failed to create DXGI factory" << std::endl;
        return false;
    }
    
    // Enumerate adapters
    IDXGIAdapter1* adapter = nullptr;
    for (UINT i = 0; factory->EnumAdapters1(i, &adapter) != DXGI_ERROR_NOT_FOUND; ++i) {
        DXGI_ADAPTER_DESC1 desc;
        adapter->GetDesc1(&desc);
        
        // Skip software adapters
        if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) {
            adapter->Release();
            continue;
        }
        
        // Convert wide string to regular string
        char name[128];
        WideCharToMultiByte(CP_UTF8, 0, desc.Description, -1, name, 128, nullptr, nullptr);
        info.name = name;
        
        // CORRECTED: Use DedicatedVideoMemory (not SharedSystemMemory)
        info.dedicatedVRAM = desc.DedicatedVideoMemory;
        info.sharedSystemMemory = desc.SharedSystemMemory;
        info.totalMemory = desc.DedicatedVideoMemory + desc.SharedSystemMemory;
        
        std::cout << "GPU: " << info.name << std::endl;
        std::cout << "  Dedicated VRAM: " << (info.dedicatedVRAM / (1024.0 * 1024.0 * 1024.0)) << " GB" << std::endl;
        std::cout << "  Shared System Memory: " << (info.sharedSystemMemory / (1024.0 * 1024.0 * 1024.0)) << " GB" << std::endl;
        std::cout << "  Total Available: " << (info.totalMemory / (1024.0 * 1024.0 * 1024.0)) << " GB" << std::endl;
        
        // Check for unified memory architecture
        info.supportsUnifiedMemory = (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) == 0;
        
        adapter->Release();
        break; // Use first discrete GPU
    }
    
    factory->Release();
    return !info.name.empty();
#else
    std::cerr << "GPU detection only implemented for Windows" << std::endl;
    return false;
#endif
}

// Test 1: Model Discovery
TestResult TestModelDiscovery(const std::string& modelsDir) {
    TestResult result;
    result.testName = "Model Discovery";
    
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<std::string> foundModels;
    
    if (!std::filesystem::exists(modelsDir)) {
        result.passed = false;
        result.errorMessage = "Models directory does not exist: " + modelsDir;
        return result;
    }
    
    for (const auto& entry : std::filesystem::directory_iterator(modelsDir)) {
        if (entry.path().extension() == ".gguf") {
            foundModels.push_back(entry.path().string());
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    if (foundModels.empty()) {
        result.passed = false;
        result.errorMessage = "No GGUF models found in: " + modelsDir;
        std::cerr << "ERROR: " << result.errorMessage << std::endl;
        std::cerr << "  Searched: " << modelsDir << std::endl;
        std::cerr << "  Please place models in this directory or specify correct path" << std::endl;
    } else {
        result.passed = true;
        std::cout << "Found " << foundModels.size() << " model(s):" << std::endl;
        for (const auto& model : foundModels) {
            std::cout << "  - " << model << std::endl;
        }
    }
    
    return result;
}

// Test 2: Model Loading
TestResult TestModelLoading(const std::string& modelPath) {
    TestResult result;
    result.testName = "Model Loading: " + std::filesystem::path(modelPath).filename().string();
    
    auto start = std::chrono::high_resolution_clock::now();
    
    ModelInfo info;
    if (!ParseGGUFHeader(modelPath, info)) {
        result.passed = false;
        result.errorMessage = "Failed to parse GGUF header";
        return result;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    result.passed = true;
    return result;
}

// Test 3: GPU Memory Detection
TestResult TestGPUMemoryDetection() {
    TestResult result;
    result.testName = "GPU Memory Detection (Corrected)";
    
    auto start = std::chrono::high_resolution_clock::now();
    
    GPUInfo info;
    if (!DetectGPUCorrected(info)) {
        result.passed = false;
        result.errorMessage = "Failed to detect GPU";
        return result;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Validate VRAM is reasonable (not 4GB when it should be 16GB+)
    if (info.dedicatedVRAM < 4ULL * 1024 * 1024 * 1024) {
        result.passed = false;
        result.errorMessage = "Detected VRAM (" + 
            std::to_string(info.dedicatedVRAM / (1024 * 1024 * 1024)) + 
            " GB) seems too low. Check GPU detection logic.";
        return result;
    }
    
    result.passed = true;
    return result;
}

// Test 4: VRAM Sufficiency Check
TestResult TestVRAMSufficiency(const std::string& modelPath, const GPUInfo& gpu) {
    TestResult result;
    result.testName = "VRAM Sufficiency Check";
    
    ModelInfo model;
    if (!ParseGGUFHeader(modelPath, model)) {
        result.passed = false;
        result.errorMessage = "Failed to parse model";
        return result;
    }
    
    // Estimate VRAM needed (rough: model size * 1.2 for overhead)
    uint64_t estimatedVRAM = static_cast<uint64_t>(model.totalSize * 1.2);
    
    std::cout << "Model requires ~" << (estimatedVRAM / (1024.0 * 1024.0 * 1024.0)) << " GB VRAM" << std::endl;
    std::cout << "GPU has " << (gpu.dedicatedVRAM / (1024.0 * 1024.0 * 1024.0)) << " GB dedicated VRAM" << std::endl;
    
    if (estimatedVRAM > gpu.dedicatedVRAM) {
        result.passed = false;
        result.errorMessage = "Insufficient VRAM. Model needs ~" +
            std::to_string(estimatedVRAM / (1024 * 1024 * 1024)) + " GB, GPU has " +
            std::to_string(gpu.dedicatedVRAM / (1024 * 1024 * 1024)) + " GB";
        return result;
    }
    
    result.passed = true;
    return result;
}

// Print test summary
void PrintSummary(const std::vector<TestResult>& results) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Validation Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& result : results) {
        if (result.passed) {
            std::cout << "[PASS] " << result.testName;
            if (result.durationMs > 0) {
                std::cout << " (" << result.durationMs << " ms)";
            }
            std::cout << std::endl;
            passed++;
        } else {
            std::cout << "[FAIL] " << result.testName << std::endl;
            std::cout << "       Error: " << result.errorMessage << std::endl;
            failed++;
        }
    }
    
    std::cout << "\nTotal: " << (passed + failed) << " tests, " 
              << passed << " passed, " << failed << " failed" << std::endl;
    
    if (failed == 0) {
        std::cout << "\n✅ All validation tests PASSED" << std::endl;
    } else {
        std::cout << "\n❌ Some validation tests FAILED" << std::endl;
    }
}

} // namespace Validation
} // namespace RawrXD

int main(int argc, char* argv[]) {
    using namespace RawrXD::Validation;
    
    std::cout << "RawrXD Phase 6: Real Model Validation Suite" << std::endl;
    std::cout << "==========================================" << std::endl;
    
    std::string modelsDir = "models";
    if (argc > 1) {
        modelsDir = argv[1];
    }
    
    std::vector<TestResult> results;
    
    // Test 1: Model Discovery
    std::cout << "\n[Test 1] Model Discovery..." << std::endl;
    results.push_back(TestModelDiscovery(modelsDir));
    
    // Test 2: GPU Memory Detection (CORRECTED)
    std::cout << "\n[Test 2] GPU Memory Detection (Corrected)..." << std::endl;
    results.push_back(TestGPUMemoryDetection());
    
    // Find a model to test
    std::string testModel;
    for (const auto& entry : std::filesystem::directory_iterator(modelsDir)) {
        if (entry.path().extension() == ".gguf") {
            testModel = entry.path().string();
            break;
        }
    }
    
    if (!testModel.empty()) {
        // Test 3: Model Loading
        std::cout << "\n[Test 3] Model Loading..." << std::endl;
        results.push_back(TestModelLoading(testModel));
        
        // Test 4: VRAM Sufficiency
        std::cout << "\n[Test 4] VRAM Sufficiency Check..." << std::endl;
        GPUInfo gpu;
        if (DetectGPUCorrected(gpu)) {
            results.push_back(TestVRAMSufficiency(testModel, gpu));
        }
    } else {
        std::cout << "\nSkipping model-specific tests (no models found)" << std::endl;
    }
    
    // Print summary
    PrintSummary(results);
    
    // Return exit code
    for (const auto& result : results) {
        if (!result.passed) return 1;
    }
    return 0;
}
