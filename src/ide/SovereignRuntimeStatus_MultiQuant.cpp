/*===========================================================================
 * SovereignRuntimeStatus_MultiQuant.cpp
 *
 * Implementation of multi-format runtime status monitoring
 *===========================================================================*/

#include "SovereignRuntimeStatus_MultiQuant.hpp"
#include "../kernel/SovereignKernelRegistry.hpp"
#include "../kernel/SovereignKernelRuntimeLog.hpp"
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

namespace RawrXD {
namespace IDE {

/*===========================================================================
 * MultiQuantRuntimeMonitor Implementation
 *===========================================================================*/

void MultiQuantRuntimeMonitor::Initialize(const std::wstring& modelPath,
                                           Deep2::QuantType quantType,
                                           uint64_t modelParams) {
    status_.initialized = true;
    status_.modelPath = modelPath;
    status_.modelParams = modelParams;
    status_.quantType = quantType;
    status_.quantName = Deep2::QuantTypeToString(quantType);

    // Extract model name from path
    size_t pos = modelPath.find_last_of(L"/\\");
    if (pos != std::wstring::npos) {
        status_.modelName = modelPath.substr(pos + 1);
    } else {
        status_.modelName = modelPath;
    }

    // Set quantization bits based on type
    switch (quantType) {
        case Deep2::QuantType::Q4_K_M: status_.quantBits = 4; break;
        case Deep2::QuantType::Q5_K_M: status_.quantBits = 5; break;
        case Deep2::QuantType::Q6_K:   status_.quantBits = 6; break;
        case Deep2::QuantType::Q8_0:   status_.quantBits = 8; break;
        case Deep2::QuantType::FP16:   status_.quantBits = 16; break;
        case Deep2::QuantType::FP32:   status_.quantBits = 32; break;
        default: status_.quantBits = 0; break;
    }

    // Detect CPU features
    auto& detector = Kernel::CPUFeatureDetector::Instance();
    status_.hasAVX2 = detector.HasAVX2();
    status_.hasAVX512 = detector.HasAVX512();

    // Determine kernel name
    auto* kernel = Deep2::QuantizationRouter::Instance().Resolve(quantType);
    if (kernel) {
        status_.kernelName = Deep2::QuantTypeToString(quantType);
        status_.kernelVersion = kernel->version;

        // Append CPU variant
        if (status_.hasAVX512) {
            status_.kernelName = "Sovereign_Q?K_AVX512";  // Placeholder
        } else if (status_.hasAVX2) {
            status_.kernelName = "Sovereign_Q?K_AVX2";    // Placeholder
        }
    }

    // Get device info
#ifdef _WIN32
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    status_.numCores = sysInfo.dwNumberOfProcessors;

    // Try to get CPU brand string
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0x80000002);
    char brand[48] = {0};
    memcpy(brand, cpuInfo, sizeof(cpuInfo));
    __cpuid(cpuInfo, 0x80000003);
    memcpy(brand + 16, cpuInfo, sizeof(cpuInfo));
    __cpuid(cpuInfo, 0x80000004);
    memcpy(brand + 32, cpuInfo, sizeof(cpuInfo));

    // Convert to wstring
    int len = MultiByteToWideChar(CP_ACP, 0, brand, -1, nullptr, 0);
    if (len > 0) {
        status_.deviceName.resize(len);
        MultiByteToWideChar(CP_ACP, 0, brand, -1, &status_.deviceName[0], len);
        // Trim whitespace
        size_t start = status_.deviceName.find_first_not_of(L" \t");
        size_t end = status_.deviceName.find_last_not_of(L" \t");
        if (start != std::wstring::npos) {
            status_.deviceName = status_.deviceName.substr(start, end - start + 1);
        }
    }
#endif

    status_.ready = true;
    status_.statusMessage = L"Model loaded successfully";
}

void MultiQuantRuntimeMonitor::UpdateMetrics(uint64_t tokens, double timeMs) {
    status_.tokensGenerated += tokens;
    status_.totalTokens += tokens;

    // Update TPS with exponential moving average
    double instantTPS = (timeMs > 0) ? (tokens * 1000.0 / timeMs) : 0.0;
    const double alpha = 0.3;  // Smoothing factor
    if (status_.currentTPS == 0.0) {
        status_.currentTPS = instantTPS;
    } else {
        status_.currentTPS = alpha * instantTPS + (1.0 - alpha) * status_.currentTPS;
    }

    // Update average latency
    status_.avgLatencyMs = (status_.currentTPS > 0) ? (1000.0 / status_.currentTPS) : 0.0;
}

Deep2::QuantType MultiQuantRuntimeMonitor::GetRecommendedFormat() const {
    // Recommend format based on model size and available VRAM
    // This is a simplified version - production would check actual VRAM
    uint64_t params = status_.modelParams;

    if (params < 8e9) {
        return Deep2::QuantType::Q4_K_M;  // 7B models: Q4 is fine
    } else if (params < 35e9) {
        return Deep2::QuantType::Q5_K_M;  // 13B-30B: Q5 for quality
    } else if (params < 70e9) {
        return Deep2::QuantType::Q6_K;    // 70B: Q6 for best quality
    } else {
        return Deep2::QuantType::Q8_0;    // 70B+: Q8 if memory allows
    }
}

/*===========================================================================
 * IDE Integration
 *===========================================================================*/

void IDE_InitMultiQuantRuntime() {
    // Initialize the quantization router
    auto features = Kernel::CPUFeatureDetector::Instance().GetFeatures();
    Deep2::QuantizationRouter::Instance().Initialize(
        static_cast<Deep2::CPUFeature>(features)
    );

    // Initialize logging
    Kernel::KernelRuntimeLog::Instance().Initialize(
        Kernel::KernelRuntimeLog::Level::Info
    );

    // Print startup banner
    Kernel::KernelRuntimeLog::Instance().PrintStartupBanner();
}

void IDE_SetMultiQuantModel(const std::wstring& path,
                            Deep2::QuantType quantType,
                            uint64_t params) {
    MultiQuantRuntimeMonitor::Instance().Initialize(path, quantType, params);
}

void IDE_UpdateMultiQuantMetrics(uint64_t tokens, double timeMs) {
    MultiQuantRuntimeMonitor::Instance().UpdateMetrics(tokens, timeMs);
}

std::wstring IDE_GetMultiQuantStatusString() {
    return MultiQuantRuntimeMonitor::Instance().GetStatus().ToStatusBarString();
}

std::wstring IDE_GetMultiQuantTooltipString() {
    return MultiQuantRuntimeMonitor::Instance().GetStatus().ToTooltipString();
}

} // namespace IDE
} // namespace RawrXD

/*===========================================================================
 * C API for IDE Integration
 *===========================================================================*/

extern "C" {

// Initialize multi-format runtime
__declspec(dllexport)
void RawrXD_IDE_InitMultiQuantRuntime(void) {
    RawrXD::IDE::IDE_InitMultiQuantRuntime();
}

// Set current model
__declspec(dllexport)
void RawrXD_IDE_SetMultiQuantModel(const wchar_t* path, int quantType, uint64_t params) {
    RawrXD::IDE::IDE_SetMultiQuantModel(path,
                                       static_cast<RawrXD::Deep2::QuantType>(quantType),
                                       params);
}

// Get status string
__declspec(dllexport)
const wchar_t* RawrXD_IDE_GetMultiQuantStatusString(void) {
    static thread_local wchar_t buffer[256];
    std::wstring status = RawrXD::IDE::IDE_GetMultiQuantStatusString();
    wcsncpy_s(buffer, 256, status.c_str(), _TRUNCATE);
    return buffer;
}

// Get tooltip string
__declspec(dllexport)
const wchar_t* RawrXD_IDE_GetMultiQuantTooltipString(void) {
    static thread_local wchar_t buffer[1024];
    std::wstring tooltip = RawrXD::IDE::IDE_GetMultiQuantTooltipString();
    wcsncpy_s(buffer, 1024, tooltip.c_str(), _TRUNCATE);
    return buffer;
}

// Check if format is active
__declspec(dllexport)
int RawrXD_IDE_IsQuantFormatActive(int quantType) {
    return RawrXD::IDE::MultiQuantRuntimeMonitor::Instance().IsFormatActive(
        static_cast<RawrXD::Deep2::QuantType>(quantType)
    ) ? 1 : 0;
}

// Get recommended format for model
__declspec(dllexport)
int RawrXD_IDE_GetRecommendedQuantFormat(void) {
    auto type = RawrXD::IDE::MultiQuantRuntimeMonitor::Instance().GetRecommendedFormat();
    return static_cast<int>(type);
}

} // extern "C"
