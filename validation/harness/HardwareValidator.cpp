// ============================================================================
// RawrXD Hardware Validation Module
// Detects and validates Radeon AI PRO R9700 and RX 7800 XT presence
// ============================================================================

#include <winsock2.h>
#include <windows.h>
#include <wbemidl.h>
#include <oleauto.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <json/json.hpp>



using json = nlohmann::json;

// ============================================================================
// GPU Information Structure
// ============================================================================
struct GPUInfo {
    std::string name;
    std::string deviceId;
    std::string driverVersion;
    uint64_t adapterRam;
    uint32_t videoModeWidth;
    uint32_t videoModeHeight;
    uint32_t refreshRate;
    std::string status;
    bool isR9700;
    bool isRX7800XT;
    bool isPrimary;
};

// ============================================================================
// Hardware Validator Class
// ============================================================================
class HardwareValidator {
public:
    struct ValidationResult {
        bool r9700Detected;
        bool rx7800XTDetected;
        bool multiGPUReady;
        std::vector<GPUInfo> detectedGPUs;
        std::string errorMessage;
    };

    bool Initialize() {
        HRESULT hres;

        // Initialize COM
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) {
            error_ = "Failed to initialize COM library";
            return false;
        }

        // Set COM security levels
        hres = CoInitializeSecurity(
            NULL,
            -1,
            NULL,
            NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE,
            NULL
        );

        // Create WMI locator
        hres = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            (LPVOID *)&pLoc_
        );

        if (FAILED(hres)) {
            error_ = "Failed to create WMI locator";
            CoUninitialize();
            return false;
        }

        // Connect to WMI
        BSTR bstrNamespace = SysAllocString(L"ROOT\\CIMV2");
        hres = pLoc_->ConnectServer(
            bstrNamespace,
            NULL,
            NULL,
            0,
            0,
            NULL,
            0,
            &pSvc_
        );
        SysFreeString(bstrNamespace);

        if (FAILED(hres)) {
            error_ = "Failed to connect to WMI";
            pLoc_->Release();
            CoUninitialize();
            return false;
        }

        // Set security levels on the proxy
        hres = CoSetProxyBlanket(
            pSvc_,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            NULL,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE
        );

        if (FAILED(hres)) {
            error_ = "Failed to set proxy blanket";
            pSvc_->Release();
            pLoc_->Release();
            CoUninitialize();
            return false;
        }

        initialized_ = true;
        return true;
    }

    void Shutdown() {
        if (pSvc_) pSvc_->Release();
        if (pLoc_) pLoc_->Release();
        CoUninitialize();
        initialized_ = false;
    }

    ValidationResult ValidateHardware() {
        ValidationResult result = {};
        result.r9700Detected = false;
        result.rx7800XTDetected = false;
        result.multiGPUReady = false;

        if (!initialized_) {
            result.errorMessage = "HardwareValidator not initialized";
            return result;
        }

        // Query video controllers
        IEnumWbemClassObject* pEnumerator = NULL;
        BSTR bstrQueryLanguage = SysAllocString(L"WQL");
        BSTR bstrQuery = SysAllocString(L"SELECT * FROM Win32_VideoController");
        HRESULT hres = pSvc_->ExecQuery(
            bstrQueryLanguage,
            bstrQuery,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );
        SysFreeString(bstrQueryLanguage);
        SysFreeString(bstrQuery);

        if (FAILED(hres)) {
            result.errorMessage = "Failed to query video controllers";
            return result;
        }

        // Enumerate results
        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;

        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) {
                break;
            }

            GPUInfo gpu = {};
            gpu = ExtractGPUInfo(pclsObj);
            
            // Check for target GPUs
            if (gpu.isR9700) {
                result.r9700Detected = true;
            }
            if (gpu.isRX7800XT) {
                result.rx7800XTDetected = true;
            }

            result.detectedGPUs.push_back(gpu);
            pclsObj->Release();
        }

        pEnumerator->Release();

        // Determine if multi-GPU ready
        result.multiGPUReady = result.r9700Detected && result.rx7800XTDetected;

        return result;
    }

    json ExportToJSON(const ValidationResult& result) {
        json j;
        j["timestamp"] = GetTimestamp();
        j["r9700_detected"] = result.r9700Detected;
        j["rx7800xt_detected"] = result.rx7800XTDetected;
        j["multi_gpu_ready"] = result.multiGPUReady;
        j["gpu_count"] = result.detectedGPUs.size();
        
        if (!result.errorMessage.empty()) {
            j["error"] = result.errorMessage;
        }

        json gpuArray = json::array();
        for (const auto& gpu : result.detectedGPUs) {
            json g;
            g["name"] = gpu.name;
            g["device_id"] = gpu.deviceId;
            g["driver_version"] = gpu.driverVersion;
            g["adapter_ram_gb"] = (gpu.adapterRam + (1024ULL * 1024ULL * 1024ULL) / 2) / (1024ULL * 1024ULL * 1024ULL);
            g["video_mode"] = std::to_string(gpu.videoModeWidth) + "x" + 
                             std::to_string(gpu.videoModeHeight) + "@" +
                             std::to_string(gpu.refreshRate) + "Hz";
            g["status"] = gpu.status;
            g["is_r9700"] = gpu.isR9700;
            g["is_rx7800xt"] = gpu.isRX7800XT;
            g["is_primary"] = gpu.isPrimary;
            gpuArray.push_back(g);
        }
        j["gpus"] = gpuArray;

        return j;
    }

    std::string GetLastError() const {
        return error_;
    }

private:
    IWbemLocator* pLoc_ = NULL;
    IWbemServices* pSvc_ = NULL;
    bool initialized_ = false;
    std::string error_;

    GPUInfo ExtractGPUInfo(IWbemClassObject* pclsObj) {
        GPUInfo gpu = {};

        // Get Name
        VARIANT vtProp;
        HRESULT hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
            BSTR bstrName = vtProp.bstrVal;
            int len = WideCharToMultiByte(CP_UTF8, 0, bstrName, -1, NULL, 0, NULL, NULL);
            if (len > 0) {
                gpu.name.resize(len - 1);
                WideCharToMultiByte(CP_UTF8, 0, bstrName, -1, &gpu.name[0], len, NULL, NULL);
            }
            
            // Check for target GPUs
            std::string nameLower = gpu.name;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
            
            gpu.isR9700 = (nameLower.find("r9700") != std::string::npos) ||
                         (nameLower.find("ai pro") != std::string::npos);
            gpu.isRX7800XT = (nameLower.find("7800") != std::string::npos) &&
                             (nameLower.find("xt") != std::string::npos);
        }
        VariantClear(&vtProp);

        // Get DeviceID
        hr = pclsObj->Get(L"DeviceID", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
            BSTR bstrVal = vtProp.bstrVal;
            int len = WideCharToMultiByte(CP_UTF8, 0, bstrVal, -1, NULL, 0, NULL, NULL);
            if (len > 0) {
                gpu.deviceId.resize(len - 1);
                WideCharToMultiByte(CP_UTF8, 0, bstrVal, -1, &gpu.deviceId[0], len, NULL, NULL);
            }
        }
        VariantClear(&vtProp);

        // Get DriverVersion
        hr = pclsObj->Get(L"DriverVersion", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
            BSTR bstrVal = vtProp.bstrVal;
            int len = WideCharToMultiByte(CP_UTF8, 0, bstrVal, -1, NULL, 0, NULL, NULL);
            if (len > 0) {
                gpu.driverVersion.resize(len - 1);
                WideCharToMultiByte(CP_UTF8, 0, bstrVal, -1, &gpu.driverVersion[0], len, NULL, NULL);
            }
        }
        VariantClear(&vtProp);

        // Get AdapterRAM
        // NOTE: WMI often returns AdapterRAM as VT_I4 (signed LONG) even for
        // values >2GB. The bits are unsigned but the type is signed, so we
        // must cast through uint32_t to avoid sign-extension to uint64_t.
        hr = pclsObj->Get(L"AdapterRAM", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            if (vtProp.vt == VT_UI8) {
                gpu.adapterRam = vtProp.ullVal;
            } else if (vtProp.vt == VT_I4) {
                gpu.adapterRam = static_cast<uint64_t>(static_cast<uint32_t>(vtProp.lVal));
            } else if (vtProp.vt == VT_UI4) {
                gpu.adapterRam = static_cast<uint64_t>(vtProp.ulVal);
            }
        }
        VariantClear(&vtProp);

        // Get CurrentHorizontalResolution
        hr = pclsObj->Get(L"CurrentHorizontalResolution", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_I4) {
            gpu.videoModeWidth = vtProp.lVal;
        }
        VariantClear(&vtProp);

        // Get CurrentVerticalResolution
        hr = pclsObj->Get(L"CurrentVerticalResolution", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_I4) {
            gpu.videoModeHeight = vtProp.lVal;
        }
        VariantClear(&vtProp);

        // Get CurrentRefreshRate
        hr = pclsObj->Get(L"CurrentRefreshRate", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_I4) {
            gpu.refreshRate = vtProp.lVal;
        }
        VariantClear(&vtProp);

        // Get Status
        hr = pclsObj->Get(L"Status", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
            BSTR bstrVal = vtProp.bstrVal;
            int len = WideCharToMultiByte(CP_UTF8, 0, bstrVal, -1, NULL, 0, NULL, NULL);
            if (len > 0) {
                gpu.status.resize(len - 1);
                WideCharToMultiByte(CP_UTF8, 0, bstrVal, -1, &gpu.status[0], len, NULL, NULL);
            }
        }
        VariantClear(&vtProp);

        return gpu;
    }

    std::string GetTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

// ============================================================================
// Standalone Hardware Validation Main
// ============================================================================
int main(int argc, char* argv[]) {
    std::cout << "RawrXD Hardware Validator" << std::endl;
    std::cout << "=========================" << std::endl;
    std::cout << std::endl;

    HardwareValidator validator;
    
    std::cout << "Initializing WMI..." << std::endl;
    if (!validator.Initialize()) {
        std::cerr << "Failed to initialize: " << validator.GetLastError() << std::endl;
        return 1;
    }
    std::cout << "  WMI initialized successfully" << std::endl;
    std::cout << std::endl;

    std::cout << "Detecting GPUs..." << std::endl;
    auto result = validator.ValidateHardware();
    std::cout << std::endl;

    // Display results
    std::cout << "Detection Results:" << std::endl;
    std::cout << "  Total GPUs found: " << result.detectedGPUs.size() << std::endl;
    std::cout << "  Radeon AI PRO R9700: " << (result.r9700Detected ? "DETECTED" : "NOT FOUND") << std::endl;
    std::cout << "  RX 7800 XT: " << (result.rx7800XTDetected ? "DETECTED" : "NOT FOUND") << std::endl;
    std::cout << "  Multi-GPU Ready: " << (result.multiGPUReady ? "YES" : "NO") << std::endl;
    std::cout << std::endl;

    // Display detailed GPU info
    if (!result.detectedGPUs.empty()) {
        std::cout << "GPU Details:" << std::endl;
        for (size_t i = 0; i < result.detectedGPUs.size(); i++) {
            const auto& gpu = result.detectedGPUs[i];
            std::cout << "  [" << i << "] " << gpu.name << std::endl;
            std::cout << "      Device ID: " << gpu.deviceId << std::endl;
            std::cout << "      Driver: " << gpu.driverVersion << std::endl;
            uint64_t vramBytes = gpu.adapterRam;
            uint64_t vramDivisor = 1024ULL * 1024ULL * 1024ULL;
            uint64_t vramGB = (vramBytes + vramDivisor / 2) / vramDivisor;
            std::cout << "      VRAM: " << vramGB << " GB" << std::endl;
            std::cout << "      Status: " << gpu.status << std::endl;
            if (gpu.isR9700) std::cout << "      *** R9700 TARGET GPU ***" << std::endl;
            if (gpu.isRX7800XT) std::cout << "      *** RX 7800 XT TARGET GPU ***" << std::endl;
            std::cout << std::endl;
        }
    }

    // Export to JSON if requested
    if (argc > 1) {
        std::string outputPath = argv[1];
        json output = validator.ExportToJSON(result);
        
        std::ofstream file(outputPath);
        if (file.is_open()) {
            file << output.dump(2);
            file.close();
            std::cout << "Results exported to: " << outputPath << std::endl;
        } else {
            std::cerr << "Failed to open output file: " << outputPath << std::endl;
        }
    }

    validator.Shutdown();

    // Return code indicates success
    return result.multiGPUReady ? 0 : 1;
}
