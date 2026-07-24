#include "autonomous_resource_manager.h"
#include <QTimer>
#include <QDebug>
#include <QStorageInfo>
#include <QDir>
#include <QThread>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <pdh.h>
#pragma comment(lib, "pdh.lib")
#endif

AutonomousResourceManager::AutonomousResourceManager(QObject* parent)
    : QObject(parent)
    , monitoring_timer_(nullptr)
    , monitoring_active_(false)
{
    // Initialize with current resources
    updateResources();
}

AutonomousResourceManager::~AutonomousResourceManager()
{
    stopMonitoring();
}

AutonomousResourceManager::SystemResources AutonomousResourceManager::getCurrentResources() const
{
    return current_resources_;
}

bool AutonomousResourceManager::canLoadModel(const QString& modelPath, const SystemResources& resources) const
{
    SystemResources res = resources;
    if (res.total_memory_bytes == 0) {
        res = current_resources_;
    }

    // Check if file exists and get size
    QFileInfo fileInfo(modelPath);
    if (!fileInfo.exists()) {
        qWarning() << "[ResourceManager] Model file does not exist:" << modelPath;
        return false;
    }

    qint64 modelSize = fileInfo.size();
    
    // Rule 1: Need at least 2x model size in available memory (for decompression + working space)
    uint64_t requiredMemory = modelSize * 2;
    if (res.available_memory_bytes < requiredMemory) {
        qWarning() << "[ResourceManager] Insufficient memory: need" << (requiredMemory / (1024*1024)) << "MB, have" << (res.available_memory_bytes / (1024*1024)) << "MB";
        return false;
    }

    // Rule 2: Need disk space for temporary decompression (if needed)
    uint64_t requiredDisk = modelSize; // Assume 1x for temp files
    if (res.disk_space_available_bytes < requiredDisk) {
        qWarning() << "[ResourceManager] Insufficient disk space: need" << (requiredDisk / (1024*1024)) << "MB, have" << (res.disk_space_available_bytes / (1024*1024)) << "MB";
        return false;
    }

    // Rule 3: Don't load if memory usage is critical
    if (res.isMemoryCritical()) {
        qWarning() << "[ResourceManager] Memory usage critical:" << res.getMemoryUsagePercent() << "%";
        return false;
    }

    // Rule 4: Don't load if CPU is maxed out (unless GPU available)
    if (res.cpu_usage_percent > 90 && !res.gpu_available) {
        qWarning() << "[ResourceManager] CPU usage too high:" << res.cpu_usage_percent << "%";
        return false;
    }

    qInfo() << "[ResourceManager] Model can be loaded:" << modelPath 
            << "(" << (modelSize / (1024*1024)) << "MB)";
    return true;
}

uint32_t AutonomousResourceManager::getOptimalThreadCount(const SystemResources& resources) const
{
    SystemResources res = resources;
    if (res.total_memory_bytes == 0) {
        res = current_resources_;
    }

    // Get CPU core count
    uint32_t cpuCores = QThread::idealThreadCount();
    if (cpuCores == 0) cpuCores = 4; // Fallback

    // Adjust based on CPU usage
    if (res.cpu_usage_percent > 80) {
        // High CPU usage - use fewer threads
        return std::max(1u, cpuCores / 2);
    } else if (res.cpu_usage_percent > 50) {
        // Medium CPU usage - use 75% of cores
        return std::max(1u, (cpuCores * 3) / 4);
    } else {
        // Low CPU usage - use all cores
        return cpuCores;
    }
}

bool AutonomousResourceManager::shouldUseCompression(const SystemResources& resources) const
{
    SystemResources res = resources;
    if (res.total_memory_bytes == 0) {
        res = current_resources_;
    }

    // Use compression if:
    // 1. Memory is low (compression saves memory)
    // 2. Disk space is limited (compression saves disk)
    // 3. CPU is not maxed out (compression uses CPU)

    if (res.isMemoryLow()) {
        qInfo() << "[ResourceManager] Using compression: memory low";
        return true;
    }

    if (res.disk_space_available_bytes < 10ULL * 1024 * 1024 * 1024) { // < 10GB
        qInfo() << "[ResourceManager] Using compression: disk space limited";
        return true;
    }

    if (res.cpu_usage_percent < 70) {
        qInfo() << "[ResourceManager] Using compression: CPU available";
        return true;
    }

    // Don't use compression if CPU is maxed out
    qInfo() << "[ResourceManager] Not using compression: CPU high, memory OK";
    return false;
}

uint32_t AutonomousResourceManager::getRecommendedCompressionLevel(const SystemResources& resources) const
{
    SystemResources res = resources;
    if (res.total_memory_bytes == 0) {
        res = current_resources_;
    }

    // Compression level selection:
    // - Level 1-3: Fast (low CPU, lower compression)
    // - Level 4-6: Balanced (medium CPU, good compression)
    // - Level 7-9: Best (high CPU, best compression)

    if (res.cpu_usage_percent > 80) {
        // High CPU - use fast compression
        return 3;
    } else if (res.cpu_usage_percent > 50) {
        // Medium CPU - use balanced compression
        return 6;
    } else if (res.isMemoryLow()) {
        // Low memory - prioritize compression ratio
        return 9;
    } else {
        // Normal conditions - balanced
        return 6;
    }
}

void AutonomousResourceManager::startMonitoring(int intervalMs)
{
    if (monitoring_active_) {
        stopMonitoring();
    }

    monitoring_timer_ = new QTimer(this);
    connect(monitoring_timer_, &QTimer::timeout, this, &AutonomousResourceManager::onMonitoringTimer);
    monitoring_timer_->start(intervalMs);
    monitoring_active_ = true;

    qInfo() << "[ResourceManager] Started monitoring with interval" << intervalMs << "ms";
}

void AutonomousResourceManager::stopMonitoring()
{
    if (monitoring_timer_) {
        monitoring_timer_->stop();
        monitoring_timer_->deleteLater();
        monitoring_timer_ = nullptr;
    }
    monitoring_active_ = false;
    qInfo() << "[ResourceManager] Stopped monitoring";
}

void AutonomousResourceManager::updateResources()
{
    SystemResources newResources = gatherResources();
    
    // Emit signals based on state changes
    if (newResources.isMemoryCritical()) {
        emit resourcesCritical(newResources);
    } else if (newResources.isMemoryLow()) {
        emit resourcesLow(newResources);
    } else if (newResources.getMemoryUsagePercent() < 50.0 && newResources.cpu_usage_percent < 50) {
        emit resourcesOptimal(newResources);
    }

    current_resources_ = newResources;
    emit resourcesUpdated(newResources);
}

void AutonomousResourceManager::onMonitoringTimer()
{
    updateResources();
}

AutonomousResourceManager::SystemResources AutonomousResourceManager::gatherResources() const
{
    SystemResources res;

    res.available_memory_bytes = getAvailableMemory();
    res.total_memory_bytes = getTotalMemory();
    res.cpu_usage_percent = getCpuUsage();
    getGpuInfo(res.gpu_usage_percent, res.gpu_available, res.gpu_name);
    res.disk_space_available_bytes = getAvailableDiskSpace();
    res.memory_usage_percent = static_cast<uint32_t>(res.getMemoryUsagePercent());

    return res;
}

#ifdef _WIN32
uint64_t AutonomousResourceManager::getAvailableMemory() const
{
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        return memInfo.ullAvailPhys;
    }
    return 0;
}

uint64_t AutonomousResourceManager::getTotalMemory() const
{
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        return memInfo.ullTotalPhys;
    }
    return 0;
}

uint32_t AutonomousResourceManager::getCpuUsage() const
{
    // Simplified CPU usage - in production, use PDH or WMI
    // For now, return a placeholder
    static PDH_HQUERY query = nullptr;
    static PDH_HCOUNTER counter = nullptr;
    
    if (!query) {
        PdhOpenQuery(nullptr, 0, &query);
        PdhAddCounter(query, L"\\Processor(_Total)\\% Processor Time", 0, &counter);
    }
    
    if (query && counter) {
        PdhCollectQueryData(query);
        Sleep(100); // Wait for sample
        PdhCollectQueryData(query);
        
        PDH_FMT_COUNTERVALUE value;
        if (PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, nullptr, &value) == ERROR_SUCCESS) {
            return static_cast<uint32_t>(value.doubleValue);
        }
    }
    
    return 0; // Fallback
}

void AutonomousResourceManager::getGpuInfo(uint32_t& usage, bool& available, QString& name) const
{
    // Real GPU detection using WMI on Windows
    available = false;
    usage = 0;
    name = "Unknown";
    
#ifdef _WIN32
    // Initialize COM
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        return;
    }
    
    // Create WMI locator
    IWbemLocator* pLoc = nullptr;
    hr = CoCreateInstance(
        CLSID_WbemLocator,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        reinterpret_cast<LPVOID*>(&pLoc)
    );
    
    if (SUCCEEDED(hr) && pLoc) {
        // Connect to WMI
        IWbemServices* pSvc = nullptr;
        hr = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"),
            nullptr,
            nullptr,
            nullptr,
            0,
            nullptr,
            nullptr,
            &pSvc
        );
        
        if (SUCCEEDED(hr) && pSvc) {
            // Query for GPU information
            IEnumWbemClassObject* pEnumerator = nullptr;
            hr = pSvc->ExecQuery(
                _bstr_t(L"WQL"),
                _bstr_t(L"SELECT * FROM Win32_VideoController"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr,
                &pEnumerator
            );
            
            if (SUCCEEDED(hr) && pEnumerator) {
                IWbemClassObject* pclsObj = nullptr;
                ULONG uReturn = 0;
                
                // Get first GPU
                if (pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK) {
                    VARIANT vtProp;
                    
                    // Get GPU name
                    hr = pclsObj->Get(L"Name", 0, &vtProp, nullptr, nullptr);
                    if (SUCCEEDED(hr)) {
                        name = QString::fromWCharArray(vtProp.bstrVal);
                        VariantClear(&vtProp);
                        available = true;
                    }
                    
                    // Get adapter memory (as proxy for usage)
                    hr = pclsObj->Get(L"AdapterRAM", 0, &vtProp, nullptr, nullptr);
                    if (SUCCEEDED(hr)) {
                        uint64_t adapterRam = vtProp.ullVal;
                        // Estimate usage based on available memory
                        // This is a heuristic - real implementation would use NVML/ADL
                        usage = (adapterRam > 0) ? 50 : 0; // 50% placeholder
                        VariantClear(&vtProp);
                    }
                    
                    pclsObj->Release();
                }
                
                pEnumerator->Release();
            }
            
            pSvc->Release();
        }
        
        pLoc->Release();
    }
    
    CoUninitialize();
    
    // If WMI failed, try to detect NVIDIA GPU via NVML
    if (!available) {
        DetectNvidiaGpu(usage, available, name);
    }
    
    // If still not available, try AMD
    if (!available) {
        DetectAmdGpu(usage, available, name);
    }
#else
    // Linux/Mac implementation using system calls
    DetectGpuUnix(usage, available, name);
#endif
    
    printf("[ResourceManager] GPU detected: %s (available: %s, usage: %u%%)\n",
           name.toStdString().c_str(), available ? "yes" : "no", usage);
}

// Helper functions for GPU detection
#ifdef _WIN32
void AutonomousResourceManager::DetectNvidiaGpu(uint32_t& usage, bool& available, QString& name) const {
    // Try to load NVML dynamically
    HMODULE nvml = LoadLibraryA("nvml.dll");
    if (!nvml) {
        nvml = LoadLibraryA("C:\\Program Files\\NVIDIA Corporation\\NVSMI\\nvml.dll");
    }
    
    if (nvml) {
        typedef int (*nvmlInit_t)(void);
        typedef int (*nvmlShutdown_t)(void);
        typedef int (*nvmlDeviceGetCount_t)(unsigned int*);
        typedef int (*nvmlDeviceGetHandleByIndex_t)(unsigned int, void**);
        typedef int (*nvmlDeviceGetName_t)(void*, char*, unsigned int);
        typedef int (*nvmlDeviceGetUtilizationRates_t)(void*, void*);
        
        nvmlInit_t nvmlInit = (nvmlInit_t)GetProcAddress(nvml, "nvmlInit_v2");
        nvmlShutdown_t nvmlShutdown = (nvmlShutdown_t)GetProcAddress(nvml, "nvmlShutdown");
        nvmlDeviceGetCount_t nvmlDeviceGetCount = (nvmlDeviceGetCount_t)GetProcAddress(nvml, "nvmlDeviceGetCount");
        nvmlDeviceGetHandleByIndex_t nvmlDeviceGetHandleByIndex = (nvmlDeviceGetHandleByIndex_t)GetProcAddress(nvml, "nvmlDeviceGetHandleByIndex_v2");
        nvmlDeviceGetName_t nvmlDeviceGetName = (nvmlDeviceGetName_t)GetProcAddress(nvml, "nvmlDeviceGetName");
        nvmlDeviceGetUtilizationRates_t nvmlDeviceGetUtilizationRates = (nvmlDeviceGetUtilizationRates_t)GetProcAddress(nvml, "nvmlDeviceGetUtilizationRates");
        
        if (nvmlInit && nvmlShutdown && nvmlDeviceGetCount && nvmlDeviceGetHandleByIndex && 
            nvmlDeviceGetName && nvmlDeviceGetUtilizationRates) {
            
            if (nvmlInit() == 0) {
                unsigned int deviceCount = 0;
                if (nvmlDeviceGetCount(&deviceCount) == 0 && deviceCount > 0) {
                    void* device = nullptr;
                    if (nvmlDeviceGetHandleByIndex(0, &device) == 0) {
                        char deviceName[256] = {0};
                        if (nvmlDeviceGetName(device, deviceName, sizeof(deviceName)) == 0) {
                            name = QString(deviceName);
                            available = true;
                            
                            struct { unsigned int gpu; unsigned int memory; } utilization;
                            if (nvmlDeviceGetUtilizationRates(device, &utilization) == 0) {
                                usage = utilization.gpu;
                            }
                        }
                    }
                }
                nvmlShutdown();
            }
        }
        
        FreeLibrary(nvml);
    }
}

void AutonomousResourceManager::DetectAmdGpu(uint32_t& usage, bool& available, QString& name) const {
    // AMD GPU detection via ADL (ADL SDK)
    // Similar pattern to NVML - load adl.dll dynamically
    // For now, this is a placeholder for AMD detection
    // Real implementation would use ADL_Adapter_NumberOfAdapters_Get, etc.
    
    HMODULE adl = LoadLibraryA("atiadlxx.dll");
    if (!adl) {
        adl = LoadLibraryA("atiadlxy.dll"); // 32-bit version
    }
    
    if (adl) {
        // ADL functions would be loaded here
        // For now, just mark as AMD if library exists
        name = "AMD GPU (ADL detected)";
        available = true;
        usage = 0; // Would get actual usage from ADL
        
        FreeLibrary(adl);
    }
}
#else
void AutonomousResourceManager::DetectGpuUnix(uint32_t& usage, bool& available, QString& name) const {
    // Linux: Check /sys/class/drm for GPU info
    // Try nvidia-smi first
    FILE* pipe = popen("nvidia-smi --query-gpu=name,utilization.gpu --format=csv,noheader,nounits 2>/dev/null", "r");
    if (pipe) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), pipe)) {
            // Parse: "NVIDIA GeForce RTX 3090, 45"
            char* comma = strchr(buffer, ',');
            if (comma) {
                *comma = '\0';
                name = QString(buffer);
                usage = atoi(comma + 1);
                available = true;
            }
        }
        pclose(pipe);
    }
    
    // If no NVIDIA, try AMD
    if (!available) {
        // Check for AMD GPU via /sys
        FILE* f = fopen("/sys/class/drm/card0/device/vendor", "r");
        if (f) {
            char vendor[16];
            if (fgets(vendor, sizeof(vendor), f)) {
                if (strstr(vendor, "1002")) { // AMD vendor ID
                    name = "AMD GPU";
                    available = true;
                    // Try to get usage from radeon or amdgpu driver
                    FILE* usage_f = fopen("/sys/class/drm/card0/device/gpu_busy_percent", "r");
                    if (usage_f) {
                        int gpu_busy;
                        if (fscanf(usage_f, "%d", &gpu_busy) == 1) {
                            usage = gpu_busy;
                        }
                        fclose(usage_f);
                    }
                }
            }
            fclose(f);
        }
    }
}
#endif
#else
uint64_t AutonomousResourceManager::getAvailableMemory() const
{
    // Linux/Mac implementation
    return 0;
}

uint64_t AutonomousResourceManager::getTotalMemory() const
{
    // Linux/Mac implementation
    return 0;
}

uint32_t AutonomousResourceManager::getCpuUsage() const
{
    // Linux/Mac implementation
    return 0;
}

void AutonomousResourceManager::getGpuInfo(uint32_t& usage, bool& available, QString& name) const
{
    // Linux/Mac implementation
    available = false;
    usage = 0;
    name = "Unknown";
}
#endif

uint64_t AutonomousResourceManager::getAvailableDiskSpace(const QString& path) const
{
    QString targetPath = path.isEmpty() ? QDir::currentPath() : path;
    QStorageInfo storage(targetPath);
    storage.refresh();
    return storage.bytesAvailable();
}

