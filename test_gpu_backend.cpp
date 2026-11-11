// test_gpu_backend.cpp - Test the GPU backend DLL
#include <windows.h>
#include <stdio.h>

// Function pointer types matching the DLL exports
typedef BOOL (*InitializeGPU_t)();
typedef void (*ShutdownGPU_t)();
typedef BOOL (*IsGPUAvailable_t)();
typedef const char* (*GetGPUDeviceName_t)();
typedef BOOL (*ExecuteCompute_t)();

int main() {
    printf("=== GPU Backend DLL Test ===\n\n");
    
    // Load the DLL
    HMODULE hDll = LoadLibraryA("gpu_backend.dll");
    if (!hDll) {
        printf("[ERROR] Failed to load gpu_backend.dll (error: %lu)\n", GetLastError());
        return 1;
    }
    printf("[OK] gpu_backend.dll loaded successfully\n\n");
    
    // Get function pointers
    InitializeGPU_t InitializeGPU = (InitializeGPU_t)GetProcAddress(hDll, "InitializeGPU");
    ShutdownGPU_t ShutdownGPU = (ShutdownGPU_t)GetProcAddress(hDll, "ShutdownGPU");
    IsGPUAvailable_t IsGPUAvailable = (IsGPUAvailable_t)GetProcAddress(hDll, "IsGPUAvailable");
    GetGPUDeviceName_t GetGPUDeviceName = (GetGPUDeviceName_t)GetProcAddress(hDll, "GetGPUDeviceName");
    ExecuteCompute_t ExecuteCompute = (ExecuteCompute_t)GetProcAddress(hDll, "ExecuteCompute");
    
    // Check all functions exist
    if (!InitializeGPU || !ShutdownGPU || !IsGPUAvailable || !GetGPUDeviceName || !ExecuteCompute) {
        printf("[ERROR] Failed to get one or more function pointers\n");
        FreeLibrary(hDll);
        return 1;
    }
    printf("[OK] All function pointers resolved\n\n");
    
    // Test InitializeGPU
    printf("[TEST] InitializeGPU()...\n");
    BOOL initResult = InitializeGPU();
    if (initResult) {
        printf("[OK] InitializeGPU() returned TRUE\n\n");
    } else {
        printf("[WARN] InitializeGPU() returned FALSE (Vulkan may not be available)\n\n");
    }
    
    // Test IsGPUAvailable
    printf("[TEST] IsGPUAvailable()...\n");
    BOOL available = IsGPUAvailable();
    printf("[OK] IsGPUAvailable() returned %s\n\n", available ? "TRUE" : "FALSE");
    
    // Test GetGPUDeviceName
    printf("[TEST] GetGPUDeviceName()...\n");
    const char* deviceName = GetGPUDeviceName();
    if (deviceName && deviceName[0]) {
        printf("[OK] GPU Device: %s\n\n", deviceName);
    } else {
        printf("[INFO] No GPU device name available\n\n");
    }
    
    // Test ExecuteCompute
    printf("[TEST] ExecuteCompute()...\n");
    BOOL computeResult = ExecuteCompute();
    if (computeResult) {
        printf("[OK] ExecuteCompute() returned TRUE\n\n");
    } else {
        printf("[WARN] ExecuteCompute() returned FALSE\n\n");
    }
    
    // Test ShutdownGPU
    printf("[TEST] ShutdownGPU()...\n");
    ShutdownGPU();
    printf("[OK] ShutdownGPU() completed\n\n");
    
    // Cleanup
    FreeLibrary(hDll);
    printf("[OK] DLL unloaded\n\n");
    
    printf("=== All Tests Complete ===\n");
    return 0;
}
