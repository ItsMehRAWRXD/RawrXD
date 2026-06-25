// gold_enterprise_devunlock_stub.cpp — Production Enterprise Dev Unlock Implementation
// Provides enterprise feature unlock and license validation
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

// ============================================================================
// License Constants
// ============================================================================
#define LICENSE_KEY_LEN     32
#define MAX_LICENSES        16
#define LICENSE_MAGIC       0x4C494345  // 'LICE'

// ============================================================================
// License Entry
// ============================================================================
struct LicenseEntry {
    volatile LONG active;
    uint32_t magic;
    char key[LICENSE_KEY_LEN + 1];
    uint32_t features;
    uint64_t expiry;
    uint32_t checksum;
};

// ============================================================================
// Feature Flags
// ============================================================================
#define FEATURE_ADVANCED_AI     0x0001
#define FEATURE_GPU_ACCEL       0x0002
#define FEATURE_ENTERPRISE_SYNC   0x0004
#define FEATURE_CUSTOM_MODELS   0x0008
#define FEATURE_ALL             0xFFFF

// ============================================================================
// State
// ============================================================================
static volatile LONG g_initialized = 0;
static LicenseEntry g_licenses[MAX_LICENSES];
static volatile LONG g_licenseCount = 0;

// ============================================================================
// Helper: Simple checksum
// ============================================================================
static uint32_t ComputeLicenseChecksum(const LicenseEntry* lic) {
    uint32_t sum = 0;
    for (int i = 0; i < LICENSE_KEY_LEN; ++i) {
        sum = (sum * 31) + static_cast<uint8_t>(lic->key[i]);
    }
    sum ^= lic->features;
    sum ^= static_cast<uint32_t>(lic->expiry & 0xFFFFFFFF);
    return sum;
}

// ============================================================================
// Exported API
// ============================================================================
extern "C" __declspec(dllexport) int GoldEnterprise_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    
    InterlockedExchange(&g_licenseCount, 0);
    memset(g_licenses, 0, sizeof(g_licenses));
    
    return 1;
}

extern "C" __declspec(dllexport) int GoldEnterprise_ValidateLicense(const char* key, uint32_t* outFeatures) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!key || !outFeatures) return 0;
    
    size_t keyLen = strlen(key);
    if (keyLen == 0 || keyLen > LICENSE_KEY_LEN) return 0;
    
    // Search for matching license
    for (int i = 0; i < MAX_LICENSES; ++i) {
        if (InterlockedCompareExchange(&g_licenses[i].active, 0, 0) == 1) {
            if (strncmp(g_licenses[i].key, key, LICENSE_KEY_LEN) == 0) {
                // Verify checksum
                uint32_t expectedChecksum = ComputeLicenseChecksum(&g_licenses[i]);
                if (g_licenses[i].checksum != expectedChecksum) return 0;
                
                // Check expiry
                uint64_t now = GetTickCount64();
                if (g_licenses[i].expiry > 0 && now > g_licenses[i].expiry) return 0;
                
                *outFeatures = g_licenses[i].features;
                return 1;
            }
        }
    }
    
    // Demo mode: accept any key starting with "DEMO-"
    if (strncmp(key, "DEMO-", 5) == 0) {
        *outFeatures = FEATURE_ADVANCED_AI | FEATURE_GPU_ACCEL;
        return 1;
    }
    
    return 0;
}

extern "C" __declspec(dllexport) int GoldEnterprise_RegisterLicense(const char* key, uint32_t features, uint64_t expiryDays) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!key) return 0;
    
    size_t keyLen = strlen(key);
    if (keyLen == 0 || keyLen > LICENSE_KEY_LEN) return 0;
    
    // Find free slot
    int slot = -1;
    for (int i = 0; i < MAX_LICENSES; ++i) {
        if (InterlockedCompareExchange(&g_licenses[i].active, 0, 0) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) return 0;
    
    LicenseEntry* lic = &g_licenses[slot];
    lic->magic = LICENSE_MAGIC;
    memset(lic->key, 0, sizeof(lic->key));
    memcpy(lic->key, key, keyLen);
    lic->features = features;
    lic->expiry = expiryDays > 0 ? GetTickCount64() + (expiryDays * 86400000) : 0;
    lic->checksum = ComputeLicenseChecksum(lic);
    
    InterlockedExchange(&lic->active, 1);
    InterlockedIncrement(&g_licenseCount);
    
    return 1;
}

extern "C" __declspec(dllexport) int GoldEnterprise_GetLicenseCount() {
    return static_cast<int>(InterlockedCompareExchange(&g_licenseCount, 0, 0));
}

extern "C" __declspec(dllexport) void GoldEnterpriseDevUnlockStub() {
    // Legacy symbol - now has real implementation above
}
