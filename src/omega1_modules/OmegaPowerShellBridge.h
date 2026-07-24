// ═════════════════════════════════════════════════════════════════════════════
// RawrXD OMEGA-1 PowerShell Bridge Header
// IAT Export Declarations (Slots 64-75) - Self-Mutating Engine Interface
// ═════════════════════════════════════════════════════════════════════════════

#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
// ═════════════════════════════════════════════════════════════════════════════
// Linker Symbol Preservation (MSVC)
// Prevent /OPT:REF from stripping IAT exports when called reflectively
// ═════════════════════════════════════════════════════════════════════════════

#ifdef _MSC_VER
    #pragma comment(linker, "/INCLUDE:Omega1_Initialize")
    #pragma comment(linker, "/INCLUDE:Omega1_Shutdown")
    #pragma comment(linker, "/INCLUDE:Omega1_GetModuleCount")
    #pragma comment(linker, "/INCLUDE:Omega1_IsMutant")
    #pragma comment(linker, "/INCLUDE:Omega1_GetMutationCount")
    #pragma comment(linker, "/INCLUDE:Omega1_ExecuteReflective")
    #pragma comment(linker, "/INCLUDE:Omega1_ValidateIntegrity")
    #pragma comment(linker, "/INCLUDE:Omega1_TriggerMutation")
    #pragma comment(linker, "/INCLUDE:Omega1_GetManifestJson")
    #pragma comment(linker, "/INCLUDE:Omega1_ExecutePowerShell")
    #pragma comment(linker, "/INCLUDE:Omega1_LoadModule")
    #pragma comment(linker, "/INCLUDE:Omega1_InvokeModule")
    // C API preservation
    #pragma comment(linker, "/INCLUDE:Omega1_CreateContext")
    #pragma comment(linker, "/INCLUDE:Omega1_DestroyContext")
    #pragma comment(linker, "/INCLUDE:Omega1_EnumModules")
    #pragma comment(linker, "/INCLUDE:Omega1_GetVersion")
    #pragma comment(linker, "/INCLUDE:Omega1_GetStatus")
#endif
// ═════════════════════════════════════════════════════════════════════════════
// IAT Export Slot Definitions (64-75 reserved for OMEGA-1)
// ═════════════════════════════════════════════════════════════════════════════

#define OMEGA1_IAT_SLOT_BASE      64
#define OMEGA1_IAT_SLOT_COUNT     12

// Individual slot assignments
#define OMEGA1_SLOT_INITIALIZE          64
#define OMEGA1_SLOT_SHUTDOWN            65
#define OMEGA1_SLOT_GETMODULECOUNT      66
#define OMEGA1_SLOT_ISMUTANT            67
#define OMEGA1_SLOT_GETMUTATIONCOUNT    68
#define OMEGA1_SLOT_EXECUTEREFLECTIVE   69
#define OMEGA1_SLOT_VALIDATEINTEGRITY   70
#define OMEGA1_SLOT_TRIGGERMUTATION     71
#define OMEGA1_SLOT_GETMANIFESTJSON     72
#define OMEGA1_SLOT_EXECUTEPOWERSHELL   73
#define OMEGA1_SLOT_LOADMODULE          74
#define OMEGA1_SLOT_INVOKEMODULE        75

// ═════════════════════════════════════════════════════════════════════════════
// Opaque Handle Types
// ═════════════════════════════════════════════════════════════════════════════

typedef void* HMODULE_OMEGA1;
typedef void* HPSMODULE;
typedef void* HMUTATIONCTX;

// ═════════════════════════════════════════════════════════════════════════════
// Export Function Pointer Types (for IAT binding)
// ═════════════════════════════════════════════════════════════════════════════

extern "C" {
    // Slot 64: Initialize
    typedef BOOL (WINAPI *OMEGA1_INITIALIZE_FN)(void** ppContext, uint32_t flags);
    __declspec(dllexport) BOOL Omega1_Initialize(void** ppContext, uint32_t flags);

    // Slot 65: Shutdown
    typedef void (WINAPI *OMEGA1_SHUTDOWN_FN)(void* pContext);
    __declspec(dllexport) void Omega1_Shutdown(void* pContext);

    // Slot 66: GetModuleCount
    typedef uint32_t (WINAPI *OMEGA1_GETMODULECOUNT_FN)(void* pContext);
    __declspec(dllexport) uint32_t Omega1_GetModuleCount(void* pContext);

    // Slot 67: IsMutant
    typedef BOOL (WINAPI *OMEGA1_ISMUTANT_FN)(void* pContext);
    __declspec(dllexport) BOOL Omega1_IsMutant(void* pContext);

    // Slot 68: GetMutationCount
    typedef uint32_t (WINAPI *OMEGA1_GETMUTATIONCOUNT_FN)(void* pContext);
    __declspec(dllexport) uint32_t Omega1_GetMutationCount(void* pContext);

    // Slot 69: ExecuteReflective
    typedef BOOL (WINAPI *OMEGA1_EXECUTEREFLECTIVE_FN)(void* pContext, const char* payload, uint32_t payloadSize, char* output, uint32_t outputSize);
    __declspec(dllexport) BOOL Omega1_ExecuteReflective(void* pContext, const char* payload, uint32_t payloadSize, char* output, uint32_t outputSize);

    // Slot 70: ValidateIntegrity
    typedef BOOL (WINAPI *OMEGA1_VALIDATEINTEGRITY_FN)(void* pContext, uint32_t* pChecksum);
    __declspec(dllexport) BOOL Omega1_ValidateIntegrity(void* pContext, uint32_t* pChecksum);

    // Slot 71: TriggerMutation
    typedef BOOL (WINAPI *OMEGA1_TRIGGERMUTATION_FN)(void* pContext, uint32_t mutationType);
    __declspec(dllexport) BOOL Omega1_TriggerMutation(void* pContext, uint32_t mutationType);

    // Slot 72: GetManifestJson
    typedef BOOL (WINAPI *OMEGA1_GETMANIFESTJSON_FN)(void* pContext, char* buffer, uint32_t bufferSize);
    __declspec(dllexport) BOOL Omega1_GetManifestJson(void* pContext, char* buffer, uint32_t bufferSize);

    // Slot 73: ExecutePowerShell
    typedef BOOL (WINAPI *OMEGA1_EXECUTEPOWERSHELL_FN)(void* pContext, const char* command, char* output, uint32_t outputSize);
    __declspec(dllexport) BOOL Omega1_ExecutePowerShell(void* pContext, const char* command, char* output, uint32_t outputSize);

    // Slot 74: LoadModule
    typedef HPSMODULE (WINAPI *OMEGA1_LOADMODULE_FN)(void* pContext, const char* moduleName);
    __declspec(dllexport) HPSMODULE Omega1_LoadModule(void* pContext, const char* moduleName);

    // Slot 75: InvokeModule
    typedef BOOL (WINAPI *OMEGA1_INVOKEMODULE_FN)(void* pContext, HPSMODULE hModule, const char* function, char* output, uint32_t outputSize);
    __declspec(dllexport) BOOL Omega1_InvokeModule(void* pContext, HPSMODULE hModule, const char* function, char* output, uint32_t outputSize);
}

// ═════════════════════════════════════════════════════════════════════════════
// C++ Bridge Namespace
// ═════════════════════════════════════════════════════════════════════════════

namespace RawrXD::Bridge {

    // Forward declarations
    class PowerShellExecutor;

    // OMEGA-1 Engine Context
    struct Omega1Context {
        void* pInternal;
        uint32_t flags;
        uint32_t mutationCount;
        BOOL isMutant;
        char manifestJson[8192];
    };

    // Module information structure
    struct Omega1ModuleInfo {
        char name[256];
        char version[32];
        uint32_t slotIndex;
        BOOL loaded;
    };

    // ═════════════════════════════════════════════════════════════════════════
    // PowerShell Executor Class
    // ═════════════════════════════════════════════════════════════════════════
    class PowerShellExecutor {
    private:
        std::string m_modulePath;
        HANDLE m_hReadPipe = nullptr;
        HANDLE m_hWritePipe = nullptr;
        SECURITY_ATTRIBUTES m_sa;

        void CleanupPipes();
        std::string BuildPowerShellCommand(const char* command);

    public:
        explicit PowerShellExecutor(const std::string& modulePath);
        ~PowerShellExecutor();

        bool Initialize();
        bool ExecuteCommand(const char* command, char* output, uint32_t outputSize);
        bool LoadModule(const char* moduleName);
        bool InvokeModuleFunction(const char* moduleName, const char* function, char* output, uint32_t outputSize);
        bool ExecuteOmegaBootstrap();
        bool ExecuteGenesis();
        bool GetModuleManifest(const char* moduleName, char* output, uint32_t outputSize);
    };

    // ═════════════════════════════════════════════════════════════════════════
    // OMEGA-1 Engine Interface
    // ═════════════════════════════════════════════════════════════════════════
    class Omega1Engine {
    private:
        Omega1Context* m_pContext;
        PowerShellExecutor* m_pExecutor;

    public:
        Omega1Engine();
        ~Omega1Engine();

        // Lifecycle
        bool Initialize(uint32_t flags = 0);
        void Shutdown();

        // Module Management
        uint32_t GetModuleCount() const;
        std::vector<Omega1ModuleInfo> GetLoadedModules() const;
        HPSMODULE LoadModule(const char* moduleName);
        bool InvokeModule(HPSMODULE hModule, const char* function, char* output, uint32_t outputSize);

        // Mutation System
        bool IsMutant() const;
        uint32_t GetMutationCount() const;
        bool TriggerMutation(uint32_t mutationType);

        // Execution
        bool ExecuteReflective(const char* payload, uint32_t payloadSize, char* output, uint32_t outputSize);
        bool ExecutePowerShell(const char* command, char* output, uint32_t outputSize);

        // Integrity
        bool ValidateIntegrity(uint32_t* pChecksum);
        std::string GetManifestJson() const;

        // Bootstrap
        bool BootstrapFromGenesis();
    };

    // ═════════════════════════════════════════════════════════════════════════
    // Utility Functions
    // ═════════════════════════════════════════════════════════════════════════
    namespace Omega1Utils {
        std::string GetModulePath();
        bool ValidateModuleExists(const char* moduleName);
        std::vector<std::string> DiscoverModules();
        std::string GetOmegaRoot();
    }

} // namespace RawrXD::Bridge

// ═════════════════════════════════════════════════════════════════════════════
// C API for External Binding (IAT-compatible)
// ═════════════════════════════════════════════════════════════════════════════

extern "C" {
    // Context management
    __declspec(dllexport) void* Omega1_CreateContext();
    __declspec(dllexport) void Omega1_DestroyContext(void* pContext);

    // Module enumeration
    __declspec(dllexport) uint32_t Omega1_EnumModules(void* pContext, char* buffer, uint32_t bufferSize);

    // Status queries
    __declspec(dllexport) uint32_t Omega1_GetVersion(char* buffer, uint32_t bufferSize);
    __declspec(dllexport) uint32_t Omega1_GetStatus(void* pContext);
}

// ═════════════════════════════════════════════════════════════════════════════
// Manifest Constants
// ═════════════════════════════════════════════════════════════════════════════

#define OMEGA1_VERSION_MAJOR    1
#define OMEGA1_VERSION_MINOR    0
#define OMEGA1_VERSION_PATCH    0
#define OMEGA1_VERSION_STRING   "1.0.0"

// Mutation types
#define OMEGA1_MUTATION_NONE        0
#define OMEGA1_MUTATION_HOTPATCH    1
#define OMEGA1_MUTATION_REFLECTIVE  2
#define OMEGA1_MUTATION_GENESIS     3

// Flags
#define OMEGA1_FLAG_NONE            0x00000000
#define OMEGA1_FLAG_VERBOSE         0x00000001
#define OMEGA1_FLAG_STRICT          0x00000002
#define OMEGA1_FLAG_MUTANT          0x00000004

// Status codes
#define OMEGA1_STATUS_OK            0
#define OMEGA1_STATUS_ERROR         1
#define OMEGA1_STATUS_NOT_INIT      2
#define OMEGA1_STATUS_MUTATION      3
