//==============================================================================
// SovereignSubsystemRegistry.h
// Unified registry for all sovereign subsystems
//
// This is the central dispatch hub that wires together:
// - CodexPro (reverse engineering)
// - SunshineFPS (game engine)
// - MASM Roslyn (C# compiler)
// - MASM Java Backend (JVM)
// - MASM Kernels (inference)
// - Titan (DMA/memory)
// - Vulkan (GPU compute)
// - MemoryBridge (unified memory)
// - Audit subsystem
//
// Phase 8: Unified Runtime Architecture
//==============================================================================

#ifndef SOVEREIGNSUBSYSTEMREGISTRY_H
#define SOVEREIGNSUBSYSTEMREGISTRY_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Subsystem Types
//==============================================================================

typedef enum {
    SUBSYSTEM_KERNEL = 0,       // MASM inference kernels
    SUBSYSTEM_ROSLYN,           // MASM C# compiler
    SUBSYSTEM_JAVA,             // MASM Java backend
    SUBSYSTEM_CODEXPRO,         // Reverse engineering platform
    SUBSYSTEM_SUNSHINEFPS,      // Game engine
    SUBSYSTEM_TITAN,            // DMA/memory management
    SUBSYSTEM_VULKAN,           // GPU compute
    SUBSYSTEM_MEMORYBRIDGE,     // Unified memory fabric
    SUBSYSTEM_AUDIT,            // Codebase audit
    SUBSYSTEM_CLI,              // Command line interface
    SUBSYSTEM_GUI,              // Graphical interface
    SUBSYSTEM_COUNT
} SovereignSubsystemType;

//==============================================================================
// Subsystem Capabilities
//==============================================================================

typedef enum {
    CAP_NONE = 0,
    CAP_EXECUTE = 1 << 0,      // Can execute commands
    CAP_COMPILE = 1 << 1,        // Can compile code
    CAP_ANALYZE = 1 << 2,        // Can analyze binaries
    CAP_RENDER = 1 << 3,         // Can render graphics
    CAP_COMPUTE = 1 << 4,        // Can perform compute
    CAP_MEMORY = 1 << 5,         // Can manage memory
    CAP_AUDIT = 1 << 6,          // Can audit codebase
    CAP_ALL = 0xFFFFFFFF
} SovereignSubsystemCaps;

//==============================================================================
// Subsystem State
//==============================================================================

typedef enum {
    STATE_UNINITIALIZED = 0,
    STATE_INITIALIZING,
    STATE_READY,
    STATE_BUSY,
    STATE_ERROR,
    STATE_SHUTDOWN
} SovereignSubsystemState;

//==============================================================================
// Subsystem Entry
//==============================================================================

typedef struct SovereignSubsystem {
    const char* name;                           // Subsystem name
    const char* version;                      // Version string
    SovereignSubsystemType type;                // Type enum
    uint32_t capabilities;                      // Capability flags
    SovereignSubsystemState state;              // Current state
    
    // Handler function - all subsystems expose this interface
    int (*handler)(int argc, char** argv, char* output, size_t output_size);
    
    // Lifecycle functions
    int (*init)(void);
    int (*shutdown)(void);
    int (*get_status)(char* status, size_t status_size);
    
    // Metadata
    const char* product_line;                   // e.g., "AI-IDE-Runtime"
    const char* build_system;                   // e.g., "MASM", "CMake"
    uint64_t file_count;                        // Files in subsystem
    uint64_t code_size_bytes;                     // Total code size
} SovereignSubsystem;

//==============================================================================
// Global Registry Access (for diagnostic subsystems)
//==============================================================================

#ifdef __cplusplus
extern "C" {
#endif

// These are defined in SovereignSubsystemRegistry.cpp
extern int g_subsystem_count;
extern SovereignSubsystem* g_registry[];

#ifdef __cplusplus
}
#endif

//==============================================================================
// Registry Functions
//==============================================================================

// Initialize the subsystem registry
int Sovereign_InitRegistry(void);

// Shutdown the subsystem registry
int Sovereign_ShutdownRegistry(void);

// Register a subsystem
int Sovereign_RegisterSubsystem(SovereignSubsystem* subsystem);

// Unregister a subsystem
int Sovereign_UnregisterSubsystem(const char* name);

// Find a subsystem by name
SovereignSubsystem* Sovereign_FindSubsystem(const char* name);

// Find a subsystem by type
SovereignSubsystem* Sovereign_FindSubsystemByType(SovereignSubsystemType type);

// Dispatch a command to a subsystem
int Sovereign_Dispatch(const char* subsystem_name, int argc, char** argv, 
                       char* output, size_t output_size);

// Dispatch by type
int Sovereign_DispatchByType(SovereignSubsystemType type, int argc, char** argv,
                              char* output, size_t output_size);

// Get all registered subsystems
int Sovereign_GetAllSubsystems(SovereignSubsystem** subsystems, int* count);

// Get subsystems by capability
int Sovereign_GetSubsystemsByCap(uint32_t capabilities, SovereignSubsystem** subsystems, int* count);

// Get registry status
int Sovereign_GetRegistryStatus(char* status, size_t status_size);

// Get subsystem count
int Sovereign_GetSubsystemCount(void);

// Get ready subsystem count
int Sovereign_GetReadySubsystemCount(void);

//==============================================================================
// Predefined Subsystem Names
//==============================================================================

#define SUBSYSTEM_NAME_KERNEL       "kernel"
#define SUBSYSTEM_NAME_ROSLYN       "roslyn"
#define SUBSYSTEM_NAME_JAVA         "java"
#define SUBSYSTEM_NAME_CODEXPRO     "codexpro"
#define SUBSYSTEM_NAME_SUNSHINE     "sunshine"
#define SUBSYSTEM_NAME_TITAN        "titan"
#define SUBSYSTEM_NAME_VULKAN       "vulkan"
#define SUBSYSTEM_NAME_MEMORYBRIDGE "memorybridge"
#define SUBSYSTEM_NAME_AUDIT        "audit"
#define SUBSYSTEM_NAME_CLI          "cli"
#define SUBSYSTEM_NAME_GUI          "gui"

//==============================================================================
// Command Router Integration
//==============================================================================

// Route a command string to the appropriate subsystem
// Format: "subsystem command args..."
// Example: "kernel status", "roslyn compile file.cs", "codexpro analyze exe"
int Sovereign_RouteCommand(const char* command_line, char* output, size_t output_size);

// Parse and route with automatic subsystem detection
int Sovereign_AutoRoute(int argc, char** argv, char* output, size_t output_size);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGNSUBSYSTEMREGISTRY_H
