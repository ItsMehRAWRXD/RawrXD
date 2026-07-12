//==============================================================================
// SovereignHypervisor.h - Phase 16: VM Subsystem for Isolated Execution
//
// Hard isolation boundaries for the Sovereign Runtime:
// - Per-workflow sandboxes (micro-VMs)
// - Crash-proof experimentation
// - Security boundaries between agents
// - SEG-addressable VM lifecycle
// - Tenant isolation for multi-user deployments
//==============================================================================

#ifndef SOVEREIGN_HYPERVISOR_H
#define SOVEREIGN_HYPERVISOR_H

#include <windows.h>
#include <cstdint>
#include <cstddef>

#define MAX_VMS 32
#define MAX_VM_NAME 64
#define MAX_VM_ID 32
#define VM_MEMORY_MIN_MB 64
#define VM_MEMORY_MAX_MB 8192
#define VM_CPU_MIN 1
#define VM_CPU_MAX 16

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// VM Types
//==============================================================================

typedef enum {
    VM_TYPE_MICRO = 0,      // Lightweight sandbox (64-256MB)
    VM_TYPE_STANDARD = 1,   // Standard isolation (512MB-2GB)
    VM_TYPE_HEAVY = 2,      // Full VM (2GB-8GB)
    VM_TYPE_BARE = 3        // Bare-metal container (shared kernel)
} VMType;

//==============================================================================
// VM States
//==============================================================================

typedef enum {
    VM_STATE_NONE = 0,
    VM_STATE_CREATING = 1,
    VM_STATE_RUNNING = 2,
    VM_STATE_PAUSED = 3,
    VM_STATE_STOPPED = 4,
    VM_STATE_DESTROYING = 5,
    VM_STATE_ERROR = -1
} VMState;

//==============================================================================
// VM Configuration
//==============================================================================

typedef struct VMConfig {
    char name[MAX_VM_NAME];
    VMType type;
    
    // Resources
    uint32_t memory_mb;
    uint32_t cpu_count;
    uint32_t cpu_shares;      // Relative CPU priority
    
    // Storage
    uint32_t disk_size_mb;
    char disk_image_path[MAX_PATH];
    
    // Network
    int enable_network;
    int isolated_network;     // No external access
    char network_subnet[32];  // e.g., "10.0.x.0/24"
    
    // Security
    int enable_seccomp;       // System call filtering
    int enable_apparmor;      // Mandatory access control
    int read_only_root;       // Immutable root filesystem
    
    // Capabilities to drop
    uint32_t dropped_caps;    // Bitmask of capabilities
    
    // Bind mounts (host_path:vm_path)
    char mounts[8][2][MAX_PATH];
    int mount_count;
    
    // Environment variables
    char env[16][2][256];     // key=value
    int env_count;
} VMConfig;

//==============================================================================
// VM Info
//==============================================================================

typedef struct VMInfo {
    char id[MAX_VM_ID];
    char name[MAX_VM_NAME];
    VMState state;
    VMType type;
    
    // Resources
    uint32_t memory_mb;
    uint32_t cpu_count;
    
    // Runtime metrics
    uint64_t start_time_ms;
    uint64_t cpu_time_ms;
    uint64_t memory_used_mb;
    uint32_t process_count;
    
    // Owner
    char owner[64];           // Agent/workflow that created this VM
    char tenant[64];          // Multi-tenant isolation
    
    // Security context
    int sandbox_level;        // 0-3 (0=none, 3=max)
} VMInfo;

//==============================================================================
// VM Lifecycle Events (for ExecutionJournal)
//==============================================================================

typedef enum {
    VM_EVENT_CREATED = 0,
    VM_EVENT_STARTED = 1,
    VM_EVENT_PAUSED = 2,
    VM_EVENT_RESUMED = 3,
    VM_EVENT_STOPPED = 4,
    VM_EVENT_DESTROYED = 5,
    VM_EVENT_CRASHED = 6,
    VM_EVENT_SEC_VIOLATION = 7
} VMEventType;

//==============================================================================
// Hypervisor Lifecycle
//==============================================================================

int SovereignHypervisor_Init(void);
int SovereignHypervisor_Shutdown(void);
int SovereignHypervisor_IsInitialized(void);

//==============================================================================
// VM Lifecycle
//==============================================================================

// Create a new VM (returns VM ID on success, NULL on failure)
int SovereignVM_Create(const VMConfig* config, char* out_vm_id, size_t id_size);

// Start a VM
int SovereignVM_Start(const char* vm_id);

// Pause a VM (freeze state)
int SovereignVM_Pause(const char* vm_id);

// Resume a paused VM
int SovereignVM_Resume(const char* vm_id);

// Stop a VM (graceful shutdown)
int SovereignVM_Stop(const char* vm_id, int timeout_ms);

// Force stop a VM
int SovereignVM_Kill(const char* vm_id);

// Destroy a VM (free all resources)
int SovereignVM_Destroy(const char* vm_id);

// Get VM info
int SovereignVM_GetInfo(const char* vm_id, VMInfo* out_info);

//==============================================================================
// VM Execution
//==============================================================================

// Execute command inside VM
// Returns process ID (>0) on success, -1 on failure
int SovereignVM_Exec(const char* vm_id, const char* command, 
                     char* const envp[], char* const argv[]);

// Execute with I/O redirection
int SovereignVM_ExecWithIO(const char* vm_id, const char* command,
                           HANDLE* out_stdin, HANDLE* out_stdout, HANDLE* out_stderr);

// Wait for process completion
int SovereignVM_WaitProcess(const char* vm_id, int pid, int* exit_code, int timeout_ms);

// Kill process in VM
int SovereignVM_KillProcess(const char* vm_id, int pid);

//==============================================================================
// VM Query
//==============================================================================

// List all VMs
int SovereignVM_List(VMInfo* out_vms, int max_vms, int* out_count);

// List VMs by owner
int SovereignVM_ListByOwner(const char* owner, VMInfo* out_vms, int max_vms, int* out_count);

// List VMs by tenant
int SovereignVM_ListByTenant(const char* tenant, VMInfo* out_vms, int max_vms, int* out_count);

// Find VM by name
int SovereignVM_FindByName(const char* name, VMInfo* out_info);

//==============================================================================
// Security & Isolation
//==============================================================================

// Set sandbox level (0-3)
int SovereignVM_SetSandboxLevel(const char* vm_id, int level);

// Apply seccomp filter
int SovereignVM_ApplySeccomp(const char* vm_id, const char* profile_path);

// Set read-only root
int SovereignVM_SetReadOnlyRoot(const char* vm_id, int enable);

// Drop capabilities
int SovereignVM_DropCapabilities(const char* vm_id, uint32_t caps);

// Check if VM has capability
int SovereignVM_HasCapability(const char* vm_id, uint32_t cap);

//==============================================================================
// Resource Limits
//==============================================================================

// Set memory limit
int SovereignVM_SetMemoryLimit(const char* vm_id, uint32_t memory_mb);

// Set CPU limit
int SovereignVM_SetCPULimit(const char* vm_id, uint32_t cpu_shares);

// Set disk quota
int SovereignVM_SetDiskQuota(const char* vm_id, uint32_t disk_mb);

// Get resource usage
int SovereignVM_GetResourceUsage(const char* vm_id, 
                                   uint64_t* out_memory_used,
                                   uint64_t* out_cpu_time_ms,
                                   uint64_t* out_disk_used);

//==============================================================================
// Checkpoint / Restore
//==============================================================================

// Create checkpoint (snapshot)
int SovereignVM_Checkpoint(const char* vm_id, const char* checkpoint_path);

// Restore from checkpoint
int SovereignVM_Restore(const char* vm_id, const char* checkpoint_path);

// List checkpoints
int SovereignVM_ListCheckpoints(const char* vm_id, char** out_paths, int max_paths, int* out_count);

//==============================================================================
// SEG Integration
//==============================================================================

// Register VM operations with SEG
int SovereignHypervisor_RegisterWithSEG(void);

// SEG node handler for VM spawn
int SovereignVM_SEGSpawnHandler(void* workflow, void* node_data, void* output);

// SEG node handler for VM exec
int SovereignVM_SEGExecHandler(void* workflow, void* node_data, void* output);

// SEG node handler for VM destroy
int SovereignVM_SEGDestroyHandler(void* workflow, void* node_data, void* output);

//==============================================================================
// Multi-Tenant Support
//==============================================================================

// Create tenant namespace
int SovereignHypervisor_CreateTenant(const char* tenant_id, const char* config_json);

// Destroy tenant namespace
int SovereignHypervisor_DestroyTenant(const char* tenant_id);

// Set VM tenant
int SovereignVM_SetTenant(const char* vm_id, const char* tenant_id);

// Get tenant resource usage
int SovereignHypervisor_GetTenantUsage(const char* tenant_id,
                                       uint64_t* out_memory_used,
                                       uint64_t* out_cpu_time_ms,
                                       int* out_vm_count);

//==============================================================================
// Utility
//==============================================================================

const char* SovereignVM_StateToString(VMState state);
const char* SovereignVM_TypeToString(VMType type);
VMState SovereignVM_StringToState(const char* str);

// Format VM info for display
void SovereignVM_FormatInfo(const VMInfo* info, char* out, size_t out_size);

// Validate VM config
int SovereignVM_ValidateConfig(const VMConfig* config, char* error_msg, size_t error_size);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_HYPERVISOR_H
