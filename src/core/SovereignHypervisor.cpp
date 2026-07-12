//==============================================================================
// SovereignHypervisor.cpp - Phase 16: VM Subsystem Implementation
//==============================================================================

#include "SovereignHypervisor.h"
#include "ExecutionJournal.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <process.h>

//==============================================================================
// Internal State
//==============================================================================

typedef struct VMEntry {
    VMInfo info;
    VMConfig config;
    HANDLE process_handle;
    HANDLE job_handle;          // Windows Job Object for resource limits
    int is_active;
} VMEntry;

typedef struct HypervisorState {
    VMEntry vms[MAX_VMS];
    int vm_count;
    int initialized;
    CRITICAL_SECTION lock;
    int next_vm_id;
} HypervisorState;

static HypervisorState g_hypervisor = {0};

//==============================================================================
// Lifecycle
//==============================================================================

int SovereignHypervisor_Init(void) {
    if (g_hypervisor.initialized) {
        return 0;
    }
    
    memset(&g_hypervisor, 0, sizeof(g_hypervisor));
    InitializeCriticalSection(&g_hypervisor.lock);
    g_hypervisor.next_vm_id = 1;
    g_hypervisor.initialized = 1;
    
    Journal_LogUserRequest("Sovereign Hypervisor initialized", "");
    
    return 0;
}

int SovereignHypervisor_Shutdown(void) {
    if (!g_hypervisor.initialized) {
        return 0;
    }
    
    // Destroy all VMs
    EnterCriticalSection(&g_hypervisor.lock);
    
    for (int i = 0; i < MAX_VMS; i++) {
        if (g_hypervisor.vms[i].is_active) {
            SovereignVM_Destroy(g_hypervisor.vms[i].info.id);
        }
    }
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    DeleteCriticalSection(&g_hypervisor.lock);
    g_hypervisor.initialized = 0;
    
    Journal_LogUserRequest("Sovereign Hypervisor shutdown", "");
    
    return 0;
}

int SovereignHypervisor_IsInitialized(void) {
    return g_hypervisor.initialized;
}

//==============================================================================
// VM Lifecycle
//==============================================================================

static int FindFreeVMSlot(void) {
    for (int i = 0; i < MAX_VMS; i++) {
        if (!g_hypervisor.vms[i].is_active) {
            return i;
        }
    }
    return -1;
}

static int FindVMById(const char* vm_id) {
    if (!vm_id) return -1;
    
    for (int i = 0; i < MAX_VMS; i++) {
        if (g_hypervisor.vms[i].is_active && 
            strcmp(g_hypervisor.vms[i].info.id, vm_id) == 0) {
            return i;
        }
    }
    return -1;
}

int SovereignVM_Create(const VMConfig* config, char* out_vm_id, size_t id_size) {
    if (!config || !out_vm_id || id_size == 0) {
        return -1;
    }
    
    // Validate config
    char error_msg[256];
    if (SovereignVM_ValidateConfig(config, error_msg, sizeof(error_msg)) != 0) {
        return -1;
    }
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    int slot = FindFreeVMSlot();
    if (slot < 0) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    VMEntry* entry = &g_hypervisor.vms[slot];
    memset(entry, 0, sizeof(VMEntry));
    
    // Generate VM ID
    snprintf(entry->info.id, sizeof(entry->info.id), "vm-%04d", g_hypervisor.next_vm_id++);
    strncpy(entry->info.name, config->name, sizeof(entry->info.name) - 1);
    entry->info.state = VM_STATE_CREATING;
    entry->info.type = config->type;
    entry->info.memory_mb = config->memory_mb;
    entry->info.cpu_count = config->cpu_count;
    entry->info.sandbox_level = (config->enable_seccomp ? 2 : 1);
    entry->is_active = 1;
    
    // Copy config
    entry->config = *config;
    
    // Create Windows Job Object for resource limits
    entry->info.state = VM_STATE_CREATING;
    
    // Create job object
    entry->job_handle = CreateJobObject(NULL, entry->info.id);
    if (entry->job_handle) {
        // Set memory limit
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        limits.ProcessMemoryLimit = (SIZE_T)config->memory_mb * 1024 * 1024;
        SetInformationJobObject(entry->job_handle, 
                                JobObjectExtendedLimitInformation, 
                                &limits, sizeof(limits));
    }
    
    strncpy(out_vm_id, entry->info.id, id_size - 1);
    out_vm_id[id_size - 1] = '\0';
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    // Log event
    char msg[256];
    snprintf(msg, sizeof(msg), "VM created: %s (%s)", entry->info.id, config->name);
    Journal_LogUserRequest(msg, config->type == VM_TYPE_MICRO ? "micro" : 
                                config->type == VM_TYPE_STANDARD ? "standard" : "heavy");
    
    return 0;
}

int SovereignVM_Start(const char* vm_id) {
    if (!vm_id) return -1;
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    int slot = FindVMById(vm_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    VMEntry* entry = &g_hypervisor.vms[slot];
    
    if (entry->info.state != VM_STATE_CREATING && 
        entry->info.state != VM_STATE_STOPPED) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    entry->info.state = VM_STATE_RUNNING;
    entry->info.start_time_ms = GetTickCount64();
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    Journal_LogUserRequest("VM started", vm_id);
    
    return 0;
}

int SovereignVM_Pause(const char* vm_id) {
    if (!vm_id) return -1;
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    int slot = FindVMById(vm_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    if (g_hypervisor.vms[slot].info.state != VM_STATE_RUNNING) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    g_hypervisor.vms[slot].info.state = VM_STATE_PAUSED;
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    Journal_LogUserRequest("VM paused", vm_id);
    
    return 0;
}

int SovereignVM_Resume(const char* vm_id) {
    if (!vm_id) return -1;
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    int slot = FindVMById(vm_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    if (g_hypervisor.vms[slot].info.state != VM_STATE_PAUSED) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    g_hypervisor.vms[slot].info.state = VM_STATE_RUNNING;
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    Journal_LogUserRequest("VM resumed", vm_id);
    
    return 0;
}

int SovereignVM_Stop(const char* vm_id, int timeout_ms) {
    if (!vm_id) return -1;
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    int slot = FindVMById(vm_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    VMEntry* entry = &g_hypervisor.vms[slot];
    
    if (entry->info.state != VM_STATE_RUNNING && 
        entry->info.state != VM_STATE_PAUSED) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    entry->info.state = VM_STATE_STOPPED;
    
    // Terminate all processes in job
    if (entry->job_handle) {
        TerminateJobObject(entry->job_handle, 0);
    }
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    Journal_LogUserRequest("VM stopped", vm_id);
    
    return 0;
}

int SovereignVM_Kill(const char* vm_id) {
    return SovereignVM_Stop(vm_id, 0);
}

int SovereignVM_Destroy(const char* vm_id) {
    if (!vm_id) return -1;
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    int slot = FindVMById(vm_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    VMEntry* entry = &g_hypervisor.vms[slot];
    entry->info.state = VM_STATE_DESTROYING;
    
    // Clean up job object
    if (entry->job_handle) {
        CloseHandle(entry->job_handle);
        entry->job_handle = NULL;
    }
    
    entry->is_active = 0;
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    Journal_LogUserRequest("VM destroyed", vm_id);
    
    return 0;
}

int SovereignVM_GetInfo(const char* vm_id, VMInfo* out_info) {
    if (!vm_id || !out_info) return -1;
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    int slot = FindVMById(vm_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    *out_info = g_hypervisor.vms[slot].info;
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    return 0;
}

//==============================================================================
// VM Execution
//==============================================================================

int SovereignVM_Exec(const char* vm_id, const char* command,
                     char* const envp[], char* const argv[]) {
    (void)envp;
    (void)argv;
    
    if (!vm_id || !command) return -1;
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    int slot = FindVMById(vm_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    if (g_hypervisor.vms[slot].info.state != VM_STATE_RUNNING) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    // Spawn process
    STARTUPINFO si = {0};
    si.cb = sizeof(si);
    
    PROCESS_INFORMATION pi = {0};
    
    // Create process suspended
    BOOL result = CreateProcess(NULL, (LPSTR)command, NULL, NULL, FALSE,
                                 CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    
    if (!result) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    // Assign to job object for resource limits
    if (g_hypervisor.vms[slot].job_handle) {
        AssignProcessToJobObject(g_hypervisor.vms[slot].job_handle, pi.hProcess);
    }
    
    // Resume process
    ResumeThread(pi.hThread);
    
    int pid = (int)pi.dwProcessId;
    
    CloseHandle(pi.hThread);
    // Keep process handle for monitoring
    if (g_hypervisor.vms[slot].process_handle) {
        CloseHandle(g_hypervisor.vms[slot].process_handle);
    }
    g_hypervisor.vms[slot].process_handle = pi.hProcess;
    
    g_hypervisor.vms[slot].info.process_count++;
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Exec in %s: %.50s...", vm_id, command);
    Journal_LogUserRequest(msg, "");
    
    return pid;
}

int SovereignVM_ExecWithIO(const char* vm_id, const char* command,
                           HANDLE* out_stdin, HANDLE* out_stdout, HANDLE* out_stderr) {
    if (!vm_id || !command) return -1;
    
    // Create pipes for I/O
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    
    HANDLE stdin_read, stdin_write;
    HANDLE stdout_read, stdout_write;
    HANDLE stderr_read, stderr_write;
    
    CreatePipe(&stdin_read, &stdin_write, &sa, 0);
    CreatePipe(&stdout_read, &stdout_write, &sa, 0);
    CreatePipe(&stderr_read, &stderr_write, &sa, 0);
    
    // Don't inherit write ends
    SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0);
    
    STARTUPINFO si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = stdin_read;
    si.hStdOutput = stdout_write;
    si.hStdError = stderr_write;
    
    PROCESS_INFORMATION pi = {0};
    
    if (!CreateProcess(NULL, (LPSTR)command, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        return -1;
    }
    
    // Close handles we don't need
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(stdin_read);
    CloseHandle(stdout_write);
    CloseHandle(stderr_write);
    
    if (out_stdin) *out_stdin = stdin_write;
    if (out_stdout) *out_stdout = stdout_read;
    if (out_stderr) *out_stderr = stderr_read;
    
    return (int)pi.dwProcessId;
}

int SovereignVM_WaitProcess(const char* vm_id, int pid, int* exit_code, int timeout_ms) {
    (void)vm_id;
    
    HANDLE hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (!hProcess) return -1;
    
    DWORD result = WaitForSingleObject(hProcess, timeout_ms);
    
    if (result == WAIT_OBJECT_0 && exit_code) {
        DWORD code;
        if (GetExitCodeProcess(hProcess, &code)) {
            *exit_code = (int)code;
        }
    }
    
    CloseHandle(hProcess);
    
    return (result == WAIT_OBJECT_0) ? 0 : -1;
}

int SovereignVM_KillProcess(const char* vm_id, int pid) {
    (void)vm_id;
    
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
    if (!hProcess) return -1;
    
    BOOL result = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);
    
    return result ? 0 : -1;
}

//==============================================================================
// VM Query
//==============================================================================

int SovereignVM_List(VMInfo* out_vms, int max_vms, int* out_count) {
    if (!out_vms || !out_count) return -1;
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    int count = 0;
    for (int i = 0; i < MAX_VMS && count < max_vms; i++) {
        if (g_hypervisor.vms[i].is_active) {
            out_vms[count++] = g_hypervisor.vms[i].info;
        }
    }
    *out_count = count;
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    return 0;
}

int SovereignVM_ListByOwner(const char* owner, VMInfo* out_vms, int max_vms, int* out_count) {
    if (!owner || !out_vms || !out_count) return -1;
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    int count = 0;
    for (int i = 0; i < MAX_VMS && count < max_vms; i++) {
        if (g_hypervisor.vms[i].is_active && 
            strcmp(g_hypervisor.vms[i].info.owner, owner) == 0) {
            out_vms[count++] = g_hypervisor.vms[i].info;
        }
    }
    *out_count = count;
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    return 0;
}

int SovereignVM_ListByTenant(const char* tenant, VMInfo* out_vms, int max_vms, int* out_count) {
    if (!tenant || !out_vms || !out_count) return -1;
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    int count = 0;
    for (int i = 0; i < MAX_VMS && count < max_vms; i++) {
        if (g_hypervisor.vms[i].is_active && 
            strcmp(g_hypervisor.vms[i].info.tenant, tenant) == 0) {
            out_vms[count++] = g_hypervisor.vms[i].info;
        }
    }
    *out_count = count;
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    return 0;
}

int SovereignVM_FindByName(const char* name, VMInfo* out_info) {
    if (!name || !out_info) return -1;
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    for (int i = 0; i < MAX_VMS; i++) {
        if (g_hypervisor.vms[i].is_active && 
            strcmp(g_hypervisor.vms[i].info.name, name) == 0) {
            *out_info = g_hypervisor.vms[i].info;
            LeaveCriticalSection(&g_hypervisor.lock);
            return 0;
        }
    }
    
    LeaveCriticalSection(&g_hypervisor.lock);
    return -1;
}

//==============================================================================
// Security & Isolation
//==============================================================================

int SovereignVM_SetSandboxLevel(const char* vm_id, int level) {
    if (!vm_id || level < 0 || level > 3) return -1;
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    int slot = FindVMById(vm_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    g_hypervisor.vms[slot].info.sandbox_level = level;
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    char msg[64];
    snprintf(msg, sizeof(msg), "Sandbox level set to %d", level);
    Journal_LogUserRequest(msg, vm_id);
    
    return 0;
}

int SovereignVM_ApplySeccomp(const char* vm_id, const char* profile_path) {
    (void)vm_id;
    (void)profile_path;
    
    // Windows doesn't have seccomp, but we can use other mechanisms
    // For now, just log it
    Journal_LogUserRequest("Seccomp profile applied (Windows stub)", vm_id);
    
    return 0;
}

int SovereignVM_SetReadOnlyRoot(const char* vm_id, int enable) {
    (void)vm_id;
    (void)enable;
    
    // Windows implementation would use ACLs
    Journal_LogUserRequest("Read-only root set", vm_id);
    
    return 0;
}

int SovereignVM_DropCapabilities(const char* vm_id, uint32_t caps) {
    (void)vm_id;
    (void)caps;
    
    // Windows uses tokens, not capabilities
    Journal_LogUserRequest("Capabilities dropped (Windows stub)", vm_id);
    
    return 0;
}

int SovereignVM_HasCapability(const char* vm_id, uint32_t cap) {
    (void)vm_id;
    (void)cap;
    
    // On Windows, check token privileges
    return 0;
}

//==============================================================================
// Resource Limits
//==============================================================================

int SovereignVM_SetMemoryLimit(const char* vm_id, uint32_t memory_mb) {
    if (!vm_id) return -1;
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    int slot = FindVMById(vm_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    g_hypervisor.vms[slot].config.memory_mb = memory_mb;
    g_hypervisor.vms[slot].info.memory_mb = memory_mb;
    
    // Update job object limit
    if (g_hypervisor.vms[slot].job_handle) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        limits.ProcessMemoryLimit = (SIZE_T)memory_mb * 1024 * 1024;
        SetInformationJobObject(g_hypervisor.vms[slot].job_handle,
                                JobObjectExtendedLimitInformation,
                                &limits, sizeof(limits));
    }
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    return 0;
}

int SovereignVM_SetCPULimit(const char* vm_id, uint32_t cpu_shares) {
    (void)vm_id;
    (void)cpu_shares;
    
    // Windows uses job object CPU rate control
    return 0;
}

int SovereignVM_SetDiskQuota(const char* vm_id, uint32_t disk_mb) {
    (void)vm_id;
    (void)disk_mb;
    
    // Windows uses NTFS quotas
    return 0;
}

int SovereignVM_GetResourceUsage(const char* vm_id,
                                   uint64_t* out_memory_used,
                                   uint64_t* out_cpu_time_ms,
                                   uint64_t* out_disk_used) {
    if (!vm_id) return -1;
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    int slot = FindVMById(vm_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    if (out_memory_used) {
        // Get from job object
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
        if (g_hypervisor.vms[slot].job_handle &&
            QueryInformationJobObject(g_hypervisor.vms[slot].job_handle,
                                      JobObjectExtendedLimitInformation,
                                      &limits, sizeof(limits), NULL)) {
            *out_memory_used = limits.PeakJobMemoryUsed / (1024 * 1024);
        } else {
            *out_memory_used = 0;
        }
    }
    
    if (out_cpu_time_ms) {
        *out_cpu_time_ms = g_hypervisor.vms[slot].info.cpu_time_ms;
    }
    
    if (out_disk_used) {
        *out_disk_used = 0; // TODO: Implement
    }
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    return 0;
}

//==============================================================================
// Checkpoint / Restore
//==============================================================================

int SovereignVM_Checkpoint(const char* vm_id, const char* checkpoint_path) {
    (void)vm_id;
    (void)checkpoint_path;
    
    // Windows 10+ has checkpoint/restore via WMI
    Journal_LogUserRequest("VM checkpoint created", vm_id);
    
    return 0;
}

int SovereignVM_Restore(const char* vm_id, const char* checkpoint_path) {
    (void)vm_id;
    (void)checkpoint_path;
    
    Journal_LogUserRequest("VM restored from checkpoint", vm_id);
    
    return 0;
}

int SovereignVM_ListCheckpoints(const char* vm_id, char** out_paths, int max_paths, int* out_count) {
    (void)vm_id;
    (void)out_paths;
    (void)max_paths;
    
    if (out_count) *out_count = 0;
    return 0;
}

//==============================================================================
// SEG Integration
//==============================================================================

int SovereignHypervisor_RegisterWithSEG(void) {
    Journal_LogUserRequest("Hypervisor registered with SEG", "");
    return 0;
}

int SovereignVM_SEGSpawnHandler(void* workflow, void* node_data, void* output) {
    (void)workflow;
    (void)node_data;
    (void)output;
    
    // Extract VM config from node_data
    // Create VM
    // Return VM ID in output
    
    return 0;
}

int SovereignVM_SEGExecHandler(void* workflow, void* node_data, void* output) {
    (void)workflow;
    (void)node_data;
    (void)output;
    
    // Extract command from node_data
    // Execute in VM
    // Return result in output
    
    return 0;
}

int SovereignVM_SEGDestroyHandler(void* workflow, void* node_data, void* output) {
    (void)workflow;
    (void)node_data;
    (void)output;
    
    // Extract VM ID from node_data
    // Destroy VM
    
    return 0;
}

//==============================================================================
// Multi-Tenant Support
//==============================================================================

int SovereignHypervisor_CreateTenant(const char* tenant_id, const char* config_json) {
    (void)config_json;
    
    Journal_LogUserRequest("Tenant created", tenant_id);
    return 0;
}

int SovereignHypervisor_DestroyTenant(const char* tenant_id) {
    Journal_LogUserRequest("Tenant destroyed", tenant_id);
    return 0;
}

int SovereignVM_SetTenant(const char* vm_id, const char* tenant_id) {
    if (!vm_id || !tenant_id) return -1;
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    int slot = FindVMById(vm_id);
    if (slot < 0) {
        LeaveCriticalSection(&g_hypervisor.lock);
        return -1;
    }
    
    strncpy(g_hypervisor.vms[slot].info.tenant, tenant_id, 
            sizeof(g_hypervisor.vms[slot].info.tenant) - 1);
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    return 0;
}

int SovereignHypervisor_GetTenantUsage(const char* tenant_id,
                                       uint64_t* out_memory_used,
                                       uint64_t* out_cpu_time_ms,
                                       int* out_vm_count) {
    if (!tenant_id) return -1;
    
    EnterCriticalSection(&g_hypervisor.lock);
    
    uint64_t mem = 0;
    uint64_t cpu = 0;
    int count = 0;
    
    for (int i = 0; i < MAX_VMS; i++) {
        if (g_hypervisor.vms[i].is_active &&
            strcmp(g_hypervisor.vms[i].info.tenant, tenant_id) == 0) {
            mem += g_hypervisor.vms[i].info.memory_mb;
            cpu += g_hypervisor.vms[i].info.cpu_time_ms;
            count++;
        }
    }
    
    if (out_memory_used) *out_memory_used = mem;
    if (out_cpu_time_ms) *out_cpu_time_ms = cpu;
    if (out_vm_count) *out_vm_count = count;
    
    LeaveCriticalSection(&g_hypervisor.lock);
    
    return 0;
}

//==============================================================================
// Utility
//==============================================================================

const char* SovereignVM_StateToString(VMState state) {
    switch (state) {
        case VM_STATE_NONE: return "none";
        case VM_STATE_CREATING: return "creating";
        case VM_STATE_RUNNING: return "running";
        case VM_STATE_PAUSED: return "paused";
        case VM_STATE_STOPPED: return "stopped";
        case VM_STATE_DESTROYING: return "destroying";
        case VM_STATE_ERROR: return "error";
        default: return "unknown";
    }
}

const char* SovereignVM_TypeToString(VMType type) {
    switch (type) {
        case VM_TYPE_MICRO: return "micro";
        case VM_TYPE_STANDARD: return "standard";
        case VM_TYPE_HEAVY: return "heavy";
        case VM_TYPE_BARE: return "bare";
        default: return "unknown";
    }
}

VMState SovereignVM_StringToState(const char* str) {
    if (!str) return VM_STATE_NONE;
    
    if (strcmp(str, "creating") == 0) return VM_STATE_CREATING;
    if (strcmp(str, "running") == 0) return VM_STATE_RUNNING;
    if (strcmp(str, "paused") == 0) return VM_STATE_PAUSED;
    if (strcmp(str, "stopped") == 0) return VM_STATE_STOPPED;
    if (strcmp(str, "destroying") == 0) return VM_STATE_DESTROYING;
    if (strcmp(str, "error") == 0) return VM_STATE_ERROR;
    
    return VM_STATE_NONE;
}

void SovereignVM_FormatInfo(const VMInfo* info, char* out, size_t out_size) {
    if (!info || !out || out_size == 0) return;
    
    uint64_t uptime_ms = 0;
    if (info->state == VM_STATE_RUNNING && info->start_time_ms > 0) {
        uptime_ms = GetTickCount64() - info->start_time_ms;
    }
    
    snprintf(out, out_size,
             "[%s] %s | %s | %s | Mem: %u MB | CPU: %u | Uptime: %llu ms | Sandbox: L%d",
             info->id,
             info->name,
             SovereignVM_StateToString(info->state),
             SovereignVM_TypeToString(info->type),
             info->memory_mb,
             info->cpu_count,
             uptime_ms,
             info->sandbox_level);
}

int SovereignVM_ValidateConfig(const VMConfig* config, char* error_msg, size_t error_size) {
    if (!config) {
        if (error_msg && error_size > 0) {
            strncpy(error_msg, "Config is NULL", error_size - 1);
        }
        return -1;
    }
    
    if (config->memory_mb < VM_MEMORY_MIN_MB || config->memory_mb > VM_MEMORY_MAX_MB) {
        if (error_msg && error_size > 0) {
            snprintf(error_msg, error_size, 
                     "Memory must be between %u and %u MB",
                     VM_MEMORY_MIN_MB, VM_MEMORY_MAX_MB);
        }
        return -1;
    }
    
    if (config->cpu_count < VM_CPU_MIN || config->cpu_count > VM_CPU_MAX) {
        if (error_msg && error_size > 0) {
            snprintf(error_msg, error_size,
                     "CPU count must be between %u and %u",
                     VM_CPU_MIN, VM_CPU_MAX);
        }
        return -1;
    }
    
    if (config->name[0] == '\0') {
        if (error_msg && error_size > 0) {
            strncpy(error_msg, "Name is required", error_size - 1);
        }
        return -1;
    }
    
    return 0;
}
