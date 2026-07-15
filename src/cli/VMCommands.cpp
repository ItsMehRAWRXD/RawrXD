//==============================================================================
// VMCommands.cpp - Phase 16: CLI Commands for VM Management
//
// CLI commands:
//   agent vm create <name> [options]    - Create new VM
//   agent vm start <id>                 - Start VM
//   agent vm stop <id>                  - Stop VM
//   agent vm destroy <id>               - Destroy VM
//   agent vm list                       - List all VMs
//   agent vm exec <id> <command>        - Execute command in VM
//   agent vm checkpoint <id>            - Create checkpoint
//   agent vm status <id>                - Show VM status
//==============================================================================

#include "../core/SovereignHypervisor.h"
#include "../core/ExecutionJournal.h"
#include <cstdio>
#include <cstring>

//==============================================================================
// Command: vm create
//==============================================================================

int CLI_VMCreate(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: agent vm create <name> [options]\n");
        printf("\nOptions:\n");
        printf("  --type <micro|standard|heavy>   VM type (default: standard)\n");
        printf("  --memory <MB>                   Memory in MB (default: 512)\n");
        printf("  --cpu <n>                       CPU count (default: 2)\n");
        printf("  --sandbox <0-3>                 Sandbox level (default: 1)\n");
        printf("  --tenant <id>                   Assign to tenant\n");
        return 1;
    }

    const char* name = argv[2];

    // Default config
    VMConfig config = {0};
    strncpy(config.name, name, sizeof(config.name) - 1);
    config.type = VM_TYPE_STANDARD;
    config.memory_mb = 512;
    config.cpu_count = 2;
    config.enable_seccomp = 1;
    config.read_only_root = 0;

    // Parse options
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
            const char* type = argv[++i];
            if (strcmp(type, "micro") == 0) config.type = VM_TYPE_MICRO;
            else if (strcmp(type, "standard") == 0) config.type = VM_TYPE_STANDARD;
            else if (strcmp(type, "heavy") == 0) config.type = VM_TYPE_HEAVY;
        } else if (strcmp(argv[i], "--memory") == 0 && i + 1 < argc) {
            config.memory_mb = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--cpu") == 0 && i + 1 < argc) {
            config.cpu_count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--sandbox") == 0 && i + 1 < argc) {
            int level = atoi(argv[++i]);
            config.enable_seccomp = (level >= 2);
            config.read_only_root = (level >= 3);
        }
    }

    // Validate
    char error_msg[256];
    if (SovereignVM_ValidateConfig(&config, error_msg, sizeof(error_msg)) != 0) {
        printf("Error: %s\n", error_msg);
        return 1;
    }

    // Create VM
    char vm_id[32];
    if (SovereignVM_Create(&config, vm_id, sizeof(vm_id)) != 0) {
        printf("Error: Failed to create VM\n");
        return 1;
    }

    printf("VM created: %s\n", vm_id);
    printf("  Name: %s\n", config.name);
    printf("  Type: %s\n", SovereignVM_TypeToString(config.type));
    printf("  Memory: %u MB\n", config.memory_mb);
    printf("  CPU: %u\n", config.cpu_count);

    // Auto-start
    SovereignVM_Start(vm_id);
    printf("  Status: Running\n");

    Journal_LogUserRequest("CLI VM created", vm_id);

    return 0;
}

//==============================================================================
// Command: vm start
//==============================================================================

int CLI_VMStart(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: agent vm start <vm-id>\n");
        return 1;
    }

    const char* vm_id = argv[2];

    if (SovereignVM_Start(vm_id) != 0) {
        printf("Error: Failed to start VM %s\n", vm_id);
        return 1;
    }

    printf("VM %s started\n", vm_id);

    Journal_LogUserRequest("CLI VM started", vm_id);

    return 0;
}

//==============================================================================
// Command: vm stop
//==============================================================================

int CLI_VMStop(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: agent vm stop <vm-id> [--force]\n");
        return 1;
    }

    const char* vm_id = argv[2];
    int force = 0;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--force") == 0) {
            force = 1;
        }
    }

    int result;
    if (force) {
        result = SovereignVM_Kill(vm_id);
    } else {
        result = SovereignVM_Stop(vm_id, 10000);
    }

    if (result != 0) {
        printf("Error: Failed to stop VM %s\n", vm_id);
        return 1;
    }

    printf("VM %s stopped%s\n", vm_id, force ? " (forced)" : "");

    Journal_LogUserRequest("CLI VM stopped", vm_id);

    return 0;
}

//==============================================================================
// Command: vm destroy
//==============================================================================

int CLI_VMDestroy(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: agent vm destroy <vm-id>\n");
        return 1;
    }

    const char* vm_id = argv[2];

    // Confirm
    printf("Destroying VM %s...\n", vm_id);

    if (SovereignVM_Destroy(vm_id) != 0) {
        printf("Error: Failed to destroy VM %s\n", vm_id);
        return 1;
    }

    printf("VM %s destroyed\n", vm_id);

    Journal_LogUserRequest("CLI VM destroyed", vm_id);

    return 0;
}

//==============================================================================
// Command: vm list
//==============================================================================

int CLI_VMList(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    VMInfo vms[32];
    int count;

    if (SovereignVM_List(vms, 32, &count) != 0) {
        printf("Error: Failed to list VMs\n");
        return 1;
    }

    if (count == 0) {
        printf("No VMs found.\n");
        printf("Use 'agent vm create <name>' to create one.\n");
        return 0;
    }

    printf("Virtual Machines (%d):\n\n", count);
    printf("%-12s %-20s %-12s %-10s %-8s %-6s %-8s %-10s\n",
           "ID", "Name", "State", "Type", "Memory", "CPU", "Sandbox", "Tenant");
    printf("--------------------------------------------------------------------------------\n");

    for (int i = 0; i < count; i++) {
        printf("%-12s %-20s %-12s %-10s %-6u MB %-4u   L%-3d     %-10s\n",
               vms[i].id,
               vms[i].name,
               SovereignVM_StateToString(vms[i].state),
               SovereignVM_TypeToString(vms[i].type),
               vms[i].memory_mb,
               vms[i].cpu_count,
               vms[i].sandbox_level,
               vms[i].tenant[0] ? vms[i].tenant : "-");
    }

    return 0;
}

//==============================================================================
// Command: vm exec
//==============================================================================

int CLI_VMExec(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: agent vm exec <vm-id> <command> [args...]\n");
        return 1;
    }

    const char* vm_id = argv[2];
    const char* command = argv[3];

    // Build command line
    char cmd_line[1024];
    strncpy(cmd_line, command, sizeof(cmd_line) - 1);

    for (int i = 4; i < argc && strlen(cmd_line) < sizeof(cmd_line) - 2; i++) {
        strcat(cmd_line, " ");
        strncat(cmd_line, argv[i], sizeof(cmd_line) - strlen(cmd_line) - 1);
    }

    printf("Executing in VM %s: %s\n", vm_id, cmd_line);

    int pid = SovereignVM_Exec(vm_id, cmd_line, NULL, NULL);
    if (pid < 0) {
        printf("Error: Failed to execute command\n");
        return 1;
    }

    printf("Process started (PID: %d)\n", pid);

    // Wait for completion
    int exit_code;
    if (SovereignVM_WaitProcess(vm_id, pid, &exit_code, 30000) == 0) {
        printf("Process exited with code: %d\n", exit_code);
    } else {
        printf("Process timed out or failed\n");
    }

    Journal_LogUserRequest("CLI VM exec", vm_id);

    return 0;
}

//==============================================================================
// Command: vm checkpoint
//==============================================================================

int CLI_VMCheckpoint(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: agent vm checkpoint <vm-id> [checkpoint-name]\n");
        return 1;
    }

    const char* vm_id = argv[2];
    char checkpoint_name[256];

    if (argc >= 4) {
        strncpy(checkpoint_name, argv[3], sizeof(checkpoint_name) - 1);
    } else {
        snprintf(checkpoint_name, sizeof(checkpoint_name), "%s_%llu",
                 vm_id, GetTickCount64());
    }

    char path[MAX_PATH];
    snprintf(path, sizeof(path), "checkpoints/%s.chk", checkpoint_name);

    printf("Creating checkpoint for VM %s...\n", vm_id);

    if (SovereignVM_Checkpoint(vm_id, path) != 0) {
        printf("Error: Failed to create checkpoint\n");
        return 1;
    }

    printf("Checkpoint created: %s\n", checkpoint_name);

    Journal_LogUserRequest("CLI VM checkpoint", vm_id);

    return 0;
}

//==============================================================================
// Command: vm status
//==============================================================================

int CLI_VMStatus(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: agent vm status <vm-id>\n");
        return 1;
    }

    const char* vm_id = argv[2];

    VMInfo info;
    if (SovereignVM_GetInfo(vm_id, &info) != 0) {
        printf("Error: VM %s not found\n", vm_id);
        return 1;
    }

    printf("VM Status: %s\n", vm_id);
    printf("===================\n\n");
    printf("Name:        %s\n", info.name);
    printf("State:       %s\n", SovereignVM_StateToString(info.state));
    printf("Type:        %s\n", SovereignVM_TypeToString(info.type));
    printf("Memory:      %u MB\n", info.memory_mb);
    printf("CPU:         %u cores\n", info.cpu_count);
    printf("Sandbox:     Level %d\n", info.sandbox_level);
    printf("Tenant:      %s\n", info.tenant[0] ? info.tenant : "-");
    printf("Owner:       %s\n", info.owner[0] ? info.owner : "-");

    // Resource usage
    uint64_t mem_used, cpu_time, disk_used;
    if (SovereignVM_GetResourceUsage(vm_id, &mem_used, &cpu_time, &disk_used) == 0) {
        printf("\nResource Usage:\n");
        printf("  Memory Used: %llu MB\n", mem_used);
        printf("  CPU Time:    %llu ms\n", cpu_time);
        printf("  Disk Used:   %llu MB\n", disk_used);
    }

    if (info.state == VM_STATE_RUNNING && info.start_time_ms > 0) {
        uint64_t uptime = GetTickCount64() - info.start_time_ms;
        printf("\nUptime: %llu ms\n", uptime);
    }

    return 0;
}

//==============================================================================
// Command Router
//==============================================================================

int CLI_VMCommand(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: agent vm <subcommand> [args]\n");
        printf("\nSubcommands:\n");
        printf("  create <name> [options]  Create new VM\n");
        printf("  start <id>               Start VM\n");
        printf("  stop <id> [--force]      Stop VM\n");
        printf("  destroy <id>               Destroy VM\n");
        printf("  list                       List all VMs\n");
        printf("  exec <id> <command>        Execute command in VM\n");
        printf("  checkpoint <id> [name]     Create checkpoint\n");
        printf("  status <id>                Show VM status\n");
        return 1;
    }

    const char* subcmd = argv[1];

    if (strcmp(subcmd, "create") == 0) {
        return CLI_VMCreate(argc, argv);
    } else if (strcmp(subcmd, "start") == 0) {
        return CLI_VMStart(argc, argv);
    } else if (strcmp(subcmd, "stop") == 0) {
        return CLI_VMStop(argc, argv);
    } else if (strcmp(subcmd, "destroy") == 0) {
        return CLI_VMDestroy(argc, argv);
    } else if (strcmp(subcmd, "list") == 0) {
        return CLI_VMList(argc, argv);
    } else if (strcmp(subcmd, "exec") == 0) {
        return CLI_VMExec(argc, argv);
    } else if (strcmp(subcmd, "checkpoint") == 0) {
        return CLI_VMCheckpoint(argc, argv);
    } else if (strcmp(subcmd, "status") == 0) {
        return CLI_VMStatus(argc, argv);
    } else {
        printf("Unknown subcommand: %s\n", subcmd);
        return 1;
    }
}
