//==============================================================================
// SEGCommands.cpp - Phase 11: Sovereign Execution Graph CLI Integration
//
// Adds SEG commands to the unified CLI:
//   seg run <workflow.json>     - Execute workflow
//   seg validate <workflow.json> - Validate workflow
//   seg list                     - List available workflows
//==============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>

#include "../core/SovereignSEG.h"

//==============================================================================
// SEG Command Handlers
//==============================================================================

int SEG_CmdRun(int argc, char** argv, char* output, size_t output_size) {
    if (argc < 2) {
        snprintf(output, output_size,
            "{\"error\":\"Usage: seg run <workflow.json>\"}");
        return -1;
    }
    
    const char* workflow_path = argv[1];
    
    // Load workflow
    SegWorkflow workflow;
    int result = Seg_LoadWorkflow(workflow_path, &workflow);
    
    if (result != 0) {
        snprintf(output, output_size,
            "{\"error\":\"Failed to load workflow: %s\",\"code\":%d}",
            workflow_path, result);
        return -1;
    }
    
    // Validate workflow
    char error_buffer[512];
    if (Seg_ValidateWorkflow(&workflow, error_buffer, sizeof(error_buffer)) != 0) {
        snprintf(output, output_size,
            "{\"error\":\"Invalid workflow: %s\"}", error_buffer);
        return -1;
    }
    
    // Execute workflow
    SegResult seg_result;
    snprintf(output, output_size, "Executing workflow: %s\n", workflow.name);
    
    int exec_result = Seg_ExecuteGraph(&workflow, &seg_result);
    
    // Get JSON summary
    char summary[8192];
    Seg_GetSummaryJSON(&workflow, &seg_result, summary, sizeof(summary));
    
    // Append to output
    strncat(output, "\n", output_size - strlen(output) - 1);
    strncat(output, summary, output_size - strlen(output) - 1);
    
    return exec_result;
}

int SEG_CmdValidate(int argc, char** argv, char* output, size_t output_size) {
    if (argc < 2) {
        snprintf(output, output_size,
            "{\"error\":\"Usage: seg validate <workflow.json>\"}");
        return -1;
    }
    
    const char* workflow_path = argv[1];
    
    // Load workflow
    SegWorkflow workflow;
    int result = Seg_LoadWorkflow(workflow_path, &workflow);
    
    if (result != 0) {
        snprintf(output, output_size,
            "{\"error\":\"Failed to load workflow: %s\",\"code\":%d}",
            workflow_path, result);
        return -1;
    }
    
    // Validate
    char error_buffer[512];
    if (Seg_ValidateWorkflow(&workflow, error_buffer, sizeof(error_buffer)) == 0) {
        snprintf(output, output_size,
            "{\"workflow\":\"%s\",\"valid\":true,\"nodes\":%d}",
            workflow.name, workflow.node_count);
        return 0;
    } else {
        snprintf(output, output_size,
            "{\"workflow\":\"%s\",\"valid\":false,\"error\":\"%s\"}",
            workflow.name, error_buffer);
        return -1;
    }
}

int SEG_CmdHelp(char* output, size_t output_size) {
    snprintf(output, output_size,
        "Sovereign Execution Graph (SEG) v%s\n"
        "\n"
        "Commands:\n"
        "  seg run <workflow.json>     Execute workflow\n"
        "  seg validate <file>         Validate workflow JSON\n"
        "  seg help                    Show this help\n"
        "\n"
        "Workflow Format:\n"
        "  {\n"
        "    \"workflow\": \"name\",\n"
        "    \"nodes\": [\n"
        "      {\n"
        "        \"id\": 1,\n"
        "        \"type\": \"language\",\n"
        "        \"subsystem\": \"rust\",\n"
        "        \"command\": \"compile\",\n"
        "        \"args\": \"main.rs\",\n"
        "        \"depends_on\": []\n"
        "      }\n"
        "    ]\n"
        "  }\n",
        SEG_VERSION);
    return 0;
}

//==============================================================================
// SEG Subsystem Handler
//==============================================================================

int SEGSubsystem_Handler(int argc, char** argv, char* output, size_t output_size) {
    if (argc < 1) {
        return SEG_CmdHelp(output, output_size);
    }
    
    const char* cmd = argv[0];
    
    if (strcmp(cmd, "run") == 0) {
        return SEG_CmdRun(argc, argv, output, output_size);
    }
    else if (strcmp(cmd, "validate") == 0) {
        return SEG_CmdValidate(argc, argv, output, output_size);
    }
    else if (strcmp(cmd, "help") == 0) {
        return SEG_CmdHelp(output, output_size);
    }
    else {
        snprintf(output, output_size,
            "{\"error\":\"Unknown SEG command: %s\"}", cmd);
        return -1;
    }
}

//==============================================================================
// Lifecycle Functions
//==============================================================================

int SEG_Init(void) {
    return Seg_Init();
}

int SEG_Shutdown(void) {
    return Seg_Shutdown();
}

int SEG_GetStatus(char* status, size_t status_size) {
    snprintf(status, status_size,
        "SEG v%s - Execution Graph ready", SEG_VERSION);
    return 0;
}
