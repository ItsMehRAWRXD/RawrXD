//==============================================================================
// AutoLoopCommands.cpp - Phase 12: Autonomous Loop CLI Integration
//
// Adds AutoLoop commands to the unified CLI:
//   loop run <template> [options]  - Execute autonomous loop
//   loop create <template>         - Create loop from template
//   loop status                    - Show active loops
//==============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>

#include "../core/SovereignAutoLoop.h"

//==============================================================================
// Command Handlers
//==============================================================================

int AutoLoop_CmdRun(int argc, char** argv, char* output, size_t output_size) {
    if (argc < 2) {
        snprintf(output, output_size,
            "{\"error\":\"Usage: loop run <template> [target_file] [language] [spec]\"}\n"
            "\n"
            "Templates:\n"
            "  write_execute_fix    - Generate, run, fix until success\n"
            "  optimize_benchmark   - Optimize until performance converges\n"
            "  multi_language       - Generate in multiple languages\n");
        return -1;
    }
    
    const char* template_name = argv[1];
    const char* target_file = (argc > 2) ? argv[2] : "generated.rs";
    const char* language = (argc > 3) ? argv[3] : "rust";
    const char* spec = (argc > 4) ? argv[4] : "Generate a hello world program";
    
    // Initialize AutoLoop
    AutoLoop_Init();
    
    // Create loop from template
    AutoLoop loop;
    int result = -1;
    
    if (strcmp(template_name, "write_execute_fix") == 0) {
        result = AutoLoop_CreateWriteExecuteFix(target_file, language, spec, &loop);
    } else if (strcmp(template_name, "optimize_benchmark") == 0) {
        result = AutoLoop_CreateOptimizeBenchmark(target_file, language, "throughput", &loop);
    } else if (strcmp(template_name, "multi_language") == 0) {
        const char* langs[] = { "rust", "go", "python" };
        result = AutoLoop_CreateMultiLanguage(spec, langs, 3, &loop);
    } else {
        snprintf(output, output_size,
            "{\"error\":\"Unknown template: %s\"}", template_name);
        return -1;
    }
    
    if (result != 0) {
        snprintf(output, output_size,
            "{\"error\":\"Failed to create loop from template\"}");
        return -1;
    }
    
    // Execute loop
    AutoLoopContext ctx;
    AutoLoopResult loop_result;
    
    // Set context
    strncpy(ctx.source_file, target_file, sizeof(ctx.source_file) - 1);
    strncpy(ctx.target_language, language, sizeof(ctx.target_language) - 1);
    
    snprintf(output, output_size, 
        "Starting AutoLoop: %s\n"
        "Target: %s\n"
        "Language: %s\n"
        "Max iterations: %d\n"
        "\n",
        loop.name, target_file, language, loop.max_iterations);
    
    int exec_result = AutoLoop_Execute(&loop, &ctx, &loop_result);
    
    // Get summary
    char summary[8192];
    AutoLoop_GetSummaryJSON(&loop, &loop_result, summary, sizeof(summary));
    
    // Append to output
    strncat(output, "\n=== AutoLoop Complete ===\n\n", 
            output_size - strlen(output) - 1);
    strncat(output, summary, output_size - strlen(output) - 1);
    
    return exec_result;
}

int AutoLoop_CmdCreate(int argc, char** argv, char* output, size_t output_size) {
    if (argc < 3) {
        snprintf(output, output_size,
            "{\"error\":\"Usage: loop create <template> <output.json>\"}");
        return -1;
    }
    
    const char* template_name = argv[1];
    const char* output_path = argv[2];
    
    AutoLoop loop;
    int result = -1;
    
    if (strcmp(template_name, "write_execute_fix") == 0) {
        result = AutoLoop_CreateWriteExecuteFix("main.rs", "rust", 
                                                  "Generate hello world", &loop);
    } else if (strcmp(template_name, "optimize_benchmark") == 0) {
        result = AutoLoop_CreateOptimizeBenchmark("main.rs", "rust", 
                                                   "throughput", &loop);
    } else {
        snprintf(output, output_size,
            "{\"error\":\"Unknown template: %s\"}", template_name);
        return -1;
    }
    
    if (result != 0) {
        snprintf(output, output_size,
            "{\"error\":\"Failed to create loop\"}");
        return -1;
    }
    
    // Save to file
    if (AutoLoop_Save(&loop, output_path) != 0) {
        snprintf(output, output_size,
            "{\"error\":\"Failed to save loop to %s\"}", output_path);
        return -1;
    }
    
    snprintf(output, output_size,
        "{\"success\":true,\"template\":\"%s\",\"output\":\"%s\",\"steps\":%d}",
        template_name, output_path, loop.step_count);
    
    return 0;
}

int AutoLoop_CmdHelp(char* output, size_t output_size) {
    snprintf(output, output_size,
        "Sovereign AutoLoop v%s - Autonomous Code Generation\n"
        "\n"
        "Commands:\n"
        "  loop run <template> [file] [lang] [spec]  Execute autonomous loop\n"
        "  loop create <template> <output.json>       Create loop definition\n"
        "  loop help                                 Show this help\n"
        "\n"
        "Templates:\n"
        "  write_execute_fix    - Generate, compile, run, fix errors\n"
        "  optimize_benchmark   - Optimize until performance converges\n"
        "  multi_language       - Generate in multiple languages, choose best\n"
        "\n"
        "Examples:\n"
        "  loop run write_execute_fix main.rs rust \"Hello world\"\n"
        "  loop run optimize_benchmark kernel.rs rust throughput\n"
        "  loop create write_execute_fix my_loop.json\n",
        AUTOLOOP_VERSION);
    return 0;
}

//==============================================================================
// AutoLoop Subsystem Handler
//==============================================================================

int AutoLoopSubsystem_Handler(int argc, char** argv, char* output, size_t output_size) {
    if (argc < 1) {
        return AutoLoop_CmdHelp(output, output_size);
    }
    
    const char* cmd = argv[0];
    
    if (strcmp(cmd, "run") == 0) {
        return AutoLoop_CmdRun(argc, argv, output, output_size);
    }
    else if (strcmp(cmd, "create") == 0) {
        return AutoLoop_CmdCreate(argc, argv, output, output_size);
    }
    else if (strcmp(cmd, "help") == 0) {
        return AutoLoop_CmdHelp(output, output_size);
    }
    else {
        snprintf(output, output_size,
            "{\"error\":\"Unknown AutoLoop command: %s\"}", cmd);
        return -1;
    }
}

//==============================================================================
// Lifecycle Functions
//==============================================================================

int AutoLoopSubsystem_Init(void) {
    return AutoLoop_Init();
}

int AutoLoopSubsystem_Shutdown(void) {
    return AutoLoop_Shutdown();
}

int AutoLoopSubsystem_GetStatus(char* status, size_t status_size) {
    snprintf(status, status_size,
        "AutoLoop v%s - Autonomous code generation ready", AUTOLOOP_VERSION);
    return 0;
}
