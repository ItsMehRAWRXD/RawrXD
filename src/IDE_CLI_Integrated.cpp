// IDE_CLI_Integrated.cpp - Unified IDE CLI hosting GUI and all tools
// Integrates: sovereign_cli, model_manager, native_toolchain, and GUI
// No stubs - only real verified working tools

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <commctrl.h>
#include <richedit.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <direct.h>
#include <process.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")

// Tool paths - REAL verified working executables
#define SOVEREIGN_CLI      "d:\\rawrxd\\sovereign_cli.exe"
#define MODEL_MANAGER      "d:\\rawrxd\\model_manager.exe"
#define C_COMPILER         "d:\\rawrxd\\native_toolchain\\c_compiler_minimal.exe"
#define ASSEMBLER          "d:\\rawrxd\\native_toolchain\\minimal_assembler_fixed.exe"
#define LINKER             "d:\\rawrxd\\native_toolchain\\linker_with_relocations.exe"
#define RAWRXD_GUI         "d:\\rawrxd\\RawrXD.exe"

// Tool registry - only REAL verified tools
struct Tool {
    const char* id;
    const char* name;
    const char* path;
    const char* type;      // "cli", "gui", "compiler", "assembler", "linker"
    const char* category;  // "core", "model", "build", "ide"
    BOOL available;
};

struct Tool g_tools[] = {
    // Core IDE
    {"sovereign",   "Sovereign CLI IDE",        SOVEREIGN_CLI,      "cli",      "core",     FALSE},
    {"rawrxd",      "RawrXD GUI IDE",           RAWRXD_GUI,         "gui",      "ide",      FALSE},
    
    // Model Management
    {"modelmgr",    "Model Manager",            MODEL_MANAGER,      "cli",      "model",    FALSE},
    
    // Native Toolchain (Self-Hosting)
    {"cc",          "C Compiler",               C_COMPILER,         "compiler", "build",    FALSE},
    {"asm",         "Native Assembler",         ASSEMBLER,          "assembler","build",    FALSE},
    {"ld",          "Native Linker",            LINKER,             "linker",   "build",    FALSE},
    
    // End of list
    {NULL, NULL, NULL, NULL, NULL, FALSE}
};

// IDE State
struct IDEState {
    HWND mainWindow;
    HWND consoleWindow;
    HWND guiWindow;
    BOOL guiMode;
    BOOL autonomousMode;
    char currentProject[256];
    char currentFile[256];
};

struct IDEState g_ide = {0};

// Forward declarations
void InitTools();
void PrintBanner();
void PrintTools();
BOOL CheckTool(const char* id);
BOOL LaunchTool(const char* id, const char* args);
BOOL LaunchToolAsync(const char* id, const char* args);
void RunCLILoop();
void LaunchGUI();
void ShowIntegrationMenu(HWND hwnd);

// Initialize tool availability
void InitTools() {
    for (int i = 0; g_tools[i].id != NULL; i++) {
        DWORD attribs = GetFileAttributesA(g_tools[i].path);
        g_tools[i].available = (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY));
    }
}

// Check if tool is available
BOOL CheckTool(const char* id) {
    for (int i = 0; g_tools[i].id != NULL; i++) {
        if (strcmp(g_tools[i].id, id) == 0) {
            return g_tools[i].available;
        }
    }
    return FALSE;
}

// Get tool info
struct Tool* GetTool(const char* id) {
    for (int i = 0; g_tools[i].id != NULL; i++) {
        if (strcmp(g_tools[i].id, id) == 0) {
            return &g_tools[i];
        }
    }
    return NULL;
}

// Launch tool synchronously (wait for completion)
BOOL LaunchTool(const char* id, const char* args) {
    struct Tool* tool = GetTool(id);
    if (!tool || !tool->available) {
        printf("[ERROR] Tool '%s' not available\n", id);
        return FALSE;
    }
    
    printf("[LAUNCH] %s...\n", tool->name);
    
    char cmdLine[1024];
    if (args && *args) {
        sprintf(cmdLine, "\"%s\" %s", tool->path, args);
    } else {
        sprintf(cmdLine, "\"%s\"", tool->path);
    }
    
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    
    // For CLI tools, redirect output to console
    if (strcmp(tool->type, "cli") == 0 || strcmp(tool->type, "compiler") == 0) {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    }
    
    if (CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        printf("[DONE] Exit code: %lu\n", exitCode);
        return exitCode == 0;
    } else {
        printf("[ERROR] Failed to launch: %s (Error: %lu)\n", tool->name, GetLastError());
        return FALSE;
    }
}

// Launch tool asynchronously (don't wait)
BOOL LaunchToolAsync(const char* id, const char* args) {
    struct Tool* tool = GetTool(id);
    if (!tool || !tool->available) {
        printf("[ERROR] Tool '%s' not available\n", id);
        return FALSE;
    }
    
    printf("[LAUNCH] %s (async)...\n", tool->name);
    
    char cmdLine[1024];
    if (args && *args) {
        sprintf(cmdLine, "\"%s\" %s", tool->path, args);
    } else {
        sprintf(cmdLine, "\"%s\"", tool->path);
    }
    
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    
    if (CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        printf("[RUNNING] %s started\n", tool->name);
        return TRUE;
    } else {
        printf("[ERROR] Failed to launch: %s\n", tool->name);
        return FALSE;
    }
}

// Print banner
void PrintBanner() {
    printf("\n");
    printf("=================================================\n");
    printf("  RawrXD IDE - Integrated CLI v2.0\n");
    printf("  Unified CLI hosting GUI and all tools\n");
    printf("=================================================\n");
    printf("\n");
}

// Print available tools
void PrintTools() {
    printf("Available Tools:\n");
    printf("---------------\n");
    
    const char* currentCategory = "";
    for (int i = 0; g_tools[i].id != NULL; i++) {
        if (strcmp(g_tools[i].category, currentCategory) != 0) {
            currentCategory = g_tools[i].category;
            printf("\n[%s]\n", currentCategory);
        }
        
        printf("  %-10s %-25s %s\n", 
               g_tools[i].id,
               g_tools[i].name,
               g_tools[i].available ? "[READY]" : "[MISSING]");
    }
    printf("\n");
}

// Build command: compile C to executable
BOOL BuildC(const char* sourceFile, const char* outputFile) {
    if (!CheckTool("cc") || !CheckTool("asm") || !CheckTool("ld")) {
        printf("[ERROR] Native toolchain not available\n");
        return FALSE;
    }
    
    printf("[BUILD] Compiling %s -> %s\n", sourceFile, outputFile);
    
    // Step 1: C Compiler (C -> ASM)
    char asmFile[256];
    sprintf(asmFile, "temp_%lu.asm", GetTickCount());
    
    char ccArgs[512];
    sprintf(ccArgs, "\"%s\" -o \"%s\"", sourceFile, asmFile);
    
    if (!LaunchTool("cc", ccArgs)) {
        printf("[ERROR] C compilation failed\n");
        return FALSE;
    }
    
    // Step 2: Assembler (ASM -> OBJ)
    char objFile[256];
    sprintf(objFile, "temp_%lu.obj", GetTickCount());
    
    char asmArgs[512];
    sprintf(asmArgs, "\"%s\" \"%s\"", asmFile, objFile);
    
    if (!LaunchTool("asm", asmArgs)) {
        printf("[ERROR] Assembly failed\n");
        DeleteFileA(asmFile);
        return FALSE;
    }
    
    // Step 3: Linker (OBJ -> EXE)
    char ldArgs[512];
    sprintf(ldArgs, "\"%s\" \"%s\"", objFile, outputFile);
    
    if (!LaunchTool("ld", ldArgs)) {
        printf("[ERROR] Linking failed\n");
        DeleteFileA(asmFile);
        DeleteFileA(objFile);
        return FALSE;
    }
    
    // Cleanup temp files
    DeleteFileA(asmFile);
    DeleteFileA(objFile);
    
    printf("[SUCCESS] Built: %s\n", outputFile);
    return TRUE;
}

// Launch GUI mode
void LaunchGUI() {
    if (!CheckTool("rawrxd")) {
        printf("[ERROR] RawrXD GUI not available\n");
        return;
    }
    
    printf("[LAUNCH] Starting RawrXD GUI...\n");
    LaunchToolAsync("rawrxd", NULL);
}

// Launch Sovereign CLI IDE
void LaunchSovereign() {
    if (!CheckTool("sovereign")) {
        printf("[ERROR] Sovereign CLI not available\n");
        return;
    }
    
    printf("[LAUNCH] Starting Sovereign CLI IDE...\n");
    printf("[NOTE] This will take over the console. Type 'quit' to return.\n\n");
    
    // Launch sovereign_cli which is interactive
    LaunchTool("sovereign", NULL);
    
    printf("\n[RETURNED] Sovereign CLI exited\n");
}

// Launch Model Manager
void LaunchModelManager() {
    if (!CheckTool("modelmgr")) {
        printf("[ERROR] Model Manager not available\n");
        return;
    }
    
    printf("[LAUNCH] Starting Model Manager...\n");
    printf("[NOTE] This will take over the console. Select option 5 to exit.\n\n");
    
    // Launch model_manager which is interactive
    LaunchTool("modelmgr", NULL);
    
    printf("\n[RETURNED] Model Manager exited\n");
}

// Show help
void ShowHelp() {
    printf("Commands:\n");
    printf("  help              Show this help\n");
    printf("  tools             List available tools\n");
    printf("  gui               Launch RawrXD GUI\n");
    printf("  sovereign         Launch Sovereign CLI IDE\n");
    printf("  models            Launch Model Manager\n");
    printf("  build <file>      Build C file to executable\n");
    printf("  compile <file>    Alias for build\n");
    printf("  run <tool>        Run a tool by ID\n");
    printf("  status            Show IDE status\n");
    printf("  quit/exit         Exit IDE CLI\n");
    printf("\n");
    printf("Tool IDs: sovereign, rawrxd, modelmgr, cc, asm, ld\n");
    printf("\n");
}

// Show status
void ShowStatus() {
    printf("IDE Status:\n");
    printf("-----------\n");
    printf("  GUI Mode:     %s\n", g_ide.guiMode ? "Active" : "Inactive");
    printf("  Autonomous:   %s\n", g_ide.autonomousMode ? "Enabled" : "Disabled");
    printf("  Current File: %s\n", g_ide.currentFile[0] ? g_ide.currentFile : "(none)");
    printf("  Project:      %s\n", g_ide.currentProject[0] ? g_ide.currentProject : "(none)");
    printf("\n");
    
    int available = 0, total = 0;
    for (int i = 0; g_tools[i].id != NULL; i++) {
        total++;
        if (g_tools[i].available) available++;
    }
    printf("Tools: %d/%d available\n\n", available, total);
}

// Main CLI loop
void RunCLILoop() {
    char input[1024];
    
    while (1) {
        printf("RawrXD> ");
        if (!fgets(input, sizeof(input), stdin)) {
            break;
        }
        
        // Remove newline
        size_t len = strlen(input);
        if (len > 0 && input[len-1] == '\n') {
            input[len-1] = '\0';
        }
        
        // Parse command
        char* cmd = strtok(input, " \t");
        if (!cmd || *cmd == '\0') continue;
        
        if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
            printf("[EXIT] Shutting down IDE CLI...\n");
            break;
        }
        else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
            ShowHelp();
        }
        else if (strcmp(cmd, "tools") == 0 || strcmp(cmd, "list") == 0) {
            PrintTools();
        }
        else if (strcmp(cmd, "status") == 0) {
            ShowStatus();
        }
        else if (strcmp(cmd, "gui") == 0) {
            LaunchGUI();
        }
        else if (strcmp(cmd, "sovereign") == 0 || strcmp(cmd, "cli") == 0) {
            LaunchSovereign();
        }
        else if (strcmp(cmd, "models") == 0 || strcmp(cmd, "modelmgr") == 0) {
            LaunchModelManager();
        }
        else if (strcmp(cmd, "build") == 0 || strcmp(cmd, "compile") == 0) {
            char* file = strtok(NULL, " \t");
            if (!file) {
                printf("[ERROR] Usage: build <source.c>\n");
                continue;
            }
            
            char outFile[256];
            char* dot = strrchr(file, '.');
            if (dot) {
                strncpy(outFile, file, dot - file);
                outFile[dot - file] = '\0';
                strcat(outFile, ".exe");
            } else {
                sprintf(outFile, "%s.exe", file);
            }
            
            BuildC(file, outFile);
        }
        else if (strcmp(cmd, "run") == 0) {
            char* tool = strtok(NULL, " \t");
            if (!tool) {
                printf("[ERROR] Usage: run <tool_id>\n");
                continue;
            }
            
            // Collect remaining args
            char args[512] = {0};
            char* arg;
            while ((arg = strtok(NULL, " \t")) != NULL) {
                if (args[0]) strcat(args, " ");
                strcat(args, arg);
            }
            
            LaunchTool(tool, args[0] ? args : NULL);
        }
        else {
            printf("[ERROR] Unknown command: %s\n", cmd);
            printf("Type 'help' for available commands\n");
        }
    }
}

// Entry point
int main(int argc, char* argv[]) {
    // Initialize
    InitTools();
    
    // Check command line
    if (argc > 1) {
        if (strcmp(argv[1], "--gui") == 0 || strcmp(argv[1], "/gui") == 0) {
            PrintBanner();
            LaunchGUI();
            return 0;
        }
        else if (strcmp(argv[1], "--sovereign") == 0) {
            PrintBanner();
            LaunchSovereign();
            return 0;
        }
        else if (strcmp(argv[1], "--models") == 0) {
            PrintBanner();
            LaunchModelManager();
            return 0;
        }
        else if (strcmp(argv[1], "--build") == 0 && argc > 2) {
            PrintBanner();
            return BuildC(argv[2], "output.exe") ? 0 : 1;
        }
        else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "/?") == 0) {
            PrintBanner();
            ShowHelp();
            return 0;
        }
    }
    
    // Default: Interactive CLI mode
    PrintBanner();
    PrintTools();
    ShowHelp();
    RunCLILoop();
    
    return 0;
}
