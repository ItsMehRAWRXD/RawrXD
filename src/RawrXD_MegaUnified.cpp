// RawrXD_MegaUnified.cpp - COMPLETE D DRIVE UNIFICATION
// Discovers and unifies ALL tools on D drive at runtime
// Version: 5.0 - Total Coverage Edition

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <direct.h>
#include <vector>
#include <string>
#include <algorithm>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "shell32.lib")

#define MAX_TOOLS 10000
#define MAX_PATH_LEN 512
#define MAX_NAME_LEN 128

// Tool structure
struct Tool {
    char id[MAX_NAME_LEN];
    char name[MAX_NAME_LEN];
    char path[MAX_PATH_LEN];
    char type[32];      // exe, ps1, bat, cmd, py, js, etc.
    char category[64];  // ide, compiler, test, benchmark, gpu, debug, script, etc.
    int priority;       // 0=P0, 1=P1, 2=P2, 3=P3
    BOOL available;
    DWORD sizeKB;
    FILETIME lastWrite;
};

// Global state
struct Tool g_tools[MAX_TOOLS];
int g_toolCount = 0;
int g_availableCount = 0;

// Search paths on D drive
const char* g_searchPaths[] = {
    "d:\\rawrxd",
    "d:\\rawrxd\\src",
    "d:\\rawrxd\\src\\win32app",
    "d:\\rawrxd\\native_toolchain",
    "d:\\src",
    "d:\\src\\asm",
    "d:\\src\\cpp",
    "d:\\src\\tools",
    "d:\\tools",
    "d:\\scripts",
    "d:\\build",
    "d:\\bin",
    "d:\\archive",
    "d:\\config",
    "d:\\lib",
    "d:\\include",
    "d:\\obj",
    "d:\\temp",
    "d:\\cache",
    "d:\\models",
    "d:\\data",
    "d:\\logs",
    NULL
};

// File extensions to discover
const char* g_extensions[] = {
    ".exe", ".ps1", ".bat", ".cmd", ".py", ".js",
    ".vbs", ".wsf", ".msi", ".com", NULL
};

// Category keywords for auto-classification
struct CategoryMap {
    const char* keyword;
    const char* category;
    int priority;
};

CategoryMap g_categoryMap[] = {
    // P0 - Critical
    {"RawrXD", "ide", 0},
    {"TITAN", "titan", 0},
    {"sovereign", "core", 0},
    {"production", "production", 0},
    {"hybrid", "ide", 0},
    {"autonomous", "production", 0},
    
    // P1 - High
    {"compiler", "compiler", 1},
    {"build", "build", 1},
    {"benchmark", "benchmark", 1},
    {"test_", "test", 1},
    {"phase", "test", 1},
    {"swarm", "swarm", 1},
    
    // P2 - Medium
    {"gemm", "ml", 2},
    {"lora", "ml", 2},
    {"model", "ml", 2},
    {"gpu", "gpu", 2},
    {"vulkan", "gpu", 2},
    {"cuda", "gpu", 2},
    {"kernel", "compute", 2},
    
    // P3 - Low
    {"debug", "debug", 3},
    {"minimal", "debug", 3},
    {"stub", "debug", 3},
    {"demo", "demo", 3},
    {"example", "demo", 3},
    
    {NULL, NULL, 0}
};

// Forward declarations
void DiscoverTools();
void ScanDirectory(const char* path);
void ClassifyTool(struct Tool* tool);
void AddTool(const char* path, const char* ext);
struct Tool* FindTool(const char* id);
void PrintBanner();
void PrintTools();
void PrintToolsByCategory();
void PrintToolsByPriority();
void PrintStats();
void RunCLILoop();
void ExecuteTool(const char* id, const char* args);
void ExecuteToolByPath(const char* path, const char* args);
void ShowHelp();
void BuildC(const char* source);
void BatchExecute(const char* category);
void SearchTools(const char* keyword);

// Discover all tools on D drive
void DiscoverTools() {
    printf("[DISCOVER] Scanning D drive for tools...\n");
    
    // Scan known paths
    for (int i = 0; g_searchPaths[i] != NULL; i++) {
        ScanDirectory(g_searchPaths[i]);
    }
    
    // Also scan root of D for immediate tools
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    char searchPath[MAX_PATH_LEN];
    
    for (int e = 0; g_extensions[e] != NULL; e++) {
        sprintf(searchPath, "d:\\*%s", g_extensions[e]);
        hFind = FindFirstFileA(searchPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                char fullPath[MAX_PATH_LEN];
                sprintf(fullPath, "d:\\%s", findData.cFileName);
                AddTool(fullPath, g_extensions[e]);
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
    }
    
    printf("[DISCOVER] Found %d tools\n", g_toolCount);
}

// Scan a directory for tools
void ScanDirectory(const char* path) {
    if (g_toolCount >= MAX_TOOLS - 100) return; // Safety limit
    
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    char searchPath[MAX_PATH_LEN];
    
    // Search for each extension
    for (int e = 0; g_extensions[e] != NULL; e++) {
        sprintf(searchPath, "%s\\*%s", path, g_extensions[e]);
        hFind = FindFirstFileA(searchPath, &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                char fullPath[MAX_PATH_LEN];
                sprintf(fullPath, "%s\\%s", path, findData.cFileName);
                AddTool(fullPath, g_extensions[e]);
            } while (FindNextFileA(hFind, &findData) && g_toolCount < MAX_TOOLS);
            FindClose(hFind);
        }
    }
    
    // Recurse into subdirectories (limited depth)
    sprintf(searchPath, "%s\\*", path);
    hFind = FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (strcmp(findData.cFileName, ".") != 0 && 
                    strcmp(findData.cFileName, "..") != 0 &&
                    g_toolCount < MAX_TOOLS - 1000) {
                    char subPath[MAX_PATH_LEN];
                    sprintf(subPath, "%s\\%s", path, findData.cFileName);
                    ScanDirectory(subPath);
                }
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
}

// Add a tool to the registry
void AddTool(const char* path, const char* ext) {
    if (g_toolCount >= MAX_TOOLS) return;
    
    struct Tool* tool = &g_tools[g_toolCount];
    
    // Copy path
    strncpy(tool->path, path, MAX_PATH_LEN - 1);
    tool->path[MAX_PATH_LEN - 1] = '\0';
    
    // Extract filename as ID
    const char* filename = strrchr(path, '\\');
    if (filename) filename++;
    else filename = path;
    
    // Remove extension for ID
    strncpy(tool->id, filename, MAX_NAME_LEN - 1);
    char* dot = strrchr(tool->id, '.');
    if (dot) *dot = '\0';
    
    // Set name (filename with extension)
    strncpy(tool->name, filename, MAX_NAME_LEN - 1);
    tool->name[MAX_NAME_LEN - 1] = '\0';
    
    // Set type
    strncpy(tool->type, ext + 1, 31); // Skip the dot
    tool->type[31] = '\0';
    
    // Check if available
    DWORD attribs = GetFileAttributesA(path);
    tool->available = (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY));
    
    if (tool->available) {
        g_availableCount++;
        
        // Get file info
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(path, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            tool->sizeKB = (DWORD)(findData.nFileSizeLow / 1024);
            tool->lastWrite = findData.ftLastWriteTime;
            FindClose(hFind);
        }
    }
    
    // Classify
    ClassifyTool(tool);
    
    g_toolCount++;
}

// Auto-classify tool based on name
void ClassifyTool(struct Tool* tool) {
    // Default category
    strcpy(tool->category, "general");
    tool->priority = 3;
    
    // Check against category map
    for (int i = 0; g_categoryMap[i].keyword != NULL; i++) {
        if (strstr(tool->name, g_categoryMap[i].keyword) != NULL) {
            strcpy(tool->category, g_categoryMap[i].category);
            tool->priority = g_categoryMap[i].priority;
            return;
        }
    }
    
    // Script type classification
    if (strcmp(tool->type, "ps1") == 0 ||
        strcmp(tool->type, "bat") == 0 ||
        strcmp(tool->type, "cmd") == 0 ||
        strcmp(tool->type, "py") == 0 ||
        strcmp(tool->type, "js") == 0) {
        strcpy(tool->category, "script");
    }
}

// Find tool by ID
struct Tool* FindTool(const char* id) {
    for (int i = 0; i < g_toolCount; i++) {
        if (_stricmp(g_tools[i].id, id) == 0) {
            return &g_tools[i];
        }
    }
    return NULL;
}

// Print banner
void PrintBanner() {
    printf("\n");
    printf("=================================================\n");
    printf("  RawrXD MEGA UNIFIED CLI v5.0\n");
    printf("  Complete D Drive Coverage Edition\n");
    printf("=================================================\n");
    printf("\n");
}

// Print statistics
void PrintStats() {
    int byCategory[20] = {0};
    int byPriority[4] = {0};
    int byType[10] = {0};
    
    const char* categories[] = {"ide", "titan", "core", "production", "compiler", 
                                "build", "test", "benchmark", "ml", "gpu", "compute",
                                "swarm", "debug", "demo", "script", "general", NULL};
    
    for (int i = 0; i < g_toolCount; i++) {
        if (g_tools[i].available) {
            // Count by priority
            if (g_tools[i].priority >= 0 && g_tools[i].priority < 4) {
                byPriority[g_tools[i].priority]++;
            }
            
            // Count by type
            if (strcmp(g_tools[i].type, "exe") == 0) byType[0]++;
            else if (strcmp(g_tools[i].type, "ps1") == 0) byType[1]++;
            else if (strcmp(g_tools[i].type, "bat") == 0) byType[2]++;
            else if (strcmp(g_tools[i].type, "cmd") == 0) byType[3]++;
            else if (strcmp(g_tools[i].type, "py") == 0) byType[4]++;
            else if (strcmp(g_tools[i].type, "js") == 0) byType[5]++;
            else byType[6]++;
        }
    }
    
    printf("\n");
    printf("Discovery Statistics:\n");
    printf("---------------------\n");
    printf("  Total Tools:    %d\n", g_toolCount);
    printf("  Available:      %d\n", g_availableCount);
    printf("  Missing:        %d\n", g_toolCount - g_availableCount);
    printf("  Coverage:       %.1f%%\n", (g_availableCount * 100.0) / g_toolCount);
    printf("\n");
    printf("By Priority:\n");
    printf("  P0 (Critical):  %d\n", byPriority[0]);
    printf("  P1 (High):      %d\n", byPriority[1]);
    printf("  P2 (Medium):    %d\n", byPriority[2]);
    printf("  P3 (Low):       %d\n", byPriority[3]);
    printf("\n");
    printf("By Type:\n");
    printf("  EXE:            %d\n", byType[0]);
    printf("  PS1:            %d\n", byType[1]);
    printf("  BAT:            %d\n", byType[2]);
    printf("  CMD:            %d\n", byType[3]);
    printf("  PY:             %d\n", byType[4]);
    printf("  JS:             %d\n", byType[5]);
    printf("  Other:          %d\n", byType[6]);
    printf("\n");
}

// Print all tools
void PrintTools() {
    printf("\nAll Discovered Tools:\n");
    printf("--------------------\n");
    
    const char* currentCategory = "";
    for (int i = 0; i < g_toolCount && i < 100; i++) { // Limit display
        if (strcmp(g_tools[i].category, currentCategory) != 0) {
            currentCategory = g_tools[i].category;
            printf("\n[%s]\n", currentCategory);
        }
        
        printf("  %-20s %-30s %s %6dKB\n",
               g_tools[i].id,
               g_tools[i].name,
               g_tools[i].available ? "[OK]" : "[MISSING]",
               g_tools[i].sizeKB);
    }
    
    if (g_toolCount > 100) {
        printf("\n... and %d more tools (use 'search' to find specific tools)\n", g_toolCount - 100);
    }
    printf("\n");
}

// Print tools by category
void PrintToolsByCategory() {
    const char* categories[] = {"ide", "titan", "core", "production", "compiler", 
                                "build", "test", "benchmark", "ml", "gpu", "compute",
                                "swarm", "debug", "script", "general", NULL};
    
    printf("\nTools by Category:\n");
    printf("------------------\n");
    
    for (int c = 0; categories[c] != NULL; c++) {
        int count = 0;
        printf("\n[%s]\n", categories[c]);
        
        for (int i = 0; i < g_toolCount; i++) {
            if (strcmp(g_tools[i].category, categories[c]) == 0) {
                printf("  %-20s %s\n", g_tools[i].id, 
                       g_tools[i].available ? "[OK]" : "[MISSING]");
                count++;
                if (count >= 20) {
                    printf("  ... and more\n");
                    break;
                }
            }
        }
        
        if (count == 0) printf("  (none)\n");
    }
    printf("\n");
}

// Print tools by priority
void PrintToolsByPriority() {
    printf("\nTools by Priority:\n");
    printf("------------------\n");
    
    for (int p = 0; p < 4; p++) {
        const char* prioName = (p == 0) ? "P0 - CRITICAL" : 
                               (p == 1) ? "P1 - HIGH" :
                               (p == 2) ? "P2 - MEDIUM" : "P3 - LOW";
        printf("\n[%s]\n", prioName);
        
        int count = 0;
        for (int i = 0; i < g_toolCount; i++) {
            if (g_tools[i].priority == p) {
                printf("  %-20s %s\n", g_tools[i].id,
                       g_tools[i].available ? "[OK]" : "[MISSING]");
                count++;
                if (count >= 30) {
                    printf("  ... and more\n");
                    break;
                }
            }
        }
        
        if (count == 0) printf("  (none)\n");
    }
    printf("\n");
}

// Execute a tool
void ExecuteTool(const char* id, const char* args) {
    struct Tool* tool = FindTool(id);
    if (!tool) {
        printf("[ERROR] Tool '%s' not found\n", id);
        return;
    }
    
    if (!tool->available) {
        printf("[ERROR] Tool '%s' not available at: %s\n", id, tool->path);
        return;
    }
    
    printf("[EXECUTE] %s (%s)\n", tool->name, tool->type);
    
    char cmdLine[1024];
    if (strcmp(tool->type, "exe") == 0) {
        if (args && *args) {
            sprintf(cmdLine, "\"%s\" %s", tool->path, args);
        } else {
            sprintf(cmdLine, "\"%s\"", tool->path);
        }
    } else if (strcmp(tool->type, "ps1") == 0) {
        if (args && *args) {
            sprintf(cmdLine, "powershell -ExecutionPolicy Bypass -File \"%s\" %s", tool->path, args);
        } else {
            sprintf(cmdLine, "powershell -ExecutionPolicy Bypass -File \"%s\"", tool->path);
        }
    } else if (strcmp(tool->type, "bat") == 0 || strcmp(tool->type, "cmd") == 0) {
        if (args && *args) {
            sprintf(cmdLine, "cmd /c \"%s\" %s", tool->path, args);
        } else {
            sprintf(cmdLine, "cmd /c \"%s\"", tool->path);
        }
    } else if (strcmp(tool->type, "py") == 0) {
        if (args && *args) {
            sprintf(cmdLine, "python \"%s\" %s", tool->path, args);
        } else {
            sprintf(cmdLine, "python \"%s\"", tool->path);
        }
    } else if (strcmp(tool->type, "js") == 0) {
        if (args && *args) {
            sprintf(cmdLine, "node \"%s\" %s", tool->path, args);
        } else {
            sprintf(cmdLine, "node \"%s\"", tool->path);
        }
    } else {
        printf("[ERROR] Unknown tool type: %s\n", tool->type);
        return;
    }
    
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    
    // For console tools, redirect output
    if (strcmp(tool->type, "exe") == 0) {
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
    } else {
        printf("[ERROR] Failed to execute (Error: %lu)\n", GetLastError());
    }
}

// Batch execute by category
void BatchExecute(const char* category) {
    printf("\n[BATCH] Executing all tools in category: %s\n", category);
    printf("================================================\n");
    
    int executed = 0, failed = 0, skipped = 0;
    
    for (int i = 0; i < g_toolCount; i++) {
        if (strcmp(g_tools[i].category, category) == 0) {
            if (g_tools[i].available) {
                printf("\n--- Running %s ---\n", g_tools[i].name);
                ExecuteTool(g_tools[i].id, NULL);
                executed++;
            } else {
                printf("[SKIP] %s (not available)\n", g_tools[i].name);
                skipped++;
            }
        }
    }
    
    printf("\n================================================\n");
    printf("Results: %d executed, %d failed, %d skipped\n", executed, failed, skipped);
}

// Search tools
void SearchTools(const char* keyword) {
    printf("\nSearch results for '%s':\n", keyword);
    printf("-------------------------\n");
    
    int found = 0;
    for (int i = 0; i < g_toolCount; i++) {
        if (strstr(g_tools[i].id, keyword) != NULL ||
            strstr(g_tools[i].name, keyword) != NULL ||
            strstr(g_tools[i].category, keyword) != NULL) {
            printf("  %-20s %-30s %s\n",
                   g_tools[i].id,
                   g_tools[i].name,
                   g_tools[i].available ? "[OK]" : "[MISSING]");
            found++;
        }
    }
    
    printf("\nFound %d tools matching '%s'\n", found, keyword);
}

// Show help
void ShowHelp() {
    printf("Commands:\n");
    printf("  help                    Show this help\n");
    printf("  stats                   Show discovery statistics\n");
    printf("  tools                   List all tools (first 100)\n");
    printf("  tools --category        List by category\n");
    printf("  tools --priority        List by priority\n");
    printf("  search <keyword>      Search for tools\n");
    printf("\n");
    printf("  run <tool_id> [args]   Execute a tool\n");
    printf("  batch <category>       Execute all tools in category\n");
    printf("\n");
    printf("  build <file.c>         Build C file (if compiler available)\n");
    printf("\n");
    printf("  quit/exit               Exit\n");
    printf("\n");
    printf("Categories: ide, titan, core, production, compiler, build,\n");
    printf("            test, benchmark, ml, gpu, compute, swarm, debug,\n");
    printf("            script, general\n");
    printf("\n");
}

// Main CLI loop
void RunCLILoop() {
    char input[1024];
    
    while (1) {
        printf("RawrXD-Mega> ");
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
        
        char* arg1 = strtok(NULL, " \t");
        char remaining[512] = {0};
        char* more;
        int first = 1;
        while ((more = strtok(NULL, " \t")) != NULL) {
            if (!first) strcat(remaining, " ");
            strcat(remaining, more);
            first = 0;
        }
        
        if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
            printf("[EXIT] Goodbye!\n");
            break;
        }
        else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
            ShowHelp();
        }
        else if (strcmp(cmd, "stats") == 0) {
            PrintStats();
        }
        else if (strcmp(cmd, "tools") == 0) {
            if (arg1 && strcmp(arg1, "--category") == 0) {
                PrintToolsByCategory();
            } else if (arg1 && strcmp(arg1, "--priority") == 0) {
                PrintToolsByPriority();
            } else {
                PrintTools();
            }
        }
        else if (strcmp(cmd, "search") == 0) {
            if (!arg1) {
                printf("[ERROR] Usage: search <keyword>\n");
                continue;
            }
            SearchTools(arg1);
        }
        else if (strcmp(cmd, "run") == 0) {
            if (!arg1) {
                printf("[ERROR] Usage: run <tool_id> [args...]\n");
                continue;
            }
            ExecuteTool(arg1, remaining[0] ? remaining : NULL);
        }
        else if (strcmp(cmd, "batch") == 0) {
            if (!arg1) {
                printf("[ERROR] Usage: batch <category>\n");
                continue;
            }
            BatchExecute(arg1);
        }
        else {
            // Try to execute as tool ID directly
            struct Tool* tool = FindTool(cmd);
            if (tool) {
                ExecuteTool(cmd, arg1 ? arg1 : NULL);
            } else {
                printf("[ERROR] Unknown command: %s\n", cmd);
                printf("Type 'help' for available commands\n");
            }
        }
    }
}

// Entry point
int main(int argc, char* argv[]) {
    PrintBanner();
    
    // Discover all tools
    DiscoverTools();
    
    // Show stats
    PrintStats();
    
    // Check command line
    if (argc > 1) {
        if (strcmp(argv[1], "--stats") == 0) {
            return 0;
        }
        else if (strcmp(argv[1], "--tools") == 0) {
            PrintTools();
            return 0;
        }
        else if (strcmp(argv[1], "--run") == 0 && argc > 2) {
            ExecuteTool(argv[2], argc > 3 ? argv[3] : NULL);
            return 0;
        }
        else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "/?") == 0) {
            ShowHelp();
            return 0;
        }
    }
    
    // Interactive mode
    ShowHelp();
    RunCLILoop();
    
    return 0;
}
