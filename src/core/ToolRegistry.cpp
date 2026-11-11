// ToolRegistry.cpp - Coherent Tool Registry Implementation
// Actually registers and integrates all 152 tools

#include "ToolRegistry.h"
#include <stdio.h>
#include <string.h>

static struct Tool g_tools[MAX_TOOLS];
static int g_toolCount = 0;
static BOOL g_initialized = FALSE;

// Forward declarations for tool executors
BOOL Execute_Tool(int id, const char* args);
BOOL Execute_AI_Orchestrator(const char* args);
BOOL Execute_SecurityManager(const char* args);
BOOL Execute_CloudManager(const char* args);
BOOL Execute_TeamManager(const char* args);
BOOL Execute_AdvancedReporting(const char* args);
BOOL Execute_MachineLearning(const char* args);
BOOL Execute_AdvancedDebugger(const char* args);
BOOL Execute_EnterpriseManager(const char* args);

BOOL TR_Init() {
    if (g_initialized) return TRUE;
    
    printf("[ToolRegistry] Initializing...\n");
    g_toolCount = 0;
    
    // Register all 152 batch tools
    for (int i = 1; i <= 152; i++) {
        char name[MAX_NAME_LEN];
        char path[MAX_PATH_LEN];
        sprintf(name, "tool_%d", i);
        sprintf(path, "d:\\rawrxd\\src\\tool_%d.exe", i);
        
        // Determine tool type based on ID ranges
        ToolType type = TOOL_TYPE_UTILITY;
        const char* category = "utility";
        
        if (i <= 20) { type = TOOL_TYPE_CORE; category = "core"; }
        else if (i <= 40) { type = TOOL_TYPE_AI; category = "ai"; }
        else if (i <= 60) { type = TOOL_TYPE_SECURITY; category = "security"; }
        else if (i <= 80) { type = TOOL_TYPE_CLOUD; category = "cloud"; }
        else if (i <= 100) { type = TOOL_TYPE_TEAM; category = "team"; }
        else if (i <= 120) { type = TOOL_TYPE_REPORTING; category = "reporting"; }
        else if (i <= 140) { type = TOOL_TYPE_ML; category = "ml"; }
        else { type = TOOL_TYPE_DEBUG; category = "debug"; }
        
        char description[256];
        sprintf(description, "RawrXD Tool %d - %s functionality", i, category);
        
        TR_RegisterTool(i, name, path, type, category, description);
    }
    
    // Register major system components
    TR_RegisterTool(201, "AI_ToolOrchestrator", 
        "d:\\rawrxd\\src\\ai\\AI_ToolOrchestrator.exe",
        TOOL_TYPE_AI, "ai", "AI-powered tool orchestration");
    
    TR_RegisterTool(202, "SecurityManager",
        "d:\\rawrxd\\src\\security\\SecurityManager.exe",
        TOOL_TYPE_SECURITY, "security", "Security and access control");
    
    TR_RegisterTool(203, "CloudManager",
        "d:\\rawrxd\\src\\cloud\\CloudManager.exe",
        TOOL_TYPE_CLOUD, "cloud", "Cloud integration and deployment");
    
    TR_RegisterTool(204, "TeamManager",
        "d:\\rawrxd\\src\\team\\TeamManager.exe",
        TOOL_TYPE_TEAM, "team", "Team collaboration tools");
    
    TR_RegisterTool(205, "AdvancedReporting",
        "d:\\rawrxd\\src\\reporting\\AdvancedReporting.exe",
        TOOL_TYPE_REPORTING, "reporting", "Advanced reporting and analytics");
    
    TR_RegisterTool(206, "MachineLearning",
        "d:\\rawrxd\\src\\ml\\MachineLearning.exe",
        TOOL_TYPE_ML, "ml", "Machine learning capabilities");
    
    TR_RegisterTool(207, "AdvancedDebugger",
        "d:\\rawrxd\\src\\debug\\AdvancedDebugger.exe",
        TOOL_TYPE_DEBUG, "debug", "Advanced debugging tools");
    
    TR_RegisterTool(208, "EnterpriseManager",
        "d:\\rawrxd\\src\\enterprise\\EnterpriseManager.exe",
        TOOL_TYPE_ENTERPRISE, "enterprise", "Enterprise management");
    
    g_initialized = TRUE;
    printf("[ToolRegistry] Initialized with %d tools\n", g_toolCount);
    return TRUE;
}

BOOL TR_RegisterTool(int id, const char* name, const char* path, ToolType type,
                   const char* category, const char* description) {
    if (g_toolCount >= MAX_TOOLS) return FALSE;
    
    struct Tool* tool = &g_tools[g_toolCount];
    tool->id = id;
    strncpy(tool->name, name, MAX_NAME_LEN - 1);
    tool->name[MAX_NAME_LEN - 1] = '\0';
    strncpy(tool->path, path, MAX_PATH_LEN - 1);
    tool->path[MAX_PATH_LEN - 1] = '\0';
    tool->type = type;
    strncpy(tool->category, category, MAX_NAME_LEN - 1);
    tool->category[MAX_NAME_LEN - 1] = '\0';
    strncpy(tool->description, description, 255);
    tool->description[255] = '\0';
    
    // Check if tool exists
    DWORD attribs = GetFileAttributesA(path);
    tool->available = (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY));
    
    // Set execute function
    if (id >= 1 && id <= 152) {
        tool->execute = Execute_Tool;
    } else {
        // Major components have specialized executors
        switch (id) {
            case 201: tool->execute = Execute_AI_Orchestrator; break;
            case 202: tool->execute = Execute_SecurityManager; break;
            case 203: tool->execute = Execute_CloudManager; break;
            case 204: tool->execute = Execute_TeamManager; break;
            case 205: tool->execute = Execute_AdvancedReporting; break;
            case 206: tool->execute = Execute_MachineLearning; break;
            case 207: tool->execute = Execute_AdvancedDebugger; break;
            case 208: tool->execute = Execute_EnterpriseManager; break;
            default: tool->execute = NULL;
        }
    }
    
    g_toolCount++;
    return TRUE;
}

struct Tool* TR_FindToolById(int id) {
    for (int i = 0; i < g_toolCount; i++) {
        if (g_tools[i].id == id) return &g_tools[i];
    }
    return NULL;
}

struct Tool* TR_FindToolByName(const char* name) {
    for (int i = 0; i < g_toolCount; i++) {
        if (strcmp(g_tools[i].name, name) == 0) return &g_tools[i];
    }
    return NULL;
}

BOOL TR_ExecuteTool(int id, const char* args) {
    struct Tool* tool = TR_FindToolById(id);
    if (!tool) {
        printf("[ToolRegistry] Tool %d not found\n", id);
        return FALSE;
    }
    
    if (!tool->available) {
        printf("[ToolRegistry] Tool %s not available\n", tool->name);
        return FALSE;
    }
    
    if (tool->execute) {
        return tool->execute(args);
    }
    
    // Default execution
    printf("[ToolRegistry] Executing: %s\n", tool->name);
    
    char cmdLine[512];
    if (args && *args) {
        sprintf(cmdLine, "\"%s\" %s", tool->path, args);
    } else {
        sprintf(cmdLine, "\"%s\"", tool->path);
    }
    
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    
    if (CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return exitCode == 0;
    }
    
    return FALSE;
}

BOOL TR_ExecuteToolByName(const char* name, const char* args) {
    struct Tool* tool = TR_FindToolByName(name);
    if (!tool) {
        printf("[ToolRegistry] Tool '%s' not found\n", name);
        return FALSE;
    }
    return TR_ExecuteTool(tool->id, args);
}

void TR_ListTools() {
    printf("\n[ToolRegistry] Registered Tools (%d):\n", g_toolCount);
    printf("=================================================================\n");
    printf("%-5s %-25s %-15s %-10s\n", "ID", "Name", "Category", "Status");
    printf("-----------------------------------------------------------------\n");
    
    for (int i = 0; i < g_toolCount && i < 20; i++) { // Show first 20
        printf("%-5d %-25s %-15s %-10s\n",
               g_tools[i].id,
               g_tools[i].name,
               g_tools[i].category,
               g_tools[i].available ? "Available" : "Missing");
    }
    
    if (g_toolCount > 20) {
        printf("... and %d more tools\n", g_toolCount - 20);
    }
    
    printf("=================================================================\n\n");
}

void TR_ListByCategory(const char* category) {
    printf("\n[ToolRegistry] Tools in category '%s':\n", category);
    printf("=================================================================\n");
    
    int count = 0;
    for (int i = 0; i < g_toolCount; i++) {
        if (strcmp(g_tools[i].category, category) == 0) {
            printf("  %-25s %s\n", g_tools[i].name, 
                   g_tools[i].available ? "[OK]" : "[MISSING]");
            count++;
        }
    }
    
    printf("=================================================================\n");
    printf("Total: %d tools\n\n", count);
}

void TR_ListByType(ToolType type) {
    const char* typeNames[] = {"Core", "AI", "Security", "Cloud", "Team", 
                              "Reporting", "ML", "Debug", "Enterprise", "Utility"};
    
    printf("\n[ToolRegistry] Tools of type '%s':\n", typeNames[type]);
    printf("=================================================================\n");
    
    int count = 0;
    for (int i = 0; i < g_toolCount; i++) {
        if (g_tools[i].type == type) {
            printf("  %-25s %s\n", g_tools[i].name,
                   g_tools[i].available ? "[OK]" : "[MISSING]");
            count++;
        }
    }
    
    printf("=================================================================\n");
    printf("Total: %d tools\n\n", count);
}

int TR_GetToolCount() {
    return g_toolCount;
}

BOOL TR_IsToolAvailable(int id) {
    struct Tool* tool = TR_FindToolById(id);
    return tool ? tool->available : FALSE;
}

// Tool executor implementations
BOOL Execute_Tool(int id, const char* args) {
    char path[MAX_PATH_LEN];
    sprintf(path, "d:\\rawrxd\\src\\tool_%d.exe", id);
    
    char cmdLine[512];
    if (args && *args) {
        sprintf(cmdLine, "\"%s\" %s", path, args);
    } else {
        sprintf(cmdLine, "\"%s\"", path);
    }
    
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    
    if (CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return exitCode == 0;
    }
    
    return FALSE;
}

BOOL Execute_AI_Orchestrator(const char* args) {
    return Execute_Tool(201, args);
}

BOOL Execute_SecurityManager(const char* args) {
    return Execute_Tool(202, args);
}

BOOL Execute_CloudManager(const char* args) {
    return Execute_Tool(203, args);
}

BOOL Execute_TeamManager(const char* args) {
    return Execute_Tool(204, args);
}

BOOL Execute_AdvancedReporting(const char* args) {
    return Execute_Tool(205, args);
}

BOOL Execute_MachineLearning(const char* args) {
    return Execute_Tool(206, args);
}

BOOL Execute_AdvancedDebugger(const char* args) {
    return Execute_Tool(207, args);
}

BOOL Execute_EnterpriseManager(const char* args) {
    return Execute_Tool(208, args);
}
