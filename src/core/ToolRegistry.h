// ToolRegistry.h - Coherent Tool Registry Architecture
// Central registry for all 152 tools with actual integration

#ifndef TOOL_REGISTRY_H
#define TOOL_REGISTRY_H

#include <windows.h>

#define MAX_TOOLS 200
#define MAX_CATEGORIES 20
#define MAX_NAME_LEN 64
#define MAX_PATH_LEN 256

// Tool types
enum ToolType {
    TOOL_TYPE_CORE,
    TOOL_TYPE_AI,
    TOOL_TYPE_SECURITY,
    TOOL_TYPE_CLOUD,
    TOOL_TYPE_TEAM,
    TOOL_TYPE_REPORTING,
    TOOL_TYPE_ML,
    TOOL_TYPE_DEBUG,
    TOOL_TYPE_ENTERPRISE,
    TOOL_TYPE_UTILITY
};

// Tool structure
struct Tool {
    int id;
    char name[MAX_NAME_LEN];
    char path[MAX_PATH_LEN];
    ToolType type;
    char category[MAX_NAME_LEN];
    BOOL available;
    BOOL (*execute)(const char* args);
    char description[256];
};

// Registry functions
BOOL TR_Init();
BOOL TR_RegisterTool(int id, const char* name, const char* path, ToolType type, 
                   const char* category, const char* description);
struct Tool* TR_FindToolById(int id);
struct Tool* TR_FindToolByName(const char* name);
BOOL TR_ExecuteTool(int id, const char* args);
BOOL TR_ExecuteToolByName(const char* name, const char* args);
void TR_ListTools();
void TR_ListByCategory(const char* category);
void TR_ListByType(ToolType type);
int TR_GetToolCount();
BOOL TR_IsToolAvailable(int id);

// Integration functions
BOOL TR_ExecuteBatch(int* toolIds, int count, const char** args);
BOOL TR_ExecutePipeline(const char* pipelineName);
BOOL TR_ExecuteWorkflow(const char* workflowName);

#endif // TOOL_REGISTRY_H
