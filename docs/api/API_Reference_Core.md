# Sovereign IDE — API Reference: Core SDK
## Complete API Documentation for Core IDE Functions

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** Complete

---

## 1. Overview

The Core SDK provides fundamental APIs for interacting with the Sovereign IDE's basic functionality: editor operations, workspace management, build system, debugger, and Git integration.

### 1.1 API Categories

| Category | Description | Header |
|----------|-------------|--------|
| Initialization | SDK lifecycle management | `sdk/core/init.h` |
| Editor | Text editing operations | `sdk/core/editor.h` |
| Workspace | Project and file management | `sdk/core/workspace.h` |
| Build | Compilation and building | `sdk/core/build.h` |
| Debugger | Debugging operations | `sdk/core/debugger.h` |
| Git | Version control | `sdk/core/git.h` |

---

## 2. Initialization API

### 2.1 SDK Lifecycle

```cpp
// sdk/core/init.h

/**
 * Initialize the SDK
 * @param config Configuration options
 * @param outHandle Output SDK handle
 * @return SDKResult indicating success or failure
 */
SDKResult SDK_Initialize(
    const SDKConfig* config,
    SDKHandle* outHandle
);

/**
 * Shutdown the SDK and release resources
 * @param sdk SDK handle
 * @return SDKResult indicating success or failure
 */
SDKResult SDK_Shutdown(SDKHandle sdk);

/**
 * Check if SDK is initialized
 * @param sdk SDK handle
 * @return true if initialized, false otherwise
 */
bool SDK_IsInitialized(SDKHandle sdk);
```

### 2.2 Configuration Structure

```cpp
// SDK configuration options
typedef struct {
    uint32_t version;           // SDK version requested
    const char* workspacePath;  // Default workspace path
    uint32_t flags;             // Feature flags
    LogLevel logLevel;          // Logging verbosity
} SDKConfig;

// Feature flags
#define SDK_FLAG_ENABLE_DEBUGGER  0x0001
#define SDK_FLAG_ENABLE_PROFILER 0x0002
#define SDK_FLAG_ENABLE_GIT       0x0004
#define SDK_FLAG_ENABLE_AI       0x0008
```

### 2.3 Error Handling

```cpp
// SDK result codes
typedef enum {
    SDK_OK = 0,
    SDK_ERROR_INVALID_PARAMETER = -1,
    SDK_ERROR_OUT_OF_MEMORY = -2,
    SDK_ERROR_NOT_INITIALIZED = -3,
    SDK_ERROR_FILE_NOT_FOUND = -4,
    SDK_ERROR_PERMISSION_DENIED = -5,
    SDK_ERROR_TIMEOUT = -6,
    SDK_ERROR_UNKNOWN = -99
} SDKResult;

/**
 * Get error message for result code
 * @param result Result code
 * @return Human-readable error message
 */
const char* SDK_GetErrorString(SDKResult result);
```

---

## 3. Editor API

### 3.1 File Operations

```cpp
// sdk/core/editor.h

/**
 * Open a file in the editor
 * @param sdk SDK handle
 * @param filePath Path to file
 * @param outDocument Output document handle
 * @return SDKResult
 */
SDKResult SDK_Editor_OpenFile(
    SDKHandle sdk,
    const char* filePath,
    DocumentHandle* outDocument
);

/**
 * Create a new file
 * @param sdk SDK handle
 * @param filePath Path for new file
 * @param outDocument Output document handle
 * @return SDKResult
 */
SDKResult SDK_Editor_CreateFile(
    SDKHandle sdk,
    const char* filePath,
    DocumentHandle* outDocument
);

/**
 * Save the current document
 * @param sdk SDK handle
 * @param document Document handle
 * @return SDKResult
 */
SDKResult SDK_Editor_SaveFile(
    SDKHandle sdk,
    DocumentHandle document
);

/**
 * Close a document
 * @param sdk SDK handle
 * @param document Document handle
 * @return SDKResult
 */
SDKResult SDK_Editor_CloseFile(
    SDKHandle sdk,
    DocumentHandle document
);
```

### 3.2 Text Operations

```cpp
/**
 * Get document text
 * @param sdk SDK handle
 * @param document Document handle
 * @param buffer Output buffer (can be NULL to get size)
 * @param bufferSize Buffer size
 * @param outSize Output text size
 * @return SDKResult
 */
SDKResult SDK_Editor_GetText(
    SDKHandle sdk,
    DocumentHandle document,
    char* buffer,
    uint32_t bufferSize,
    uint32_t* outSize
);

/**
 * Set document text
 * @param sdk SDK handle
 * @param document Document handle
 * @param text New text content
 * @return SDKResult
 */
SDKResult SDK_Editor_SetText(
    SDKHandle sdk,
    DocumentHandle document,
    const char* text
);

/**
 * Insert text at position
 * @param sdk SDK handle
 * @param document Document handle
 * @param position Character position
 * @param text Text to insert
 * @return SDKResult
 */
SDKResult SDK_Editor_InsertText(
    SDKHandle sdk,
    DocumentHandle document,
    uint32_t position,
    const char* text
);

/**
 * Delete text range
 * @param sdk SDK handle
 * @param document Document handle
 * @param start Start position
 * @param end End position
 * @return SDKResult
 */
SDKResult SDK_Editor_DeleteText(
    SDKHandle sdk,
    DocumentHandle document,
    uint32_t start,
    uint32_t end
);
```

### 3.3 Cursor and Selection

```cpp
/**
 * Get cursor position
 * @param sdk SDK handle
 * @param document Document handle
 * @param outLine Output line number
 * @param outColumn Output column number
 * @return SDKResult
 */
SDKResult SDK_Editor_GetCursorPosition(
    SDKHandle sdk,
    DocumentHandle document,
    uint32_t* outLine,
    uint32_t* outColumn
);

/**
 * Set cursor position
 * @param sdk SDK handle
 * @param document Document handle
 * @param line Line number
 * @param column Column number
 * @return SDKResult
 */
SDKResult SDK_Editor_SetCursorPosition(
    SDKHandle sdk,
    DocumentHandle document,
    uint32_t line,
    uint32_t column
);

/**
 * Get selected text
 * @param sdk SDK handle
 * @param document Document handle
 * @param buffer Output buffer
 * @param bufferSize Buffer size
 * @param outSize Output size
 * @return SDKResult
 */
SDKResult SDK_Editor_GetSelection(
    SDKHandle sdk,
    DocumentHandle document,
    char* buffer,
    uint32_t bufferSize,
    uint32_t* outSize
);

/**
 * Replace selected text
 * @param sdk SDK handle
 * @param document Document handle
 * @param text Replacement text
 * @return SDKResult
 */
SDKResult SDK_Editor_ReplaceSelection(
    SDKHandle sdk,
    DocumentHandle document,
    const char* text
);
```

---

## 4. Workspace API

### 4.1 Project Management

```cpp
// sdk/core/workspace.h

/**
 * Open a project
 * @param sdk SDK handle
 * @param projectPath Path to project file
 * @param outProject Output project handle
 * @return SDKResult
 */
SDKResult SDK_Workspace_OpenProject(
    SDKHandle sdk,
    const char* projectPath,
    ProjectHandle* outProject
);

/**
 * Create a new project
 * @param sdk SDK handle
 * @param projectPath Path for new project
 * @param templateType Project template
 * @param outProject Output project handle
 * @return SDKResult
 */
SDKResult SDK_Workspace_CreateProject(
    SDKHandle sdk,
    const char* projectPath,
    ProjectTemplate templateType,
    ProjectHandle* outProject
);

/**
 * Close current project
 * @param sdk SDK handle
 * @param project Project handle
 * @return SDKResult
 */
SDKResult SDK_Workspace_CloseProject(
    SDKHandle sdk,
    ProjectHandle project
);
```

### 4.2 File Operations

```cpp
/**
 * List files in directory
 * @param sdk SDK handle
 * @param directoryPath Directory path
 * @param outFiles Output file list
 * @param outCount Output file count
 * @return SDKResult
 */
SDKResult SDK_Workspace_ListFiles(
    SDKHandle sdk,
    const char* directoryPath,
    FileInfo** outFiles,
    uint32_t* outCount
);

/**
 * Create directory
 * @param sdk SDK handle
 * @param directoryPath Directory path
 * @return SDKResult
 */
SDKResult SDK_Workspace_CreateDirectory(
    SDKHandle sdk,
    const char* directoryPath
);

/**
 * Delete file or directory
 * @param sdk SDK handle
 * @param path Path to delete
 * @param recursive Delete recursively
 * @return SDKResult
 */
SDKResult SDK_Workspace_Delete(
    SDKHandle sdk,
    const char* path,
    bool recursive
);

/**
 * Rename file or directory
 * @param sdk SDK handle
 * @param oldPath Current path
 * @param newPath New path
 * @return SDKResult
 */
SDKResult SDK_Workspace_Rename(
    SDKHandle sdk,
    const char* oldPath,
    const char* newPath
);
```

---

## 5. Build API

### 5.1 Build Operations

```cpp
// sdk/core/build.h

/**
 * Configure build
 * @param sdk SDK handle
 * @param config Build configuration
 * @return SDKResult
 */
SDKResult SDK_Build_Configure(
    SDKHandle sdk,
    const BuildConfig* config
);

/**
 * Start build
 * @param sdk SDK handle
 * @param target Build target
 * @param outBuild Output build handle
 * @return SDKResult
 */
SDKResult SDK_Build_Start(
    SDKHandle sdk,
    const char* target,
    BuildHandle* outBuild
);

/**
 * Get build status
 * @param sdk SDK handle
 * @param build Build handle
 * @param outStatus Output status
 * @return SDKResult
 */
SDKResult SDK_Build_GetStatus(
    SDKHandle sdk,
    BuildHandle build,
    BuildStatus* outStatus
);

/**
 * Wait for build completion
 * @param sdk SDK handle
 * @param build Build handle
 * @param timeoutMs Timeout in milliseconds
 * @param outResult Output build result
 * @return SDKResult
 */
SDKResult SDK_Build_Wait(
    SDKHandle sdk,
    BuildHandle build,
    uint32_t timeoutMs,
    BuildResult* outResult
);
```

### 5.2 Build Configuration

```cpp
// Build configuration
typedef struct {
    const char* buildType;      // "Debug", "Release", "Profile"
    const char* toolchain;      // "MSVC", "GCC", "Clang"
    const char** defines;       // Preprocessor defines
    uint32_t defineCount;
    const char** includePaths;  // Include directories
    uint32_t includeCount;
    const char** libraryPaths;  // Library directories
    uint32_t libraryCount;
    uint32_t parallelJobs;      // Parallel compilation jobs
} BuildConfig;
```

---

## 6. Debugger API

### 6.1 Session Management

```cpp
// sdk/core/debugger.h

/**
 * Start debugging session
 * @param sdk SDK handle
 * @param executablePath Path to executable
 * @param outSession Output debug session
 * @return SDKResult
 */
SDKResult SDK_Debugger_Start(
    SDKHandle sdk,
    const char* executablePath,
    DebugSession* outSession
);

/**
 * Attach to running process
 * @param sdk SDK handle
 * @param processId Process ID
 * @param outSession Output debug session
 * @return SDKResult
 */
SDKResult SDK_Debugger_Attach(
    SDKHandle sdk,
    uint32_t processId,
    DebugSession* outSession
);

/**
 * Stop debugging
 * @param sdk SDK handle
 * @param session Debug session
 * @return SDKResult
 */
SDKResult SDK_Debugger_Stop(
    SDKHandle sdk,
    DebugSession session
);
```

### 6.2 Breakpoints

```cpp
/**
 * Set breakpoint
 * @param sdk SDK handle
 * @param session Debug session
 * @param filePath Source file
 * @param line Line number
 * @param outBreakpoint Output breakpoint ID
 * @return SDKResult
 */
SDKResult SDK_Debugger_SetBreakpoint(
    SDKHandle sdk,
    DebugSession session,
    const char* filePath,
    uint32_t line,
    BreakpointId* outBreakpoint
);

/**
 * Remove breakpoint
 * @param sdk SDK handle
 * @param session Debug session
 * @param breakpoint Breakpoint ID
 * @return SDKResult
 */
SDKResult SDK_Debugger_RemoveBreakpoint(
    SDKHandle sdk,
    DebugSession session,
    BreakpointId breakpoint
);

/**
 * Continue execution
 * @param sdk SDK handle
 * @param session Debug session
 * @return SDKResult
 */
SDKResult SDK_Debugger_Continue(
    SDKHandle sdk,
    DebugSession session
);

/**
 * Step over
 * @param sdk SDK handle
 * @param session Debug session
 * @return SDKResult
 */
SDKResult SDK_Debugger_StepOver(
    SDKHandle sdk,
    DebugSession session
);

/**
 * Step into
 * @param sdk SDK handle
 * @param session Debug session
 * @return SDKResult
 */
SDKResult SDK_Debugger_StepInto(
    SDKHandle sdk,
    DebugSession session
);

/**
 * Step out
 * @param sdk SDK handle
 * @param session Debug session
 * @return SDKResult
 */
SDKResult SDK_Debugger_StepOut(
    SDKHandle sdk,
    DebugSession session
);
```

---

## 7. Git API

### 7.1 Repository Operations

```cpp
// sdk/core/git.h

/**
 * Initialize Git repository
 * @param sdk SDK handle
 * @param path Repository path
 * @return SDKResult
 */
SDKResult SDK_Git_Init(
    SDKHandle sdk,
    const char* path
);

/**
 * Clone repository
 * @param sdk SDK handle
 * @param url Repository URL
 * @param localPath Local path
 * @param outRepo Output repository handle
 * @return SDKResult
 */
SDKResult SDK_Git_Clone(
    SDKHandle sdk,
    const char* url,
    const char* localPath,
    GitRepository* outRepo
);

/**
 * Open existing repository
 * @param sdk SDK handle
 * @param path Repository path
 * @param outRepo Output repository handle
 * @return SDKResult
 */
SDKResult SDK_Git_Open(
    SDKHandle sdk,
    const char* path,
    GitRepository* outRepo
);
```

### 7.2 Basic Operations

```cpp
/**
 * Stage files
 * @param sdk SDK handle
 * @param repo Repository handle
 * @param paths Files to stage
 * @param pathCount Number of paths
 * @return SDKResult
 */
SDKResult SDK_Git_Stage(
    SDKHandle sdk,
    GitRepository repo,
    const char** paths,
    uint32_t pathCount
);

/**
 * Commit changes
 * @param sdk SDK handle
 * @param repo Repository handle
 * @param message Commit message
 * @return SDKResult
 */
SDKResult SDK_Git_Commit(
    SDKHandle sdk,
    GitRepository repo,
    const char* message
);

/**
 * Push to remote
 * @param sdk SDK handle
 * @param repo Repository handle
 * @param remote Remote name
 * @param branch Branch name
 * @return SDKResult
 */
SDKResult SDK_Git_Push(
    SDKHandle sdk,
    GitRepository repo,
    const char* remote,
    const char* branch
);

/**
 * Pull from remote
 * @param sdk SDK handle
 * @param repo Repository handle
 * @param remote Remote name
 * @param branch Branch name
 * @return SDKResult
 */
SDKResult SDK_Git_Pull(
    SDKHandle sdk,
    GitRepository repo,
    const char* remote,
    const char* branch
);
```

---

## 8. Usage Examples

### 8.1 Basic Editor Operations

```cpp
#include <sdk/core/init.h>
#include <sdk/core/editor.h>

int main() {
    // Initialize SDK
    SDKConfig config = {
        .version = 1,
        .workspacePath = "C:/Projects",
        .flags = SDK_FLAG_ENABLE_DEBUGGER | SDK_FLAG_ENABLE_GIT,
        .logLevel = LOG_LEVEL_INFO
    };
    
    SDKHandle sdk;
    SDKResult result = SDK_Initialize(&config, &sdk);
    if (result != SDK_OK) {
        printf("Failed to initialize: %s\n", SDK_GetErrorString(result));
        return 1;
    }
    
    // Open file
    DocumentHandle doc;
    result = SDK_Editor_OpenFile(sdk, "main.cpp", &doc);
    if (result != SDK_OK) {
        printf("Failed to open file\n");
        SDK_Shutdown(sdk);
        return 1;
    }
    
    // Get text
    uint32_t size;
    SDK_Editor_GetText(sdk, doc, NULL, 0, &size);
    char* buffer = new char[size + 1];
    SDK_Editor_GetText(sdk, doc, buffer, size + 1, &size);
    
    printf("File content:\n%s\n", buffer);
    
    // Cleanup
    delete[] buffer;
    SDK_Editor_CloseFile(sdk, doc);
    SDK_Shutdown(sdk);
    
    return 0;
}
```

### 8.2 Build Integration

```cpp
#include <sdk/core/build.h>

void buildProject(SDKHandle sdk) {
    // Configure build
    BuildConfig config = {
        .buildType = "Release",
        .toolchain = "MSVC",
        .defines = NULL,
        .defineCount = 0,
        .includePaths = NULL,
        .includeCount = 0,
        .libraryPaths = NULL,
        .libraryCount = 0,
        .parallelJobs = 16
    };
    
    SDK_Build_Configure(sdk, &config);
    
    // Start build
    BuildHandle build;
    SDK_Build_Start(sdk, "MyProject", &build);
    
    // Wait for completion
    BuildResult result;
    SDK_Build_Wait(sdk, build, 60000, &result);
    
    if (result.success) {
        printf("Build successful!\n");
    } else {
        printf("Build failed: %s\n", result.errorMessage);
    }
}
```

---

## Summary

The Core SDK API provides:

- ✅ Complete lifecycle management
- ✅ Comprehensive editor operations
- ✅ Workspace and file management
- ✅ Build system integration
- ✅ Debugger control
- ✅ Git version control
- ✅ Error handling and logging

**Status:** Complete

---

*End of API Reference: Core SDK*
