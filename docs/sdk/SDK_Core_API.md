# Sovereign IDE SDK - Core API Reference
## Batches 1-10: Editor, Workspace, Debugger, Git, Build

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** ✅ Complete

---

## Table of Contents

1. [Editor API](#editor-api)
2. [Workspace API](#workspace-api)
3. [Debugger API](#debugger-api)
4. [Git API](#git-api)
5. [Build API](#build-api)
6. [Data Types](#data-types)
7. [Constants](#constants)

---

## Editor API

### Overview

The Editor API provides programmatic access to the Sovereign IDE text editor, allowing extensions to manipulate text, navigate documents, and interact with the editing surface.

### Functions

#### SDK_Editor_OpenFile

Opens a file in the editor.

```cpp
SDKResult SDK_Editor_OpenFile(
    SDKHandle sdk,
    const char* path,
    EditorHandle* outEditor
);
```

**Parameters:**
- `sdk` - SDK handle
- `path` - File path to open
- `outEditor` - Output editor handle

**Returns:** `SDK_SUCCESS` on success

**Example:**
```cpp
EditorHandle editor;
SDKResult result = SDK_Editor_OpenFile(sdk, "src/main.cpp", &editor);
if (result == SDK_SUCCESS) {
    // File opened successfully
}
```

---

#### SDK_Editor_GetText

Retrieves the entire text content of the editor.

```cpp
SDKResult SDK_Editor_GetText(
    SDKHandle sdk,
    EditorHandle editor,
    char* buffer,
    uint32_t* bufferSize
);
```

**Parameters:**
- `sdk` - SDK handle
- `editor` - Editor handle
- `buffer` - Buffer to receive text
- `bufferSize` - On input: buffer size; on output: actual text size

**Returns:** `SDK_SUCCESS` on success, `SDK_ERROR_BUFFER_TOO_SMALL` if buffer is too small

**Example:**
```cpp
// First call to get size
uint32_t size = 0;
SDK_Editor_GetText(sdk, editor, NULL, &size);

// Allocate buffer and get text
char* text = (char*)malloc(size);
SDK_Editor_GetText(sdk, editor, text, &size);

// Use text...

free(text);
```

---

#### SDK_Editor_SetText

Sets the entire text content of the editor.

```cpp
SDKResult SDK_Editor_SetText(
    SDKHandle sdk,
    EditorHandle editor,
    const char* text
);
```

**Parameters:**
- `sdk` - SDK handle
- `editor` - Editor handle
- `text` - New text content

**Returns:** `SDK_SUCCESS` on success

**Example:**
```cpp
const char* newContent = "// New file content\n";
SDK_Editor_SetText(sdk, editor, newContent);
```

---

#### SDK_Editor_InsertText

Inserts text at a specific position.

```cpp
SDKResult SDK_Editor_InsertText(
    SDKHandle sdk,
    EditorHandle editor,
    uint32_t position,
    const char* text
);
```

**Parameters:**
- `sdk` - SDK handle
- `editor` - Editor handle
- `position` - Character position (0-based)
- `text` - Text to insert

**Returns:** `SDK_SUCCESS` on success

**Example:**
```cpp
// Insert at beginning
SDK_Editor_InsertText(sdk, editor, 0, "// Header comment\n");

// Insert at current cursor position
uint32_t cursorPos;
SDK_Editor_GetCursorPosition(sdk, editor, &cursorPos);
SDK_Editor_InsertText(sdk, editor, cursorPos, "inserted text");
```

---

#### SDK_Editor_DeleteText

Deletes text in a range.

```cpp
SDKResult SDK_Editor_DeleteText(
    SDKHandle sdk,
    EditorHandle editor,
    uint32_t start,
    uint32_t end
);
```

**Parameters:**
- `sdk` - SDK handle
- `editor` - Editor handle
- `start` - Start position (inclusive)
- `end` - End position (exclusive)

**Returns:** `SDK_SUCCESS` on success

**Example:**
```cpp
// Delete first 10 characters
SDK_Editor_DeleteText(sdk, editor, 0, 10);

// Delete selected text
Selection sel;
SDK_Editor_GetSelection(sdk, editor, &sel);
SDK_Editor_DeleteText(sdk, editor, sel.start, sel.end);
```

---

#### SDK_Editor_GetCursorPosition

Gets the current cursor position.

```cpp
SDKResult SDK_Editor_GetCursorPosition(
    SDKHandle sdk,
    EditorHandle editor,
    CursorPosition* outPosition
);
```

**Parameters:**
- `sdk` - SDK handle
- `editor` - Editor handle
- `outPosition` - Output cursor position

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Editor_SetCursorPosition

Sets the cursor position.

```cpp
SDKResult SDK_Editor_SetCursorPosition(
    SDKHandle sdk,
    EditorHandle editor,
    const CursorPosition* position
);
```

**Parameters:**
- `sdk` - SDK handle
- `editor` - Editor handle
- `position` - New cursor position

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Editor_GetSelection

Gets the current selection.

```cpp
SDKResult SDK_Editor_GetSelection(
    SDKHandle sdk,
    EditorHandle editor,
    Selection* outSelection
);
```

**Parameters:**
- `sdk` - SDK handle
- `editor` - Editor handle
- `outSelection` - Output selection

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Editor_SetSelection

Sets the selection.

```cpp
SDKResult SDK_Editor_SetSelection(
    SDKHandle sdk,
    EditorHandle editor,
    const Selection* selection
);
```

**Parameters:**
- `sdk` - SDK handle
- `editor` - Editor handle
- `selection` - New selection

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Editor_ScrollToLine

Scrolls the editor to a specific line.

```cpp
SDKResult SDK_Editor_ScrollToLine(
    SDKHandle sdk,
    EditorHandle editor,
    uint32_t line
);
```

**Parameters:**
- `sdk` - SDK handle
- `editor` - Editor handle
- `line` - Line number (1-based)

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Editor_HighlightRange

Highlights a range of text.

```cpp
SDKResult SDK_Editor_HighlightRange(
    SDKHandle sdk,
    EditorHandle editor,
    uint32_t start,
    uint32_t end,
    HighlightStyle style
);
```

**Parameters:**
- `sdk` - SDK handle
- `editor` - Editor handle
- `start` - Start position
- `end` - End position
- `style` - Highlight style

**Returns:** `SDK_SUCCESS` on success

---

## Workspace API

### Overview

The Workspace API manages project workspaces, including file operations, project configuration, and workspace state.

### Functions

#### SDK_Workspace_Open

Opens a workspace.

```cpp
SDKResult SDK_Workspace_Open(
    SDKHandle sdk,
    const char* path,
    WorkspaceHandle* outWorkspace
);
```

**Parameters:**
- `sdk` - SDK handle
- `path` - Workspace path
- `outWorkspace` - Output workspace handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Workspace_Close

Closes a workspace.

```cpp
SDKResult SDK_Workspace_Close(
    SDKHandle sdk,
    WorkspaceHandle workspace
);
```

**Parameters:**
- `sdk` - SDK handle
- `workspace` - Workspace handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Workspace_GetFiles

Gets all files in the workspace.

```cpp
SDKResult SDK_Workspace_GetFiles(
    SDKHandle sdk,
    WorkspaceHandle workspace,
    FileInfo* files,
    uint32_t* fileCount
);
```

**Parameters:**
- `sdk` - SDK handle
- `workspace` - Workspace handle
- `files` - Array to receive file info
- `fileCount` - On input: array size; on output: actual count

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Workspace_GetRootPath

Gets the workspace root path.

```cpp
SDKResult SDK_Workspace_GetRootPath(
    SDKHandle sdk,
    WorkspaceHandle workspace,
    char* path,
    uint32_t pathSize
);
```

**Parameters:**
- `sdk` - SDK handle
- `workspace` - Workspace handle
- `path` - Buffer to receive path
- `pathSize` - Buffer size

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Workspace_Save

Saves the workspace state.

```cpp
SDKResult SDK_Workspace_Save(
    SDKHandle sdk,
    WorkspaceHandle workspace
);
```

**Parameters:**
- `sdk` - SDK handle
- `workspace` - Workspace handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Workspace_CreateFile

Creates a new file in the workspace.

```cpp
SDKResult SDK_Workspace_CreateFile(
    SDKHandle sdk,
    WorkspaceHandle workspace,
    const char* relativePath,
    const char* content
);
```

**Parameters:**
- `sdk` - SDK handle
- `workspace` - Workspace handle
- `relativePath` - Relative path from workspace root
- `content` - Initial file content (can be NULL)

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Workspace_DeleteFile

Deletes a file from the workspace.

```cpp
SDKResult SDK_Workspace_DeleteFile(
    SDKHandle sdk,
    WorkspaceHandle workspace,
    const char* relativePath
);
```

**Parameters:**
- `sdk` - SDK handle
- `workspace` - Workspace handle
- `relativePath` - Relative path from workspace root

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Workspace_RenameFile

Renames a file in the workspace.

```cpp
SDKResult SDK_Workspace_RenameFile(
    SDKHandle sdk,
    WorkspaceHandle workspace,
    const char* oldPath,
    const char* newPath
);
```

**Parameters:**
- `sdk` - SDK handle
- `workspace` - Workspace handle
- `oldPath` - Current relative path
- `newPath` - New relative path

**Returns:** `SDK_SUCCESS` on success

---

## Debugger API

### Overview

The Debugger API provides programmatic control over the debugging session, including breakpoints, stepping, and variable inspection.

### Functions

#### SDK_Debugger_Start

Starts a debugging session.

```cpp
SDKResult SDK_Debugger_Start(
    SDKHandle sdk,
    const DebugConfig* config,
    DebuggerHandle* outDebugger
);
```

**Parameters:**
- `sdk` - SDK handle
- `config` - Debug configuration
- `outDebugger` - Output debugger handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Debugger_Stop

Stops a debugging session.

```cpp
SDKResult SDK_Debugger_Stop(
    SDKHandle sdk,
    DebuggerHandle debugger
);
```

**Parameters:**
- `sdk` - SDK handle
- `debugger` - Debugger handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Debugger_SetBreakpoint

Sets a breakpoint.

```cpp
SDKResult SDK_Debugger_SetBreakpoint(
    SDKHandle sdk,
    DebuggerHandle debugger,
    const char* file,
    uint32_t line,
    BreakpointHandle* outBreakpoint
);
```

**Parameters:**
- `sdk` - SDK handle
- `debugger` - Debugger handle
- `file` - Source file path
- `line` - Line number
- `outBreakpoint` - Output breakpoint handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Debugger_RemoveBreakpoint

Removes a breakpoint.

```cpp
SDKResult SDK_Debugger_RemoveBreakpoint(
    SDKHandle sdk,
    DebuggerHandle debugger,
    BreakpointHandle breakpoint
);
```

**Parameters:**
- `sdk` - SDK handle
- `debugger` - Debugger handle
- `breakpoint` - Breakpoint handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Debugger_Continue

Continues execution.

```cpp
SDKResult SDK_Debugger_Continue(
    SDKHandle sdk,
    DebuggerHandle debugger
);
```

**Parameters:**
- `sdk` - SDK handle
- `debugger` - Debugger handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Debugger_StepOver

Steps over the current line.

```cpp
SDKResult SDK_Debugger_StepOver(
    SDKHandle sdk,
    DebuggerHandle debugger
);
```

**Parameters:**
- `sdk` - SDK handle
- `debugger` - Debugger handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Debugger_StepInto

Steps into the current function call.

```cpp
SDKResult SDK_Debugger_StepInto(
    SDKHandle sdk,
    DebuggerHandle debugger
);
```

**Parameters:**
- `sdk` - SDK handle
- `debugger` - Debugger handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Debugger_StepOut

Steps out of the current function.

```cpp
SDKResult SDK_Debugger_StepOut(
    SDKHandle sdk,
    DebuggerHandle debugger
);
```

**Parameters:**
- `sdk` - SDK handle
- `debugger` - Debugger handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Debugger_GetCallStack

Gets the current call stack.

```cpp
SDKResult SDK_Debugger_GetCallStack(
    SDKHandle sdk,
    DebuggerHandle debugger,
    StackFrame* frames,
    uint32_t* frameCount
);
```

**Parameters:**
- `sdk` - SDK handle
- `debugger` - Debugger handle
- `frames` - Array to receive stack frames
- `frameCount` - On input: array size; on output: actual count

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Debugger_GetVariables

Gets variables in the current scope.

```cpp
SDKResult SDK_Debugger_GetVariables(
    SDKHandle sdk,
    DebuggerHandle debugger,
    Variable* variables,
    uint32_t* variableCount
);
```

**Parameters:**
- `sdk` - SDK handle
- `debugger` - Debugger handle
- `variables` - Array to receive variables
- `variableCount` - On input: array size; on output: actual count

**Returns:** `SDK_SUCCESS` on success

---

## Git API

### Overview

The Git API provides version control operations, allowing extensions to interact with Git repositories.

### Functions

#### SDK_Git_OpenRepository

Opens a Git repository.

```cpp
SDKResult SDK_Git_OpenRepository(
    SDKHandle sdk,
    const char* path,
    GitRepositoryHandle* outRepo
);
```

**Parameters:**
- `sdk` - SDK handle
- `path` - Repository path
- `outRepo` - Output repository handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Git_CloseRepository

Closes a Git repository.

```cpp
SDKResult SDK_Git_CloseRepository(
    SDKHandle sdk,
    GitRepositoryHandle repo
);
```

**Parameters:**
- `sdk` - SDK handle
- `repo` - Repository handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Git_GetStatus

Gets the repository status.

```cpp
SDKResult SDK_Git_GetStatus(
    SDKHandle sdk,
    GitRepositoryHandle repo,
    GitStatus* status
);
```

**Parameters:**
- `sdk` - SDK handle
- `repo` - Repository handle
- `status` - Output status

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Git_StageFile

Stages a file for commit.

```cpp
SDKResult SDK_Git_StageFile(
    SDKHandle sdk,
    GitRepositoryHandle repo,
    const char* path
);
```

**Parameters:**
- `sdk` - SDK handle
- `repo` - Repository handle
- `path` - File path

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Git_UnstageFile

Unstages a file.

```cpp
SDKResult SDK_Git_UnstageFile(
    SDKHandle sdk,
    GitRepositoryHandle repo,
    const char* path
);
```

**Parameters:**
- `sdk` - SDK handle
- `repo` - Repository handle
- `path` - File path

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Git_Commit

Creates a commit.

```cpp
SDKResult SDK_Git_Commit(
    SDKHandle sdk,
    GitRepositoryHandle repo,
    const char* message,
    const char* author,
    const char* email
);
```

**Parameters:**
- `sdk` - SDK handle
- `repo` - Repository handle
- `message` - Commit message
- `author` - Author name
- `email` - Author email

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Git_GetLog

Gets the commit log.

```cpp
SDKResult SDK_Git_GetLog(
    SDKHandle sdk,
    GitRepositoryHandle repo,
    CommitInfo* commits,
    uint32_t* commitCount,
    uint32_t maxCount
);
```

**Parameters:**
- `sdk` - SDK handle
- `repo` - Repository handle
- `commits` - Array to receive commits
- `commitCount` - On input: array size; on output: actual count
- `maxCount` - Maximum commits to retrieve

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Git_CreateBranch

Creates a new branch.

```cpp
SDKResult SDK_Git_CreateBranch(
    SDKHandle sdk,
    GitRepositoryHandle repo,
    const char* branchName,
    const char* baseCommit
);
```

**Parameters:**
- `sdk` - SDK handle
- `repo` - Repository handle
- `branchName` - New branch name
- `baseCommit` - Base commit (NULL for current HEAD)

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Git_CheckoutBranch

Checks out a branch.

```cpp
SDKResult SDK_Git_CheckoutBranch(
    SDKHandle sdk,
    GitRepositoryHandle repo,
    const char* branchName
);
```

**Parameters:**
- `sdk` - SDK handle
- `repo` - Repository handle
- `branchName` - Branch name

**Returns:** `SDK_SUCCESS` on success

---

## Build API

### Overview

The Build API provides access to the build system, allowing extensions to configure, start, and monitor builds.

### Functions

#### SDK_Build_Configure

Configures the build system.

```cpp
SDKResult SDK_Build_Configure(
    SDKHandle sdk,
    const BuildConfig* config
);
```

**Parameters:**
- `sdk` - SDK handle
- `config` - Build configuration

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Build_Start

Starts a build.

```cpp
SDKResult SDK_Build_Start(
    SDKHandle sdk,
    const char* target,
    BuildHandle* outBuild
);
```

**Parameters:**
- `sdk` - SDK handle
- `target` - Build target (NULL for default)
- `outBuild` - Output build handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Build_Stop

Stops a running build.

```cpp
SDKResult SDK_Build_Stop(
    SDKHandle sdk,
    BuildHandle build
);
```

**Parameters:**
- `sdk` - SDK handle
- `build` - Build handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Build_GetStatus

Gets the current build status.

```cpp
SDKResult SDK_Build_GetStatus(
    SDKHandle sdk,
    BuildHandle build,
    BuildStatus* status
);
```

**Parameters:**
- `sdk` - SDK handle
- `build` - Build handle
- `status` - Output status

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Build_GetOutput

Gets the build output.

```cpp
SDKResult SDK_Build_GetOutput(
    SDKHandle sdk,
    BuildHandle build,
    char* buffer,
    uint32_t* bufferSize
);
```

**Parameters:**
- `sdk` - SDK handle
- `build` - Build handle
- `buffer` - Buffer to receive output
- `bufferSize` - On input: buffer size; on output: actual size

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Build_GetErrors

Gets build errors.

```cpp
SDKResult SDK_Build_GetErrors(
    SDKHandle sdk,
    BuildHandle build,
    BuildError* errors,
    uint32_t* errorCount
);
```

**Parameters:**
- `sdk` - SDK handle
- `build` - Build handle
- `errors` - Array to receive errors
- `errorCount` - On input: array size; on output: actual count

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Build_Clean

Cleans the build output.

```cpp
SDKResult SDK_Build_Clean(
    SDKHandle sdk,
    BuildHandle build
);
```

**Parameters:**
- `sdk` - SDK handle
- `build` - Build handle

**Returns:** `SDK_SUCCESS` on success

---

## Data Types

### CursorPosition

```cpp
struct CursorPosition {
    uint32_t line;      // Line number (1-based)
    uint32_t column;    // Column number (1-based)
    uint32_t offset;    // Character offset (0-based)
};
```

### Selection

```cpp
struct Selection {
    uint32_t start;     // Start position
    uint32_t end;       // End position
    CursorPosition startLineCol;
    CursorPosition endLineCol;
};
```

### FileInfo

```cpp
struct FileInfo {
    char path[256];
    char name[128];
    uint64_t size;
    uint64_t modifiedTime;
    bool isDirectory;
};
```

### DebugConfig

```cpp
struct DebugConfig {
    char executable[256];
    char workingDirectory[256];
    char arguments[1024];
    char environment[4096];
    bool stopOnEntry;
};
```

### StackFrame

```cpp
struct StackFrame {
    char function[128];
    char file[256];
    uint32_t line;
    uint64_t address;
    uint32_t frameId;
};
```

### Variable

```cpp
struct Variable {
    char name[128];
    char type[64];
    char value[256];
    bool hasChildren;
    uint32_t variableId;
};
```

### GitStatus

```cpp
struct GitStatus {
    char branch[128];
    bool isDirty;
    uint32_t aheadCount;
    uint32_t behindCount;
    uint32_t modifiedCount;
    uint32_t stagedCount;
    uint32_t untrackedCount;
};
```

### CommitInfo

```cpp
struct CommitInfo {
    char hash[41];
    char message[256];
    char author[128];
    char email[128];
    uint64_t timestamp;
};
```

### BuildConfig

```cpp
struct BuildConfig {
    char buildDirectory[256];
    char generator[64];
    char configuration[32];
    char platform[32];
    char toolset[64];
    char additionalFlags[1024];
};
```

### BuildStatus

```cpp
struct BuildStatus {
    BuildState state;
    uint32_t totalSteps;
    uint32_t completedSteps;
    uint32_t errorCount;
    uint32_t warningCount;
    uint64_t startTime;
    uint64_t elapsedTime;
};
```

### BuildError

```cpp
struct BuildError {
    char file[256];
    uint32_t line;
    uint32_t column;
    char message[512];
    ErrorSeverity severity;
};
```

---

## Constants

### HighlightStyle

```cpp
enum HighlightStyle {
    HIGHLIGHT_NONE = 0,
    HIGHLIGHT_SELECTION = 1,
    HIGHLIGHT_SEARCH = 2,
    HIGHLIGHT_ERROR = 3,
    HIGHLIGHT_WARNING = 4,
    HIGHLIGHT_BREAKPOINT = 5,
    HIGHLIGHT_CURRENT_LINE = 6
};
```

### BuildState

```cpp
enum BuildState {
    BUILD_IDLE = 0,
    BUILD_RUNNING = 1,
    BUILD_SUCCEEDED = 2,
    BUILD_FAILED = 3,
    BUILD_CANCELLED = 4
};
```

### ErrorSeverity

```cpp
enum ErrorSeverity {
    SEVERITY_INFO = 0,
    SEVERITY_WARNING = 1,
    SEVERITY_ERROR = 2,
    SEVERITY_FATAL = 3
};
```

---

## Summary

The Core API provides:

- ✅ **Editor API** - Text manipulation, cursor, selection
- ✅ **Workspace API** - File operations, project management
- ✅ **Debugger API** - Breakpoints, stepping, variables
- ✅ **Git API** - Version control operations
- ✅ **Build API** - Build configuration and execution
- ✅ **Comprehensive data types** for all operations

**Status:** ✅ Complete

---

*End of Core API Documentation*
