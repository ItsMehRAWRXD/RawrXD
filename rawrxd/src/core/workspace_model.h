// workspace_model.h — RAWRXD_WORKSPACE_IDE_BINDING_001
//
// Multi-root workspace model for the IDE. This header did not exist: the
// translation unit was fully implemented but reachable only through locally
// declared C API symbols, which is part of why nothing referenced it.
//
// The diagnostics struct exists so the product path can be receipted. Every field
// is set by the code that performs the operation; the booleans start false and
// the counters at zero, so a caller cannot report a workspace as loaded without
// load() having actually run.
#pragma once

#include <cstddef>
#include <string>

// LoadOutcome mirrors the three states that a bool cannot distinguish, all of
// which occur in practice and mean different things:
//
//   0 NeverRun  the workspace has not been initialised
//   1 Absent    no document on disk; a first run is not a failure
//   2 Refused   the document existed but was not adopted -- unparsable, schema
//               error, or zero folders -- and the previous config was left intact
//   3 Applied   the document was parsed and committed
struct RawrXDWorkspaceDiagnostics {
    bool        initialized = false;
    std::string docPath;
    std::string name;
    std::string rootPath;
    std::size_t folders = 0;
    std::size_t roots = 0;
    std::size_t openFiles = 0;
    bool        dirty = false;
    int         loadOutcome = 0;      // see RawrXDWorkspaceLoadOutcome above
    std::size_t saveCalls = 0;
    bool        saveWrote = false;
    std::size_t saveBytes = 0;
};

extern "C" {

// Creates the process-wide workspace and loads <rootPath>/.rawrxd/workspace.json,
// falling back to a synthetic single-root workspace when there is none.
bool RawrXD_IDE_InitWorkspace(const char* rootPath);

const char* RawrXD_IDE_GetWorkspaceName();

void RawrXD_IDE_AddOpenFile(const char* filePath, int line, int column);
void RawrXD_IDE_RemoveOpenFile(const char* filePath);

bool RawrXD_IDE_SaveWorkspace();

// RAWRXD_WORKSPACE_IDE_BINDING_001: measured state for the runtime receipt.
RawrXDWorkspaceDiagnostics RawrXD_IDE_GetWorkspaceDiagnostics();

} // extern "C"
