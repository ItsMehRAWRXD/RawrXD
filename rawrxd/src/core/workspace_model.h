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
#include <vector>

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

// RAWRXD_MULTIROOT_EXPLORER_001
//
// The folder list, not just the counts. The explorer needs each root's own path,
// name and primary flag to render one top-level node per root, and a diagnostics
// struct carrying only totals cannot produce that. Returns an empty vector when
// no workspace has been initialised, which the caller must handle -- that is not
// the same as a workspace with zero roots, which the model refuses to hold.
struct RawrXDWorkspaceFolder {
    std::string path;
    std::string name;
    bool        isRoot = false;      // the workspace's declared primary root
};

extern "C" {

// Creates the process-wide workspace and loads <rootPath>/.rawrxd/workspace.json,
// falling back to a synthetic single-root workspace when there is none.
bool RawrXD_IDE_InitWorkspace(const char* rootPath);

const char* RawrXD_IDE_GetWorkspaceName();

void RawrXD_IDE_AddOpenFile(const char* filePath, int line, int column);
void RawrXD_IDE_RemoveOpenFile(const char* filePath);

bool RawrXD_IDE_SaveWorkspace();

} // extern "C"

// ============================================================================
// C++-typed results live OUTSIDE the extern "C" block.
//
// RAWRXD_END_TO_END_STATE_001
//
// Both functions below were declared inside extern "C" while returning C++
// types, which is ill-formed: a C-linkage function cannot return a class type
// (MSVC C2526). That single declaration was the whole reason RawrXD-Win32IDE
// did not compile -- it produced 9 errors, 8 of them cascading into the call
// site at Win32IDE_Sidebar.cpp:264 where the compiler had already decided the
// call was ill-formed and reported the type as void.
//
// A genuine C ABI cannot carry std::string or std::vector. The fix is not to
// weaken the types -- it is to stop claiming C linkage for functions that are
// not C. All four referencing translation units
// (workspace_model.cpp, main_win32.cpp, Win32IDE_Sidebar.cpp, this header)
// call these directly; nothing resolves them by unmangled name through
// GetProcAddress or dlsym, so giving them C++ linkage changes no binding that
// anything depends on.
//
// If a true C caller ever needs this data, add a POD accessor
// (size_t Count(); bool At(i, const char** path, const char** name, int* isRoot);)
// inside the extern "C" block. Do not put a std::vector in one.
// ============================================================================

// Both diagnostics and the folder list are declared with C++ linkage; see the
// comment above for why. The struct definitions themselves are earlier in this
// header, also outside extern "C".

RawrXDWorkspaceDiagnostics RawrXD_IDE_GetWorkspaceDiagnostics();
std::vector<RawrXDWorkspaceFolder> RawrXD_IDE_GetWorkspaceFolders();
