// Win32IDE_Session.h — canonical session persistence for the Win32 IDE
//
// RAWRXD_SESSION_PERSISTENCE_001
//
// Before this pass Session_SetPath() had no caller anywhere in the tree, so
// g_sessionPath stayed empty and both Session_Save() and Session_Load() returned
// at their first line. The session code was linked into the shipping IDE and
// structurally incapable of doing anything. This is the same class of defect as
// the settings one, in the same subsystem.
//
// One path, one load, one save, one diagnostics surface. The session file lives
// beside the settings file so "my configuration" is one directory, not two
// conventions to discover.

#pragma once
#include <string>
#include <cstddef>

namespace RawrXD::IDE {

struct SessionFile {
    std::string path;
    int line = 0;
    int col  = 0;
};

// Every field is measured at runtime; the booleans start false and the counters
// at zero, so a receipt cannot report PASS without the operation having run.
struct SessionDiagnostics {
    bool        loadCalled = false;
    bool        pathResolved = false;
    bool        fileExisted = false;
    bool        saveCalled = false;
    bool        saveWroteFile = false;
    bool        recovered = false;
    std::size_t linesRead = 0;
    std::size_t linesRejected = 0;
    std::size_t filesInSession = 0;
    std::size_t filesTracked = 0;
    std::size_t saveBytesWritten = 0;
    std::string resolvedPath;
    std::string lastError;
};

const SessionDiagnostics& Session_Diagnostics();

// Resolves the session file next to the settings file, so both are in one place.
bool Session_InitDefaultPath();

// Loads the session if a path is set. Safe to call from WM_CREATE.
bool Session_Load();

// Tracks a file for the next save. Recording the same path twice updates the
// cursor position instead of adding a duplicate entry.
void Session_AddFile(const std::string& path, int line, int col);

// Returns whether a real file was written.
bool Session_Persist();

// Original entry points, unchanged signatures.
void Session_SetPath(const std::string& path);
void Session_Save();
void Session_Clear();
const std::vector<SessionFile>& Session_GetFiles();

} // namespace RawrXD::IDE