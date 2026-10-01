// IDEConfig.h — compatibility shim, RETAINED DELIBERATELY.
//
// RAWRXD_PER_PROJECT_CONFIG_001
//
// This header used to be three lines whose entire content was:
//
//     #pragma once
//     // Stub header
//
// and IDEConfig.cpp was one line: `#include "IDEConfig.h"`. Both were listed in
// three CMake targets, so the build compiled a 909-byte object containing no
// code, and CMakeLists.txt annotated one of the entries "required by
// OrchestratorBridge", which a file that defines nothing cannot satisfy.
//
// The implementation now lives in ide_project_config.h / .cpp, and all three
// CMake references were repointed there. This header is kept because other
// translation units may still include "config/IDEConfig.h" and removing it would
// turn a silent no-op into a hard include error in files this pass has not
// audited.
//
// To finish the removal: delete this file once
//   grep -rn "IDEConfig.h" src/ tools/
// returns nothing outside this comment. That check has not been performed here,
// which is why this shim is retained rather than deleted.

#pragma once

// Intentionally does NOT include ide_project_config.h. Including it here would
// make every existing consumer of the old stub silently acquire a project
// configuration authority, which is a behaviour change disguised as a no-op
// rename. Consumers migrate deliberately.

// The authority and its diagnostics live in config/ide_project_config.h, under
// namespace RawrXD:
//
//   class IDEProjectConfig
//   struct ProjectConfigDiagnostics
//
// and are layered over the user settings authority in
// win32app/Win32IDE_Settings.h (namespace RawrXD::IDE). Both are included
// directly by the IDE entry point, main_win32.cpp.
