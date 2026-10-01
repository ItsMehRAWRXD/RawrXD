// IDEConfig.cpp — RAWRXD_PER_PROJECT_CONFIG_001
//
// This translation unit used to be exactly one line:
//
//     #include "IDEConfig.h"
//
// and it was listed in three CMake targets (CMakeLists.txt:442, :2572, :5431),
// so the build produced a 909-byte object with no symbols and no behaviour. The
// CMake entry carried the comment "required by OrchestratorBridge", which a file
// that defines nothing cannot be required by.
//
// All three CMake references now point at src/config/ide_project_config.cpp,
// which implements the real per-project configuration authority. This file is
// kept for the same reason the header is kept: some translation unit may still
// name it, and the alternative to a retained empty TU is an unresolved-symbol
// error discovered at link time in a file this pass has not audited.
//
// It deliberately does NOT include ide_project_config.h. Pulling a real
// implementation in under the old name would change the behaviour of any
// consumer that included the stub expecting nothing to happen. The old name
// keeps meaning "no per-project configuration here"; the new header is
// included explicitly by the code that wants one.
//
// To finish the removal:
//   grep -rn "IDEConfig.cpp" CMakeLists.txt cmake/
//   grep -rn "IDEConfig.h"  src/ tools/
// Both must return nothing outside these two files.

#include "IDEConfig.h"

// Intentionally empty. See the file comment above.
