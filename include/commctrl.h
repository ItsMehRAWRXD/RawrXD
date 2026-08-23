#pragma once

// Wrapper to stabilize SAL/CALLBACK macro availability before including
// the WinSDK common controls header. The project include path precedes
// the SDK include path, so this file centralizes the compatibility fix.
#ifndef _Return_type_success_
#define _Return_type_success_(expr)
#endif

#ifndef CALLBACK
#define CALLBACK __stdcall
#endif

// MSVC doesn't support #include_next. Use a relative path that resolves
// from any SDK subdirectory (ucrt/shared/um/winrt) to the real um/commctrl.h.
#include <../um/commctrl.h>
