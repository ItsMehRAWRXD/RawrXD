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

#if __has_include("C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/um/commctrl.h")
#include "C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/um/commctrl.h"
#elif __has_include("C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um/commctrl.h")
#include "C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um/commctrl.h"
#elif __has_include("D:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/um/commctrl.h")
#include "D:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/um/commctrl.h"
#elif __has_include("D:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um/commctrl.h")
#include "D:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um/commctrl.h"
#else
#error "Windows SDK um/commctrl.h not found (tried 10.0.26100.0 and 10.0.22621.0 on C: and D:)"
#endif
