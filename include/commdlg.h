#pragma once

#ifndef _Return_type_success_
#define _Return_type_success_(expr)
#endif

#ifndef CALLBACK
#define CALLBACK __stdcall
#endif

// Project include/ precedes the WinSDK path; keep SAL/CALLBACK guards then
// forward to whichever installed SDK provides um/commdlg.h.
#if __has_include("C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/um/commdlg.h")
#include "C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/um/commdlg.h"
#elif __has_include("C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um/commdlg.h")
#include "C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um/commdlg.h"
#elif __has_include("D:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/um/commdlg.h")
#include "D:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/um/commdlg.h"
#elif __has_include("D:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um/commdlg.h")
#include "D:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um/commdlg.h"
#else
#error "Windows SDK um/commdlg.h not found (tried 10.0.26100.0 and 10.0.22621.0 on C: and D:)"
#endif
