#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

class Win32IDE;

bool Win32IDE_initAgenticBrowser();
void Win32IDE_showAgenticBrowser();
void Win32IDE_hideAgenticBrowser();
bool Win32IDE_isAgenticBrowserVisible();
