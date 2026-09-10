#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void RawrNative_CollectGgufRoots(char roots[][MAX_PATH], int* n, int cap);

#ifdef __cplusplus
}
#endif
