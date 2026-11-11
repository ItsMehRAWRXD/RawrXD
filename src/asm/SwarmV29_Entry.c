// SwarmV29_Entry.c - C entry point wrapper
// This provides mainCRTStartup for the C runtime

#include <windows.h>

// External assembly entry point
extern void SwarmV29_Entry(void);

// C entry point
int main(void) {
    SwarmV29_Entry();
    return 0;
}

// CRT startup stub
void mainCRTStartup(void) {
    int result = main();
    ExitProcess(result);
}