#include <windows.h>

extern "C" {
    void Sovereign_Ghost_PushToken(const char* token);
    bool Sovereign_Ghost_ReadFrame(char* outBuffer, int maxLen, int* outBytesRead);
}

extern "C" void OnTokenGenerated(const char* token) {
    // Hardware readout verification: Print the token to console.
    DWORD written;
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteConsoleA(hConsole, token, lstrlenA(token), &written, NULL);
}

DWORD WINAPI GhostRenderThread(LPVOID lpParam) {
    // Must remain at NORMAL_PRIORITY_CLASS to validate hardware read-out.
    // If inference starves this, gravity is broken.
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    
    // Allocate static buffer to avoid __chkstk stack probing from compiler
    static char buffer[4096];
    while (true) {
        int bytesRead = 0;
        if (Sovereign_Ghost_ReadFrame(buffer, sizeof(buffer) - 1, &bytesRead)) {
            if (bytesRead > 0) {
                OnTokenGenerated(buffer);
            }
        }
        Sleep(1); // Yield timeslice to OS, avoid bottlenecking 144Hz
    }
    return 0;
}

extern "C" void Sovereign_Ghost_StartRenderer() {
    CreateThread(NULL, 0, GhostRenderThread, NULL, 0, NULL);
}
