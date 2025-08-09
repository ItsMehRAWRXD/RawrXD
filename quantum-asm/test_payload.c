// Test Payload DLL for Windows 11 Process Injection
// Compile: i686-w64-mingw32-gcc -shared -O2 test_payload.c -o payload32.dll
//          x86_64-w64-mingw32-gcc -shared -O2 test_payload.c -o payload64.dll

#include <windows.h>
#include <stdio.h>

// Export functions for testing
__declspec(dllexport) void TestFunction() {
    MessageBoxA(NULL, "DLL Successfully Injected!", "Success", MB_OK | MB_ICONINFORMATION);
}

__declspec(dllexport) int GetProcessInfo(char* buffer, int bufSize) {
    DWORD pid = GetCurrentProcessId();
    char exePath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    return snprintf(buffer, bufSize, "PID: %lu\nProcess: %s", pid, exePath);
}

// Thread function for continuous operation
DWORD WINAPI WorkerThread(LPVOID lpParam) {
    // Create a log file
    char logPath[MAX_PATH];
    GetTempPathA(MAX_PATH, logPath);
    strcat(logPath, "injection_log.txt");
    
    FILE* log = fopen(logPath, "a");
    if (log) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(log, "[%02d:%02d:%02d] DLL injected into PID %lu\n", 
                st.wHour, st.wMinute, st.wSecond, GetCurrentProcessId());
        fclose(log);
    }
    
    // Keep thread alive
    while (1) {
        Sleep(1000);
        // Thread can perform continuous monitoring or other tasks
    }
    
    return 0;
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            // Disable thread notifications for performance
            DisableThreadLibraryCalls(hModule);
            
            // Create worker thread
            CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
            
            // Show injection success (optional - remove for stealth)
            #ifdef SHOW_MESSAGE
            TestFunction();
            #endif
            
            break;
            
        case DLL_PROCESS_DETACH:
            // Cleanup if needed
            break;
    }
    
    return TRUE;
}