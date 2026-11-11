#include <windows.h>
#include <cstdio>
#include <cstdint>

int main() {
    const char* path = "G:\\~dev\\rawrxd\\models\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed: %lu\n", GetLastError());
        return 1;
    }
    
    uint32_t magic = 0;
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, &magic, 4, &bytesRead, nullptr)) {
        printf("ReadFile failed: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
    
    printf("Magic: 0x%08x (%c%c%c%c)\n", magic, 
           (magic & 0xFF), ((magic >> 8) & 0xFF), ((magic >> 16) & 0xFF), ((magic >> 24) & 0xFF));
    
    CloseHandle(hFile);
    return 0;
}