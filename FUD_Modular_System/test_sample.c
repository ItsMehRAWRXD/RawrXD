#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// ===============================================================================
// SAMPLE TEST FILE - SIMULATES GITHUB .C FILE
// ===============================================================================

int main() {
    printf("Hello from GitHub .c file!\n");
    printf("This is a test file to verify GitHub integration works.\n");
    
    // Test Windows API
    DWORD uptime = GetTickCount();
    printf("System uptime: %lu ms\n", uptime);
    
    // Test registry access
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        printf("Registry access: SUCCESS\n");
        RegCloseKey(hKey);
    } else {
        printf("Registry access: FAILED\n");
    }
    
    // Test file operations
    FILE* test_file = fopen("test_output.txt", "w");
    if (test_file) {
        fprintf(test_file, "GitHub integration test successful!\n");
        fclose(test_file);
        printf("File operations: SUCCESS\n");
    } else {
        printf("File operations: FAILED\n");
    }
    
    printf("\nGitHub .c file test completed successfully!\n");
    return 0;
}