// secure_settings_api.cpp — Production secure settings implementation

#include "secure_settings_api.h"
#include <cryptprotect.h>
#include <string>
#include <cstdio>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <algorithm>

// LAZY SINGLETON PATTERN: Avoid SIOF - non-trivial constructors
inline std::unordered_map<std::string, std::vector<BYTE>>& GetEncryptedKeys() {
    static std::unordered_map<std::string, std::vector<BYTE>>* inst = new std::unordered_map<std::string, std::vector<BYTE>>();
    return *inst;
}
#define g_encryptedKeys GetEncryptedKeys()

inline std::mutex& GetStorageMutex() {
    static std::mutex* inst = new std::mutex();
    return *inst;
}
#define g_storageMutex GetStorageMutex()

extern "C" bool SecureStorage_SaveApiKey(const char* keyName, const char* apiKey) {
    if (!keyName || !apiKey) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(g_storageMutex);
    
    DATA_BLOB inBlob;
    inBlob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(apiKey));
    inBlob.cbData = static_cast<DWORD>(strlen(apiKey) + 1);
    
    DATA_BLOB outBlob = {};
    if (!CryptProtectData(&inBlob, L"RawrXD API Key", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &outBlob)) {
        return false;
    }
    
    std::vector<BYTE> encrypted(outBlob.pbData, outBlob.pbData + outBlob.cbData);
    LocalFree(outBlob.pbData);
    
    g_encryptedKeys[keyName] = std::move(encrypted);
    return true;
}

extern "C" bool SecureStorage_LoadApiKey(const char* keyName, char* buffer, size_t bufferSize) {
    if (!keyName || !buffer || bufferSize == 0) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(g_storageMutex);
    
    auto it = g_encryptedKeys.find(keyName);
    if (it == g_encryptedKeys.end()) {
        return false;
    }
    
    DATA_BLOB inBlob;
    inBlob.pbData = it->second.data();
    inBlob.cbData = static_cast<DWORD>(it->second.size());
    
    DATA_BLOB outBlob = {};
    if (!CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &outBlob)) {
        return false;
    }
    
    bool success = false;
    if (outBlob.cbData < bufferSize) {
        memcpy(buffer, outBlob.pbData, outBlob.cbData);
        buffer[outBlob.cbData] = '\0';
        success = true;
    }
    
    SecureZeroMemory(outBlob.pbData, outBlob.cbData);
    LocalFree(outBlob.pbData);
    
    return success;
}

extern "C" void SecureStorage_DeleteApiKey(const char* keyName) {
    if (!keyName) return;
    
    std::lock_guard<std::mutex> lock(g_storageMutex);
    auto it = g_encryptedKeys.find(keyName);
    if (it != g_encryptedKeys.end()) {
        SecureZeroMemory(it->second.data(), it->second.size());
        g_encryptedKeys.erase(it);
    }
}

extern "C" bool SecureStorage_HasKey(const char* keyName) {
    if (!keyName) return false;
    
    std::lock_guard<std::mutex> lock(g_storageMutex);
    return g_encryptedKeys.find(keyName) != g_encryptedKeys.end();
}

extern "C" bool MonacoSettingsDialog_ShowModal(HWND hwndParent, MonacoSettings* settings) {
    if (!settings) {
        return false;
    }
    
    // Create a modal dialog for Monaco editor settings
    // This provides a proper UI for users to configure editor settings
    
    // Validate current settings first
    if (settings->fontSize < 8) settings->fontSize = 8;
    if (settings->fontSize > 72) settings->fontSize = 72;
    if (settings->lineHeight < 1.0f) settings->lineHeight = 1.0f;
    if (settings->lineHeight > 3.0f) settings->lineHeight = 3.0f;
    
    // Create dialog procedure
    auto DialogProc = [](HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) -> INT_PTR {
        switch (message) {
            case WM_INITDIALOG: {
                // Center dialog on parent
                HWND hwndParent = GetParent(hwndDlg);
                if (hwndParent) {
                    RECT rcParent, rcDlg;
                    GetWindowRect(hwndParent, &rcParent);
                    GetWindowRect(hwndDlg, &rcDlg);
                    int x = rcParent.left + (rcParent.right - rcParent.left - (rcDlg.right - rcDlg.left)) / 2;
                    int y = rcParent.top + (rcParent.bottom - rcParent.top - (rcDlg.bottom - rcDlg.top)) / 2;
                    SetWindowPos(hwndDlg, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
                }
                
                // Load current settings into controls
                MonacoSettings* pSettings = (MonacoSettings*)lParam;
                SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)pSettings);
                
                // Initialize font size spinner
                HWND hwndFontSize = GetDlgItem(hwndDlg, IDC_FONTSIZE);
                if (hwndFontSize) {
                    SendMessage(hwndFontSize, UDM_SETRANGE32, 8, 72);
                    SendMessage(hwndFontSize, UDM_SETPOS32, 0, pSettings->fontSize);
                }
                
                // Initialize line height edit
                HWND hwndLineHeight = GetDlgItem(hwndDlg, IDC_LINEHEIGHT);
                if (hwndLineHeight) {
                    char buf[32];
                    snprintf(buf, sizeof(buf), "%.2f", pSettings->lineHeight);
                    SetWindowTextA(hwndLineHeight, buf);
                }
                
                // Initialize theme dropdown
                HWND hwndTheme = GetDlgItem(hwndDlg, IDC_THEME);
                if (hwndTheme) {
                    SendMessageA(hwndTheme, CB_ADDSTRING, 0, (LPARAM)"dark");
                    SendMessageA(hwndTheme, CB_ADDSTRING, 0, (LPARAM)"light");
                    SendMessageA(hwndTheme, CB_ADDSTRING, 0, (LPARAM)"high-contrast");
                    SendMessageA(hwndTheme, CB_SELECTSTRING, 0, (LPARAM)pSettings->theme);
                }
                
                // Initialize word wrap checkbox
                HWND hwndWordWrap = GetDlgItem(hwndDlg, IDC_WORDWRAP);
                if (hwndWordWrap) {
                    SendMessage(hwndWordWrap, BM_SETCHECK, pSettings->wordWrap ? BST_CHECKED : BST_UNCHECKED, 0);
                }
                
                return TRUE;
            }
            
            case WM_COMMAND:
                switch (LOWORD(wParam)) {
                    case IDOK: {
                        MonacoSettings* pSettings = (MonacoSettings*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
                        if (pSettings) {
                            // Get font size
                            HWND hwndFontSize = GetDlgItem(hwndDlg, IDC_FONTSIZE_EDIT);
                            if (hwndFontSize) {
                                char buf[32];
                                GetWindowTextA(hwndFontSize, buf, sizeof(buf));
                                pSettings->fontSize = atoi(buf);
                            }
                            
                            // Get line height
                            HWND hwndLineHeight = GetDlgItem(hwndDlg, IDC_LINEHEIGHT);
                            if (hwndLineHeight) {
                                char buf[32];
                                GetWindowTextA(hwndLineHeight, buf, sizeof(buf));
                                pSettings->lineHeight = (float)atof(buf);
                            }
                            
                            // Get theme
                            HWND hwndTheme = GetDlgItem(hwndDlg, IDC_THEME);
                            if (hwndTheme) {
                                int sel = (int)SendMessage(hwndTheme, CB_GETCURSEL, 0, 0);
                                if (sel != CB_ERR) {
                                    SendMessageA(hwndTheme, CB_GETLBTEXT, sel, (LPARAM)pSettings->theme);
                                }
                            }
                            
                            // Get word wrap
                            HWND hwndWordWrap = GetDlgItem(hwndDlg, IDC_WORDWRAP);
                            if (hwndWordWrap) {
                                pSettings->wordWrap = (SendMessage(hwndWordWrap, BM_GETCHECK, 0, 0) == BST_CHECKED);
                            }
                        }
                        EndDialog(hwndDlg, IDOK);
                        return TRUE;
                    }
                    
                    case IDCANCEL:
                        EndDialog(hwndDlg, IDCANCEL);
                        return TRUE;
                }
                break;
        }
        return FALSE;
    };
    
    // Show modal dialog
    INT_PTR result = DialogBoxParamA(GetModuleHandle(nullptr), 
                                      MAKEINTRESOURCEA(IDD_MONACO_SETTINGS),
                                      hwndParent, DialogProc, (LPARAM)settings);
    
    return (result == IDOK);
}

extern "C" bool MonacoSettingsDialog_LoadFromFile(const char* path, MonacoSettings* settings) {
    if (!path || !settings) {
        return false;
    }
    
    // Real file loading: parse settings from JSON or INI file
    std::ifstream file(path);
    if (!file.is_open()) {
        // File doesn't exist - set defaults
        strcpy_s(settings->theme, sizeof(settings->theme), "dark");
        settings->fontSize = 14;
        settings->lineHeight = 1.5f;
        settings->backgroundColor = RGB(30, 30, 30);
        settings->foregroundColor = RGB(220, 220, 220);
        settings->wordWrap = true;
        return true;
    }
    
    // Set defaults first
    strcpy_s(settings->theme, sizeof(settings->theme), "dark");
    settings->fontSize = 14;
    settings->lineHeight = 1.5f;
    settings->backgroundColor = RGB(30, 30, 30);
    settings->foregroundColor = RGB(220, 220, 220);
    settings->wordWrap = true;
    
    // Parse settings from file (simple key=value format)
    std::string line;
    while (std::getline(file, line)) {
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        // Trim whitespace
        while (!key.empty() && key.back() == ' ') key.pop_back();
        while (!val.empty() && val.front() == ' ') val.erase(val.begin());
        
        if (key == "theme") {
            strcpy_s(settings->theme, sizeof(settings->theme), val.c_str());
        } else if (key == "fontSize") {
            settings->fontSize = std::max(8, std::min(72, std::stoi(val)));
        } else if (key == "lineHeight") {
            settings->lineHeight = std::max(1.0f, std::min(3.0f, std::stof(val)));
        } else if (key == "wordWrap") {
            settings->wordWrap = (val == "true" || val == "1");
        }
    }
    file.close();
    
    return true;
}
