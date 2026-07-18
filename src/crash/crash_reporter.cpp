// RawrXD Crash Reporter
// Phase 8 - Task 19: Crash Reporter

#include <windows.h>
#include <dbghelp.h>
#include <string>
#include <vector>
#include <wininet.h>
#include <time.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "wininet.lib")

// Crash information
struct CrashInfo {
    EXCEPTION_POINTERS* exception;
    CONTEXT context;
    DWORD threadId;
    time_t timestamp;
    char moduleName[MAX_PATH];
    char version[32];
    char userDescription[512];
};

// Crash reporter class
class CrashReporter {
private:
    static CrashReporter* instance;
    std::wstring dumpPath;
    std::wstring uploadUrl;
    bool uploadEnabled;
    char version[32];
    
    // Write minidump
    static BOOL CALLBACK MinidumpCallback(PVOID callbackParam,
                                          const PMINIDUMP_CALLBACK_INPUT callbackInput,
                                          PMINIDUMP_CALLBACK_OUTPUT callbackOutput) {
        switch (callbackInput->CallbackType) {
            case ModuleCallback:
            case ThreadCallback:
            case ThreadExCallback:
                return TRUE;
            default:
                return FALSE;
        }
    }
    
    bool WriteMinidump(const std::wstring& path, EXCEPTION_POINTERS* exception) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }
        
        MINIDUMP_EXCEPTION_INFORMATION mdei;
        mdei.ThreadId = GetCurrentThreadId();
        mdei.ExceptionPointers = exception;
        mdei.ClientPointers = FALSE;
        
        MINIDUMP_CALLBACK_INFORMATION mci;
        mci.CallbackRoutine = MinidumpCallback;
        mci.CallbackParam = NULL;
        
        BOOL result = MiniDumpWriteDump(
            GetCurrentProcess(),
            GetCurrentProcessId(),
            hFile,
            MiniDumpWithDataSegs,
            exception ? &mdei : NULL,
            NULL,
            &mci
        );
        
        CloseHandle(hFile);
        return result == TRUE;
    }
    
    bool UploadDump(const std::wstring& dumpPath) {
        if (!uploadEnabled || uploadUrl.empty()) {
            return false;
        }
        
        // Read dump file
        HANDLE hFile = CreateFileW(dumpPath.c_str(), GENERIC_READ, 0, NULL,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }
        
        LARGE_INTEGER fileSize;
        GetFileSizeEx(hFile, &fileSize);
        
        std::vector<BYTE> fileData(fileSize.LowPart);
        DWORD bytesRead = 0;
        ReadFile(hFile, fileData.data(), fileSize.LowPart, &bytesRead, NULL);
        CloseHandle(hFile);
        
        // Upload via HTTP POST (simplified)
        HINTERNET hInternet = InternetOpenA("RawrXD Crash Reporter",
                                            INTERNET_OPEN_TYPE_PRECONFIG,
                                            NULL, NULL, 0);
        if (!hInternet) return false;
        
        // Would construct multipart/form-data here in production
        // For now, just simulate success
        InternetCloseHandle(hInternet);
        
        return true;
    }
    
    void ShowCrashDialog(const CrashInfo& info) {
        // Create crash report dialog
        wchar_t message[1024];
        swprintf_s(message, L"RawrXD has encountered an unexpected error and needs to close.\n\n"
                            L"Exception: 0x%08X\n"
                            L"Address: 0x%p\n\n"
                            L"Would you like to send a crash report to help us improve?",
                   info.exception->ExceptionRecord->ExceptionCode,
                   info.exception->ExceptionRecord->ExceptionAddress);
        
        int result = MessageBoxW(NULL, message, L"RawrXD Crash Reporter",
                                 MB_YESNO | MB_ICONERROR);
        
        if (result == IDYES) {
            // User agreed to upload
            // Would show progress dialog here
        }
    }
    
public:
    CrashReporter() : uploadEnabled(true) {
        // Get temp path for dumps
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        dumpPath = std::wstring(tempPath) + L"RawrXD_Crashes\\";
        
        // Create dump directory
        CreateDirectoryW(dumpPath.c_str(), NULL);
        
        strcpy_s(version, "1.1.0");
    }
    
    static CrashReporter* GetInstance() {
        if (!instance) {
            instance = new CrashReporter();
        }
        return instance;
    }
    
    void SetUploadUrl(const char* url) {
        uploadUrl = std::wstring(url, url + strlen(url));
    }
    
    void SetUploadEnabled(bool enabled) {
        uploadEnabled = enabled;
    }
    
    void SetVersion(const char* ver) {
        strcpy_s(version, ver);
    }
    
    // Handle crash
    LONG HandleCrash(EXCEPTION_POINTERS* exception) {
        // Generate dump filename
        time_t now = time(NULL);
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        
        wchar_t dumpFile[MAX_PATH];
        swprintf_s(dumpFile, L"RawrXD_Crash_%04d%02d%02d_%02d%02d%02d.dmp",
                   timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                   timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
        
        std::wstring fullPath = dumpPath + dumpFile;
        
        // Write minidump
        if (WriteMinidump(fullPath, exception)) {
            // Collect crash info
            CrashInfo info;
            info.exception = exception;
            info.context = *exception->ContextRecord;
            info.threadId = GetCurrentThreadId();
            info.timestamp = now;
            GetModuleFileNameA(NULL, info.moduleName, MAX_PATH);
            strcpy_s(info.version, version);
            strcpy_s(info.userDescription, "No user description provided");
            
            // Show dialog
            ShowCrashDialog(info);
            
            // Upload if enabled
            if (uploadEnabled) {
                UploadDump(fullPath);
            }
        }
        
        return EXCEPTION_EXECUTE_HANDLER;
    }
    
    // Install handler
    void InstallHandler() {
        SetUnhandledExceptionFilter([](EXCEPTION_POINTERS* exception) -> LONG {
            return CrashReporter::GetInstance()->HandleCrash(exception);
        });
        
        // Also handle pure virtual calls, invalid parameter, etc.
        _set_purecall_handler([]() {
            RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, NULL);
        });
        
        _set_invalid_parameter_handler([](const wchar_t*, const wchar_t*,
                                          const wchar_t*, unsigned int, uintptr_t) {
            RaiseException(EXCEPTION_INVALID_PARAMETER, 0, 0, NULL);
        });
    }
};

CrashReporter* CrashReporter::instance = nullptr;

// C API
extern "C" {

void CrashReporter_Init() {
    CrashReporter::GetInstance()->InstallHandler();
}

void CrashReporter_SetUploadUrl(const char* url) {
    CrashReporter::GetInstance()->SetUploadUrl(url);
}

void CrashReporter_SetUploadEnabled(int enabled) {
    CrashReporter::GetInstance()->SetUploadEnabled(enabled != 0);
}

void CrashReporter_SetVersion(const char* version) {
    CrashReporter::GetInstance()->SetVersion(version);
}

} // extern "C"

// Test function that crashes
void TestCrash_NullPointer() {
    int* p = nullptr;
    *p = 42;  // Crash!
}

void TestCrash_DivideByZero() {
    int x = 1;
    int y = 0;
    int z = x / y;  // Crash!
    (void)z;
}

void TestCrash_StackOverflow() {
    TestCrash_StackOverflow();  // Infinite recursion
}

int main(int argc, char* argv[]) {
    printf("RawrXD Crash Reporter Test\n");
    printf("==========================\n\n");
    
    // Initialize crash reporter
    CrashReporter_Init();
    CrashReporter::GetInstance()->SetVersion("1.1.0-test");
    CrashReporter::GetInstance()->SetUploadEnabled(false);  // Disable for test
    
    printf("Crash reporter installed.\n\n");
    
    if (argc > 1) {
        if (strcmp(argv[1], "null") == 0) {
            printf("Triggering null pointer crash...\n");
            TestCrash_NullPointer();
        } else if (strcmp(argv[1], "div0") == 0) {
            printf("Triggering divide by zero crash...\n");
            TestCrash_DivideByZero();
        } else if (strcmp(argv[1], "stack") == 0) {
            printf("Triggering stack overflow...\n");
            TestCrash_StackOverflow();
        }
    } else {
        printf("Usage: %s [null|div0|stack]\n", argv[0]);
        printf("Run with an argument to trigger a crash.\n");
    }
    
    printf("\nNo crash triggered. Exiting normally.\n");
    return 0;
}
