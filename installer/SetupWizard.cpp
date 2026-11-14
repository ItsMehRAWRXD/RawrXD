/* SetupWizard.cpp — M4 offline installer (real CopyFile). PROMOTE=0 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <shlobj.h>

int SwFs_CopyTreeFiles(const char* srcDir, const char* dstDir);
int SwFs_RemoveTree(const char* dir);

static void SelfDir(char* out, size_t cap) {
    DWORD n = GetModuleFileNameA(nullptr, out, (DWORD)cap);
    if (n == 0 || n >= cap) {
        out[0] = '.';
        out[1] = 0;
        return;
    }
    char* slash = strrchr(out, '\\');
    if (slash) *slash = 0;
}

static void DefaultTarget(char* out, size_t cap) {
    char base[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, base)))
        _snprintf_s(out, cap, _TRUNCATE, "%s\\RawrXD\\offline-M4", base);
    else
        _snprintf_s(out, cap, _TRUNCATE, ".\\RawrXD-offline-M4");
}

static void ResolvePayload(char* payload, size_t cap, const char* self) {
    char probe[MAX_PATH];
    _snprintf_s(payload, cap, _TRUNCATE, "%s", self);
    _snprintf_s(probe, _TRUNCATE, "%s\\bin", self);
    if (GetFileAttributesA(probe) != INVALID_FILE_ATTRIBUTES) return;
    char* slash = strrchr(payload, '\\');
    if (slash) *slash = 0; /* strip \installer when bin is sibling of installer\ */
}

static int DoInstall(const char* payloadRoot, const char* target) {
    char srcBin[MAX_PATH], dstBin[MAX_PATH], srcExt[MAX_PATH], dstExt[MAX_PATH];
    char srcSw[MAX_PATH], dstSw[MAX_PATH];
    printf("OFFLINE_INSTALL target=%s\nPAYLOAD=%s\n", target, payloadRoot);
    _snprintf_s(srcBin, _TRUNCATE, "%s\\bin", payloadRoot);
    _snprintf_s(dstBin, _TRUNCATE, "%s\\bin", target);
    _snprintf_s(srcExt, _TRUNCATE, "%s\\extensions", payloadRoot);
    _snprintf_s(dstExt, _TRUNCATE, "%s\\extensions", target);
    if (!SwFs_CopyTreeFiles(srcBin, dstBin)) {
        printf("INSTALL_FAIL=BIN_COPY\n");
        return 1;
    }
    SwFs_CopyTreeFiles(srcExt, dstExt);
    _snprintf_s(srcSw, _TRUNCATE, "%s\\SetupWizard.exe", payloadRoot);
    _snprintf_s(dstSw, _TRUNCATE, "%s\\SetupWizard.exe", target);
    if (GetFileAttributesA(srcSw) != INVALID_FILE_ATTRIBUTES)
        CopyFileA(srcSw, dstSw, FALSE);
    printf("FILE_COPY=1\nSIMULATED=0\nOFFLINE=1\nCLOUD_MODELS=0\nPROMOTE=0\n");
    printf("INSTALL_OK=1\n");
    return 0;
}

static int DoUninstall(const char* target) {
    printf("OFFLINE_UNINSTALL target=%s\n", target);
    if (GetFileAttributesA(target) == INVALID_FILE_ATTRIBUTES) {
        printf("UNINSTALL_ALREADY_GONE=1\nROLLBACK_OK=1\nPROMOTE=0\n");
        return 0;
    }
    int ok = SwFs_RemoveTree(target);
    printf("ROLLBACK_OK=%d\nPROMOTE=0\n", ok ? 1 : 0);
    return ok ? 0 : 1;
}

int main(int argc, char** argv) {
    char self[MAX_PATH], payload[MAX_PATH], target[MAX_PATH];
    int mode = 0;
    printf("RawrXD Offline SetupWizard M4 (real CopyFile)\n");
    SelfDir(self, sizeof(self));
    ResolvePayload(payload, sizeof(payload), self);
    DefaultTarget(target, sizeof(target));
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "/?") || !strcmp(argv[i], "--help") || !strcmp(argv[i], "help"))
            mode = 0;
        else if (!strcmp(argv[i], "/install") || !strcmp(argv[i], "--install") || !strcmp(argv[i], "install"))
            mode = 1;
        else if (!strcmp(argv[i], "/uninstall") || !strcmp(argv[i], "--uninstall") || !strcmp(argv[i], "uninstall"))
            mode = 2;
        else if (!strncmp(argv[i], "/target=", 8))
            strncpy_s(target, argv[i] + 8, _TRUNCATE);
        else if (!strncmp(argv[i], "--target=", 9))
            strncpy_s(target, argv[i] + 9, _TRUNCATE);
        else if (!strncmp(argv[i], "/payload=", 9))
            strncpy_s(payload, argv[i] + 9, _TRUNCATE);
    }
    if (mode == 1) return DoInstall(payload, target);
    if (mode == 2) return DoUninstall(target);
    printf("Usage: SetupWizard.exe /install|/uninstall [/target=PATH] [/payload=PATH]\n");
    printf("OFFLINE=1 FILE_COPY=1 SIMULATED=0 PROMOTE=0\n");
    return 0;
}
