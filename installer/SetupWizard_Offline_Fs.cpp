/* SetupWizard_Offline_Fs.cpp — real CopyFile / RemoveDir for M4 offline. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "shell32.lib")

static int EnsureDir(const char* path) {
    char tmp[MAX_PATH];
    size_t n = strlen(path);
    if (n >= MAX_PATH) return 0;
    memcpy(tmp, path, n + 1);
    for (char* p = tmp + 3; *p; ++p) {
        if (*p == '\\' || *p == '/') {
            char c = *p;
            *p = 0;
            CreateDirectoryA(tmp, nullptr);
            *p = c;
        }
    }
    return CreateDirectoryA(tmp, nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
}

static int CopyOne(const char* src, const char* dst) {
    if (!CopyFileA(src, dst, FALSE)) {
        printf("COPY_FAIL src=%s dst=%s err=%lu\n", src, dst, GetLastError());
        return 0;
    }
    printf("COPY_OK %s\n", dst);
    return 1;
}

int SwFs_CopyTreeFiles(const char* srcDir, const char* dstDir) {
    char pattern[MAX_PATH];
    char src[MAX_PATH];
    char dst[MAX_PATH];
    WIN32_FIND_DATAA fd;
    int ok = 1;
    int n = 0;
    if (!EnsureDir(dstDir)) return 0;
    _snprintf_s(pattern, _TRUNCATE, "%s\\*", srcDir);
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        if (fd.cFileName[0] == '.') continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        _snprintf_s(src, _TRUNCATE, "%s\\%s", srcDir, fd.cFileName);
        _snprintf_s(dst, _TRUNCATE, "%s\\%s", dstDir, fd.cFileName);
        if (!CopyOne(src, dst)) ok = 0;
        else ++n;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    printf("FILE_COPY_COUNT=%d\n", n);
    return ok && n > 0;
}

int SwFs_RemoveTree(const char* dir) {
    char from[MAX_PATH + 2];
    SHFILEOPSTRUCTA op = {};
    size_t n = strlen(dir);
    if (n == 0 || n >= MAX_PATH) return 0;
    memcpy(from, dir, n);
    from[n] = 0;
    from[n + 1] = 0;
    op.wFunc = FO_DELETE;
    op.pFrom = from;
    op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    int r = SHFileOperationA(&op);
    printf("REMOVE_DIR path=%s code=%d\n", dir, r);
    return r == 0 && !op.fAnyOperationsAborted;
}
