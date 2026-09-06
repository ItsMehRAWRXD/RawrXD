// ============================================================================
// MemoryMappedFile.cpp — Windows implementation (Linux mmap stub)
// ============================================================================
#include "MemoryMappedFile.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <cstdio>

namespace Deep2 {
namespace {

static bool RangeWithinFile(uint64_t offset, uint64_t size, uint64_t fileSize) {
    return offset <= fileSize && size <= (fileSize - offset);
}

} // namespace

bool MemoryMappedFile::Map(const char* filePath) {
    Unmap();
    path = filePath ? filePath : "";
    if (path.empty()) {
        error = "empty path";
        return false;
    }

#ifdef _WIN32
    fileHandle = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        error = "CreateFileA failed";
        fileHandle = nullptr;
        return false;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx((HANDLE)fileHandle, &size)) {
        error = "GetFileSizeEx failed";
        CloseHandle((HANDLE)fileHandle);
        fileHandle = nullptr;
        return false;
    }
    fileSize = static_cast<uint64_t>(size.QuadPart);

    if (fileSize == 0) {
        error = "empty file";
        CloseHandle((HANDLE)fileHandle);
        fileHandle = nullptr;
        return false;
    }

    mappingHandle = CreateFileMapping((HANDLE)fileHandle, nullptr, PAGE_READONLY,
                                      0, 0, nullptr);
    if (!mappingHandle) {
        error = "CreateFileMapping failed";
        CloseHandle((HANDLE)fileHandle);
        fileHandle = nullptr;
        return false;
    }

    data = static_cast<const uint8_t*>(MapViewOfFile((HANDLE)mappingHandle,
                                                       FILE_MAP_READ, 0, 0, 0));
    if (!data) {
        error = "MapViewOfFile failed";
        CloseHandle((HANDLE)mappingHandle);
        mappingHandle = nullptr;
        CloseHandle((HANDLE)fileHandle);
        fileHandle = nullptr;
        return false;
    }
#else
    fd = open(filePath, O_RDONLY);
    if (fd < 0) {
        error = "open failed";
        return false;
    }
    struct stat st{};
    if (fstat(fd, &st) != 0) {
        error = "fstat failed";
        close(fd);
        fd = -1;
        return false;
    }
    fileSize = static_cast<uint64_t>(st.st_size);
    if (fileSize == 0) {
        error = "empty file";
        close(fd);
        fd = -1;
        return false;
    }
    void* p = mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) {
        error = "mmap failed";
        close(fd);
        fd = -1;
        return false;
    }
    data = static_cast<const uint8_t*>(p);
#endif

    ok = true;
    return true;
}

bool MemoryMappedFile::Prefetch(uint64_t offset, uint64_t size) {
    if (!ok || !data) {
        error = "mapping not ready";
        return false;
    }
    if (!RangeWithinFile(offset, size, fileSize)) {
        error = "prefetch range out of bounds";
        return false;
    }
    if (size == 0) {
        return true;
    }

    // Trigger page faults in a controlled stride so only requested regions go hot.
    volatile uint8_t sink = 0;
#ifdef _WIN32
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const uint64_t pageSize = si.dwPageSize ? static_cast<uint64_t>(si.dwPageSize) : 4096ull;
#else
    const uint64_t pageSize = 4096ull;
#endif
    const uint8_t* start = data + offset;
    const uint8_t* end = start + size;
    for (const uint8_t* p = start; p < end; p += pageSize) {
        sink ^= *p;
    }
    sink ^= *(end - 1);
    (void)sink;
    return true;
}

void MemoryMappedFile::Unmap() {
    if (!ok) return;
#ifdef _WIN32
    if (data) {
        UnmapViewOfFile((LPCVOID)data);
        data = nullptr;
    }
    if (mappingHandle) {
        CloseHandle((HANDLE)mappingHandle);
        mappingHandle = nullptr;
    }
    if (fileHandle) {
        CloseHandle((HANDLE)fileHandle);
        fileHandle = nullptr;
    }
#else
    if (data && fileSize) {
        munmap((void*)data, fileSize);
        data = nullptr;
    }
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
#endif
    fileSize = 0;
    ok = false;
    error.clear();
}

} // namespace Deep2
