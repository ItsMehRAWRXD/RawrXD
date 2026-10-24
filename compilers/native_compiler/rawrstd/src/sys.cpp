// rawrstd - Win32 syscall layer implementation.
//
// Direct Win32 API calls only. No C runtime.

#include "rawrstd/sys.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace rawrstd {

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

void* heap_alloc(size_type size) {
    if (size == 0) size = 1;
    return HeapAlloc(GetProcessHeap(), 0, size);
}

void* heap_realloc(void* p, size_type old_size, size_type new_size) {
    if (p == nullptr) return heap_alloc(new_size);
    if (new_size == 0) new_size = 1;
    return HeapReAlloc(GetProcessHeap(), 0, p, new_size);
}

void heap_free(void* p, size_type size) {
    (void)size;
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

void* virtual_alloc(size_type size) {
    if (size == 0) size = 4096;
    return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

void virtual_free(void* p) {
    if (p) VirtualFree(p, 0, MEM_RELEASE);
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

File::~File() { close(); }

bool File::open(const char* path, FileMode mode) {
    close();
    DWORD access = 0;
    DWORD creation = 0;
    switch (mode) {
    case FileMode::Read:
        access = GENERIC_READ;
        creation = OPEN_EXISTING;
        break;
    case FileMode::Write:
        access = GENERIC_WRITE;
        creation = CREATE_ALWAYS;
        break;
    case FileMode::Append:
        access = GENERIC_READ | GENERIC_WRITE;
        creation = OPEN_ALWAYS;
        break;
    }
    HANDLE h = CreateFileA(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, creation, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    handle_ = reinterpret_cast<uint64>(h);
    position_ = 0;
    if (mode == FileMode::Append) {
        LARGE_INTEGER li;
        li.QuadPart = 0;
        SetFilePointerEx(h, li, nullptr, FILE_END);
    }
    return true;
}

void File::close() {
    if (handle_ != invalid_handle) {
        CloseHandle(reinterpret_cast<HANDLE>(handle_));
        handle_ = invalid_handle;
    }
    position_ = 0;
}

int64 File::read(void* buffer, size_type size) {
    if (handle_ == invalid_handle || size == 0) return 0;
    DWORD got = 0;
    if (!ReadFile(reinterpret_cast<HANDLE>(handle_), buffer, static_cast<DWORD>(size), &got, nullptr))
        return -1;
    position_ += got;
    return static_cast<int64>(got);
}

int64 File::write(const void* buffer, size_type size) {
    if (handle_ == invalid_handle || size == 0) return 0;
    DWORD put = 0;
    if (!WriteFile(reinterpret_cast<HANDLE>(handle_), buffer, static_cast<DWORD>(size), &put, nullptr))
        return -1;
    position_ += put;
    return static_cast<int64>(put);
}

bool File::seek(int64 offset) {
    if (handle_ == invalid_handle) return false;
    LARGE_INTEGER li;
    li.QuadPart = offset;
    if (!SetFilePointerEx(reinterpret_cast<HANDLE>(handle_), li, nullptr, FILE_BEGIN)) return false;
    position_ = offset;
    return true;
}

bool File::flush() {
    if (handle_ == invalid_handle) return false;
    return FlushFileBuffers(reinterpret_cast<HANDLE>(handle_)) != 0;
}

// ---------------------------------------------------------------------------
// Console
// ---------------------------------------------------------------------------

void write_stdout(const void* data, size_type size) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    WriteFile(h, data, static_cast<DWORD>(size), &written, nullptr);
}

void write_stderr(const void* data, size_type size) {
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    DWORD written = 0;
    WriteFile(h, data, static_cast<DWORD>(size), &written, nullptr);
}

// ---------------------------------------------------------------------------
// Process
// ---------------------------------------------------------------------------

void exit_process(int code) {
    ExitProcess(static_cast<UINT>(code));
}

void abort_process() {
    ExitProcess(3);
}

int64 get_timestamp_ms() {
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    if (freq.QuadPart == 0) return 0;
    return (counter.QuadPart * 1000) / freq.QuadPart;
}

// ---------------------------------------------------------------------------
// Raw string helpers
// ---------------------------------------------------------------------------

size_type strlen_raw(const char* s) {
    size_type n = 0;
    if (!s) return 0;
    while (s[n]) ++n;
    return n;
}

int memcmp_raw(const void* a, const void* b, size_type n) {
    const unsigned char* pa = static_cast<const unsigned char*>(a);
    const unsigned char* pb = static_cast<const unsigned char*>(b);
    for (size_type i = 0; i < n; ++i) {
        if (pa[i] != pb[i]) return pa[i] < pb[i] ? -1 : 1;
    }
    return 0;
}

void memcpy_raw(void* dst, const void* src, size_type n) {
    unsigned char* d = static_cast<unsigned char*>(dst);
    const unsigned char* s = static_cast<const unsigned char*>(src);
    for (size_type i = 0; i < n; ++i) d[i] = s[i];
}

void memset_raw(void* dst, int value, size_type n) {
    unsigned char* d = static_cast<unsigned char*>(dst);
    for (size_type i = 0; i < n; ++i) d[i] = static_cast<unsigned char>(value);
}

int strcmp_raw(const char* a, const char* b) {
    size_type i = 0;
    while (a[i] && b[i]) {
        unsigned char ca = static_cast<unsigned char>(a[i]);
        unsigned char cb = static_cast<unsigned char>(b[i]);
        if (ca != cb) return ca < cb ? -1 : 1;
        ++i;
    }
    unsigned char ca = static_cast<unsigned char>(a[i]);
    unsigned char cb = static_cast<unsigned char>(b[i]);
    if (ca == cb) return 0;
    return ca < cb ? -1 : 1;
}

int strncmp_raw(const char* a, const char* b, size_type n) {
    for (size_type i = 0; i < n; ++i) {
        unsigned char ca = static_cast<unsigned char>(a[i]);
        unsigned char cb = static_cast<unsigned char>(b[i]);
        if (ca != cb) return ca < cb ? -1 : 1;
        if (ca == 0) return 0;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Integer formatting
// ---------------------------------------------------------------------------

static size_type emit_u64(char* out, uint64 value) {
    char tmp[24];
    size_type n = 0;
    if (value == 0) {
        tmp[n++] = '0';
    } else {
        while (value > 0) {
            tmp[n++] = static_cast<char>('0' + (value % 10));
            value /= 10;
        }
    }
    for (size_type i = 0; i < n; ++i) out[i] = tmp[n - 1 - i];
    return n;
}

size_type format_u64(char* out, uint64 value) {
    return emit_u64(out, value);
}

size_type format_i64(char* out, int64 value) {
    size_type n = 0;
    if (value < 0) {
        out[n++] = '-';
        // Negate in unsigned space so INT64_MIN is handled.
        uint64 mag = static_cast<uint64>(-(value + 1)) + 1ull;
        n += emit_u64(out + n, mag);
    } else {
        n += emit_u64(out, static_cast<uint64>(value));
    }
    return n;
}

size_type format_hex_u64(char* out, uint64 value) {
    static const char kDigits[] = "0123456789ABCDEF";
    char tmp[16];
    size_type n = 0;
    if (value == 0) {
        tmp[n++] = '0';
    } else {
        while (value > 0) {
            tmp[n++] = kDigits[value & 0xF];
            value >>= 4;
        }
    }
    for (size_type i = 0; i < n; ++i) out[i] = tmp[n - 1 - i];
    return n;
}

} // namespace rawrstd
