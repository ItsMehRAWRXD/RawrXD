// rawrstd - thin Win32 syscall layer.
//
// The RawrXD compiler talks to the OS directly. No C runtime is involved:
// no printf, no malloc, no FILE*. This is what makes the compiler binary
// runnable on a clean Windows host with no development installation.

#ifndef RAWRSTD_SYS_H
#define RAWRSTD_SYS_H

#include "rawrstd/base.h"

namespace rawrstd {

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

// Allocate `size` bytes. Returns nullptr on failure.
void* heap_alloc(size_type size);
void* heap_realloc(void* p, size_type old_size, size_type new_size);
void heap_free(void* p, size_type size);

// Raw VirtualAlloc for large blocks (no CRT heap involvement).
void* virtual_alloc(size_type size);
void virtual_free(void* p);

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

enum class FileMode {
    Read,        // open existing for reading
    Write,       // create/truncate for writing
    Append,      // open existing (or create) for appending
};

class File {
public:
    File() = default;
    ~File();

    File(const File&) = delete;
    File& operator=(const File&) = delete;

    bool open(const char* path, FileMode mode);
    void close();
    bool is_open() const { return handle_ != invalid_handle; }

    // Returns bytes read, 0 at EOF, or -1 on error.
    int64 read(void* buffer, size_type size);
    // Returns bytes written or -1 on error.
    int64 write(const void* buffer, size_type size);
    bool seek(int64 offset);
    int64 tell() const { return position_; }
    bool flush();

    static constexpr uint64 invalid_handle = ~uint64(0);

private:
    uint64 handle_ = invalid_handle;
    int64 position_ = 0;
};

// ---------------------------------------------------------------------------
// Console / stdout
// ---------------------------------------------------------------------------

void write_stdout(const void* data, size_type size);
void write_stderr(const void* data, size_type size);

// ---------------------------------------------------------------------------
// Process
// ---------------------------------------------------------------------------

[[noreturn]] void exit_process(int code);
[[noreturn]] void abort_process();

int64 get_timestamp_ms();

// ---------------------------------------------------------------------------
// Strings (no CRT)
// ---------------------------------------------------------------------------

size_type strlen_raw(const char* s);
int memcmp_raw(const void* a, const void* b, size_type n);
void memcpy_raw(void* dst, const void* src, size_type n);
void memset_raw(void* dst, int value, size_type n);
int strcmp_raw(const char* a, const char* b);
int strncmp_raw(const char* a, const char* b, size_type n);

// Integer formatting helpers used by the diagnostics engine.
size_type format_i64(char* out, int64 value);
size_type format_u64(char* out, uint64 value);
size_type format_hex_u64(char* out, uint64 value);

} // namespace rawrstd

#endif // RAWRSTD_SYS_H
