#pragma once
#include <cstddef>
namespace rawrxd::extensions {
// Reader returns bytes transferred, or zero on failure/EOF. Never accept partial data.
template <class Reader>
bool readExactly(char* destination, std::size_t length, Reader&& reader) {
    if (length && !destination) return false;
    std::size_t offset = 0;
    while (offset < length) {
        const std::size_t n = reader(destination + offset, length - offset);
        if (n == 0 || n > length - offset) return false;
        offset += n;
    }
    return true;
}

// Writer returns bytes transferred, or zero on failure. A short write is
// retried; no caller may report success until all bytes are written.
template <class Writer>
bool writeExactly(const char* source, std::size_t length, Writer&& writer) {
    if (length && !source) return false;
    std::size_t offset = 0;
    while (offset < length) {
        const std::size_t n = writer(source + offset, length - offset);
        if (n == 0 || n > length - offset) return false;
        offset += n;
    }
    return true;
}
}
