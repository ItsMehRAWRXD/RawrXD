#pragma once
#include <cstdint>
#include <string>
namespace Deep2 {
inline bool IsValidUtf8(const std::string& s) {
    const unsigned char* p = (const unsigned char*)s.data();
    size_t n = s.size(), i = 0;
    while (i < n) {
        unsigned char c = p[i];
        if (c <= 0x7F) { ++i; continue; }
        size_t need = 0;
        if ((c & 0xE0) == 0xC0) need = 1;
        else if ((c & 0xF0) == 0xE0) need = 2;
        else if ((c & 0xF8) == 0xF0) need = 3;
        else return false;
        if (i + need >= n) return false;
        for (size_t k = 1; k <= need; ++k)
            if ((p[i + k] & 0xC0) != 0x80) return false;
        i += need + 1;
    }
    return true;
}
} // namespace Deep2
