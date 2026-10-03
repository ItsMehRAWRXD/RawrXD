#pragma once
#include <cstdint>
#include <vector>
#include <string>

namespace rawrxd { namespace monaco {

enum class MC_Token : uint32_t {
    EndOfFile = 0,
    Identifier,
    Keyword,
    Operator,
    Literal,
    Comment,
    Whitespace,
    Error
};

enum class MC_Colors : uint32_t {
    Default = 0,
    Red = 0xFF0000,
    Green = 0x00FF00,
    Blue = 0x0000FF,
    Yellow = 0xFFFF00
};

struct MonacoCoreBuffer {
    std::vector<char> data;
    uint32_t capacity = 0;
    uint32_t size = 0;
    bool resize(uint32_t newCap) {
        if (newCap > data.size()) data.resize(newCap);
        capacity = newCap;
        return true;
    }
    bool append(const char* text, uint32_t len) {
        if (size + len > capacity) return false;
        memcpy(data.data() + size, text, len);
        size += len;
        return true;
    }
};

}} // namespace rawrxd::monaco
