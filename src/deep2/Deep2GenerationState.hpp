#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace rawrxd::deep2 {

struct DecodeState {
    std::size_t position = 0;
    int32_t nextToken = 0;
    bool initialized = false;

    void begin(std::size_t promptLength, int32_t firstToken) noexcept
    {
        position = promptLength;
        nextToken = firstToken;
        initialized = true;
    }

    std::size_t currentPosition() const noexcept
    {
        return position;
    }

    int32_t currentToken() const noexcept
    {
        return nextToken;
    }

    void advance(int32_t generatedToken) noexcept
    {
        nextToken = generatedToken;

        if (position != std::numeric_limits<std::size_t>::max())
            ++position;
    }
};

struct KVCachePosition {
    std::size_t position = 0;
    std::size_t keyCount = 0;

    void set(std::size_t p) noexcept
    {
        position = p;
        keyCount = p + 1;
    }
};

} // namespace rawrxd::deep2
