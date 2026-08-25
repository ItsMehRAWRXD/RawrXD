#pragma once

#include <cstddef>
#include <cstdint>

namespace RawrXD::Deep2 {

class DeterminismTrace {
public:
    DeterminismTrace() noexcept {
        Reset();
    }

    void Reset() noexcept;

    void Add(
        const void* data,
        std::size_t bytes) noexcept;

    void AddU32(
        std::uint32_t value) noexcept;

    void AddU64(
        std::uint64_t value) noexcept;

    void AddFloats(
        const float* values,
        std::size_t count) noexcept;

    void AddTokens(
        const std::uint32_t* tokens,
        std::size_t count) noexcept;

    std::uint64_t Hash() const noexcept {
        return hash_;
    }

    std::uint64_t Bytes() const noexcept {
        return bytes_;
    }

    bool Equal(
        const DeterminismTrace& other) const noexcept;

private:
    std::uint64_t hash_;
    std::uint64_t bytes_;
};

} // namespace RawrXD::Deep2
