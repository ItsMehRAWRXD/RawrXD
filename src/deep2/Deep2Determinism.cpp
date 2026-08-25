#include "Deep2Determinism.h"

namespace RawrXD::Deep2 {

namespace {

constexpr std::uint64_t FNV_OFFSET =
    1469598103934665603ull;

constexpr std::uint64_t FNV_PRIME =
    1099511628211ull;

}

void DeterminismTrace::Reset() noexcept
{
    hash_ = FNV_OFFSET;
    bytes_ = 0;
}

void DeterminismTrace::Add(
    const void* data,
    std::size_t bytes) noexcept
{
    if (!data || bytes == 0)
        return;

    const auto* p =
        static_cast<const std::uint8_t*>(data);

    for (std::size_t i = 0; i < bytes; ++i) {
        hash_ ^= p[i];
        hash_ *= FNV_PRIME;
    }

    bytes_ +=
        static_cast<std::uint64_t>(bytes);
}

void DeterminismTrace::AddU32(
    std::uint32_t value) noexcept
{
    Add(&value, sizeof(value));
}

void DeterminismTrace::AddU64(
    std::uint64_t value) noexcept
{
    Add(&value, sizeof(value));
}

void DeterminismTrace::AddFloats(
    const float* values,
    std::size_t count) noexcept
{
    Add(values, count * sizeof(float));
}

void DeterminismTrace::AddTokens(
    const std::uint32_t* tokens,
    std::size_t count) noexcept
{
    Add(tokens, count * sizeof(std::uint32_t));
}

bool DeterminismTrace::Equal(
    const DeterminismTrace& other) const noexcept
{
    return hash_ == other.hash_ &&
           bytes_ == other.bytes_;
}

} // namespace RawrXD::Deep2
