#pragma once
#include <cstddef>
#include <cstdint>
namespace rawrxd::deep2 {
struct ExpertSlice { std::uint64_t fileOffset, tensorBytes, stride, expertCount; };
inline bool checkedExpertSlice(ExpertSlice s, std::uint64_t expert, std::uint64_t& offset) noexcept {
 if (!s.stride || expert >= s.expertCount || expert > UINT64_MAX / s.stride) return false;
 const auto relative = expert * s.stride;
 if (relative > s.tensorBytes || s.stride > s.tensorBytes - relative ||
     s.fileOffset > UINT64_MAX - relative || s.fileOffset + relative > UINT64_MAX - s.stride) return false;
 offset = s.fileOffset + relative;
 return true;
}
}
