#pragma once
#include <cstddef>
#include <cstdint>

extern "C" std::uint32_t rawrxd_gzip_crc32(
    const void* source, std::size_t length) noexcept;
