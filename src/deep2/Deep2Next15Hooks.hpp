#pragma once

#include "next15.hpp"

#include <cstdint>
#include <filesystem>
#include <string_view>

namespace deep2::next15 {

bool enabled() noexcept;
void initialize() noexcept;
rawrxd::next15::Counters& counters() noexcept;
void reset() noexcept;
void on_gpu_submit(std::uint64_t upload_bytes = 0) noexcept;
void on_gpu_kernel(bool gemm) noexcept;
void on_gpu_layer_complete() noexcept;
void on_cpu_fallback() noexcept;
rawrxd::next15::CounterView snapshot() noexcept;
rawrxd::next15::Result write_runtime_receipt(
    const std::filesystem::path& path,
    std::string_view model,
    std::string_view backend,
    std::uint32_t context,
    std::uint32_t gpu_index) noexcept;

}
