#pragma once
// RawrXD fail-closed quantized MoE tensor-view validation. C++20, standard library only.
#include <cstdint>
#include <cstddef>
#include <limits>
#include <stdexcept>
#include <string>

namespace rawrxd::moe {
struct Quant { std::uint64_t elements_per_block, bytes_per_block; };
struct Tensor { std::uint64_t in, out, experts, bytes, offset; Quant q; };
struct Slice { std::uint64_t offset, bytes, in, out; };
inline std::uint64_t mul(std::uint64_t a, std::uint64_t b) {
    if (b && a > UINT64_MAX / b) throw std::overflow_error("MoE multiply overflow");
    return a * b;
}
inline std::uint64_t add(std::uint64_t a, std::uint64_t b) {
    if (a > UINT64_MAX - b) throw std::overflow_error("MoE offset overflow");
    return a + b;
}
inline Slice expert_slice(const Tensor& t, std::uint64_t expert,
                          std::uint64_t input_length, std::uint64_t requested_output) {
    if (!t.in || !t.out || !t.experts || !t.q.elements_per_block || !t.q.bytes_per_block)
        throw std::invalid_argument("MoE empty geometry");
    if (expert >= t.experts) throw std::out_of_range("MoE expert index");
    if (input_length != t.in || requested_output != t.out)
        throw std::invalid_argument("MoE projection dimensions disagree with weight descriptor");
    if (t.in % t.q.elements_per_block)
        throw std::invalid_argument("MoE row is not quant-block aligned");
    const auto row_bytes = mul(t.in / t.q.elements_per_block, t.q.bytes_per_block);
    const auto expert_bytes = mul(t.out, row_bytes);
    const auto total = mul(t.experts, expert_bytes);
    if (t.offset > t.bytes || total > t.bytes - t.offset)
        throw std::out_of_range("MoE tensor exceeds backing allocation");
    const auto begin = add(t.offset, mul(expert, expert_bytes));
    if (begin > t.bytes || expert_bytes > t.bytes - begin)
        throw std::out_of_range("MoE slice exceeds backing allocation");
    return {begin, expert_bytes, t.in, t.out};
}
} // namespace rawrxd::moe
