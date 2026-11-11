#pragma once
// Independent, fail-closed geometry validation. C++20, standard library only.
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>
namespace rawrxd::moe {
struct QuantGeometry { std::uint64_t elementsPerBlock, bytesPerBlock; };
inline std::uint64_t checkedMul(std::uint64_t a, std::uint64_t b) {
    if (b && a > std::numeric_limits<std::uint64_t>::max() / b)
        throw std::overflow_error("MoE dimension/stride overflow");
    return a*b;
}
inline std::uint64_t rowBytes(std::uint64_t rowElements, QuantGeometry q) {
    if (!q.elementsPerBlock || !q.bytesPerBlock || !rowElements ||
        rowElements % q.elementsPerBlock)
        throw std::invalid_argument("invalid quantized row geometry");
    return checkedMul(rowElements / q.elementsPerBlock, q.bytesPerBlock);
}
struct ExpertTensor {
    std::string name;
    // GGUF order: ne[0] = input features (contiguous), ne[1] = output features,
    // ne[2] = number of experts, for this particular 3-D representation.
    std::vector<std::uint64_t> ne;
    QuantGeometry quant;
    std::uint64_t availableBytes{};
};
struct ExpertView {std::uint64_t offsetBytes, bytes, inputs, outputs;};
inline ExpertView selectExpert(const ExpertTensor& t, std::uint64_t expert,
                               std::uint64_t actualInput, std::uint64_t requestedOutput) {
    if (t.ne.size()!=3 || !t.ne[0] || !t.ne[1] || !t.ne[2])
        throw std::invalid_argument(t.name+": expected nonzero 3-D expert tensor");
    if (expert >= t.ne[2]) throw std::out_of_range(t.name+": expert index out of range");
    if (actualInput != t.ne[0]) throw std::invalid_argument(t.name+": input dimension mismatch");
    if (requestedOutput != t.ne[1])
        throw std::invalid_argument(t.name+": output dimension mismatch; check latent projection chain");
    auto bytes=checkedMul(rowBytes(t.ne[0],t.quant),t.ne[1]);
    auto offset=checkedMul(bytes,expert);
    if (offset>t.availableBytes || bytes>t.availableBytes-offset)
        throw std::out_of_range(t.name+": expert view exceeds tensor allocation");
    return {offset,bytes,t.ne[0],t.ne[1]};
}
} // namespace rawrxd::moe
