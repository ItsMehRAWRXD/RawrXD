#ifndef RAWRXD_CORE_GGUF_TENSOR_H
#define RAWRXD_CORE_GGUF_TENSOR_H
#include "core_export.h"
#include <memory>
#include <cstddef>
namespace RawrXD { namespace Core {
class RAWRXD_CORE_EXPORT GGUFTensor {
public:
    GGUFTensor();
    ~GGUFTensor();
    GGUFTensor(const GGUFTensor&) = delete;
    GGUFTensor& operator=(const GGUFTensor&) = delete;
    GGUFTensor(GGUFTensor&&) noexcept;
    GGUFTensor& operator=(GGUFTensor&&) noexcept;
    size_t GetSize() const;
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_GGUF_TENSOR_H
