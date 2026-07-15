#ifndef RAWRXD_CORE_VECTOR_STORE_H
#define RAWRXD_CORE_VECTOR_STORE_H
#include "core_export.h"
#include <memory>
#include <cstddef>
namespace RawrXD { namespace Core {
class RAWRXD_CORE_EXPORT VectorStore {
public:
    VectorStore();
    ~VectorStore();
    VectorStore(const VectorStore&) = delete;
    VectorStore& operator=(const VectorStore&) = delete;
    VectorStore(VectorStore&&) noexcept;
    VectorStore& operator=(VectorStore&&) noexcept;
    bool Add(const float* vec, size_t dim);
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_VECTOR_STORE_H
