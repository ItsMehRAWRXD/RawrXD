#ifndef RAWRXD_CORE_BUFFER_CACHE_H
#define RAWRXD_CORE_BUFFER_CACHE_H
#include "core_export.h"
#include <memory>
#include <cstddef>
namespace RawrXD { namespace Core {
class RAWRXD_CORE_EXPORT BufferCache {
public:
    BufferCache();
    ~BufferCache();
    BufferCache(const BufferCache&) = delete;
    BufferCache& operator=(const BufferCache&) = delete;
    BufferCache(BufferCache&&) noexcept;
    BufferCache& operator=(BufferCache&&) noexcept;
    void* GetBuffer(size_t size);
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_BUFFER_CACHE_H
