#pragma once
// RawrXD Deep2 resource admission governor. C++20, standard library only.
// Governs explicitly tracked allocations; OS/driver/runtime allocations must also be accounted.
#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <array>
#include <utility>

namespace rawrxd::deep2 {
enum class Pool : unsigned { Host=0, Vram=1, DiskScratch=2, Count=3 };
struct Budget { std::uint64_t host=0, vram=0, diskScratch=0; };
class Governor {
    mutable std::mutex mutex_;
    std::array<std::uint64_t,3> cap_{}, used_{};
    static constexpr unsigned index(Pool p) noexcept { return static_cast<unsigned>(p); }
public:
    explicit Governor(Budget b) : cap_{b.host,b.vram,b.diskScratch} {}
    class Lease {
        Governor* owner_ = nullptr;
        Pool pool_ = Pool::Host;
        std::uint64_t bytes_ = 0;
        friend class Governor;
        Lease(Governor* owner, Pool pool, std::uint64_t bytes) noexcept
          : owner_(owner),pool_(pool),bytes_(bytes) {}
    public:
        Lease()=default;
        Lease(const Lease&)=delete;
        Lease& operator=(const Lease&)=delete;
        Lease(Lease&& o) noexcept : owner_(std::exchange(o.owner_,nullptr)),pool_(o.pool_),bytes_(std::exchange(o.bytes_,0)) {}
        Lease& operator=(Lease&& o) noexcept { if(this!=&o){ release(); owner_=std::exchange(o.owner_,nullptr); pool_=o.pool_; bytes_=std::exchange(o.bytes_,0);} return *this; }
        ~Lease(){ release(); }
        void release() noexcept { if(owner_){owner_->release(pool_,bytes_); owner_=nullptr; bytes_=0;} }
        std::uint64_t bytes() const noexcept { return bytes_; }
        explicit operator bool() const noexcept { return owner_!=nullptr; }
    };
    std::optional<Lease> tryAcquire(Pool p, std::uint64_t bytes) {
        const auto i=index(p); if(i>=cap_.size()) return std::nullopt;
        std::lock_guard lock(mutex_);
        if(bytes>cap_[i]-used_[i]) return std::nullopt;
        used_[i]+=bytes;
        return Lease(this,p,bytes);
    }
    std::uint64_t used(Pool p) const { std::lock_guard lock(mutex_); return used_.at(index(p)); }
    std::uint64_t capacity(Pool p) const { std::lock_guard lock(mutex_); return cap_.at(index(p)); }
private:
    void release(Pool p,std::uint64_t bytes) noexcept {
        std::lock_guard lock(mutex_);
        auto& n=used_[index(p)]; n-=bytes;
    }
};
// Overflow-safe byte calculation for resident KV allocation.
inline std::optional<std::uint64_t> kvBytes(std::uint64_t layers, std::uint64_t tokens,
    std::uint64_t kvHeads, std::uint64_t headDim, std::uint64_t bytesPerElement) {
    std::uint64_t result=2; // K and V
    for(auto n : {layers,tokens,kvHeads,headDim,bytesPerElement}) {
        if(n && result>std::numeric_limits<std::uint64_t>::max()/n) return std::nullopt;
        result*=n;
    }
    return result;
}
} // namespace rawrxd::deep2
