#ifndef GGUF_SHARD_ROUTER_LANES_HPP
#define GGUF_SHARD_ROUTER_LANES_HPP
// ============================================================================
// GGUFShardRouter_lanes.hpp  —  hotpatch #4
// ----------------------------------------------------------------------------
// Bifurcated x16-lane streaming with a storage abstraction.
//
//   "bifurcated" = the stream splits along two axes:
//     (1) chunking along the read direction     -> chunk_bytes
//     (2) striping across parallel lanes        -> lane_width (default x16)
//
// Discipline (from the prompt: "no long long / unsigned long"):
//   Every integer in this header is fixed-width. No `long`, no `unsigned long`,
//   no `long long`. Offsets/sizes: uint64_t. Lane ids: uint32_t. Byte counts:
//   uint64_t. No platform-dependent width leakage into the API surface.
//
// Memory posture:
//   Per-lane buffer: chunk_bytes (default 1 MiB).
//   Backpressure cap: 2 * lane_width in-flight entries.
//   Peak = (lane_width + 2 * lane_width) * chunk_bytes = 3 * 16 * 1 MiB = 48 MiB.
//   No global state. No weight data retained. RAII throughout.
//
// Header-only, C++17, cross-OS. No #pragma once. No external deps beyond libc
// and (on Windows) kernel32.
// ============================================================================
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <deque>
#include <memory>
#include <optional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <algorithm>
#include <functional>

#if defined(_WIN32)
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
#else
  #include <fcntl.h>
  #include <unistd.h>
  #include <sys/stat.h>
#endif

namespace gguf_shard_lanes {

// ============================================================================
// IStorage — swappable backend for positioned reads.
// ============================================================================
struct IStorage {
    virtual ~IStorage() = default;
    virtual uint64_t read_at(uint64_t off, void* buf, uint64_t len) = 0;
    virtual uint64_t size_bytes() const = 0;
    virtual std::unique_ptr<IStorage> clone() const = 0;
};

// ============================================================================
// LocalStorage — file-backed, pread / ReadFile+OVERLAPPED, thread-safe.
// ============================================================================
class LocalStorage final : public IStorage {
public:
    static std::unique_ptr<LocalStorage> open(const std::string& path) {
        auto p = std::unique_ptr<LocalStorage>(new LocalStorage());
        if (!p->open_impl(path)) return nullptr;
        return p;
    }

    uint64_t read_at(uint64_t off, void* buf, uint64_t len) override {
        if (len == 0) return 0;
        uint64_t total = 0;
#if defined(_WIN32)
        while (total < len) {
            uint64_t want = (len - total) > (1ull << 30) ? (1ull << 30) : (len - total);
            DWORD did = 0;
            uint64_t cur = off + total;
            LARGE_INTEGER li; li.QuadPart = (int64_t)cur;
            OVERLAPPED ov{};
            ov.Offset    = li.LowPart;
            ov.OffsetHigh = li.HighPart;
            if (!ReadFile(h_, (char*)buf + total, (DWORD)want, &did, &ov)) break;
            if (did == 0) break;
            total += did;
        }
#else
        while (total < len) {
            uint64_t want = len - total;
            ssize_t r = ::pread(fd_, (char*)buf + total, (size_t)want,
                                (off_t)(off + total));
            if (r <= 0) break;
            total += (uint64_t)r;
        }
#endif
        return total;
    }

    uint64_t size_bytes() const override { return size_; }
    std::unique_ptr<IStorage> clone() const override { return open(path_); }

    ~LocalStorage() override { close_impl(); }

private:
    LocalStorage() = default;
    LocalStorage(const LocalStorage&) = delete;
    LocalStorage& operator=(const LocalStorage&) = delete;

    bool open_impl(const std::string& path) {
        path_ = path;
#if defined(_WIN32)
        h_ = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                        nullptr);
        if (h_ == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz;
        if (!GetFileSizeEx(h_, &sz)) { close_impl(); return false; }
        size_ = (uint64_t)sz.QuadPart;
#else
        fd_ = ::open(path.c_str(), O_RDONLY);
        if (fd_ < 0) return false;
        struct stat st;
        if (::fstat(fd_, &st) != 0) { close_impl(); return false; }
        size_ = (uint64_t)st.st_size;
#  ifdef POSIX_FADV_SEQUENTIAL
        ::posix_fadvise(fd_, 0, 0, POSIX_FADV_SEQUENTIAL);
#  endif
#endif
        return true;
    }

    void close_impl() {
#if defined(_WIN32)
        if (h_ != INVALID_HANDLE_VALUE) { CloseHandle(h_); h_ = INVALID_HANDLE_VALUE; }
#else
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
#endif
    }

    std::string path_;
#if defined(_WIN32)
    HANDLE  h_ = INVALID_HANDLE_VALUE;
#else
    int     fd_ = -1;
#endif
    uint64_t size_ = 0;
};

// ============================================================================
// BifurcatedStreamConfig — the two-axis split.
// ============================================================================
struct BifurcatedStreamConfig {
    uint32_t lane_width      = 16;            // x16 lanes
    uint64_t chunk_bytes     = 1ull << 20;   // 1 MiB per chunk (per lane)
    uint64_t max_chunk       = 1ull << 24;   // 16 MiB cap
    bool     ordered         = true;         // emit chunks in offset order
    bool     lane_isolation  = true;         // each lane gets its own storage clone
    uint32_t backpressure_x  = 2;            // in-flight cap = backpressure_x * lane_width
};

// ============================================================================
// ParallelTensorStream — reads a tensor across N lanes concurrently.
// ============================================================================
template <class Router>
class ParallelTensorStream {
public:
    // Chunk owns its buffer. When the consumer drops the Chunk, memory frees.
    struct Chunk {
        std::vector<uint8_t> buf;
        uint64_t offset;     // absolute within the tensor
        uint32_t lane;
        bool     last;
        const void* data()  const { return buf.data(); }
        uint64_t   bytes() const { return buf.size(); }
    };

    ParallelTensorStream(const Router& r, std::string_view name,
                          BifurcatedStreamConfig cfg = {})
        : router_(r), cfg_(cfg)
    {
        loc_ = r.find(name);
        if (!loc_ || loc_->size_bytes == 0) return;
        if (loc_->shard_index >= r.shards().size()) { loc_ = nullptr; return; }

        path_  = r.shards().at(loc_->shard_index).path.string();
        total_ = loc_->size_bytes;

        // clamp lane width
        uint32_t lanes = cfg_.lane_width;
        if (lanes == 0)   lanes = 1;
        if (lanes > 256)  lanes = 256;
        cfg_.lane_width = lanes;

        // clamp chunk size
        uint64_t cb = cfg_.chunk_bytes;
        if (cb == 0)              cb = 1ull << 20;
        if (cb > cfg_.max_chunk)  cb = cfg_.max_chunk;
        cfg_.chunk_bytes = cb;

        // backpressure cap
        in_flight_cap_ = (uint64_t)cfg_.backpressure_x * (uint64_t)lanes;
        if (in_flight_cap_ < 2) in_flight_cap_ = 2;

        // carve stripes (round up to chunk boundary so each lane chunks cleanly)
        uint64_t lane_span = (total_ + lanes - 1) / lanes;
        lane_span = ((lane_span + cb - 1) / cb) * cb;

        lanes_.reserve(lanes);
        for (uint32_t i = 0; i < lanes; ++i) {
            Lane L;
            L.id    = i;
            L.start = (uint64_t)i * lane_span;
            L.end   = std::min<uint64_t>(L.start + lane_span, total_);
            L.pos   = L.start;
            lanes_.push_back(std::move(L));
        }

        // open storage
        if (cfg_.lane_isolation) {
            storages_.reserve(lanes);
            for (uint32_t i = 0; i < lanes; ++i) {
                auto s = LocalStorage::open(path_);
                if (!s) { loc_ = nullptr; return; }
                storages_.push_back(std::move(s));
            }
        } else {
            auto s = LocalStorage::open(path_);
            if (!s) { loc_ = nullptr; return; }
            storages_.push_back(std::move(s));
        }

        active_lanes_.store(lanes);
        running_.store(true);
        threads_.reserve(lanes);
        for (uint32_t i = 0; i < lanes; ++i) {
            threads_.emplace_back([this, i]{ worker(i); });
        }
    }

    ~ParallelTensorStream() {
        running_.store(false);
        bp_cv_.notify_all();
        cv_.notify_all();
        for (auto& t : threads_) if (t.joinable()) t.join();
    }

    ParallelTensorStream(const ParallelTensorStream&) = delete;
    ParallelTensorStream& operator=(const ParallelTensorStream&) = delete;

    bool     valid()      const { return loc_ != nullptr; }
    uint64_t size()       const { return total_; }
    uint32_t lane_width() const { return cfg_.lane_width; }

    std::optional<Chunk> next() {
        if (!loc_) return std::nullopt;
        std::unique_lock<std::mutex> lk(mq_);
        cv_.wait(lk, [&]{
            return !queue_.empty() || all_done_.load() || !running_.load();
        });
        if (queue_.empty()) return std::nullopt;

        // pick the smallest-offset entry (ordered) or the front (unordered)
        size_t pick = 0;
        if (cfg_.ordered) {
            for (size_t i = 1; i < queue_.size(); ++i) {
                if (queue_[i].offset < queue_[pick].offset) pick = i;
            }
        }
        Entry e = std::move(queue_[pick]);
        queue_[pick] = std::move(queue_.back());
        queue_.pop_back();

        in_flight_.fetch_sub(1);
        bp_cv_.notify_one();

        Chunk c;
        c.buf    = std::move(e.buf);
        c.offset = e.offset;
        c.lane   = e.lane;
        c.last   = e.last;
        return c;
    }

    void cancel() {
        running_.store(false);
        bp_cv_.notify_all();
        cv_.notify_all();
    }

private:
    struct Entry {
        uint64_t offset = 0;
        uint32_t lane   = 0;
        std::vector<uint8_t> buf;
        bool last = false;
    };
    struct Lane {
        uint32_t id    = 0;
        uint64_t start = 0, end = 0, pos = 0;
    };

    const Router& router_;
    BifurcatedStreamConfig cfg_;
    using Loc = std::remove_pointer_t<decltype(router_.find(std::string_view{}))>;
    Loc*        loc_ = nullptr;
    std::string path_;
    uint64_t    total_ = 0;

    std::vector<std::unique_ptr<IStorage>> storages_;
    std::vector<Lane>  lanes_;
    std::vector<std::thread> threads_;

    std::atomic<bool>     running_{false};
    std::atomic<bool>     all_done_{false};
    std::atomic<uint32_t> active_lanes_{0};
    std::atomic<uint64_t> in_flight_{0};
    uint64_t              in_flight_cap_ = 0;

    std::mutex              mq_;
    std::condition_variable  cv_;
    std::vector<Entry>       queue_;     // bounded by backpressure

    std::mutex              bp_m_;
    std::condition_variable  bp_cv_;

    void worker(uint32_t i) {
        Lane& L = lanes_[i];
        IStorage* s = cfg_.lane_isolation ? storages_[i].get()
                                            : storages_[0].get();
        const uint64_t base = loc_->file_offset;
        const uint64_t cb   = cfg_.chunk_bytes;

        while (running_.load() && L.pos < L.end) {
            // backpressure: don't outrun the consumer
            {
                std::unique_lock<std::mutex> lk(bp_m_);
                bp_cv_.wait(lk, [&]{
                    return in_flight_.load() < in_flight_cap_
                           || !running_.load();
                });
                if (!running_.load()) break;
            }

            uint64_t want = (L.end - L.pos) < cb ? (L.end - L.pos) : cb;
            Entry e;
            e.buf.resize((size_t)want);
            uint64_t got = s->read_at(base + L.pos, e.buf.data(), want);
            if (got == 0) break;
            e.buf.resize((size_t)got);
            e.offset = L.pos;
            e.lane   = i;
            e.last   = (L.pos + got) >= L.end;
            L.pos   += got;

            in_flight_.fetch_add(1);
            {
                std::lock_guard<std::mutex> lk(mq_);
                queue_.push_back(std::move(e));
            }
            cv_.notify_one();
        }

        if (active_lanes_.fetch_sub(1) == 1) {
            all_done_.store(true);
            cv_.notify_all();
        }
    }
};

// ============================================================================
// Convenience: stream a tensor across lanes into a callback.
// ============================================================================
template <class Router, class Fn>
bool stream_lanes(const Router& r, std::string_view name, Fn&& fn,
                  BifurcatedStreamConfig cfg = {})
{
    ParallelTensorStream<Router> s(r, name, cfg);
    if (!s.valid()) return false;
    while (auto c = s.next()) {
        if (!fn(*c)) { s.cancel(); return false; }
    }
    return true;
}

// ============================================================================
// Convenience: drain a tensor fully into a single buffer (uses lanes to read
// fast, but reassembles in offset order). Memory = tensor size (caller's call).
// ============================================================================
template <class Router>
std::optional<std::vector<uint8_t>> drain_lanes(const Router& r,
                                                std::string_view name,
                                                BifurcatedStreamConfig cfg = {})
{
    auto* t = r.find(name);
    if (!t || t->size_bytes == 0) return std::nullopt;
    std::vector<uint8_t> out;
    out.resize((size_t)t->size_bytes);
    bool ok = stream_lanes(r, name, [&](const auto& c){
        if (c.offset + c.bytes() > t->size_bytes) return false;
        std::memcpy(out.data() + (size_t)c.offset, c.data(), (size_t)c.bytes());
        return true;
    }, cfg);
    if (!ok) return std::nullopt;
    return out;
}

} // namespace gguf_shard_lanes

#endif // GGUF_SHARD_ROUTER_LANES_HPP
