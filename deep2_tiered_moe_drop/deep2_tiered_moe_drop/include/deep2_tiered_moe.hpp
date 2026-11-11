#pragma once
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace deep2::tiered {
struct Tensor {
  std::string name;
  std::filesystem::path file;
  uint64_t offset=0, bytes=0;
  int32_t layer=-1, expert=-1;
  uint32_t ggml_type=0;
};
struct Stats {
  uint64_t hits=0, misses=0, evictions=0, disk_reads=0, disk_bytes=0;
  uint64_t resident_bytes=0, peak_resident_bytes=0, pinned_bytes=0;
};
struct Budget {
  uint64_t gpu0=0, gpu1=0, host=0, kv=0, scratch=0, staging=0;
};
struct Admission {
  bool accepted=false;
  uint64_t usable_host=0, required_host=0;
  std::string reason;
};
Admission admit(const Budget& budget, uint64_t required_host);
class TensorIndex {
  public:
    void add(Tensor tensor);
    const Tensor& at(const std::string& name) const;
    size_t size() const noexcept { return tensors_.size(); }
    uint64_t total_bytes() const;
    std::vector<std::string> list_names() const;
  private:
    std::unordered_map<std::string, Tensor> tensors_;
};
class Cache {
 public:
  struct Entry {
    std::vector<std::byte> data;
    uint64_t bytes=0;
  };
  class Lease {
   public:
    Lease()=default;
    Lease(const Lease&)=delete;
    Lease& operator=(const Lease&)=delete;
    Lease(Lease&& other) noexcept;
    Lease& operator=(Lease&& other) noexcept;
    ~Lease();
    std::span<const std::byte> bytes() const;
    explicit operator bool() const noexcept { return static_cast<bool>(entry_); }
   private:
    friend class Cache;
    Lease(Cache* owner, std::string key, std::shared_ptr<const Entry> entry);
    void release() noexcept;
    Cache* owner_=nullptr;
    std::string key_;
    std::shared_ptr<const Entry> entry_;
  };
  explicit Cache(uint64_t capacity);
  Cache(const Cache&)=delete;
  Cache& operator=(const Cache&)=delete;
  Lease acquire(const Tensor& tensor);
  Stats stats() const;
  uint64_t capacity() const noexcept { return capacity_; }
 private:
  struct Slot {
    std::shared_ptr<Entry> entry;
    uint64_t pins=0;
    std::list<std::string>::iterator lru;
  };
  void release(const std::string& key) noexcept;
  bool evict_until(uint64_t needed);
  static std::vector<std::byte> read_exact(const Tensor& tensor);
  const uint64_t capacity_;
  mutable std::mutex mu_;
  std::list<std::string> lru_;
  std::unordered_map<std::string, Slot> slots_;
  Stats stats_;
};
}
