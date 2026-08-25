// ============================================================================
// OutOfCoreRuntime.cpp — Minimal viable implementation
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace RawrXD {

class OutOfCoreRuntime {
public:
    struct TensorRef {
        std::string name;
        size_t offset;
        size_t size;
        bool resident;
    };
    
    bool Initialize(size_t maxResidentBytes = 4ULL * 1024 * 1024 * 1024) {
        maxResidentBytes_ = maxResidentBytes;
        residentBytes_ = 0;
        return true;
    }
    
    bool RegisterTensor(const std::string& name, size_t offset, size_t size) {
        std::lock_guard<std::mutex> lock(mutex_);
        tensors_[name] = {name, offset, size, false};
        return true;
    }
    
    bool MakeResident(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tensors_.find(name);
        if (it == tensors_.end()) return false;
        if (it->second.resident) return true;
        if (residentBytes_ + it->second.size > maxResidentBytes_) {
            EvictLRU(it->second.size);
        }
        it->second.resident = true;
        residentBytes_ += it->second.size;
        return true;
    }
    
    bool Evict(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tensors_.find(name);
        if (it == tensors_.end() || !it->second.resident) return false;
        it->second.resident = false;
        residentBytes_ -= it->second.size;
        return true;
    }
    
    size_t GetResidentBytes() const { return residentBytes_; }
    size_t GetMaxResidentBytes() const { return maxResidentBytes_; }
    
private:
    void EvictLRU(size_t neededBytes) {
        // Simple eviction: evict non-resident tensors until space available
        for (auto& [name, ref] : tensors_) {
            if (ref.resident) {
                ref.resident = false;
                residentBytes_ -= ref.size;
                if (residentBytes_ + neededBytes <= maxResidentBytes_) break;
            }
        }
    }
    
    std::unordered_map<std::string, TensorRef> tensors_;
    size_t maxResidentBytes_ = 0;
    size_t residentBytes_ = 0;
    mutable std::mutex mutex_;
};

} // namespace RawrXD
