// ============================================================================
// Blocker #20: MoE Weight Pinning
// Pins MoE expert weights to physical RAM using VirtualLock (Windows) / mlock (Linux)
// Prevents eviction of hot experts to page file, reducing inference latency spikes.
// ============================================================================
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace Deep2 {

class MoEWeightPinner {
public:
    MoEWeightPinner() : totalPinnedBytes_(0), maxPinnedBytes_(0) {}

    // Set maximum bytes that can be pinned (safety limit - typically 75% of physical RAM)
    void SetMaxPinnedBytes(uint64_t maxBytes) {
        maxPinnedBytes_ = maxBytes;
    }

    // Pin a tensor's memory to prevent paging
    bool PinTensor(const std::string& name, void* data, uint64_t bytes) {
        if (!data || bytes == 0) return false;
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Check if already pinned
        if (pinned_.find(name) != pinned_.end()) return true;
        
        // Check safety limit
        if (totalPinnedBytes_ + bytes > maxPinnedBytes_) {
            // Evict coldest pinned tensor to make room
            if (!EvictColdest(bytes)) {
                return false; // Cannot make room
            }
        }
        
        bool success = false;
#ifdef _WIN32
        // VirtualLock pins pages in physical RAM
        SIZE_T size = static_cast<SIZE_T>(bytes);
        success = VirtualLock(data, size) != 0;
#else
        success = mlock(data, bytes) == 0;
#endif
        
        if (success) {
            PinnedEntry entry;
            entry.name = name;
            entry.data = data;
            entry.bytes = bytes;
            entry.pinTime = GetTickCount64();
            entry.accessCount = 1;
            
            pinned_[name] = entry;
            totalPinnedBytes_ += bytes;
            
            printf("[MoEWeightPinner] Pinned '%s' (%llu MB, total pinned: %.1f GB)\n",
                   name.c_str(), (unsigned long long)(bytes / (1024*1024)),
                   totalPinnedBytes_ / (1024.0*1024.0*1024.0));
        }
        
        return success;
    }

    // Unpin a tensor (allow it to be paged out)
    bool UnpinTensor(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = pinned_.find(name);
        if (it == pinned_.end()) return false;
        
        bool success = false;
#ifdef _WIN32
        success = VirtualUnlock(it->second.data, static_cast<SIZE_T>(it->second.bytes)) != 0;
#else
        success = munlock(it->second.data, it->second.bytes) == 0;
#endif
        
        if (success) {
            totalPinnedBytes_ -= it->second.bytes;
            pinned_.erase(it);
            
            printf("[MoEWeightPinner] Unpinned '%s' (total pinned: %.1f GB)\n",
                   name.c_str(), totalPinnedBytes_ / (1024.0*1024.0*1024.0));
        }
        
        return success;
    }

    // Record access for LRU eviction
    void RecordAccess(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = pinned_.find(name);
        if (it != pinned_.end()) {
            it->second.accessCount++;
            it->second.lastAccessTime = GetTickCount64();
        }
    }

    // Unpin all tensors
    void UnpinAll() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& pair : pinned_) {
#ifdef _WIN32
            VirtualUnlock(pair.second.data, static_cast<SIZE_T>(pair.second.bytes));
#else
            munlock(pair.second.data, pair.second.bytes);
#endif
        }
        pinned_.clear();
        totalPinnedBytes_ = 0;
    }

    uint64_t GetTotalPinnedBytes() const { return totalPinnedBytes_; }
    size_t GetPinnedCount() const { return pinned_.size(); }

private:
    struct PinnedEntry {
        std::string name;
        void* data;
        uint64_t bytes;
        uint64_t pinTime;
        uint64_t lastAccessTime;
        uint64_t accessCount;
    };

    bool EvictColdest(uint64_t neededBytes) {
        // Find least recently used pinned tensor and unpin it
        if (pinned_.empty()) return false;
        
        std::string coldestName;
        uint64_t coldestTime = UINT64_MAX;
        
        for (auto& pair : pinned_) {
            if (pair.second.lastAccessTime < coldestTime) {
                coldestTime = pair.second.lastAccessTime;
                coldestName = pair.first;
            }
        }
        
        if (coldestName.empty()) return false;
        
        // Temporarily unlock mutex for unpin (recursive would be better but avoid for simplicity)
        auto it = pinned_.find(coldestName);
        if (it == pinned_.end()) return false;
        
        void* data = it->second.data;
        uint64_t bytes = it->second.bytes;
        
#ifdef _WIN32
        VirtualUnlock(data, static_cast<SIZE_T>(bytes));
#else
        munlock(data, bytes);
#endif
        
        totalPinnedBytes_ -= bytes;
        pinned_.erase(it);
        
        printf("[MoEWeightPinner] Evicted '%s' to make room\n", coldestName.c_str());
        
        // Check if we freed enough
        if (totalPinnedBytes_ + neededBytes > maxPinnedBytes_) {
            return EvictColdest(neededBytes); // Recursively evict more
        }
        
        return true;
    }

    std::unordered_map<std::string, PinnedEntry> pinned_;
    mutable std::mutex mutex_;
    uint64_t totalPinnedBytes_;
    uint64_t maxPinnedBytes_;
};

} // namespace Deep2
