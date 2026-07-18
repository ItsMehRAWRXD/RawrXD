// cache_optimized_data_structures.cpp
// Batch 9: Cache-Optimized Data Structures
//
// Provides data structures optimized for cache locality:
// - SoA (Structure of Arrays) vs AoS (Array of Structures)
// - Cache-aligned arrays
// - Prefetch-friendly iterators

#include <vector>
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <iterator>
#include <algorithm>
#include <numeric>

namespace Benchmark {
namespace Performance {

// Structure of Arrays (SoA) for sample data
// Better cache locality when iterating over single fields
class SampleDataSoA {
public:
    void Reserve(size_t capacity) {
        timestamps_.reserve(capacity);
        latencies_.reserve(capacity);
        throughputs_.reserve(capacity);
        success_flags_.reserve(capacity);
    }

    void AddSample(uint64_t timestamp, double latency, double throughput, bool success) {
        timestamps_.push_back(timestamp);
        latencies_.push_back(latency);
        throughputs_.push_back(throughput);
        success_flags_.push_back(success);
    }

    void Clear() {
        timestamps_.clear();
        latencies_.clear();
        throughputs_.clear();
        success_flags_.clear();
    }

    size_t Size() const noexcept {
        return timestamps_.size();
    }

    // Fast iteration over single field
    double SumLatencies() const {
        double sum = 0.0;
        // Compiler can vectorize this loop
        for (double latency : latencies_) {
            sum += latency;
        }
        return sum;
    }

    double MeanLatency() const {
        if (latencies_.empty()) return 0.0;
        return SumLatencies() / static_cast<double>(latencies_.size());
    }

    // Accessors
    const std::vector<uint64_t>& Timestamps() const { return timestamps_; }
    const std::vector<double>& Latencies() const { return latencies_; }
    const std::vector<double>& Throughputs() const { return throughputs_; }
    const std::vector<bool>& SuccessFlags() const { return success_flags_; }

private:
    std::vector<uint64_t> timestamps_;
    std::vector<double> latencies_;
    std::vector<double> throughputs_;
    std::vector<bool> success_flags_;
};

// Cache-aligned vector with prefetching
class alignas(64) CacheAlignedVector {
public:
    using value_type = double;
    using iterator = value_type*;
    using const_iterator = const value_type*;

    CacheAlignedVector() = default;
    explicit CacheAlignedVector(size_t size) : data_(size) {}

    void Reserve(size_t capacity) {
        data_.reserve(capacity);
    }

    void PushBack(value_type value) {
        data_.push_back(value);
    }

    void Clear() {
        data_.clear();
    }

    size_t Size() const noexcept {
        return data_.size();
    }

    value_type& operator[](size_t index) {
        return data_[index];
    }

    const value_type& operator[](size_t index) const {
        return data_[index];
    }

    // Prefetching iterator
    class PrefetchIterator {
    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = double;
        using difference_type = std::ptrdiff_t;
        using pointer = double*;
        using reference = double&;

        PrefetchIterator(pointer ptr, pointer end) 
            : ptr_(ptr), end_(end) {}

        reference operator*() const { return *ptr_; }
        pointer operator->() const { return ptr_; }

        PrefetchIterator& operator++() {
            // Prefetch next cache line
            if (ptr_ + 8 < end_) {
                __builtin_prefetch(ptr_ + 8, 0, 3);
            }
            ++ptr_;
            return *this;
        }

        PrefetchIterator operator++(int) {
            PrefetchIterator tmp = *this;
            ++(*this);
            return tmp;
        }

        bool operator==(const PrefetchIterator& other) const {
            return ptr_ == other.ptr_;
        }

        bool operator!=(const PrefetchIterator& other) const {
            return ptr_ != other.ptr_;
        }

    private:
        pointer ptr_;
        pointer end_;
    };

    PrefetchIterator BeginPrefetch() {
        return PrefetchIterator(data_.data(), data_.data() + data_.size());
    }

    PrefetchIterator EndPrefetch() {
        return PrefetchIterator(data_.data() + data_.size(), data_.data() + data_.size());
    }

    // Fast sum using prefetching
    double Sum() const {
        double sum = 0.0;
        auto it = const_cast<CacheAlignedVector*>(this)->BeginPrefetch();
        auto end = const_cast<CacheAlignedVector*>(this)->EndPrefetch();
        
        for (; it != end; ++it) {
            sum += *it;
        }
        return sum;
    }

    // SIMD-friendly sum (compiler will auto-vectorize)
    double SumVectorized() const {
        return std::accumulate(data_.begin(), data_.end(), 0.0);
    }

    // Sort with cache-friendly pattern
    void Sort() {
        std::sort(data_.begin(), data_.end());
    }

    // Get percentile (requires sorted data)
    double Percentile(double p) const {
        if (data_.empty()) return 0.0;
        size_t index = static_cast<size_t>(p * data_.size());
        if (index >= data_.size()) index = data_.size() - 1;
        return data_[index];
    }

private:
    alignas(64) std::vector<value_type> data_;
};

// Block-based array for large datasets
// Processes data in cache-sized blocks
class BlockedArray {
public:
    static constexpr size_t BLOCK_SIZE = 1024; // Elements per block

    void Add(double value) {
        if (blocks_.empty() || blocks_.back().size() >= BLOCK_SIZE) {
            blocks_.emplace_back();
            blocks_.back().reserve(BLOCK_SIZE);
        }
        blocks_.back().push_back(value);
    }

    size_t Size() const {
        size_t total = 0;
        for (const auto& block : blocks_) {
            total += block.size();
        }
        return total;
    }

    // Process each block (fits in cache)
    template<typename Func>
    void ProcessBlocks(Func&& func) const {
        for (const auto& block : blocks_) {
            func(block);
        }
    }

    // Sum with block-level accumulation
    double Sum() const {
        double total = 0.0;
        ProcessBlocks([&total](const std::vector<double>& block) {
            double block_sum = 0.0;
            for (double v : block) {
                block_sum += v;
            }
            total += block_sum;
        });
        return total;
    }

    // Parallel sum (thread-safe)
    double ParallelSum() const {
        std::vector<double> partial_sums(blocks_.size());
        
        // Process blocks in parallel
        #pragma omp parallel for
        for (size_t i = 0; i < blocks_.size(); ++i) {
            double sum = 0.0;
            for (double v : blocks_[i]) {
                sum += v;
            }
            partial_sums[i] = sum;
        }
        
        return std::accumulate(partial_sums.begin(), partial_sums.end(), 0.0);
    }

private:
    std::vector<std::vector<double>> blocks_;
};

// Compact histogram with fixed bins
class CompactHistogram {
public:
    explicit CompactHistogram(size_t num_bins = 100)
        : bins_(num_bins, 0),
          min_value_(0.0),
          max_value_(0.0),
          count_(0) {}

    void Add(double value) {
        if (count_ == 0) {
            min_value_ = max_value_ = value;
        } else {
            if (value < min_value_) min_value_ = value;
            if (value > max_value_) max_value_ = value;
        }
        
        // Store value for later binning
        values_.push_back(value);
        ++count_;
    }

    void Finalize() {
        if (count_ == 0) return;
        
        // Clear bins
        std::fill(bins_.begin(), bins_.end(), 0);
        
        // Bin values
        double range = max_value_ - min_value_;
        if (range == 0.0) range = 1.0;
        
        for (double value : values_) {
            size_t bin = static_cast<size_t>((value - min_value_) / range * (bins_.size() - 1));
            if (bin >= bins_.size()) bin = bins_.size() - 1;
            ++bins_[bin];
        }
        
        values_.clear();
        values_.shrink_to_fit();
    }

    size_t GetBinCount(size_t bin) const {
        if (bin >= bins_.size()) return 0;
        return bins_[bin];
    }

    double GetBinCenter(size_t bin) const {
        if (bins_.empty()) return 0.0;
        double range = max_value_ - min_value_;
        return min_value_ + (bin + 0.5) * range / bins_.size();
    }

    size_t NumBins() const { return bins_.size(); }
    size_t Count() const { return count_; }
    double Min() const { return min_value_; }
    double Max() const { return max_value_; }

private:
    std::vector<size_t> bins_;
    std::vector<double> values_; // Temporary storage
    double min_value_;
    double max_value_;
    size_t count_;
};

// Performance comparison utilities
struct PerformanceMetrics {
    size_t cache_hits;
    size_t cache_misses;
    double avg_latency_ns;
    double throughput_ops_per_sec;
};

// Cache-friendly statistics calculation
inline double CalculateMeanCacheFriendly(const std::vector<double>& data) {
    if (data.empty()) return 0.0;
    
    // Process in chunks that fit in L1 cache
    constexpr size_t CHUNK_SIZE = 512;
    double total = 0.0;
    
    size_t i = 0;
    for (; i + CHUNK_SIZE <= data.size(); i += CHUNK_SIZE) {
        double chunk_sum = 0.0;
        for (size_t j = 0; j < CHUNK_SIZE; ++j) {
            chunk_sum += data[i + j];
        }
        total += chunk_sum;
    }
    
    // Remaining elements
    for (; i < data.size(); ++i) {
        total += data[i];
    }
    
    return total / static_cast<double>(data.size());
}

} // namespace Performance
} // namespace Benchmark
