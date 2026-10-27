// K2MoEExpertAccounting.hpp — opt-in per-expert runtime attribution.
//
// This recorder is deliberately diagnostic-only.  It records measurements
// from the production K2 route/expert functions; it never changes routing,
// residency, or execution policy.  It is disabled unless
// DEEP2_MOE_ACCOUNTING=1 is present in the environment.
#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <vector>

namespace Deep2 {

struct K2MoEExpertTiming {
    uint64_t acquireNs = 0;
    uint64_t gateGemvNs = 0;
    uint64_t upGemvNs = 0;
    uint64_t siluNs = 0;
    uint64_t downGemvNs = 0;
    uint64_t computeNs = 0;
    uint64_t totalNs = 0;
    uint64_t readBytes = 0;
};

class K2MoEExpertAccounting final {
public:
    struct Row {
        uint64_t selected = 0;
        uint64_t executed = 0;
        uint64_t cpuExecuted = 0;
        uint64_t gpuExecuted = 0;
        uint64_t acquireHits = 0;
        uint64_t acquireMisses = 0;
        uint64_t acquireNs = 0;
        uint64_t gateGemvNs = 0;
        uint64_t upGemvNs = 0;
        uint64_t siluNs = 0;
        uint64_t downGemvNs = 0;
        uint64_t computeNs = 0;
        uint64_t totalNs = 0;
        uint64_t readBytes = 0;
    };

    static K2MoEExpertAccounting& Instance() {
        static K2MoEExpertAccounting value;
        return value;
    }

    static uint64_t NowNs() {
        const auto now = std::chrono::steady_clock::now().time_since_epoch();
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
    }

    bool Enabled() const noexcept { return enabled_; }

    void Reset() {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& layer : rows_)
            for (auto& row : layer) row = Row{};
    }

    void Selected(uint32_t layer, int expert) {
        if (!enabled_ || !Valid(layer, expert)) return;
        std::lock_guard<std::mutex> lock(mu_);
        rows_[layer][static_cast<size_t>(expert)].selected++;
    }

    void Executed(uint32_t layer, int expert, bool gpu,
                  bool cacheHit, const K2MoEExpertTiming& t) {
        if (!enabled_ || !Valid(layer, expert)) return;
        std::lock_guard<std::mutex> lock(mu_);
        Row& row = rows_[layer][static_cast<size_t>(expert)];
        row.executed++;
        if (gpu) row.gpuExecuted++; else row.cpuExecuted++;
        if (cacheHit) row.acquireHits++; else row.acquireMisses++;
        row.acquireNs += t.acquireNs;
        row.gateGemvNs += t.gateGemvNs;
        row.upGemvNs += t.upGemvNs;
        row.siluNs += t.siluNs;
        row.downGemvNs += t.downGemvNs;
        row.computeNs += t.computeNs;
        row.totalNs += t.totalNs;
        row.readBytes += t.readBytes;
    }

    void Emit(FILE* f) const {
        if (!f) f = stdout;
        if (!enabled_) {
            std::fprintf(f, "MOE_EXPERT_ACCOUNTING_001\nMOE_ACCOUNTING_ENABLED=0\n");
            return;
        }
        // Keep the complete matrix off the thread stack.  The rows are
        // intentionally retained even when most entries are zero so a
        // diagnostic run cannot turn a large topology into stack overflow.
        std::vector<Row> snapshot(64u * 512u);
        {
            std::lock_guard<std::mutex> lock(mu_);
            size_t at = 0;
            for (const auto& layer : rows_)
                for (const auto& row : layer) snapshot[at++] = row;
        }
        uint64_t selected = 0, executed = 0, cpu = 0, gpu = 0;
        uint64_t hits = 0, misses = 0, readBytes = 0, totalNs = 0;
        uint64_t gateNs = 0, upNs = 0, siluNs = 0, downNs = 0;
        uint32_t nonzero = 0;
        std::fprintf(f, "MOE_EXPERT_ACCOUNTING_001\n");
        std::fprintf(f, "MOE_ACCOUNTING_ENABLED=1\n");
        for (uint32_t layer = 0; layer < 64; ++layer) {
            for (uint32_t expert = 0; expert < 512; ++expert) {
                const Row& r = snapshot[static_cast<size_t>(layer) * 512u + expert];
                if (!r.selected && !r.executed) continue;
                ++nonzero;
                selected += r.selected; executed += r.executed;
                cpu += r.cpuExecuted; gpu += r.gpuExecuted;
                hits += r.acquireHits; misses += r.acquireMisses;
                readBytes += r.readBytes; totalNs += r.totalNs;
                gateNs += r.gateGemvNs; upNs += r.upGemvNs;
                siluNs += r.siluNs; downNs += r.downGemvNs;
                std::fprintf(f,
                    "MOE_EXPERT layer=%u expert=%u selected=%llu executed=%llu "
                    "cpu=%llu gpu=%llu acquire_hits=%llu acquire_misses=%llu "
                    "acquire_ns=%llu gate_gemv_ns=%llu up_gemv_ns=%llu silu_ns=%llu "
                    "down_gemv_ns=%llu compute_ns=%llu total_ns=%llu read_bytes=%llu\n",
                    layer, expert,
                    (unsigned long long)r.selected, (unsigned long long)r.executed,
                    (unsigned long long)r.cpuExecuted, (unsigned long long)r.gpuExecuted,
                    (unsigned long long)r.acquireHits, (unsigned long long)r.acquireMisses,
                    (unsigned long long)r.acquireNs, (unsigned long long)r.gateGemvNs,
                    (unsigned long long)r.upGemvNs, (unsigned long long)r.siluNs,
                    (unsigned long long)r.downGemvNs, (unsigned long long)r.computeNs,
                    (unsigned long long)r.totalNs, (unsigned long long)r.readBytes);
            }
        }
        std::fprintf(f, "MOE_EXPERT_ROWS=%u\n", nonzero);
        std::fprintf(f, "MOE_SELECTED=%llu\n", (unsigned long long)selected);
        std::fprintf(f, "MOE_EXECUTED=%llu\n", (unsigned long long)executed);
        std::fprintf(f, "MOE_CPU_EXECUTED=%llu\n", (unsigned long long)cpu);
        std::fprintf(f, "MOE_GPU_EXECUTED=%llu\n", (unsigned long long)gpu);
        std::fprintf(f, "MOE_ACQUIRE_HITS=%llu\n", (unsigned long long)hits);
        std::fprintf(f, "MOE_ACQUIRE_MISSES=%llu\n", (unsigned long long)misses);
        std::fprintf(f, "MOE_READ_BYTES=%llu\n", (unsigned long long)readBytes);
        std::fprintf(f, "MOE_GATE_GEMV_NS=%llu\n", (unsigned long long)gateNs);
        std::fprintf(f, "MOE_UP_GEMV_NS=%llu\n", (unsigned long long)upNs);
        std::fprintf(f, "MOE_SILU_NS=%llu\n", (unsigned long long)siluNs);
        std::fprintf(f, "MOE_DOWN_GEMV_NS=%llu\n", (unsigned long long)downNs);
        std::fprintf(f, "MOE_TOTAL_NS=%llu\n", (unsigned long long)totalNs);
        std::fprintf(f, "MOE_ACCOUNTING_COMPLETE=1\n");
        std::fflush(f);
    }

private:
    K2MoEExpertAccounting()
        : enabled_([] {
              const char* value = std::getenv("DEEP2_MOE_ACCOUNTING");
              return value && (value[0] == '1' || value[0] == 'y' || value[0] == 'Y');
          }()) {}

    static bool Valid(uint32_t layer, int expert) {
        return layer < 64 && expert >= 0 && expert < 512;
    }

    bool enabled_ = false;
    mutable std::mutex mu_;
    std::array<std::array<Row, 512>, 64> rows_{};
};

} // namespace Deep2
