// B014 — Per-Invocation Compute Decomposition Profiler
// Instrumentation-only: records mutually exclusive timing regions per StreamingMatMul call.
//
// Usage:
//   1. Call B014EnableProfiling(true) before the workload.
//   2. Run inference (StreamingMatMul invocations are recorded automatically).
//   3. Call B014ExportProfile(path) after the workload to emit JSON + CSV.
//
// Timing regions (mutually exclusive):
//   total = acquisition + dequantization + dot_product + overhead
//
// Recorded per invocation:
//   - tensor_name (e.g., "blk.0.attn_q.weight")
//   - layer_index (parsed from tensor name, -1 if unknown)
//   - op_type (attn_q, attn_k, attn_v, attn_output, ffn_up, ffn_down, ffn_gate, output)
//   - M, N, K dimensions
//   - total_ns, acq_ns, dequant_ns, dot_ns, overhead_ns
//   - rows_processed, blocks_per_row
//   - b011_hit (true/false)
//   - timestamp_ns (relative to first invocation)

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <mutex>

namespace rawrxd {
namespace b014 {

struct B014InvocationRecord
{
    std::string tensorName;
    int layerIndex = -1;
    std::string opType;
    std::size_t M = 0;
    std::size_t N = 0;
    std::size_t K = 0;
    std::uint64_t totalNs = 0;
    std::uint64_t acqNs = 0;
    std::uint64_t dequantNs = 0;
    std::uint64_t dotNs = 0;
    std::uint64_t overheadNs = 0;
    std::size_t rowsProcessed = 0;
    std::size_t blocksPerRow = 0;
    bool b011Hit = false;
    std::uint64_t timestampNs = 0;  // relative to first recorded invocation
};

class B014Profiler
{
public:
    void Enable(bool enabled);
    bool IsEnabled() const;

    // Call at the start of StreamingMatMul
    void BeginInvocation(const std::string& tensorName, std::size_t K, std::size_t N);

    // Call after tensor acquisition (cache lookup or map complete)
    void EndAcquisition();

    // Call after dequantization block
    void RecordDequantization(std::uint64_t ns);

    // Call after dot-product block
    void RecordDotProduct(std::uint64_t ns);

    // Call at the end of StreamingMatMul
    void EndInvocation(bool b011Hit);

    // Export aggregated results
    bool ExportJson(const std::string& path) const;
    bool ExportCsv(const std::string& path) const;

    // Aggregate summary
    struct Summary
    {
        std::size_t totalInvocations = 0;
        std::uint64_t totalNs = 0;
        std::uint64_t totalAcqNs = 0;
        std::uint64_t totalDequantNs = 0;
        std::uint64_t totalDotNs = 0;
        std::uint64_t totalOverheadNs = 0;
        double meanTotalMs = 0.0;
        double meanDequantMs = 0.0;
        double meanDotMs = 0.0;
        double meanOverheadMs = 0.0;
        double dequantPct = 0.0;
        double dotPct = 0.0;
        double overheadPct = 0.0;
        double acqPct = 0.0;
    };
    Summary ComputeSummary() const;

    // Per-layer aggregate
    struct LayerAggregate
    {
        int layerIndex = -1;
        std::size_t invocationCount = 0;
        std::uint64_t totalNs = 0;
        std::uint64_t dequantNs = 0;
        std::uint64_t dotNs = 0;
        std::uint64_t overheadNs = 0;
        std::uint64_t acqNs = 0;
    };
    std::vector<LayerAggregate> ComputeLayerAggregates() const;

    // Per-op-type aggregate
    struct OpTypeAggregate
    {
        std::string opType;
        std::size_t invocationCount = 0;
        std::uint64_t totalNs = 0;
        std::uint64_t dequantNs = 0;
        std::uint64_t dotNs = 0;
        std::uint64_t overheadNs = 0;
        std::uint64_t acqNs = 0;
    };
    std::vector<OpTypeAggregate> ComputeOpTypeAggregates() const;

    // Raw access
    const std::vector<B014InvocationRecord>& GetRecords() const { return m_records; }
    void Clear();

private:
    bool m_enabled = false;
    std::vector<B014InvocationRecord> m_records;
    mutable std::recursive_mutex m_mutex;

    // In-progress invocation state
    B014InvocationRecord m_current;
    std::chrono::steady_clock::time_point m_invocationStart;
    std::chrono::steady_clock::time_point m_acqStart;
    std::chrono::steady_clock::time_point m_firstInvocationStart;
    bool m_inInvocation = false;

    static int ParseLayerIndex(const std::string& tensorName);
    static std::string ParseOpType(const std::string& tensorName);
};

} // namespace b014
} // namespace rawrxd
