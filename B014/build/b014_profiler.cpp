// B014 — Per-Invocation Compute Decomposition Profiler Implementation

#include "b014_profiler.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <regex>
#include <algorithm>
#include <unordered_map>

namespace rawrxd {
namespace b014 {

// ============================================================================
// Enable / Disable
// ============================================================================
void B014Profiler::Enable(bool enabled)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_enabled = enabled;
}

bool B014Profiler::IsEnabled() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_enabled;
}

void B014Profiler::Clear()
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_records.clear();
    m_inInvocation = false;
}

// ============================================================================
// Tensor name parsing
// ============================================================================
int B014Profiler::ParseLayerIndex(const std::string& tensorName)
{
    // Match patterns like "blk.0.attn_q.weight" or "blk.12.ffn_up.weight"
    std::regex re(R"(blk\.(\d+)\.)", std::regex::ECMAScript);
    std::smatch match;
    if (std::regex_search(tensorName, match, re) && match.size() > 1)
    {
        try {
            return std::stoi(match[1].str());
        } catch (...) {
            return -1;
        }
    }
    // output.weight has no layer index
    return -1;
}

std::string B014Profiler::ParseOpType(const std::string& tensorName)
{
    if (tensorName.find("attn_q") != std::string::npos) return "attn_q";
    if (tensorName.find("attn_k") != std::string::npos) return "attn_k";
    if (tensorName.find("attn_v") != std::string::npos) return "attn_v";
    if (tensorName.find("attn_output") != std::string::npos) return "attn_output";
    if (tensorName.find("ffn_up") != std::string::npos) return "ffn_up";
    if (tensorName.find("ffn_down") != std::string::npos) return "ffn_down";
    if (tensorName.find("ffn_gate") != std::string::npos) return "ffn_gate";
    if (tensorName.find("output.weight") != std::string::npos) return "output_projection";
    if (tensorName.find("token_embd") != std::string::npos) return "token_embedding";
    return "unknown";
}

// ============================================================================
// Invocation lifecycle
// ============================================================================
void B014Profiler::BeginInvocation(const std::string& tensorName, std::size_t K, std::size_t N)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (!m_enabled) return;

    m_inInvocation = true;
    m_current = B014InvocationRecord{};
    m_current.tensorName = tensorName;
    m_current.layerIndex = ParseLayerIndex(tensorName);
    m_current.opType = ParseOpType(tensorName);
    m_current.K = K;
    m_current.N = N;
    m_current.M = 1;  // StreamingMatMul is M=1 (vector-matrix)

    m_invocationStart = std::chrono::steady_clock::now();
    m_acqStart = m_invocationStart;

    if (m_firstInvocationStart.time_since_epoch().count() == 0)
    {
        m_firstInvocationStart = m_invocationStart;
    }
}

void B014Profiler::EndAcquisition()
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (!m_enabled || !m_inInvocation) return;

    auto now = std::chrono::steady_clock::now();
    m_current.acqNs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now - m_acqStart).count());
}

void B014Profiler::RecordDequantization(std::uint64_t ns)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (!m_enabled || !m_inInvocation) return;
    m_current.dequantNs += ns;
}

void B014Profiler::RecordDotProduct(std::uint64_t ns)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (!m_enabled || !m_inInvocation) return;
    m_current.dotNs += ns;
}

void B014Profiler::EndInvocation(bool b011Hit)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (!m_enabled || !m_inInvocation) return;

    auto now = std::chrono::steady_clock::now();
    m_current.totalNs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now - m_invocationStart).count());

    // Overhead = total - acq - dequant - dot
    std::uint64_t accounted = m_current.acqNs + m_current.dequantNs + m_current.dotNs;
    if (m_current.totalNs > accounted)
        m_current.overheadNs = m_current.totalNs - accounted;
    else
        m_current.overheadNs = 0;

    m_current.b011Hit = b011Hit;
    m_current.timestampNs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(m_invocationStart - m_firstInvocationStart).count());

    m_records.push_back(m_current);
    m_inInvocation = false;
}

// ============================================================================
// Summary computation
// ============================================================================
B014Profiler::Summary B014Profiler::ComputeSummary() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    Summary s{};
    s.totalInvocations = m_records.size();
    if (s.totalInvocations == 0) return s;

    for (const auto& r : m_records)
    {
        s.totalNs += r.totalNs;
        s.totalAcqNs += r.acqNs;
        s.totalDequantNs += r.dequantNs;
        s.totalDotNs += r.dotNs;
        s.totalOverheadNs += r.overheadNs;
    }

    double totalMs = static_cast<double>(s.totalNs) / 1.0e6;
    s.meanTotalMs = totalMs / static_cast<double>(s.totalInvocations);
    s.meanDequantMs = (static_cast<double>(s.totalDequantNs) / 1.0e6) / static_cast<double>(s.totalInvocations);
    s.meanDotMs = (static_cast<double>(s.totalDotNs) / 1.0e6) / static_cast<double>(s.totalInvocations);
    s.meanOverheadMs = (static_cast<double>(s.totalOverheadNs) / 1.0e6) / static_cast<double>(s.totalInvocations);

    if (s.totalNs > 0)
    {
        s.dequantPct = 100.0 * static_cast<double>(s.totalDequantNs) / static_cast<double>(s.totalNs);
        s.dotPct = 100.0 * static_cast<double>(s.totalDotNs) / static_cast<double>(s.totalNs);
        s.overheadPct = 100.0 * static_cast<double>(s.totalOverheadNs) / static_cast<double>(s.totalNs);
        s.acqPct = 100.0 * static_cast<double>(s.totalAcqNs) / static_cast<double>(s.totalNs);
    }

    return s;
}

// ============================================================================
// Layer aggregates
// ============================================================================
std::vector<B014Profiler::LayerAggregate> B014Profiler::ComputeLayerAggregates() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    std::unordered_map<int, LayerAggregate> agg;

    for (const auto& r : m_records)
    {
        auto& a = agg[r.layerIndex];
        a.layerIndex = r.layerIndex;
        a.invocationCount++;
        a.totalNs += r.totalNs;
        a.dequantNs += r.dequantNs;
        a.dotNs += r.dotNs;
        a.overheadNs += r.overheadNs;
        a.acqNs += r.acqNs;
    }

    std::vector<LayerAggregate> result;
    for (auto& kv : agg)
        result.push_back(kv.second);
    std::sort(result.begin(), result.end(),
              [](const LayerAggregate& a, const LayerAggregate& b) {
                  return a.layerIndex < b.layerIndex;
              });
    return result;
}

// ============================================================================
// Op-type aggregates
// ============================================================================
std::vector<B014Profiler::OpTypeAggregate> B014Profiler::ComputeOpTypeAggregates() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    std::unordered_map<std::string, OpTypeAggregate> agg;

    for (const auto& r : m_records)
    {
        auto& a = agg[r.opType];
        a.opType = r.opType;
        a.invocationCount++;
        a.totalNs += r.totalNs;
        a.dequantNs += r.dequantNs;
        a.dotNs += r.dotNs;
        a.overheadNs += r.overheadNs;
        a.acqNs += r.acqNs;
    }

    std::vector<OpTypeAggregate> result;
    for (auto& kv : agg)
        result.push_back(kv.second);
    std::sort(result.begin(), result.end(),
              [](const OpTypeAggregate& a, const OpTypeAggregate& b) {
                  return a.totalNs > b.totalNs;  // sort by total time descending
              });
    return result;
}

// ============================================================================
// Export JSON
// ============================================================================
bool B014Profiler::ExportJson(const std::string& path) const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    std::ofstream ofs(path);
    if (!ofs.is_open()) return false;

    auto summary = ComputeSummary();
    auto layerAgg = ComputeLayerAggregates();
    auto opTypeAgg = ComputeOpTypeAggregates();

    ofs << "{\n";
    ofs << "  \"experiment\": \"B014\",\n";
    ofs << "  \"timestamp\": \"2026-08-10T00:00:00Z\",\n";
    ofs << "  \"summary\": {\n";
    ofs << "    \"total_invocations\": " << summary.totalInvocations << ",\n";
    ofs << "    \"total_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(summary.totalNs) / 1.0e6) << ",\n";
    ofs << "    \"mean_total_ms\": " << std::fixed << std::setprecision(3) << summary.meanTotalMs << ",\n";
    ofs << "    \"mean_acq_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(summary.totalAcqNs) / 1.0e6 / summary.totalInvocations) << ",\n";
    ofs << "    \"mean_dequant_ms\": " << std::fixed << std::setprecision(3) << summary.meanDequantMs << ",\n";
    ofs << "    \"mean_dot_ms\": " << std::fixed << std::setprecision(3) << summary.meanDotMs << ",\n";
    ofs << "    \"mean_overhead_ms\": " << std::fixed << std::setprecision(3) << summary.meanOverheadMs << ",\n";
    ofs << "    \"acq_pct\": " << std::fixed << std::setprecision(2) << summary.acqPct << ",\n";
    ofs << "    \"dequant_pct\": " << std::fixed << std::setprecision(2) << summary.dequantPct << ",\n";
    ofs << "    \"dot_pct\": " << std::fixed << std::setprecision(2) << summary.dotPct << ",\n";
    ofs << "    \"overhead_pct\": " << std::fixed << std::setprecision(2) << summary.overheadPct << "\n";
    ofs << "  },\n";

    // Layer aggregates
    ofs << "  \"layer_aggregates\": [\n";
    for (size_t i = 0; i < layerAgg.size(); ++i)
    {
        const auto& a = layerAgg[i];
        ofs << "    {\n";
        ofs << "      \"layer_index\": " << a.layerIndex << ",\n";
        ofs << "      \"invocation_count\": " << a.invocationCount << ",\n";
        ofs << "      \"total_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(a.totalNs) / 1.0e6) << ",\n";
        ofs << "      \"dequant_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(a.dequantNs) / 1.0e6) << ",\n";
        ofs << "      \"dot_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(a.dotNs) / 1.0e6) << ",\n";
        ofs << "      \"overhead_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(a.overheadNs) / 1.0e6) << ",\n";
        ofs << "      \"acq_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(a.acqNs) / 1.0e6) << "\n";
        ofs << "    }" << (i + 1 < layerAgg.size() ? "," : "") << "\n";
    }
    ofs << "  ],\n";

    // Op-type aggregates
    ofs << "  \"op_type_aggregates\": [\n";
    for (size_t i = 0; i < opTypeAgg.size(); ++i)
    {
        const auto& a = opTypeAgg[i];
        ofs << "    {\n";
        ofs << "      \"op_type\": \"" << a.opType << "\",\n";
        ofs << "      \"invocation_count\": " << a.invocationCount << ",\n";
        ofs << "      \"total_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(a.totalNs) / 1.0e6) << ",\n";
        ofs << "      \"dequant_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(a.dequantNs) / 1.0e6) << ",\n";
        ofs << "      \"dot_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(a.dotNs) / 1.0e6) << ",\n";
        ofs << "      \"overhead_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(a.overheadNs) / 1.0e6) << ",\n";
        ofs << "      \"acq_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(a.acqNs) / 1.0e6) << "\n";
        ofs << "    }" << (i + 1 < opTypeAgg.size() ? "," : "") << "\n";
    }
    ofs << "  ],\n";

    // Raw invocation records
    ofs << "  \"invocations\": [\n";
    for (size_t i = 0; i < m_records.size(); ++i)
    {
        const auto& r = m_records[i];
        ofs << "    {\n";
        ofs << "      \"tensor_name\": \"" << r.tensorName << "\",\n";
        ofs << "      \"layer_index\": " << r.layerIndex << ",\n";
        ofs << "      \"op_type\": \"" << r.opType << "\",\n";
        ofs << "      \"M\": " << r.M << ",\n";
        ofs << "      \"N\": " << r.N << ",\n";
        ofs << "      \"K\": " << r.K << ",\n";
        ofs << "      \"total_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(r.totalNs) / 1.0e6) << ",\n";
        ofs << "      \"acq_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(r.acqNs) / 1.0e6) << ",\n";
        ofs << "      \"dequant_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(r.dequantNs) / 1.0e6) << ",\n";
        ofs << "      \"dot_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(r.dotNs) / 1.0e6) << ",\n";
        ofs << "      \"overhead_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(r.overheadNs) / 1.0e6) << ",\n";
        ofs << "      \"b011_hit\": " << (r.b011Hit ? "true" : "false") << ",\n";
        ofs << "      \"timestamp_ms\": " << std::fixed << std::setprecision(3) << (static_cast<double>(r.timestampNs) / 1.0e6) << "\n";
        ofs << "    }" << (i + 1 < m_records.size() ? "," : "") << "\n";
    }
    ofs << "  ]\n";
    ofs << "}\n";
    ofs.flush();
    ofs.close();
    return true;
}

// ============================================================================
// Export CSV
// ============================================================================
bool B014Profiler::ExportCsv(const std::string& path) const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    std::ofstream ofs(path);
    if (!ofs.is_open()) return false;

    ofs << "tensor_name,layer_index,op_type,M,N,K,total_ms,acq_ms,dequant_ms,dot_ms,overhead_ms,b011_hit,timestamp_ms\n";
    for (const auto& r : m_records)
    {
        ofs << r.tensorName << ","
           << r.layerIndex << ","
           << r.opType << ","
           << r.M << ","
           << r.N << ","
           << r.K << ","
           << std::fixed << std::setprecision(3) << (static_cast<double>(r.totalNs) / 1.0e6) << ","
           << std::fixed << std::setprecision(3) << (static_cast<double>(r.acqNs) / 1.0e6) << ","
           << std::fixed << std::setprecision(3) << (static_cast<double>(r.dequantNs) / 1.0e6) << ","
           << std::fixed << std::setprecision(3) << (static_cast<double>(r.dotNs) / 1.0e6) << ","
           << std::fixed << std::setprecision(3) << (static_cast<double>(r.overheadNs) / 1.0e6) << ","
           << (r.b011Hit ? "true" : "false") << ","
           << std::fixed << std::setprecision(3) << (static_cast<double>(r.timestampNs) / 1.0e6) << "\n";
    }
    ofs.flush();
    ofs.close();
    return true;
}

} // namespace b014
} // namespace rawrxd
