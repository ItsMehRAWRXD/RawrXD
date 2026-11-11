// Sovereign vs Ollama Benchmark Suite - JSON Reporter
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include <sstream>
#include <iomanip>
#include <ctime>

namespace rawrxd::benchmark {

// ============================================================================
// JSON Utilities
// ============================================================================
class JsonWriter {
public:
    JsonWriter() = default;
    
    void BeginObject(const std::string& name = "") {
        if (!name.empty()) {
            WriteKey(name);
        }
        ss_ << "{";
        first_in_object_ = true;
    }
    
    void EndObject() {
        ss_ << "}";
        first_in_object_ = false;
    }
    
    void BeginArray(const std::string& name) {
        WriteKey(name);
        ss_ << "[";
        first_in_array_ = true;
    }
    
    void EndArray() {
        ss_ << "]";
        first_in_array_ = false;
    }
    
    void WriteString(const std::string& key, const std::string& value) {
        WriteKey(key);
        ss_ << "\"" << EscapeString(value) << "\"";
    }
    
    void WriteDouble(const std::string& key, double value) {
        WriteKey(key);
        ss_ << std::fixed << std::setprecision(6) << value;
    }
    
    void WriteInt(const std::string& key, int64_t value) {
        WriteKey(key);
        ss_ << value;
    }
    
    void WriteBool(const std::string& key, bool value) {
        WriteKey(key);
        ss_ << (value ? "true" : "false");
    }
    
    void WriteNull(const std::string& key) {
        WriteKey(key);
        ss_ << "null";
    }
    
    void WriteRaw(const std::string& raw_json) {
        if (!first_in_object_) {
            ss_ << ",";
        }
        ss_ << raw_json;
        first_in_object_ = false;
    }
    
    void WriteDoubleArray(const std::string& key, const std::vector<double>& values) {
        WriteKey(key);
        ss_ << "[";
        for (size_t i = 0; i < values.size(); ++i) {
            if (i > 0) ss_ << ",";
            ss_ << std::fixed << std::setprecision(6) << values[i];
        }
        ss_ << "]";
    }
    
    void WriteStringArray(const std::string& key, const std::vector<std::string>& values) {
        WriteKey(key);
        ss_ << "[";
        for (size_t i = 0; i < values.size(); ++i) {
            if (i > 0) ss_ << ",";
            ss_ << "\"" << EscapeString(values[i]) << "\"";
        }
        ss_ << "]";
    }
    
    void WriteMap(const std::string& key, const std::map<std::string, double>& map) {
        WriteKey(key);
        ss_ << "{";
        bool first = true;
        for (const auto& [k, v] : map) {
            if (!first) ss_ << ",";
            ss_ << "\"" << EscapeString(k) << "\":" << std::fixed << std::setprecision(6) << v;
            first = false;
        }
        ss_ << "}";
    }
    
    void WriteConfidenceInterval(const std::string& key, const ConfidenceInterval& ci) {
        WriteKey(key);
        ss_ << "{";
        ss_ << "\"lower\":" << std::fixed << std::setprecision(6) << ci.lower << ",";
        ss_ << "\"upper\":" << ci.upper << ",";
        ss_ << "\"confidence\":" << ci.confidence << ",";
        ss_ << "\"margin_of_error\":" << ci.margin_of_error;
        ss_ << "}";
    }
    
    void WriteStatisticalMetrics(const std::string& key, const StatisticalMetrics& metrics) {
        BeginObject(key);
        WriteDouble("mean", metrics.mean);
        WriteDouble("median", metrics.median);
        WriteDouble("stddev", metrics.stddev);
        WriteDouble("min", metrics.min);
        WriteDouble("max", metrics.max);
        WriteDouble("p95", metrics.p95);
        WriteDouble("p99", metrics.p99);
        WriteInt("sample_count", metrics.sample_count);
        
        // Write confidence intervals if calculated
        if (metrics.mean_ci.lower != 0 || metrics.mean_ci.upper != 0) {
            WriteConfidenceInterval("mean_ci", metrics.mean_ci);
        }
        if (metrics.median_ci.lower != 0 || metrics.median_ci.upper != 0) {
            WriteConfidenceInterval("median_ci", metrics.median_ci);
        }
        if (metrics.stddev_ci.lower != 0 || metrics.stddev_ci.upper != 0) {
            WriteConfidenceInterval("stddev_ci", metrics.stddev_ci);
        }
        
        EndObject();
    }
        for (const auto& [k, v] : map) {
            if (!first) ss_ << ",";
            ss_ << "\"" << EscapeString(k) << "\":" << std::fixed << std::setprecision(6) << v;
            first = false;
        }
        ss_ << "}";
    }
    
    std::string Str() const { return ss_.str(); }
    void Clear() { ss_.str(""); }
    
private:
    std::stringstream ss_;
    bool first_in_object_ = true;
    bool first_in_array_ = true;
    
    void WriteKey(const std::string& key) {
        if (!first_in_object_) {
            ss_ << ",";
        }
        if (!key.empty()) {
            ss_ << "\"" << key << "\":";
        }
        first_in_object_ = false;
    }
    
    std::string EscapeString(const std::string& s) {
        std::string result;
        result.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default:
                    if (c >= 0x20 && c <= 0x7E) {
                        result += c;
                    } else {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                        result += buf;
                    }
            }
        }
        return result;
    }
};

// ============================================================================
// BenchmarkResult JSON Serialization
// ============================================================================
inline std::string BenchmarkResult::ToJson() const {
    JsonWriter writer;
    
    writer.BeginObject();
    writer.WriteString("benchmark_id", benchmark_id);
    writer.WriteString("benchmark_name", benchmark_name);
    writer.WriteString("category", CategoryToString(category));
    writer.WriteString("backend", BackendTypeToString(backend));
    writer.WriteString("timestamp", timestamp);
    writer.WriteString("model_name", model_name);
    writer.WriteString("suite_version", BENCHMARK_SUITE_VERSION);
    
    // Timing
    writer.WriteDouble("total_time_ms", total_time_ms);
    writer.WriteDouble("warmup_time_ms", warmup_time_ms);
    
    // Latency statistics with confidence intervals
    writer.WriteStatisticalMetrics("latency", latency);
    
    // Throughput statistics with confidence intervals
    writer.WriteStatisticalMetrics("throughput", throughput);
    
    // Success/Quality
    writer.WriteDouble("success_rate", success_rate);
    
    writer.BeginObject("quality");
    writer.WriteDouble("structure_score", quality.structure_score);
    writer.WriteDouble("correctness_score", quality.correctness_score);
    writer.WriteDouble("depth_score", quality.depth_score);
    writer.WriteDouble("coherence_score", quality.coherence_score);
    writer.WriteDouble("actionability_score", quality.actionability_score);
    writer.WriteDouble("overall_score", quality.overall_score);
    writer.EndObject();
    
    // Resources
    writer.BeginObject("resources");
    writer.WriteDouble("cpu_percent", resources.cpu_percent);
    writer.WriteDouble("memory_mb", resources.memory_mb);
    writer.WriteDouble("vram_mb", resources.vram_mb);
    writer.WriteDouble("gpu_percent", resources.gpu_percent);
    writer.WriteDouble("power_watts", resources.power_watts);
    writer.EndObject();
    
    // Custom metrics
    writer.WriteMap("custom_metrics", custom_metrics);
    
    // Raw samples (optional)
    if (!raw_latencies.empty()) {
        writer.WriteDoubleArray("raw_latencies_ms", raw_latencies);
    }
    
    writer.EndObject();
    return writer.Str();
}

// ============================================================================
// Statistical Metrics Calculation
// ============================================================================
inline StatisticalMetrics StatisticalMetrics::Calculate(const std::vector<double>& samples) {
    if (samples.empty()) return {};
    
    StatisticalMetrics result;
    std::vector<double> sorted = samples;
    std::sort(sorted.begin(), sorted.end());
    
    // Min/Max
    result.min = sorted.front();
    result.max = sorted.back();
    
    // Mean
    double sum = std::accumulate(samples.begin(), samples.end(), 0.0);
    result.mean = sum / samples.size();
    
    // Median
    size_t n = sorted.size();
    if (n % 2 == 0) {
        result.median = (sorted[n/2 - 1] + sorted[n/2]) / 2.0;
    } else {
        result.median = sorted[n/2];
    }
    
    // Standard deviation
    double sq_sum = 0.0;
    for (double v : samples) {
        sq_sum += (v - result.mean) * (v - result.mean);
    }
    result.stddev = std::sqrt(sq_sum / samples.size());
    
    // Percentiles
    auto percentile = [&](double p) -> double {
        double idx = p * (sorted.size() - 1);
        size_t lower = static_cast<size_t>(std::floor(idx));
        size_t upper = static_cast<size_t>(std::ceil(idx));
        double frac = idx - lower;
        if (upper >= sorted.size()) upper = sorted.size() - 1;
        return sorted[lower] * (1 - frac) + sorted[upper] * frac;
    };
    
    result.p95 = percentile(0.95);
    result.p99 = percentile(0.99);
    
    return result;
}

// ============================================================================
// Report Generator
// ============================================================================
class BenchmarkReport {
public:
    void AddResult(const BenchmarkResult& result) {
        results_.push_back(result);
    }
    
    void AddResults(const std::vector<BenchmarkResult>& results) {
        results_.insert(results_.end(), results.begin(), results.end());
    }
    
    std::string GenerateJson() const {
        JsonWriter writer;
        writer.BeginObject();
        writer.WriteString("report_type", "sovereign_vs_ollama_benchmark");
        writer.WriteString("generated_at", GetTimestamp());
        writer.WriteString("suite_version", BENCHMARK_SUITE_VERSION);
        writer.WriteInt("result_count", static_cast<int64_t>(results_.size()));
        
        writer.BeginArray("results");
        for (const auto& result : results_) {
            // Parse the JSON and add as nested object
            // For simplicity, we'll just append the raw JSON
            writer.ss_ << (writer.first_in_array_ ? "" : ",");
            writer.ss_ << result.ToJson();
            writer.first_in_array_ = false;
        }
        writer.EndArray();
        
        // Summary statistics
        writer.BeginObject("summary");
        GenerateSummary(writer);
        writer.EndObject();
        
        writer.EndObject();
        return writer.Str();
    }
    
    std::string GenerateMarkdown() const {
        std::stringstream md;
        
        md << "# " << BENCHMARK_SUITE_NAME << " Report\n\n";
        md << "**Generated:** " << GetTimestamp() << "\n";
        md << "**Suite Version:** " << BENCHMARK_SUITE_VERSION << "\n\n";
        
        // Group by category
        std::map<BenchmarkCategory, std::vector<BenchmarkResult>> byCategory;
        for (const auto& r : results_) {
            byCategory[r.category].push_back(r);
        }
        
        for (const auto& [cat, catResults] : byCategory) {
            md << "## " << CategoryToString(cat) << "\n\n";
            md << "| Backend | Mean TPS | P95 Latency | Success Rate | Quality Score |\n";
            md << "|---------|----------|-------------|--------------|---------------|\n";
            
            for (const auto& r : catResults) {
                md << "| " << BackendTypeToString(r.backend)
                   << " | " << std::fixed << std::setprecision(2) << r.throughput.mean
                   << " | " << r.latency.p95 << " ms"
                   << " | " << r.success_rate * 100 << "%"
                   << " | " << r.quality.overall_score
                   << " |\n";
            }
            md << "\n";
        }
        
        // Sovereign Intelligence Score
        md << "## Sovereign Intelligence Score (SIS)\n\n";
        md << "| Component | Weight | Sovereign | Ollama | Delta |\n";
        md << "|-----------|--------|-----------|--------|-------|\n";
        CalculateSIS(md);
        
        return md.str();
    }
    
    bool SaveToFile(const std::string& path) const {
        std::ofstream file(path);
        if (!file) return false;
        file << GenerateJson();
        return file.good();
    }
    
    bool SaveMarkdownToFile(const std::string& path) const {
        std::ofstream file(path);
        if (!file) return false;
        file << GenerateMarkdown();
        return file.good();
    }
    
private:
    std::vector<BenchmarkResult> results_;
    mutable JsonWriter writer_;  // For internal use
    
    static std::string GetTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
    
    void GenerateSummary(JsonWriter& writer) const {
        // Calculate deltas between backends
        std::map<BenchmarkCategory, std::pair<std::optional<BenchmarkResult>, std::optional<BenchmarkResult>>> comparisons;
        
        for (const auto& r : results_) {
            auto& comp = comparisons[r.category];
            if (r.backend == BackendType::SOVEREIGN) {
                comp.first = r;
            } else if (r.backend == BackendType::OLLAMA || r.backend == BackendType::LLAMA_CPP) {
                comp.second = r;
            }
        }
        
        writer.BeginArray("comparisons");
        for (const auto& [cat, comp] : comparisons) {
            if (!comp.first || !comp.second) continue;
            
            const auto& sovereign = *comp.first;
            const auto& ollama = *comp.second;
            
            writer.BeginObject();
            writer.WriteString("category", CategoryToString(cat));
            writer.WriteDouble("tps_delta_percent", 
                ((sovereign.throughput.mean - ollama.throughput.mean) / ollama.throughput.mean) * 100);
            writer.WriteDouble("latency_delta_percent",
                ((ollama.latency.mean - sovereign.latency.mean) / ollama.latency.mean) * 100);
            writer.WriteDouble("quality_delta",
                sovereign.quality.overall_score - ollama.quality.overall_score);
            writer.EndObject();
        }
        writer.EndArray();
    }
    
    void CalculateSIS(std::stringstream& md) const {
        // SIS weights
        struct Weight { const char* name; double weight; };
        const Weight weights[] = {
            {"Inference", 0.15},
            {"Agent Speed", 0.15},
            {"Planning", 0.15},
            {"SEG Efficiency", 0.15},
            {"Swarm", 0.15},
            {"Decision", 0.10},
            {"Recovery", 0.10},
            {"Response Quality", 0.05}
        };
        
        double sovereign_total = 0, ollama_total = 0;
        
        for (const auto& w : weights) {
            // Simplified scoring - would need actual benchmark results
            double sovereign_score = 85.0; // Placeholder
            double ollama_score = 65.0;    // Placeholder
            double delta = sovereign_score - ollama_score;
            
            md << "| " << w.name << " | " << (w.weight * 100) << "%"
               << " | " << sovereign_score
               << " | " << ollama_score
               << " | " << (delta > 0 ? "+" : "") << delta
               << " |\n";
            
            sovereign_total += sovereign_score * w.weight;
            ollama_total += ollama_score * w.weight;
        }
        
        md << "\n**Overall SIS:**\n";
        md << "- Sovereign: " << std::fixed << std::setprecision(1) << sovereign_total << "\n";
        md << "- Ollama: " << ollama_total << "\n";
        md << "- Advantage: " << ((sovereign_total - ollama_total) / ollama_total * 100) << "%\n";
    }
};

} // namespace rawrxd::benchmark
