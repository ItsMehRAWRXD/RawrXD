// data_api.cpp
// Batch 11: REST API Data Endpoints
//
// Provides JSON API for dashboard data access
// Features: Benchmark results, comparisons, trends, system metrics

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <fstream>
#include <sstream>

namespace Benchmark {
namespace Dashboard {

// JSON serialization helper (simplified)
class JsonBuilder {
public:
    JsonBuilder& Object() {
        if (!first_) ss_ << "{";
        first_ = false;
        return *this;
    }
    
    JsonBuilder& Array() {
        if (!first_) ss_ << "[";
        first_ = false;
        return *this;
    }
    
    JsonBuilder& Key(const std::string& key) {
        if (!first_) ss_ << ",";
        ss_ << "\"" << Escape(key) << "\":";
        first_ = false;
        return *this;
    }
    
    JsonBuilder& Value(const std::string& val) {
        ss_ << "\"" << Escape(val) << "\"";
        return *this;
    }
    
    JsonBuilder& Value(int val) {
        ss_ << val;
        return *this;
    }
    
    JsonBuilder& Value(double val) {
        ss_ << val;
        return *this;
    }
    
    JsonBuilder& Value(bool val) {
        ss_ << (val ? "true" : "false");
        return *this;
    }
    
    JsonBuilder& Null() {
        ss_ << "null";
        return *this;
    }
    
    JsonBuilder& EndObject() {
        ss_ << "}";
        return *this;
    }
    
    JsonBuilder& EndArray() {
        ss_ << "]";
        return *this;
    }
    
    std::string Build() const {
        return ss_.str();
    }
    
private:
    std::stringstream ss_;
    bool first_ = true;
    
    std::string Escape(const std::string& str) const {
        std::string result;
        for (char c : str) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c;
            }
        }
        return result;
    }
};

// Data API handler
class DataAPI {
public:
    // Get all benchmarks
    static std::string GetBenchmarks() {
        JsonBuilder json;
        json.Object()
            .Key("benchmarks").Array();
        
        // Tier 1: Core Runtime
        AddBenchmark(json, "inference_tps", "Inference TPS", 1, "core");
        AddBenchmark(json, "context_scaling", "Context Scaling", 1, "core");
        AddBenchmark(json, "concurrent_load", "Concurrent Load", 1, "core");
        AddBenchmark(json, "latency_percentiles", "Latency Percentiles", 1, "core");
        AddBenchmark(json, "resource_monitoring", "Resource Monitoring", 1, "core");
        
        // Tier 2: Agentic & Sovereign
        AddBenchmark(json, "planning_task", "Planning Task", 2, "agentic");
        AddBenchmark(json, "tool_use", "Tool Use", 2, "agentic");
        
        // Tier 3: Advanced
        AddBenchmark(json, "seg_mutation", "SEG Mutation", 3, "advanced");
        AddBenchmark(json, "swarm_coordination", "Swarm Coordination", 3, "advanced");
        AddBenchmark(json, "autonomous_recovery", "Autonomous Recovery", 3, "advanced");
        
        // Tier 4: Stress
        AddBenchmark(json, "stress_overload", "Stress Overload", 4, "stress");
        AddBenchmark(json, "chaos_fault_injection", "Chaos Fault Injection", 4, "stress");
        AddBenchmark(json, "degradation_curve", "Degradation Curve", 4, "stress");
        AddBenchmark(json, "resource_pressure", "Resource Pressure", 4, "stress");
        AddBenchmark(json, "mutation_storm", "Mutation Storm", 4, "stress");
        AddBenchmark(json, "swarm_overload", "Swarm Overload", 4, "stress");
        
        // Workflow
        AddBenchmark(json, "workflow_explain_repo", "Workflow: Explain Repo", 2, "workflow");
        AddBenchmark(json, "workflow_bug_fix", "Workflow: Bug Fix", 2, "workflow");
        
        // Reliability
        AddBenchmark(json, "memory_leak", "Memory Leak Detection", 3, "reliability");
        AddBenchmark(json, "performance_drift", "Performance Drift", 3, "reliability");
        AddBenchmark(json, "determinism", "Determinism Check", 3, "reliability");
        
        json.EndArray()
            .EndObject();
        
        return json.Build();
    }
    
    // Get benchmark results
    static std::string GetBenchmarkResults(const std::string& benchmark_id) {
        JsonBuilder json;
        json.Object()
            .Key("benchmark_id").Value(benchmark_id)
            .Key("status").Value("completed")
            .Key("timestamp").Value(GetCurrentTimestamp())
            .Key("results").Object();
        
        // Simulated results
        json.Key("mean_tps").Value(45.2)
            .Key("std_dev").Value(2.1)
            .Key("min").Value(40.5)
            .Key("max").Value(48.3)
            .Key("samples").Value(30)
            .Key("confidence_interval").Object()
                .Key("lower").Value(43.1)
                .Key("upper").Value(47.3)
                .Key("confidence").Value(0.95)
                .EndObject()
            .Key("percentiles").Object()
                .Key("p50").Value(45.0)
                .Key("p75").Value(46.2)
                .Key("p90").Value(47.1)
                .Key("p95").Value(47.8)
                .Key("p99").Value(48.1)
                .EndObject()
            .EndObject()
            .EndObject();
        
        return json.Build();
    }
    
    // Get comparison data
    static std::string GetComparison(const std::vector<std::string>& backends) {
        JsonBuilder json;
        json.Object()
            .Key("comparison").Array();
        
        // Simulated comparison data
        struct BackendData {
            std::string name;
            double mean_tps;
            double ttft_ms;
            double p95_latency;
            double success_rate;
        };
        
        std::vector<BackendData> data = {
            {"sovereign", 45.2, 120.0, 175.0, 99.9},
            {"ollama", 38.5, 150.0, 220.0, 99.5},
            {"openai", 52.1, 85.0, 120.0, 99.9},
            {"anthropic", 48.7, 95.0, 135.0, 99.8},
            {"vllm", 55.3, 75.0, 110.0, 99.9},
            {"local_gguf", 42.8, 140.0, 195.0, 99.7}
        };
        
        for (const auto& b : data) {
            json.Object()
                .Key("backend").Value(b.name)
                .Key("mean_tps").Value(b.mean_tps)
                .Key("ttft_ms").Value(b.ttft_ms)
                .Key("p95_latency").Value(b.p95_latency)
                .Key("success_rate").Value(b.success_rate)
                .EndObject();
        }
        
        json.EndArray()
            .EndObject();
        
        return json.Build();
    }
    
    // Get trend data
    static std::string GetTrends(const std::string& benchmark_id, int days = 7) {
        JsonBuilder json;
        json.Object()
            .Key("benchmark_id").Value(benchmark_id)
            .Key("period_days").Value(days)
            .Key("trends").Array();
        
        // Generate trend data
        auto now = std::chrono::system_clock::now();
        double base_tps = 42.0;
        
        for (int i = days - 1; i >= 0; --i) {
            auto date = now - std::chrono::hours(24 * i);
            auto time_t = std::chrono::system_clock::to_time_t(date);
            
            // Simulate slight improvement over time
            double tps = base_tps + (days - i) * 0.5 + (rand() % 10) / 10.0;
            
            json.Object()
                .Key("date").Value(FormatDate(time_t))
                .Key("mean_tps").Value(tps)
                .Key("std_dev").Value(2.0 + (rand() % 5) / 10.0)
                .Key("samples").Value(30)
                .EndObject();
        }
        
        json.EndArray()
            .Key("statistics").Object()
                .Key("trend_direction").Value("improving")
                .Key("trend_slope").Value(0.5)
                .Key("volatility").Value(2.1)
                .Key("r_squared").Value(0.85)
                .EndObject()
            .EndObject();
        
        return json.Build();
    }
    
    // Get system metrics
    static std::string GetSystemMetrics() {
        JsonBuilder json;
        json.Object()
            .Key("timestamp").Value(GetCurrentTimestamp())
            .Key("cpu").Object()
                .Key("usage_percent").Value(45.2)
                .Key("cores").Value(16)
                .Key("frequency_ghz").Value(3.8)
                .EndObject()
            .Key("memory").Object()
                .Key("total_mb").Value(65536)
                .Key("used_mb").Value(2048)
                .Key("free_mb").Value(63488)
                .Key("usage_percent").Value(3.1)
                .EndObject()
            .Key("gpu").Object()
                .Key("available").Value(true)
                .Key("name").Value("NVIDIA RTX 4090")
                .Key("memory_total_mb").Value(24576)
                .Key("memory_used_mb").Value(8192)
                .Key("usage_percent").Value(78.5)
                .Key("temperature_c").Value(65)
                .EndObject()
            .Key("disk").Object()
                .Key("total_gb").Value(2000)
                .Key("used_gb").Value(450)
                .Key("free_gb").Value(1550)
                .EndObject()
            .Key("network").Object()
                .Key("connections_active").Value(12)
                .Key("bytes_sent").Value(1024000)
                .Key("bytes_received").Value(2048000)
                .EndObject()
            .Key("benchmarks").Object()
                .Key("active").Value(2)
                .Key("queued").Value(0)
                .Key("completed").Value(156)
                .EndObject()
            .EndObject();
        
        return json.Build();
    }
    
    // Get historical runs
    static std::string GetHistoricalRuns(int limit = 50) {
        JsonBuilder json;
        json.Object()
            .Key("runs").Array();
        
        // Simulated historical runs
        for (int i = 0; i < limit; ++i) {
            json.Object()
                .Key("id").Value("run_" + std::to_string(1000 + i))
                .Key("timestamp").Value(GetCurrentTimestamp())
                .Key("benchmark_count").Value(26)
                .Key("status").Value(i < 5 ? "running" : "completed")
                .Key("duration_seconds").Value(300 + i * 10)
                .EndObject();
        }
        
        json.EndArray()
            .Key("total_count").Value(limit)
            .EndObject();
        
        return json.Build();
    }
    
    // Get regression report
    static std::string GetRegressionReport(const std::string& baseline_id,
                                              const std::string& current_id) {
        JsonBuilder json;
        json.Object()
            .Key("baseline_id").Value(baseline_id)
            .Key("current_id").Value(current_id)
            .Key("generated_at").Value(GetCurrentTimestamp())
            .Key("summary").Object()
                .Key("total_benchmarks").Value(26)
                .Key("regressions").Value(2)
                .Key("improvements").Value(5)
                .Key("unchanged").Value(19)
                .EndObject()
            .Key("regressions").Array()
                .Object()
                    .Key("benchmark_id").Value("inference_tps")
                    .Key("baseline_value").Value(45.2)
                    .Key("current_value").Value(42.1)
                    .Key("change_percent").Value(-6.9)
                    .Key("severity").Value("medium")
                    .EndObject()
                .EndArray()
            .Key("improvements").Array()
                .Object()
                    .Key("benchmark_id").Value("context_scaling")
                    .Key("baseline_value").Value(38.5)
                    .Key("current_value").Value(41.2)
                    .Key("change_percent").Value(7.0)
                    .EndObject()
                .EndArray()
            .EndObject();
        
        return json.Build();
    }

private:
    static void AddBenchmark(JsonBuilder& json, const std::string& id,
                              const std::string& name, int tier,
                              const std::string& category) {
        json.Object()
            .Key("id").Value(id)
            .Key("name").Value(name)
            .Key("tier").Value(tier)
            .Key("category").Value(category)
            .Key("description").Value("Benchmark " + name)
            .EndObject();
    }
    
    static std::string GetCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        return FormatDate(time_t);
    }
    
    static std::string FormatDate(time_t time) {
        char buffer[20];
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&time));
        return std::string(buffer);
    }
};

// API Router
class APIRouter {
public:
    using Handler = std::function<std::string(const std::map<std::string, std::string>&)>;
    
    void Register(const std::string& path, Handler handler) {
        handlers_[path] = handler;
    }
    
    std::string Handle(const std::string& path,
                       const std::map<std::string, std::string>& params) {
        auto it = handlers_.find(path);
        if (it != handlers_.end()) {
            return it->second(params);
        }
        return R"({"error": "Not Found", "path": ")" + path + "\"}";
    }
    
    void RegisterDefaultRoutes() {
        // Benchmarks
        Register("/api/benchmarks", [](const auto&) {
            return DataAPI::GetBenchmarks();
        });
        
        // Benchmark results
        Register("/api/benchmarks/:id/results", [](const auto& params) {
            auto it = params.find("id");
            if (it != params.end()) {
                return DataAPI::GetBenchmarkResults(it->second);
            }
            return std::string(R"({"error": "Missing benchmark ID"})");
        });
        
        // Comparison
        Register("/api/compare", [](const auto&) {
            return DataAPI::GetComparison({});
        });
        
        // Trends
        Register("/api/trends", [](const auto& params) {
            std::string benchmark_id = "inference_tps";
            int days = 7;
            
            auto it = params.find("benchmark_id");
            if (it != params.end()) benchmark_id = it->second;
            
            it = params.find("days");
            if (it != params.end()) days = std::stoi(it->second);
            
            return DataAPI::GetTrends(benchmark_id, days);
        });
        
        // System metrics
        Register("/api/system", [](const auto&) {
            return DataAPI::GetSystemMetrics();
        });
        
        // Historical runs
        Register("/api/runs", [](const auto& params) {
            int limit = 50;
            auto it = params.find("limit");
            if (it != params.end()) limit = std::stoi(it->second);
            return DataAPI::GetHistoricalRuns(limit);
        });
        
        // Regression report
        Register("/api/regression", [](const auto& params) {
            std::string baseline = "baseline";
            std::string current = "current";
            
            auto it = params.find("baseline");
            if (it != params.end()) baseline = it->second;
            
            it = params.find("current");
            if (it != params.end()) current = it->second;
            
            return DataAPI::GetRegressionReport(baseline, current);
        });
        
        // Health check
        Register("/api/health", [](const auto&) {
            return R"({"status": "ok", "timestamp": ")" + 
                   DataAPI::GetSystemMetrics().substr(0, 50) + "\"}";
        });
    }

private:
    std::map<std::string, Handler> handlers_;
};

} // namespace Dashboard
} // namespace Benchmark
