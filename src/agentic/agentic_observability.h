#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <memory>
#include <atomic>
#include <mutex>
#include <thread>
#include <queue>
#include <functional>
#include <string_view>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace Agentic {

struct LogEntry {
    std::chrono::system_clock::time_point timestamp;
    std::string component;
    std::string level;
    std::string message;
    std::map<std::string, std::string> labels;
};

struct MetricPoint {
    std::chrono::system_clock::time_point timestamp;
    std::string name;
    double value;
    std::map<std::string, std::string> labels;
};

struct Span {
    std::string traceId;
    std::string spanId;
    std::string parentSpanId;
    std::string operationName;
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point endTime;
    std::map<std::string, std::string> tags;
    bool finished = false;
};

class AgenticObservability {
public:
    AgenticObservability() = default;
    ~AgenticObservability() = default;

    // Deleted copy/assign to prevent copying of thread-safe internal state
    AgenticObservability(const AgenticObservability&) = delete;
    AgenticObservability& operator=(const AgenticObservability&) = delete;
    AgenticObservability(AgenticObservability&&) = default;
    AgenticObservability& operator=(AgenticObservability&&) = default;

    void log(const std::string& level, const std::string& component, 
             const std::string& message, 
             const std::map<std::string, std::string>& labels = {});

    void recordMetric(const std::string& name, double value, 
                      const std::map<std::string, std::string>& labels = {});

    std::string startSpan(const std::string& operationName, 
                          const std::string& parentSpanId = "");

    void endSpan(const std::string& spanId);

    void recordAnomaly(const std::string& description);

    void setSamplingRate(float rate);

    // Observability data access
    std::vector<LogEntry> getLogs(size_t limit = 100) const;
    std::vector<MetricPoint> getMetrics(size_t limit = 100) const;
    std::vector<Span> getSpans(size_t limit = 100) const;

    // Trace utilities
    std::string generateTraceId();
    std::string generateSpanId();

private:
    struct LogEntry {
        std::chrono::system_clock::time_point timestamp;
        std::string level;
        std::string component;
        std::string message;
        std::map<std::string, std::string> labels;
    };

    struct MetricPoint {
        std::chrono::system_clock::time_point timestamp;
        std::string name;
        double value;
        std::map<std::string, std::string> labels;
    };

    struct Span {
        std::string traceId;
        std::string spanId;
        std::string parentSpanId;
        std::string operationName;
        std::chrono::system_clock::time_point startTime;
        std::chrono::system_clock::time_point endTime;
        std::map<std::string, std::string> tags;
        bool finished = false;
    };

    mutable std::mutex m_mutex;
    std::vector<LogEntry> m_logs;
    std::vector<MetricPoint> m_metrics;
    std::vector<Span> m_spans;
    std::atomic<float> m_samplingRate{1.0f};
    std::atomic<uint64_t> m_traceIdCounter{0};
    std::atomic<uint64_t> m_spanIdCounter{0};
    std::map<std::string, Span> m_activeSpans;
};

} // namespace RawrXD::Agentic

#endif // RAW_RXD_AGENTIC_OBSERVABILITY_H