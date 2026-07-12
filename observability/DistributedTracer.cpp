#include "observability/DistributedTracer.hpp"
#include <mutex>
#include <map>
#include <chrono>
#include <sstream>

static std::mutex s_mutex;
static bool s_initialized = false;

struct Span {
    std::string name;
    int64_t duration_us;
    int64_t timestamp;
};

struct Trace {
    std::string traceId;
    std::string operation;
    int64_t startTime;
    int64_t endTime;
    bool active;
    std::vector<Span> spans;
    std::map<std::string, std::string> tags;
    std::vector<std::string> errors;
};

static std::map<std::string, Trace> s_traces;
static std::vector<std::string> s_traceHistory;
static size_t s_traceCounter = 0;

static std::string GenerateTraceId() {
    s_traceCounter++;
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    std::stringstream ss;
    ss << "trace-" << now << "-" << s_traceCounter;
    return ss.str();
}

void DistributedTracer::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_traces.clear();
        s_traceHistory.clear();
        s_traceCounter = 0;
        s_initialized = true;
    }
}

void DistributedTracer::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Clean up old completed traces
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    std::vector<std::string> toRemove;
    for (const auto& [id, trace] : s_traces) {
        if (!trace.active && (now - trace.endTime) > 36000000000) { // 1 hour
            toRemove.push_back(id);
        }
    }
    for (const auto& id : toRemove) {
        s_traces.erase(id);
    }
}

bool DistributedTracer::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

std::string DistributedTracer::StartTrace(const std::string& operation) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return "";
    
    std::string traceId = GenerateTraceId();
    Trace trace;
    trace.traceId = traceId;
    trace.operation = operation;
    trace.startTime = std::chrono::system_clock::now().time_since_epoch().count();
    trace.active = true;
    
    s_traces[traceId] = trace;
    s_traceHistory.push_back(traceId);
    
    // Keep history bounded
    if (s_traceHistory.size() > 1000) {
        s_traceHistory.erase(s_traceHistory.begin(), s_traceHistory.begin() + 100);
    }
    
    return traceId;
}

void DistributedTracer::EndTrace(const std::string& traceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto it = s_traces.find(traceId);
    if (it != s_traces.end()) {
        it->second.endTime = std::chrono::system_clock::now().time_since_epoch().count();
        it->second.active = false;
    }
}

void DistributedTracer::AddSpan(const std::string& traceId, const std::string& spanName, int64_t duration_us) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto it = s_traces.find(traceId);
    if (it != s_traces.end()) {
        Span span;
        span.name = spanName;
        span.duration_us = duration_us;
        span.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
        it->second.spans.push_back(span);
    }
}

void DistributedTracer::AddTag(const std::string& traceId, const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto it = s_traces.find(traceId);
    if (it != s_traces.end()) {
        it->second.tags[key] = value;
    }
}

void DistributedTracer::AddError(const std::string& traceId, const std::string& error) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto it = s_traces.find(traceId);
    if (it != s_traces.end()) {
        it->second.errors.push_back(error);
    }
}

nlohmann::json DistributedTracer::GetTrace(const std::string& traceId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_traces.find(traceId);
    if (it != s_traces.end()) {
        const Trace& trace = it->second;
        nlohmann::json spans = nlohmann::json::array();
        for (const auto& span : trace.spans) {
            spans.push_back({
                {"name", span.name},
                {"duration_us", span.duration_us},
                {"timestamp", span.timestamp}
            });
        }
        
        return {
            {"trace_id", trace.traceId},
            {"operation", trace.operation},
            {"start_time", trace.startTime},
            {"end_time", trace.endTime},
            {"active", trace.active},
            {"spans", spans},
            {"tags", trace.tags},
            {"errors", trace.errors}
        };
    }
    return nlohmann::json{};
}

nlohmann::json DistributedTracer::GetActiveTraces() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& [id, trace] : s_traces) {
        if (trace.active) {
            result.push_back({
                {"trace_id", trace.traceId},
                {"operation", trace.operation},
                {"start_time", trace.startTime},
                {"span_count", trace.spans.size()}
            });
        }
    }
    return result;
}

nlohmann::json DistributedTracer::GetTraceHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& traceId : s_traceHistory) {
        auto it = s_traces.find(traceId);
        if (it != s_traces.end()) {
            result.push_back({
                {"trace_id", it->second.traceId},
                {"operation", it->second.operation},
                {"active", it->second.active}
            });
        }
    }
    return result;
}

void DistributedTracer::ClearTraceHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_traceHistory.clear();
}
