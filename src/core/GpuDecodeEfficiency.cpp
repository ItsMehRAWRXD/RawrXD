// GpuDecodeEfficiency.cpp — single writer for inference.tokens_per_watt_gpu
#include "GpuDecodeEfficiency.hpp"
#include "../config/IDEConfig.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace rawrxd {
namespace {

static void DbgLog(const char* loc, const char* msg, const std::string& dataJson) {
    // #region agent log
    std::ofstream f("f:\\~dev\\debug-536900.log", std::ios::app);
    if (!f) return;
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    f << "{\"sessionId\":\"536900\",\"timestamp\":" << ms
      << ",\"location\":\"" << loc << "\",\"message\":\"" << msg
      << "\",\"data\":" << dataJson << ",\"hypothesisId\":\"TPW\"}\n";
    // #endregion
}

static const char* EvidenceRoot() noexcept {
    const char* e = std::getenv("RAWRXD_EVIDENCE_ROOT");
    return (e && *e) ? e : "f:\\~dev\\rawrxd\\evidence";
}

} // namespace

bool AmdGpuPowerTelemetryAvailable() noexcept {
    return ProbeAmdGpuPowerBackend();
}

GpuDecodeEfficiencySession::GpuDecodeEfficiencySession() noexcept {
    sensor_available_ = GpuPowerSensorReady();
    sensor_source_ = ActiveGpuPowerSensor();
}

GpuDecodeEfficiencySession::~GpuDecodeEfficiencySession() = default;

void GpuDecodeEfficiencySession::AppendPowerSample(uint64_t qpc) noexcept {
#ifdef _WIN32
    if (!sensor_available_) return;
    double w = 0.0;
    if (!SampleAmdGpuPowerWatts(w)) return;
    std::lock_guard<std::mutex> lk(samples_mu_);
    samples_.emplace_back(qpc, w);
    last_sample_qpc_ = qpc;
#endif
}

void GpuDecodeEfficiencySession::SampleDuringDecode() noexcept {
#ifdef _WIN32
    if (!sensor_available_ || qpc_freq_ == 0) return;
    LARGE_INTEGER q{};
    QueryPerformanceCounter(&q);
    const uint64_t now = static_cast<uint64_t>(q.QuadPart);
    const uint64_t minDelta = qpc_freq_ / 20;
    if (last_sample_qpc_ != 0 && now - last_sample_qpc_ < minDelta) return;
    AppendPowerSample(now);
#endif
}

void GpuDecodeEfficiencySession::BeginDecodeWindow() noexcept {
    result_.reset();
    samples_.clear();
    last_sample_qpc_ = 0;
#ifdef _WIN32
    LARGE_INTEGER f{}, q{};
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&q);
    qpc_freq_ = static_cast<uint64_t>(f.QuadPart);
    window_start_qpc_ = static_cast<uint64_t>(q.QuadPart);
    window_end_qpc_ = 0;
    sensor_available_ = GpuPowerSensorReady();
    sensor_source_ = ActiveGpuPowerSensor();
    if (sensor_available_)
        AppendPowerSample(window_start_qpc_);
    DbgLog("GpuDecodeEfficiency.cpp:BeginDecodeWindow", "decode_window_open",
           std::string("{\"sensor_available\":") +
           (sensor_available_ ? "true" : "false") +
           ",\"sensor\":\"" + GpuPowerSensorSourceName(sensor_source_) + "\"}");
#endif
}

GpuDecodeEfficiencyResult GpuDecodeEfficiencySession::Finalize(
    uint64_t tokens_generated) noexcept {
    GpuDecodeEfficiencyResult r{};
    r.tokens_generated = tokens_generated;
    r.sensor_source = sensor_source_;
#ifdef _WIN32
    LARGE_INTEGER q{};
    QueryPerformanceCounter(&q);
    window_end_qpc_ = static_cast<uint64_t>(q.QuadPart);
    r.qpc_window_start = window_start_qpc_;
    r.qpc_window_end = window_end_qpc_;
    AppendPowerSample(window_end_qpc_);
    if (window_end_qpc_ > window_start_qpc_ && qpc_freq_ > 0)
        r.window_seconds = static_cast<double>(window_end_qpc_ - window_start_qpc_) /
                           static_cast<double>(qpc_freq_);
    if (r.window_seconds > 0.0 && tokens_generated > 0)
        r.decode_tps = static_cast<double>(tokens_generated) / r.window_seconds;
    double sum = 0.0;
    uint32_t n = 0;
    {
        std::lock_guard<std::mutex> lk(samples_mu_);
        for (const auto& s : samples_) {
            if (s.first < window_start_qpc_ || s.first > window_end_qpc_) continue;
            sum += s.second;
            ++n;
        }
    }
    r.power_sample_count = n;
    if (sensor_available_ && n > 0) {
        r.average_gpu_watts = sum / static_cast<double>(n);
        r.power_valid = (r.average_gpu_watts > 0.0);
        if (r.power_valid && r.decode_tps > 0.0)
            r.tokens_per_watt_gpu = r.decode_tps / r.average_gpu_watts;
    }
#endif
    result_ = r;
    DbgLog("GpuDecodeEfficiency.cpp:Finalize", "gpu_decode_efficiency",
           std::string("{\"power_valid\":") + (r.power_valid ? "true" : "false") +
           ",\"sensor\":\"" + GpuPowerSensorSourceName(r.sensor_source) +
           "\",\"decode_tps\":" + std::to_string(r.decode_tps) +
           ",\"avg_w\":" + std::to_string(r.average_gpu_watts) +
           ",\"tpw\":" + std::to_string(r.tokens_per_watt_gpu) +
           ",\"samples\":" + std::to_string(n) + "}");
    return r;
}

GpuDecodeEfficiencyResult GpuDecodeEfficiencySession::result() const noexcept {
    return result_.value_or(GpuDecodeEfficiencyResult{});
}

GpuDecodeEfficiencyAuthority& GpuDecodeEfficiencyAuthority::Instance() noexcept {
    static GpuDecodeEfficiencyAuthority inst;
    return inst;
}

void GpuDecodeEfficiencyAuthority::BeginDecodeWindow() noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    session_.BeginDecodeWindow();
}

void GpuDecodeEfficiencyAuthority::SampleDuringDecode() noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    session_.SampleDuringDecode();
}

GpuDecodeEfficiencyResult GpuDecodeEfficiencyAuthority::EndAndPublish(
    uint64_t tokens_generated) noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    last_ = session_.Finalize(tokens_generated);
    PublishGpuDecodeEfficiency(last_);
    WriteCertificationEvidence();
    return last_;
}

const GpuDecodeEfficiencyResult& GpuDecodeEfficiencyAuthority::Last() const noexcept {
    return last_;
}

bool GpuDecodeEfficiencyAuthority::PowerValidForPolicy() const noexcept {
    return last_.power_valid;
}

void GpuDecodeEfficiencyAuthority::WriteCertificationEvidence() const noexcept {
    char path[512];
    std::snprintf(path, sizeof(path),
                  "%s\\P1_PRODUCT_RUNTIME_AUTHORITY_002\\gpu_decode_efficiency.ndjson",
                  EvidenceRoot());
    std::ofstream f(path, std::ios::app);
    if (!f) return;
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    f << "{\"ts_ms\":" << ms
      << ",\"sensor_source\":\"" << GpuPowerSensorSourceName(last_.sensor_source) << "\""
      << ",\"power_valid\":" << (last_.power_valid ? "true" : "false")
      << ",\"power_sample_count\":" << last_.power_sample_count
      << ",\"window_seconds\":" << last_.window_seconds
      << ",\"qpc_start\":" << last_.qpc_window_start
      << ",\"qpc_end\":" << last_.qpc_window_end
      << ",\"decode_tps\":" << last_.decode_tps
      << ",\"average_gpu_watts\":" << last_.average_gpu_watts
      << ",\"tokens_per_watt_gpu\":" << last_.tokens_per_watt_gpu
      << ",\"tokens_generated\":" << last_.tokens_generated << "}\n";
}

void PublishGpuDecodeEfficiency(const GpuDecodeEfficiencyResult& r) noexcept {
    auto& m = METRICS;
    m.gauge("inference.gpu_power_valid", r.power_valid ? 1.0 : 0.0);
    if (!r.power_valid) {
        ClearGpuDecodeEfficiencyMetrics();
        return;
    }
    m.gauge("inference.decode_tps", r.decode_tps);
    m.gauge("inference.avg_gpu_power_watts", r.average_gpu_watts);
    m.gauge("inference.tokens_per_watt_gpu", r.tokens_per_watt_gpu);
    m.gauge("inference.gpu_power_sample_count",
            static_cast<double>(r.power_sample_count));
}

void ClearGpuDecodeEfficiencyMetrics() noexcept {
    auto& m = METRICS;
    m.gauge("inference.avg_gpu_power_watts", -1.0);
    m.gauge("inference.tokens_per_watt_gpu", -1.0);
    m.gauge("inference.gpu_power_sample_count", -1.0);
}

bool GpuPowerValidForPolicy() noexcept {
    return METRICS.getGauge("inference.gpu_power_valid") >= 1.0;
}

bool TryReadMeasuredGpuPowerWatts(double& watts_out) noexcept {
    return SampleAmdGpuPowerWatts(watts_out);
}

} // namespace rawrxd
