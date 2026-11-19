#pragma once
// Three-way Q4_K GEMV acceptance contract. Backend adapters provide actual
// measurements; this harness never fabricates timing, I/O, or parity results.
#include <cmath>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace RawrXD::LTT::Bench {
enum class Mode { Resident, NaiveStream, TileStream };

struct Metrics {
    bool executed = false;
    bool gpu_completed = false;
    uint64_t peak_device_bytes = 0;
    uint64_t physical_read_bytes = 0; // block-device delta, NOT logical read()
    uint64_t staging_reuses = 0;
    uint64_t lifetime_stalls = 0;
    double read_ms = std::numeric_limits<double>::quiet_NaN();
    double stage_ms = std::numeric_limits<double>::quiet_NaN();
    double compute_ms = std::numeric_limits<double>::quiet_NaN();
    double wall_ms = std::numeric_limits<double>::quiet_NaN();
    std::vector<float> output;
};

struct Backend {
    virtual ~Backend() = default;
    virtual Metrics run(Mode mode, const std::vector<float>& input) = 0;
};

struct Result {
    Metrics resident, naive, tiled;
    double max_abs_error = std::numeric_limits<double>::quiet_NaN();
    double relative_latency_to_resident = std::numeric_limits<double>::quiet_NaN();
    double relative_latency_to_naive = std::numeric_limits<double>::quiet_NaN();
    bool valid = false;
    bool parity_pass = false;
    bool residency_reduced = false;
    bool streaming_latency_improved = false;
};

inline void require_valid(const Metrics& m, size_t output_size) {
    if (!m.executed || !m.gpu_completed || m.output.size() != output_size ||
        output_size == 0 || !std::isfinite(m.wall_ms) || m.wall_ms <= 0 ||
        !std::isfinite(m.read_ms) || !std::isfinite(m.stage_ms) ||
        !std::isfinite(m.compute_ms) || m.read_ms < 0 ||
        m.stage_ms < 0 || m.compute_ms < 0 ||
        m.peak_device_bytes == 0)
        throw std::runtime_error("LTT benchmark missing or invalid measurements");
    for (float x : m.output)
        if (!std::isfinite(x)) throw std::runtime_error("nonfinite GEMV output");
}

inline Result compare(Backend& backend, const std::vector<float>& input,
                      double max_allowed_abs_error) {
    if (input.empty() || !std::isfinite(max_allowed_abs_error) ||
        max_allowed_abs_error < 0)
        throw std::invalid_argument("invalid LTT benchmark parameters");
    Result r;
    r.resident = backend.run(Mode::Resident, input);
    r.naive = backend.run(Mode::NaiveStream, input);
    r.tiled = backend.run(Mode::TileStream, input);
    const auto n = r.resident.output.size();
    require_valid(r.resident, n);
    require_valid(r.naive, n);
    require_valid(r.tiled, n);
    double error = 0;
    for (size_t i = 0; i < n; ++i) {
        error = std::max(error, std::abs(double(r.resident.output[i]) -
                                         double(r.naive.output[i])));
        error = std::max(error, std::abs(double(r.resident.output[i]) -
                                         double(r.tiled.output[i])));
    }
    r.max_abs_error = error;
    r.relative_latency_to_resident = r.tiled.wall_ms / r.resident.wall_ms;
    r.relative_latency_to_naive = r.tiled.wall_ms / r.naive.wall_ms;
    r.parity_pass = error <= max_allowed_abs_error;
    r.residency_reduced = r.tiled.peak_device_bytes < r.resident.peak_device_bytes;
    r.streaming_latency_improved = r.tiled.wall_ms < r.naive.wall_ms;
    r.valid = true;
    return r;
}
} // namespace RawrXD::LTT::Bench
