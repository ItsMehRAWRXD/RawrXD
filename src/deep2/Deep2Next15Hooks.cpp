#include "Deep2Next15Hooks.hpp"

#include <cstdlib>
#include <map>
#include <mutex>

namespace deep2::next15 {
namespace {

rawrxd::next15::Counters g_counters;
std::once_flag g_receipt_registration;

bool envEnabled(const char* name) noexcept {
    const char* value = std::getenv(name);
    return value && value[0] == '1';
}

std::string envOr(const char* name, const char* fallback) {
    const char* value = std::getenv(name);
    return value && value[0] ? value : fallback;
}

void writeAtExit() {
    const std::string path = envOr("RAWRXD_NEXT15_RECEIPT", "");
    if (path.empty()) return;

    rawrxd::next15::RunConfig config;
    config.model = envOr("RAWRXD_NEXT15_MODEL", "unknown");
    config.model_hash = envOr("RAWRXD_NEXT15_MODEL_HASH", "unknown");
    config.git_revision = envOr("RAWRXD_NEXT15_GIT_REVISION", "unknown");
    config.quant = envOr("RAWRXD_NEXT15_QUANT", "unknown");
    config.backend = envOr("RAWRXD_NEXT15_BACKEND", "deep2");
    config.context = static_cast<std::uint32_t>(std::strtoul(
        envOr("RAWRXD_NEXT15_CONTEXT", "0").c_str(), nullptr, 10));
    config.gpu_index = static_cast<std::uint32_t>(std::strtoul(
        envOr("RAWRXD_NEXT15_GPU", "0").c_str(), nullptr, 10));

    const auto view = rawrxd::next15::read(g_counters);
    std::map<std::string, rawrxd::next15::Stage> stages;
    std::map<std::string, rawrxd::next15::Result> gates;
    gates.emplace("production_gpu", rawrxd::next15::Result::fail(
        "NOT_RUN: independent before/after parity is required"));
    gates.emplace("runtime_hooks",
        view.gpu_submits > 0 && view.gpu_layers > 0
            ? rawrxd::next15::Result::ok()
            : rawrxd::next15::Result::fail("NOT_RUN: no completed GPU work observed"));
    (void)rawrxd::next15::write_receipt(path, config, view, stages, gates);
}

void registerReceipt() noexcept {
    if (enabled()) {
        std::call_once(g_receipt_registration, [] {
            std::atexit(writeAtExit);
        });
    }
}

}

bool enabled() noexcept {
    return envEnabled("RAWRXD_NEXT15");
}

void initialize() noexcept {
    if (enabled()) {
        (void)counters();
    }
}

rawrxd::next15::Counters& counters() noexcept {
    registerReceipt();
    return g_counters;
}

void reset() noexcept {
    if (!enabled()) return;
    g_counters.pipeline_creates.store(0, std::memory_order_relaxed);
    g_counters.gpu_submits.store(0, std::memory_order_relaxed);
    g_counters.gpu_gemv.store(0, std::memory_order_relaxed);
    g_counters.gpu_gemm.store(0, std::memory_order_relaxed);
    g_counters.gpu_layers.store(0, std::memory_order_relaxed);
    g_counters.cpu_fallbacks.store(0, std::memory_order_relaxed);
    g_counters.strict_violations.store(0, std::memory_order_relaxed);
    g_counters.host_upload_bytes.store(0, std::memory_order_relaxed);
    g_counters.residency_hits.store(0, std::memory_order_relaxed);
    g_counters.residency_misses.store(0, std::memory_order_relaxed);
    g_counters.generated_tokens.store(0, std::memory_order_relaxed);
    registerReceipt();
}

void on_gpu_submit(std::uint64_t upload_bytes) noexcept {
    if (enabled()) rawrxd::next15::on_gpu_submit(counters(), upload_bytes);
}

void on_gpu_kernel(bool gemm) noexcept {
    if (enabled()) rawrxd::next15::on_gpu_kernel(counters(), gemm);
}

void on_gpu_layer_complete() noexcept {
    if (enabled()) rawrxd::next15::on_gpu_layer_complete(counters());
}

void on_cpu_fallback() noexcept {
    if (enabled()) rawrxd::next15::on_cpu_fallback(counters());
}

rawrxd::next15::CounterView snapshot() noexcept {
    return rawrxd::next15::read(counters());
}

rawrxd::next15::Result write_runtime_receipt(
    const std::filesystem::path& path,
    std::string_view model,
    std::string_view backend,
    std::uint32_t context,
    std::uint32_t gpu_index) noexcept {
    if (!enabled()) return rawrxd::next15::Result::fail("RAWRXD_NEXT15 is disabled");
    rawrxd::next15::RunConfig config;
    config.model = std::string(model);
    config.backend = std::string(backend);
    config.context = context;
    config.gpu_index = gpu_index;
    const auto view = snapshot();
    std::map<std::string, rawrxd::next15::Stage> stages;
    std::map<std::string, rawrxd::next15::Result> gates;
    gates.emplace("production_gpu", rawrxd::next15::Result::fail(
        "NOT_RUN: independent before/after parity is required"));
    gates.emplace("runtime_hooks",
        view.gpu_submits > 0 && view.gpu_layers > 0
            ? rawrxd::next15::Result::ok()
            : rawrxd::next15::Result::fail("NOT_RUN: no completed GPU work observed"));
    return rawrxd::next15::write_receipt(path, config, view, stages, gates);
}

}
