#include "rawrxd/closure/DevicePolicy.hpp"
#include <algorithm>
#include <cctype>
#include <limits>

namespace rawrxd::closure {
namespace {
std::string lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return out;
}
bool contains_ci(std::string_view hay, std::string_view needle) {
    return lower(hay).find(lower(needle)) != std::string::npos;
}
uint64_t required_bytes(const ModelRequirements& m) {
    return m.resident_bytes + m.kv_bytes + m.scratch_bytes;
}
const MeasuredPerformanceProfile* find_profile(
    std::span<const MeasuredPerformanceProfile> p,
    std::string_view model, std::string_view key) {
    const MeasuredPerformanceProfile* best = nullptr;
    for (const auto& x : p) {
        if (x.model_id == model && x.device_key == key && x.samples > 0 &&
            (!best || (x.certified && !best->certified) || x.samples > best->samples))
            best = &x;
    }
    return best;
}
}

std::optional<DeviceSelector> DevicePolicy::parse(std::string_view s) {
    const auto v = lower(s);
    if (v == "auto") return DeviceSelector::auto_select;
    if (v == "r9700" || v == "9700" || v == "gpu0") return DeviceSelector::r9700;
    if (v == "7800xt" || v == "rx7800xt" || v == "7800" || v == "gpu1")
        return DeviceSelector::rx7800xt;
    if (v == "dual" || v == "both") return DeviceSelector::dual;
    return std::nullopt;
}

double DevicePolicy::score_single(
    const DeviceInfo& d,
    const ModelRequirements& model,
    std::span<const MeasuredPerformanceProfile> measured) {

    if (!d.healthy || !d.vulkan || d.free_bytes < required_bytes(model))
        return -std::numeric_limits<double>::infinity();

    const double headroom =
        required_bytes(model) == 0 ? 1.0 :
        static_cast<double>(d.free_bytes) / static_cast<double>(required_bytes(model));

    double tps = 1.0;
    if (const auto* p = find_profile(measured, model.model_id, d.stable_id)) {
        // Bias routing toward repeatable lower-bound throughput, not peak marketing TPS.
        tps = p->certified ? std::max(0.01, p->p10_tps) : std::max(0.01, p->median_tps * 0.75);
    }
    const double memory_bonus = std::min(2.0, headroom) * 0.15;
    return tps * (1.0 + memory_bonus);
}

DevicePlan DevicePolicy::choose(
    DeviceSelector selector,
    const ModelRequirements& model,
    std::span<const DeviceInfo> devices,
    std::span<const MeasuredPerformanceProfile> measured) {

    DevicePlan out;
    auto by_name = [&](std::string_view token) -> const DeviceInfo* {
        for (const auto& d : devices)
            if (contains_ci(d.name, token)) return &d;
        return nullptr;
    };
    auto accept_single = [&](const DeviceInfo* d, std::string_view why) {
        if (!d) { out.reason = "requested adapter not enumerated"; return; }
        if (!d->healthy || !d->vulkan) { out.reason = "requested adapter is unhealthy or lacks Vulkan"; return; }
        if (d->free_bytes < required_bytes(model)) { out.reason = "requested adapter lacks free local memory"; return; }
        out.ok = true;
        out.ordinals = {d->ordinal};
        out.device_key = d->stable_id;
        out.reason = std::string(why);
    };

    if (selector == DeviceSelector::r9700) {
        accept_single(by_name("R9700"), "explicit r9700 selector");
        return out;
    }
    if (selector == DeviceSelector::rx7800xt) {
        auto* d = by_name("7800");
        accept_single(d, "explicit 7800xt selector");
        return out;
    }

    if (selector == DeviceSelector::dual) {
        std::vector<const DeviceInfo*> good;
        for (const auto& d : devices)
            if (d.healthy && d.vulkan) good.push_back(&d);
        if (good.size() < 2) {
            out.reason = "dual requested but fewer than two healthy Vulkan adapters exist";
            return out;
        }
        std::sort(good.begin(), good.end(), [](auto* a, auto* b){ return a->free_bytes > b->free_bytes; });
        if (good[0]->free_bytes + good[1]->free_bytes < required_bytes(model)) {
            out.reason = "dual aggregate free memory is below model requirement";
            return out;
        }
        out.ok = true;
        out.ordinals = {good[0]->ordinal, good[1]->ordinal};
        out.device_key = good[0]->stable_id + "+" + good[1]->stable_id;
        out.reason = "explicit dual selector; Deep2 remains authoritative for layer/tensor placement";
        return out;
    }

    // Auto: prefer a certified single-device route when it fits. Move to dual only
    // when no healthy single device fits or the certified dual lower bound wins.
    const DeviceInfo* best = nullptr;
    double best_score = -std::numeric_limits<double>::infinity();
    for (const auto& d : devices) {
        const double s = score_single(d, model, measured);
        if (s > best_score) { best_score = s; best = &d; }
    }

    double dual_score = -std::numeric_limits<double>::infinity();
    std::vector<const DeviceInfo*> good;
    for (const auto& d : devices)
        if (d.healthy && d.vulkan) good.push_back(&d);
    if (good.size() >= 2) {
        std::sort(good.begin(), good.end(), [](auto* a, auto* b){ return a->free_bytes > b->free_bytes; });
        const std::string key = good[0]->stable_id + "+" + good[1]->stable_id;
        if (good[0]->free_bytes + good[1]->free_bytes >= required_bytes(model)) {
            if (const auto* p = find_profile(measured, model.model_id, key))
                dual_score = p->certified ? p->p10_tps : p->median_tps * 0.75;
        }
    }

    if (dual_score > best_score && good.size() >= 2) {
        out.ok = true;
        out.ordinals = {good[0]->ordinal, good[1]->ordinal};
        out.device_key = good[0]->stable_id + "+" + good[1]->stable_id;
        out.reason = "auto selected certified measured dual route";
        return out;
    }
    if (best) {
        out.ok = true;
        out.ordinals = {best->ordinal};
        out.device_key = best->stable_id;
        out.reason = "auto selected best fitting measured single-device route";
        return out;
    }
    out.reason = "no healthy device plan satisfies model memory requirements";
    return out;
}

} // namespace rawrxd::closure
