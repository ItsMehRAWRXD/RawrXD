#include "rawrxd/closure/PerformanceLedger.hpp"
#include <algorithm>
#include <fstream>
#include <sstream>

namespace rawrxd::closure {
namespace {
double tps(const PerformanceSample& x) {
    return x.elapsed_us && x.generated_tokens
        ? (static_cast<double>(x.generated_tokens) * 1'000'000.0) / static_cast<double>(x.elapsed_us)
        : 0.0;
}
double percentile(std::vector<double> v, double q) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const double pos = q * static_cast<double>(v.size() - 1);
    const size_t lo = static_cast<size_t>(pos);
    const size_t hi = std::min(v.size() - 1, lo + 1);
    const double f = pos - static_cast<double>(lo);
    return v[lo] * (1.0 - f) + v[hi] * f;
}
}

bool PerformanceLedger::append(const PerformanceSample& s, std::string* error) const {
    std::error_code ec;
    if (!path_.parent_path().empty()) std::filesystem::create_directories(path_.parent_path(), ec);
    std::ofstream out(path_, std::ios::app);
    if (!out) { if (error) *error = "cannot open performance ledger"; return false; }
    out << s.model_id << '\t' << s.device_key << '\t' << s.model_fingerprint << '\t'
        << s.prompt_tokens << '\t' << s.generated_tokens << '\t' << s.elapsed_us << '\t'
        << (s.strict ? 1 : 0) << '\t' << (s.passed ? 1 : 0) << '\n';
    return static_cast<bool>(out);
}

std::vector<PerformanceSample> PerformanceLedger::load(std::string* error) const {
    std::vector<PerformanceSample> out;
    std::ifstream in(path_);
    if (!in) return out; // empty ledger is valid
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        PerformanceSample x;
        std::string fp, pt, gt, us, strict, passed;
        if (!std::getline(ss, x.model_id, '\t') || !std::getline(ss, x.device_key, '\t') ||
            !std::getline(ss, fp, '\t') || !std::getline(ss, pt, '\t') ||
            !std::getline(ss, gt, '\t') || !std::getline(ss, us, '\t') ||
            !std::getline(ss, strict, '\t') || !std::getline(ss, passed, '\t')) continue;
        try {
            x.model_fingerprint = std::stoull(fp);
            x.prompt_tokens = static_cast<uint32_t>(std::stoul(pt));
            x.generated_tokens = static_cast<uint32_t>(std::stoul(gt));
            x.elapsed_us = std::stoull(us);
            x.strict = strict == "1";
            x.passed = passed == "1";
            out.push_back(std::move(x));
        } catch (...) {
            if (error) *error = "ignored malformed ledger row";
        }
    }
    return out;
}

std::vector<MeasuredPerformanceProfile> PerformanceLedger::summarize(uint32_t min_cert_samples) const {
    auto rows = load();
    struct Bucket { std::string model, dev; std::vector<double> tpsv; uint32_t strict_pass{}; };
    std::vector<Bucket> buckets;
    for (const auto& s : rows) {
        if (!s.passed || tps(s) <= 0.0) continue;
        auto it = std::find_if(buckets.begin(), buckets.end(), [&](const Bucket& b){
            return b.model == s.model_id && b.dev == s.device_key;
        });
        if (it == buckets.end()) {
            buckets.push_back({s.model_id, s.device_key, {}, 0});
            it = std::prev(buckets.end());
        }
        it->tpsv.push_back(tps(s));
        if (s.strict) ++it->strict_pass;
    }
    std::vector<MeasuredPerformanceProfile> out;
    for (auto& b : buckets) {
        out.push_back({
            b.model, b.dev, percentile(b.tpsv, .50), percentile(b.tpsv, .10),
            static_cast<uint32_t>(b.tpsv.size()), b.strict_pass >= min_cert_samples
        });
    }
    return out;
}

} // namespace rawrxd::closure
