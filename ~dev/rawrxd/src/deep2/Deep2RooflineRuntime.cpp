#include "Deep2RooflineRuntime.hpp"

namespace Deep2::Roofline {

Runtime::Runtime() : Runtime(Config{}) {}
Runtime::Runtime(const Config& c)
    : cfg_(c), residency_{ExpertResidency(c.residencyBytes[0]), ExpertResidency(c.residencyBytes[1])}, governor_(c.hardware) {}

void Runtime::beginModel(u64 generation) {
    persistent_.beginModel(generation);
    residency_[0].reset(cfg_.residencyBytes[0]);
    residency_[1].reset(cfg_.residencyBytes[1]);
    predictor_.reset();
    balancer_.reset();
    tokens_.clear();
}

GovernorDecision Runtime::beginToken(u64 tokenIndex, u32 rows, u64 bytesPerToken, double teraOpsPerToken) {
    currentToken_ = tokenIndex;
    persistent_.beginToken(tokenIndex);
    const TokenMetrics* prev = tokens_.empty() ? nullptr : &tokens_.back();
    auto d = governor_.decide(rows, bytesPerToken, teraOpsPerToken, prev);
    const auto adaptive = balancer_.plan(rows);
    if (balancer_.rate(0) > 0.0 && balancer_.rate(1) > 0.0) d.split = adaptive;
    return d;
}

void Runtime::observeRoute(u32 layer, const std::vector<u32>& experts, u64 expertBytes, u64 tokenIndex) {
    predictor_.observe(layer, experts);
    // Stable hash-stick assignment. Avoid token-dependent device migration.
    for (u32 e : experts) {
        const unsigned gpu = static_cast<unsigned>((static_cast<u64>(layer) * 0x9E3779B185EBCA87ull + e) & 1ull);
        residency_[gpu].ensure({layer, e}, expertBytes, tokenIndex);
    }
}

bool Runtime::prefetchPredicted(u32 layer, u64 expertBytes) {
    if (!backend_.prefetchExpert) return false;
    bool ok = true;
    for (u32 e : predictor_.predict(layer, cfg_.prefetchExpertsPerLayer)) {
        const unsigned gpu = static_cast<unsigned>((static_cast<u64>(layer) * 0x9E3779B185EBCA87ull + e) & 1ull);
        if (!residency_[gpu].contains({layer, e})) {
            ok = backend_.prefetchExpert(backend_.user, gpu, layer, e, expertBytes) && ok;
            residency_[gpu].ensure({layer, e}, expertBytes, currentToken_);
        }
    }
    return ok;
}

bool Runtime::submit(const CommandBatch& batch) {
    if (!backend_.submitBatch) return false;
    bool ok = true;
    for (unsigned gpu = 0; gpu < 2; ++gpu) {
        std::vector<KernelOp> local;
        local.reserve(batch.gpuOps(gpu));
        for (const auto& op : batch.ops()) if (op.gpu == gpu) local.push_back(op);
        if (!local.empty()) {
            persistent_.noteForward(gpu);
            ok = backend_.submitBatch(backend_.user, gpu, local.data(), local.size()) && ok;
        }
    }
    return ok;
}

bool Runtime::waitBoth() {
    if (!backend_.waitGpu) return false;
    const bool a = backend_.waitGpu(backend_.user, 0);
    const bool b = backend_.waitGpu(backend_.user, 1);
    return a && b;
}

void Runtime::endToken(TokenMetrics m) {
    m.tokenIndex = currentToken_;
    balancer_.update(0, m.gpu[0]);
    balancer_.update(1, m.gpu[1]);
    persistent_.endToken();
    tokens_.push_back(m);
}

CertResult Runtime::certify(u64 bytesPerToken, double teraOpsPerToken) const {
    const auto est = EstimateRoofline(cfg_.hardware, bytesPerToken, teraOpsPerToken);
    return Certify(tokens_, cfg_.cert, est.rooflineTps);
}

} // namespace Deep2::Roofline
