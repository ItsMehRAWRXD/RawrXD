#pragma once
#include "Deep2CommandBatch.hpp"
#include "Deep2ExpertResidency.hpp"
#include "Deep2PersistentDecode.hpp"
#include "Deep2PredictiveRouter.hpp"
#include "Deep2RooflineGovernor.hpp"
#include "Deep2RooflineCert.hpp"

namespace Deep2::Roofline {

class Runtime {
public:
    struct Config {
        HardwareProfile hardware = R9700_Rx7800XT();
        u64 residencyBytes[2]{12ull << 30, 8ull << 30};
        u32 prefetchExpertsPerLayer = 4;
        CertTargets cert{};
    };

    Runtime();
    explicit Runtime(const Config& cfg);
    void setBackend(const BackendOps& ops) noexcept { backend_ = ops; }
    void beginModel(u64 generation);
    GovernorDecision beginToken(u64 tokenIndex, u32 rows, u64 bytesPerToken, double teraOpsPerToken);
    void observeRoute(u32 layer, const std::vector<u32>& experts, u64 expertBytes, u64 tokenIndex);
    bool prefetchPredicted(u32 layer, u64 expertBytes);
    bool submit(const CommandBatch& batch);
    bool waitBoth();
    void endToken(TokenMetrics metrics);
    CertResult certify(u64 bytesPerToken, double teraOpsPerToken) const;

    const std::vector<TokenMetrics>& tokens() const noexcept { return tokens_; }
    ExpertResidency& residency(unsigned gpu) noexcept { return residency_[gpu < 2 ? gpu : 0]; }
    PersistentDecode& persistent() noexcept { return persistent_; }

private:
    Config cfg_{};
    BackendOps backend_{};
    PersistentDecode persistent_{};
    ExpertResidency residency_[2];
    PredictiveRouter predictor_{};
    DualGpuBalancer balancer_{};
    RooflineGovernor governor_{};
    std::vector<TokenMetrics> tokens_;
    u64 currentToken_ = 0;
};

} // namespace Deep2::Roofline
