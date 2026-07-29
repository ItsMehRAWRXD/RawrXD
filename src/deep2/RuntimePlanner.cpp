// ============================================================================
// RuntimePlanner.cpp
// ============================================================================

#include "RuntimePlanner.hpp"

namespace RawrXD {

RuntimePlanner::RuntimePlanner() : initialized_(false) {}

RuntimePlanner::~RuntimePlanner() = default;

bool RuntimePlanner::Initialize(const ModelMetadata& metadata,
                                  const ResolvedKernelTable& kernels) {
    metadata_ = metadata;
    kernels_ = kernels;
    initialized_ = true;
    return true;
}

ExecutionPlan RuntimePlanner::PlanLayer(uint32_t layerIdx,
                                          const UniversalTensorDescriptor& kDesc,
                                          const UniversalTensorDescriptor& vDesc,
                                          const UniversalTensorDescriptor& expertDesc) {
    ExecutionPlan plan = {};
    plan.kernels = kernels_;

    // Plan attention strategy
    bool hasTreeMask = (kDesc.layout == TensorLayout::SPARSE);
    plan.attentionStrategy = PlanAttentionStrategy(vDesc.quantType, hasTreeMask, kernels_.isa);
    plan.attentionKernel = kernels_.attention;
    plan.kWeights = kDesc.data;
    plan.vWeights = vDesc.data;
    plan.kvQuant = vDesc.quantType;

    // Plan MoE strategy
    plan.useMoE = metadata_.isMoE;
    if (plan.useMoE) {
        plan.numExperts = metadata_.numExperts;
        plan.topK = metadata_.numExpertsPerTok;
        plan.moeRouterKernel = kernels_.moeRouter;
        plan.moeExpertKernel = kernels_.moeExpert;

        bool expertsResident = expertDesc.isResident();
        bool hasNVMePaging = (expertDesc.memorySpace == UniversalTensorDescriptor::MemorySpace::NVME);
        plan.moeStrategy = PlanMoEStrategy(expertDesc.quantType, expertsResident, hasNVMePaging);

        // Set up DMA scheduler for paged experts
        if (plan.moeStrategy == ExecutionStrategy::MOE_PAGED_NVME) {
            plan.dmaScheduler = std::make_unique<Deep2::DMAScheduler>();
            plan.dmaScheduler->Initialize(4);  // 4 concurrent transfers
        }
    }

    // Plan memory strategy
    plan.memoryStrategy = PlanMemoryStrategy(kDesc);

    return plan;
}

} // namespace RawrXD