#include "../src/reap/NativeCompressionPlanner.hpp"
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    int failed = 0;
    auto check = [&](bool result, const char* name) {
        std::cout << (result ? "PASS " : "FAIL ") << name << "\n";
        if (!result) ++failed;
    };
    EngineContext ctx;
    ctx.cfg.ggufAlignment = 32;
    ctx.tensorWeightsPool.resize(64);
    GGUFTensorMeta meta;
    meta.name = "test.weight";
    meta.type = 0;
    meta.dims = {4};
    meta.offset = 0;
    ctx.tensors.emplace(meta.name,meta);
    Inventory inventory;
    check(BuildInventory(ctx,inventory)==InventoryError::None &&
          inventory.logical_bytes==16 && inventory.tensors.size()==1,
          "inventory_f32_exact");
    CompressionPlan plan;
    PlanRequest request;
    request.max_artifact_bytes=64;
    request.fixed_overhead_bytes=32;
    check(PlanLosslessPackaging(inventory,request,plan)==PlanError::None &&
          plan.minimum_artifact_bytes==48 && plan.tensors.size()==1,
          "exact_packaging_budget");
    CompressionPlan previous=plan;
    request.max_artifact_bytes=47;
    check(PlanLosslessPackaging(inventory,request,plan)==PlanError::InsufficientBudget &&
          plan.minimum_artifact_bytes==previous.minimum_artifact_bytes,
          "insufficient_budget_preserves_previous_plan");
    request.max_artifact_bytes=64;
    request.output_alignment=3;
    check(PlanLosslessPackaging(inventory,request,plan)==PlanError::InvalidBudget,
          "invalid_alignment_rejected");
    request.output_alignment=32;
    request.fixed_overhead_bytes=UINT64_MAX;
    check(PlanLosslessPackaging(inventory,request,plan)==PlanError::Overflow,
          "overhead_overflow_rejected");
    std::cout<<"REAP_PLANNER_RESULT="<<(failed?"FAIL":"PASS")
             <<" failures="<<failed<<"\n";
    return failed?1:0;
}
