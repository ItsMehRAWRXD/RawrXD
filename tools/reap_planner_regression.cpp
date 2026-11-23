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
    EngineContext overlap = ctx;
    GGUFTensorMeta second;
    second.name = "second.weight";
    second.type = 0;
    second.dims = {4};
    second.offset = 0;
    overlap.tensors.emplace(second.name, second);
    Inventory preserved = inventory;
    check(BuildInventory(overlap,inventory)==InventoryError::OverlappingTensors &&
          inventory.tensors.size()==preserved.tensors.size() &&
          inventory.logical_bytes==preserved.logical_bytes,
          "overlapping_tensors_rejected_transactionally");
    second.offset = 32;
    overlap.tensors[second.name] = second;
    check(BuildInventory(overlap,inventory)==InventoryError::None &&
          inventory.logical_bytes==32 && inventory.tensors.size()==2,
          "aligned_nonoverlapping_tensors_accepted");
    EngineContext quant;
    quant.cfg.ggufAlignment=32;
    quant.tensorWeightsPool.resize(144);
    GGUFTensorMeta q;
    q.name="quant.weight"; q.type=12; q.dims={256}; q.offset=0;
    quant.tensors.emplace(q.name,q);
    Inventory qinventory;
    check(BuildInventory(quant,qinventory)==InventoryError::None &&
          qinventory.logical_bytes==144,
          "q4_k_block_storage_accounting");
    std::cout<<"REAP_PLANNER_RESULT="<<(failed?"FAIL":"PASS")
             <<" failures="<<failed<<"\n";
    return failed?1:0;
}
