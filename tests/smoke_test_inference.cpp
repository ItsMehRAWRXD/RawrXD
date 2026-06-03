#include "cpu_inference_engine.h"
#include "inference/polymorphic_loader.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <unordered_set>
#include <string>
#include <vector>

namespace {
int testGGUFIntegration(const std::string& modelPath)
{
    if (modelPath.empty())
    {
        std::cout << "[smoke] GGUF integration skipped: no model path provided\n";
        return 0;
    }

    if (!std::filesystem::exists(modelPath))
    {
        std::cout << "[smoke] GGUF integration skipped: model not found at " << modelPath << "\n";
        return 0;
    }

    std::cout << "[smoke] GGUF integration start: " << modelPath << "\n";
    PolymorphicLoader loader;

    if (!loader.indexModel(modelPath))
    {
        std::cerr << "[smoke] GGUF integration failed: indexModel returned false\n";
        return 20;
    }

    if (!loader.beginExecution(modelPath))
    {
        std::cerr << "[smoke] GGUF integration failed: beginExecution returned false\n";
        return 21;
    }

    const StreamStep& firstStep = loader.getCurrentStep();
    std::cout << "[smoke] GGUF integration initialized: step=" << firstStep.step_id
              << " zones=" << firstStep.zone_count
              << " bytes=" << firstStep.total_bytes << "\n";

    const auto initialMetrics = loader.getMetrics();
    const uint32_t totalSteps = initialMetrics.total_steps;
    const uint32_t stepsToRun = std::min<uint32_t>(totalSteps > 0 ? totalSteps : 1, 32);

    for (uint32_t i = 0; i < stepsToRun; ++i)
    {
        if (!loader.executeStep())
        {
            std::cerr << "[smoke] GGUF integration failed: executeStep returned false at iter=" << i << "\n";
            return 22;
        }
        loader.advanceStep();
    }

    const auto metrics = loader.getMetrics();
    std::cout << "[smoke] Timing: steps=" << metrics.timed_steps
              << " avg_ms=" << metrics.avg_step_ms
              << " p95_ms=" << metrics.p95_step_ms
              << " stddev_ms=" << metrics.step_stddev_ms
              << " tps=" << metrics.tokens_per_second
              << " mbps=" << metrics.mb_per_second
              << " active_bytes=" << metrics.active_memory_bytes
              << "\n";

        std::cout << "[smoke] Step Metrics: zones_total=" << metrics.last_step_zone_count
              << " zones_loaded=" << metrics.last_step_loaded_zones
              << " zones_skipped=" << metrics.last_step_skipped_zones
              << " skip_ratio=" << metrics.last_step_skip_ratio
              << " bytes_loaded=" << metrics.last_step_bytes_loaded
              << " bytes_evicted=" << metrics.last_step_bytes_evicted
                  << " evictions=" << metrics.last_step_evictions
                  << " eviction_age_avg=" << metrics.last_step_eviction_age_avg
                  << " victim_search_ns=" << metrics.last_step_victim_search_ns
                  << " materialization_ns=" << metrics.last_step_materialization_ns
                  << " victim_search_ratio=" << metrics.last_step_victim_search_ratio
                  << " materialization_ratio=" << metrics.last_step_materialization_ratio
                  << " batch_count=" << metrics.last_step_batch_count
                  << " avg_zones_per_batch=" << metrics.last_step_avg_zones_per_batch
                  << " evict_misc=" << metrics.last_step_evictions_misc
                  << " evict_mlp=" << metrics.last_step_evictions_mlp
                  << " evict_attn=" << metrics.last_step_evictions_attn
                  << " burst_bytes_active=" << metrics.burst_bytes_active
                  << " reclaim_progress=" << metrics.reclaim_progress
                  << " sigmoid_reclaim_value=" << metrics.sigmoid_reclaim_value
                  << " adaptive_window_value=" << metrics.adaptive_window_value
                  << " self_eviction_blocked=" << metrics.last_step_self_eviction_blocked
                  << " protected_hits=" << metrics.last_step_protected_hits
                  << " protected_scan_count=" << metrics.last_step_protected_scan_count
                  << " fast_path_hits=" << metrics.last_step_fast_path_hits
                  << " unprotected_evictions=" << metrics.last_step_unprotected_evictions
                  << " hysteresis_holds=" << metrics.hysteresis_holds
              << " fail_code=" << metrics.last_slot_failure_code
              << " fail_reason="
              << PolymorphicLoader::slotAcquireFailureToString(
                  static_cast<PolymorphicLoader::SlotAcquireFailure>(metrics.last_slot_failure_code))
              << "\n";

        std::cout << "[smoke] Cumulative Metrics: zones_total=" << metrics.cumulative_zone_count
              << " zones_loaded=" << metrics.cumulative_loaded_zones
              << " zones_skipped=" << metrics.cumulative_skipped_zones
              << " skip_ratio=" << metrics.cumulative_skip_ratio
              << " bytes_loaded=" << metrics.cumulative_bytes_loaded
              << " bytes_evicted=" << metrics.cumulative_bytes_evicted
                  << " evictions=" << metrics.cumulative_evictions
                  << " eviction_age_avg=" << metrics.cumulative_eviction_age_avg
              << " victim_search_ns=" << metrics.cumulative_victim_search_ns
              << " materialization_ns=" << metrics.cumulative_materialization_ns
              << " batch_count=" << metrics.cumulative_batch_count
              << " zones_per_batch_sum=" << metrics.cumulative_zones_per_batch
              << " evict_misc=" << metrics.cumulative_evictions_misc
              << " evict_mlp=" << metrics.cumulative_evictions_mlp
              << " evict_attn=" << metrics.cumulative_evictions_attn
                  << " self_eviction_blocked=" << metrics.cumulative_self_eviction_blocked
              << " protected_hits=" << metrics.cumulative_protected_hits
              << " protected_scan_count=" << metrics.cumulative_protected_scan_count
              << " fast_path_hits=" << metrics.cumulative_fast_path_hits
              << " unprotected_evictions=" << metrics.cumulative_unprotected_evictions
                  << " hysteresis_holds=" << metrics.hysteresis_holds
              << "\n";

    std::cout << "[smoke] GGUF integration pass\n";
    return 0;
}
} // namespace

int main(int argc, char** argv)
{
    std::cout << "[smoke] RawrXD inference harness start\n";

    (void)argc;
    (void)argv;

    // Verify the CPU inference core is reachable and constructible.
    auto sharedEngine = RawrXD::CPUInferenceEngine::GetSharedInstance();
    if (!sharedEngine)
    {
        std::cerr << "[smoke] CPUInferenceEngine shared instance unavailable\n";
        return 2;
    }
    std::cout << "[smoke] Engine: " << sharedEngine->GetEngineName() << "\n";

    std::cout << "[smoke] Budget Verification:\n";
    std::cout << "[smoke]   Total(bytes): " << ActiveWindowBudget::TOTAL_BYTES << "\n";
    std::cout << "[smoke]   ATTN(bytes):  " << ActiveWindowBudget::ATTN_BYTES << "\n";
    std::cout << "[smoke]   MLP(bytes):   " << ActiveWindowBudget::MLP_BYTES << "\n";
    std::cout << "[smoke]   KV(bytes):    " << ActiveWindowBudget::KV_BYTES << "\n";
    std::cout << "[smoke]   MISC(bytes):  " << ActiveWindowBudget::MISC_BYTES << "\n";
    std::cout << "[smoke]   Total: " << (ActiveWindowBudget::TOTAL_BYTES / 1024 / 1024) << " MB\n";
    std::cout << "[smoke]   ATTN:  " << (ActiveWindowBudget::ATTN_BYTES / 1024 / 1024) << " MB\n";
    std::cout << "[smoke]   MLP:   " << (ActiveWindowBudget::MLP_BYTES / 1024 / 1024) << " MB\n";
    std::cout << "[smoke]   KV:    " << (ActiveWindowBudget::KV_BYTES / 1024 / 1024) << " MB\n";
    std::cout << "[smoke]   MISC:  " << (ActiveWindowBudget::MISC_BYTES / 1024 / 1024) << " MB\n";

    const size_t partitionSum = ActiveWindowBudget::ATTN_BYTES +
                                ActiveWindowBudget::MLP_BYTES +
                                ActiveWindowBudget::KV_BYTES +
                                ActiveWindowBudget::MISC_BYTES;
    if (partitionSum != ActiveWindowBudget::TOTAL_BYTES)
    {
        std::cerr << "[smoke] budget partition sum mismatch\n";
        return 3;
    }

    ActiveWindowBudget budget;
    SlotLattice lattice(budget);
    auto minSlotCapacity = [&lattice](SlotType type) -> uint32_t
    {
        uint32_t cap = 0;
        for (const Slot* s : lattice.getAllSlots())
        {
            if (!s || s->home_type != type)
            {
                continue;
            }
            if (cap == 0)
            {
                cap = s->capacity_bytes;
            }
            else
            {
                cap = std::min(cap, s->capacity_bytes);
            }
        }
        return cap;
    };

    uint32_t attnChunkBytes = 0;
    attnChunkBytes = minSlotCapacity(SlotType::ATTENTION);
    const uint32_t mlpChunkBytes = minSlotCapacity(SlotType::MLP);
    const uint32_t kvChunkBytes = minSlotCapacity(SlotType::KV_CACHE);
    if (attnChunkBytes == 0)
    {
        std::cerr << "[smoke] no attention slots discovered in lattice\n";
        return 4;
    }
    if (mlpChunkBytes == 0 || kvChunkBytes == 0)
    {
        std::cerr << "[smoke] no MLP/KV slots discovered in lattice\n";
        return 4;
    }
    std::unordered_set<std::uintptr_t> attnAddresses;
    std::vector<Slot*> acquiredSlots;
    acquiredSlots.reserve(8);

    for (uint64_t step = 0; step < 8; ++step)
    {
        Slot* slot = lattice.acquireSlot(SlotType::ATTENTION, attnChunkBytes, step + 1);
        if (!slot || !slot->base)
        {
            std::cerr << "[smoke] failed to acquire expected attention slot at index " << step << "\n";
            return 4;
        }

        const auto [_, inserted] = attnAddresses.insert(reinterpret_cast<std::uintptr_t>(slot->base));
        if (!inserted)
        {
            std::cerr << "[smoke] overlapping attention slot address detected\n";
            return 5;
        }

        acquiredSlots.push_back(slot);
    }

    if (lattice.getActiveCount() != 8)
    {
        std::cerr << "[smoke] active slot count mismatch after full attention allocation\n";
        return 6;
    }

    Slot* overflowProbe = lattice.acquireSlot(SlotType::ATTENTION, 1, 99);
    if (overflowProbe != nullptr)
    {
        // Gate 1 LRU may evict an older attention slot and satisfy this request.
        lattice.releaseSlot(overflowProbe);
        std::cout << "[smoke] attention over-allocation redirected via LRU eviction\n";
    }

    for (Slot* slot : acquiredSlots)
    {
        lattice.releaseSlot(slot);
    }

    if (lattice.getActiveCount() != 0 || lattice.getTotalUsage() != 0)
    {
        std::cerr << "[smoke] slot release did not restore zero usage\n";
        return 8;
    }

    // Build a minimal deterministic plan and verify slot scheduling against the budgeted lattice.
    std::vector<TensorDesc> planTensors;
    planTensors.reserve(5);

    TensorDesc t{};
    t.shape[0] = 1;
    t.shape[1] = 1;
    t.shape[2] = 1;
    t.shape[3] = 1;
    t.quant = QuantizationType::Q4_K_M;
    t.criticality = 1.0f;
    t.reuse_count = 1;

    // Layer 0: attention + MLP + KV
    t.layer_id = 0;
    t.role = TensorRole::ATTN_Q;
    t.byte_length = attnChunkBytes;
    planTensors.push_back(t);

    t.role = TensorRole::MLP_UP;
    t.byte_length = mlpChunkBytes;
    planTensors.push_back(t);

    t.role = TensorRole::KV_CACHE;
    t.byte_length = kvChunkBytes;
    planTensors.push_back(t);

    // Layer 1: attention + MLP
    t.layer_id = 1;
    t.role = TensorRole::ATTN_K;
    t.byte_length = attnChunkBytes;
    planTensors.push_back(t);

    t.role = TensorRole::MLP_DOWN;
    t.byte_length = mlpChunkBytes;
    planTensors.push_back(t);

    GlobalStreamPlan plan;
    if (!plan.buildFromTensors(planTensors, budget, 2) || !plan.verify())
    {
        std::cerr << "[smoke] GlobalStreamPlan build/verify failed\n";
        return 9;
    }

    for (uint32_t step = 0; step < plan.getTotalSteps(); ++step)
    {
        const StreamStep& s = plan.getStep(step);
        std::vector<Slot*> stepSlots;
        stepSlots.reserve(s.zones_to_load.size());

        for (const TensorDesc& zone : s.zones_to_load)
        {
            SlotType slotType = SlotType::AUXILIARY;
            switch (zone.role)
            {
                case TensorRole::ATTN_Q:
                case TensorRole::ATTN_K:
                case TensorRole::ATTN_V:
                case TensorRole::ATTN_O:
                    slotType = SlotType::ATTENTION;
                    break;
                case TensorRole::MLP_UP:
                case TensorRole::MLP_DOWN:
                    slotType = SlotType::MLP;
                    break;
                case TensorRole::KV_CACHE:
                    slotType = SlotType::KV_CACHE;
                    break;
                default:
                    slotType = SlotType::AUXILIARY;
                    break;
            }

            Slot* slot = lattice.acquireSlot(slotType, zone.byte_length, step + 1000);
            if (!slot)
            {
                std::cerr << "[smoke] plan step " << step
                          << " could not acquire slot for role=" << static_cast<int>(zone.role)
                          << " bytes=" << zone.byte_length << "\n";
                return 10;
            }
            stepSlots.push_back(slot);
        }

        for (Slot* slot : stepSlots)
        {
            lattice.releaseSlot(slot);
        }

        if (lattice.getTotalUsage() != 0)
        {
            std::cerr << "[smoke] plan step " << step << " leaked slot usage\n";
            return 11;
        }
    }

    // Deterministic rejection: a single attention tensor beyond ATTN budget must fail plan verification.
    std::vector<TensorDesc> overBudgetTensors;
    overBudgetTensors.reserve(1);
    TensorDesc over{};
    over.layer_id = 0;
    over.role = TensorRole::ATTN_Q;
    over.byte_length = static_cast<uint32_t>(ActiveWindowBudget::ATTN_BYTES + 1);
    over.shape[0] = 1;
    over.shape[1] = 1;
    over.shape[2] = 1;
    over.shape[3] = 1;
    over.quant = QuantizationType::Q4_K_M;
    over.criticality = 1.0f;
    over.reuse_count = 1;
    overBudgetTensors.push_back(over);

    GlobalStreamPlan overBudgetPlan;
    if (overBudgetPlan.buildFromTensors(overBudgetTensors, budget, 1) || overBudgetPlan.verify())
    {
        std::cerr << "[smoke] over-budget plan was not rejected deterministically\n";
        return 12;
    }

    std::cout << "[smoke] CPUInferenceEngine constructor/link smoke passed\n";
    std::cout << "[smoke] SlotLattice budget enforcement smoke passed\n";
    std::cout << "[smoke] GlobalStreamPlan scheduling smoke passed\n";
    std::cout << "[smoke] GlobalStreamPlan deterministic rejection smoke passed\n";

    std::string ggufPath;
    if (argc > 1 && argv[1] != nullptr)
    {
        ggufPath = argv[1];
    }
    else if (const char* envPath = std::getenv("RAWRXD_SMOKE_GGUF"); envPath != nullptr)
    {
        ggufPath = envPath;
    }

    const int ggufResult = testGGUFIntegration(ggufPath);
    if (ggufResult != 0)
    {
        return ggufResult;
    }

    std::cout << "[smoke] model-load/inference path is validated by orchestrator/runtime tests\n";

    std::cout << "[smoke] success\n";
    return 0;
}
