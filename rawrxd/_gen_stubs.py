import os

stubs = {
    "src/rawrxd_inference.cpp": '#include "core/rawrxd_inference.h"\n',
    "src/vulkan_kernel_bridge.cpp": '// vulkan_kernel_bridge — stub\n',
    "src/compression/zlib_runtime_loader.cpp": '// zlib_runtime_loader — stub\n',
    "src/agent/agentic_hotpatch_orchestrator.cpp": '// agentic_hotpatch_orchestrator — stub\n',
    "src/auth/rbac_engine.cpp": '// rbac_engine — stub\n',
    "src/agent/autonomous_subagent.cpp": '// autonomous_subagent — stub\n',
    "src/agent/agentic_failure_detector.cpp": '// agentic_failure_detector — stub\n',
    "src/agent/llm_http_client.cpp": '// llm_http_client — stub\n',
    "src/agent/planner.cpp": '// planner — stub\n',
    "src/agent/eval_framework.cpp": '// eval_framework — stub\n',
    "src/agent/agent_self_repair.cpp": '// agent_self_repair — stub\n',
    "src/agent/agent_self_healing_orchestrator.cpp": '// agent_self_healing_orchestrator — stub\n',
    "src/agentic/DeterministicReplayEngine.cpp": '// DeterministicReplayEngine — stub\n',
    "src/agentic/AgentToolHandlers.cpp": '// AgentToolHandlers — stub\n',
    "src/agentic/autonomous_recovery_orchestrator.cpp": '// autonomous_recovery_orchestrator — stub\n',
    "src/agentic/AgenticDeepThinkingEngine.cpp": '// AgenticDeepThinkingEngine — stub\n',
    "src/agentic/AgentOrchestrator.cpp": '#include "../../include/rawrxd/closure/AgentOrchestrator.hpp"\n\nnamespace rawrxd::closure {\n\nAgentRunResult AgentOrchestrator::run(std::string_view objective, uint32_t max_steps) {\n    std::string observation;\n    for (uint32_t step = 0; step < max_steps; ++step) {\n        auto action = reasoner_.next(objective, observation, step);\n        if (action.done)\n            return {action.success, false, step + 1, action.report};\n        if (!action.tool)\n            return {false, false, step + 1, "no tool and not done"};\n        auto result = tools_.invoke(*action.tool);\n        observation = result.output;\n    }\n    return {false, true, max_steps, "max steps reached"};\n}\n\n} // namespace rawrxd::closure\n',
    "src/agentic/OrchestratorBridge.cpp": '// OrchestratorBridge — stub\n',
    "src/agentic/AgenticNavigator.cpp": '// AgenticNavigator — stub\n',
    "src/agentic/RawrXD_ToolRegistry.cpp": '// RawrXD_ToolRegistry — stub\n',
    "src/agentic/ToolRegistry.cpp": '#include "ToolRegistry.h"\n\nnamespace RawrXD {\nnamespace Agent {\n\nToolRegistry& ToolRegistry::instance() {\n    static ToolRegistry inst;\n    return inst;\n}\n\nvoid ToolRegistry::RegisterTool(const ToolDef& tool) {\n    tools_.push_back(tool);\n}\n\nstd::vector<std::string> ToolRegistry::ListTools() const {\n    std::vector<std::string> names;\n    for (const auto& t : tools_) names.push_back(t.name);\n    return names;\n}\n\nstd::string ToolRegistry::InvokeTool(const std::string& name, const std::string& args) {\n    for (const auto& t : tools_)\n        if (t.name == name && t.invoke) return t.invoke(args);\n    return {};\n}\n\n} // namespace Agent\n} // namespace RawrXD\n',
    "src/agentic/RawrXD_AgentLoop.cpp": '// RawrXD_AgentLoop — stub\n',
    "src/agentic/agentic_executor.cpp": '// agentic_executor — stub\n',
    "src/agent/DiskRecoveryAgent.cpp": '// DiskRecoveryAgent (agent) — stub\n',
    "src/agentic/BoundedAgentLoop.cpp": '#include "BoundedAgentLoop.h"\n\nnamespace RawrXD {\nnamespace Agent {\n\nstd::string BoundedAgentLoop::Execute(const std::string& task) {\n    running_ = true;\n    currentStep_ = 0;\n    std::string result;\n    while (currentStep_ < config_.maxSteps) {\n        ++currentStep_;\n        // Stub: no real model invocation yet\n        break;\n    }\n    running_ = false;\n    return result;\n}\n\n} // namespace Agent\n} // namespace RawrXD\n',
    "src/agentic/FIMPromptBuilder.cpp": '// FIMPromptBuilder — stub\n',
    "src/config/IDEConfig.cpp": '#include "IDEConfig.h"\n',
    "src/agentic/DiskRecoveryAgent.cpp": '// DiskRecoveryAgent (agentic) — stub\n',
    "src/agentic/DiskRecoveryToolHandler.cpp": '// DiskRecoveryToolHandler — stub\n',
    "src/agent/quantum_autonomous_todo_system.cpp": '// quantum_autonomous_todo_system — stub\n',
    "src/agent/quantum_multi_model_agent_cycling.cpp": '// quantum_multi_model_agent_cycling — stub\n',
    "src/agent/quantum_dynamic_time_manager.cpp": '// quantum_dynamic_time_manager — stub\n',
    "src/agent/quantum_missing_impl.cpp": '// quantum_missing_impl — stub\n',
    "src/agent/quantum_production_orchestrator.cpp": '// quantum_production_orchestrator — stub\n',
    "src/agent/quantum_agent_orchestrator.cpp": '// quantum_agent_orchestrator — stub\n',
    "src/cli/swarm_orchestrator.cpp": '// swarm_orchestrator — stub\n',
    "src/vulkan_compute.cpp": '#include "deep2/vulkan_compute.h"\n',
    "src/agentic/multi_file_transaction.cpp": '// multi_file_transaction — stub\n',
    "src/agentic/agentic_transaction.cpp": '// agentic_transaction — stub\n',
    "src/agentic/agent_workflow_orchestrator.cpp": '// agent_workflow_orchestrator — stub\n',
    "src/agentic/model_cascade.cpp": '// model_cascade — stub\n',
    "src/agentic/context_assembler.cpp": '// context_assembler — stub\n',
    "src/ai/speculative_tree_attention_bridge.cpp": '#include "SpeculativeTreeAttentionBridge.hpp"\n\nnamespace rawrxd::ai {\n\nSpeculativeTreeAttentionBridge::SpeculativeTreeAttentionBridge(const TreeAttentionConfig& config)\n    : config_(config) {}\n\nSpeculativeTreeAttentionBridge::~SpeculativeTreeAttentionBridge() {\n    StopWorkerThreads();\n}\n\nSpeculativeTreeAttentionBridge::SpeculativeTreeAttentionBridge(SpeculativeTreeAttentionBridge&&) noexcept = default;\nSpeculativeTreeAttentionBridge& SpeculativeTreeAttentionBridge::operator=(SpeculativeTreeAttentionBridge&&) noexcept = default;\n\nbool SpeculativeTreeAttentionBridge::Initialize(\n    std::vector<DraftModelConfig> draft_configs,\n    std::shared_ptr<InferenceSession> target_session) {\n    draft_configs_ = std::move(draft_configs);\n    target_session_ = std::move(target_session);\n    StartWorkerThreads();\n    return true;\n}\n\nstd::vector<int32_t> SpeculativeTreeAttentionBridge::SpeculateAndVerify(\n    const std::vector<int32_t>& input_tokens, uint32_t max_new_tokens) {\n    return {};\n}\n\nstd::vector<std::vector<int32_t>> SpeculativeTreeAttentionBridge::BatchSpeculateAndVerify(\n    const std::vector<std::vector<int32_t>>& input_batches, uint32_t max_new_tokens_per_sequence) {\n    return std::vector<std::vector<int32_t>>(input_batches.size());\n}\n\nvoid SpeculativeTreeAttentionBridge::BuildSpeculativeTree(\n    const std::vector<int32_t>&, uint32_t, uint32_t) {}\n\nvoid SpeculativeTreeAttentionBridge::PruneTreeWithDiversity(uint32_t) {}\nvoid SpeculativeTreeAttentionBridge::ComputeCrossAttentionScores() {}\n\nTreeVerificationResult SpeculativeTreeAttentionBridge::VerifyTreeNodes(\n    const std::vector<int32_t>&) { return {}; }\n\nTreeVerificationResult SpeculativeTreeAttentionBridge::VerifyTreeAdaptive(\n    const std::vector<int32_t>&) { return {}; }\n\nfloat SpeculativeTreeAttentionBridge::GetRollingAcceptanceRate() const { return rolling_acceptance_rate_; }\nfloat SpeculativeTreeAttentionBridge::GetAverageTreeDepth() const { return 0.0f; }\nstd::vector<float> SpeculativeTreeAttentionBridge::GetPerDepthAcceptanceRates() const { return {}; }\n\nvoid SpeculativeTreeAttentionBridge::EvictCache(const std::string&) {}\nvoid SpeculativeTreeAttentionBridge::CompactCache() {}\nsize_t SpeculativeTreeAttentionBridge::GetCacheMemoryUsage() const { return cache_memory_used_; }\n\nvoid SpeculativeTreeAttentionBridge::UpdateConfig(const TreeAttentionConfig& new_config) { config_ = new_config; }\n\nstd::string SpeculativeTreeAttentionBridge::ExportTreeDOT() const { return {}; }\nvoid SpeculativeTreeAttentionBridge::DumpTreeStatistics(std::ostream&) const {}\n\nvoid SpeculativeTreeAttentionBridge::ExpandNode(uint32_t, const std::vector<std::pair<int32_t, float>>&) {}\nvoid SpeculativeTreeAttentionBridge::ScoreNodeWithAttention(uint32_t) {}\nstd::vector<uint32_t> SpeculativeTreeAttentionBridge::SelectTopKNodes(uint32_t) const { return {}; }\nstd::vector<uint32_t> SpeculativeTreeAttentionBridge::GetPathToRoot(uint32_t) const { return {}; }\nvoid SpeculativeTreeAttentionBridge::BacktrackAndResample(uint32_t) {}\n\nstd::vector<std::pair<int32_t, float>> SpeculativeTreeAttentionBridge::EnsembleDraftPredictions(\n    const std::vector<int32_t>&, uint32_t) { return {}; }\n\nstd::vector<std::pair<int32_t, float>> SpeculativeTreeAttentionBridge::SingleDraftPredictions(\n    uint32_t, const std::vector<int32_t>&, uint32_t) { return {}; }\n\nvoid SpeculativeTreeAttentionBridge::ComputeSelfAttentionForTree() {}\nvoid SpeculativeTreeAttentionBridge::ComputeTreeTargetCrossAttention() {}\nfloat SpeculativeTreeAttentionBridge::ComputeAttentionScore(\n    const SpeculativeTreeNode&, const std::vector<float>&) { return 0.0f; }\n\nstd::vector<bool> SpeculativeTreeAttentionBridge::BatchVerifyNodes(\n    const std::vector<int32_t>&, const std::vector<uint32_t>& indices) {\n    return std::vector<bool>(indices.size(), false);\n}\n\nstd::vector<float> SpeculativeTreeAttentionBridge::GetTargetLogits(\n    const std::vector<int32_t>&) { return {}; }\n\nbool SpeculativeTreeAttentionBridge::AcceptToken(\n    int32_t, float, int32_t, float) { return false; }\n\nvoid SpeculativeTreeAttentionBridge::InitializeKVCache(uint32_t, uint32_t, uint32_t) {}\nvoid SpeculativeTreeAttentionBridge::UpdateKVCache(\n    uint32_t, uint32_t, const std::vector<float>&, const std::vector<float>&) {}\nstd::pair<std::vector<float>, std::vector<float>>\nSpeculativeTreeAttentionBridge::RetrieveKVCache(uint32_t, uint32_t) const { return {}; }\n\nvoid SpeculativeTreeAttentionBridge::StartWorkerThreads() {}\nvoid SpeculativeTreeAttentionBridge::StopWorkerThreads() {\n    shutdown_.store(true);\n    queue_cv_.notify_all();\n    for (auto& w : workers_) if (w.joinable()) w.join();\n    workers_.clear();\n}\nvoid SpeculativeTreeAttentionBridge::WorkerLoop() {}\n\nstd::vector<std::pair<int32_t, float>> TopKSampling(\n    const std::vector<float>& logits, uint32_t k, float temperature) {\n    if (logits.empty() || k == 0) return {};\n    std::vector<std::pair<int32_t, float>> indexed;\n    indexed.reserve(logits.size());\n    for (size_t i = 0; i < logits.size(); ++i)\n        indexed.emplace_back(static_cast<int32_t>(i), logits[i] / temperature);\n    if (k < indexed.size()) {\n        std::partial_sort(indexed.begin(), indexed.begin() + k, indexed.end(),\n            [](const auto& a, const auto& b){ return a.second > b.second; });\n        indexed.resize(k);\n    }\n    return indexed;\n}\n\nvoid TreeAttentionKernel(\n    const float*, const float*, const float*,\n    const uint32_t*, uint32_t, uint32_t, float, float*) {}\n\n} // namespace rawrxd::ai\n',
    "src/production_config_manager.cpp": '// production_config_manager — stub\n',
}

created = 0
skipped = 0
for path, content in stubs.items():
    if os.path.exists(path):
        skipped += 1
        continue
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    created += 1
    print(f"CREATED: {path}")

print(f"\nDone. Created: {created}, Skipped (already exist): {skipped}")
