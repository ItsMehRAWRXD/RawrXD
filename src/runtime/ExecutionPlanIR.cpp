// ============================================================================
// ExecutionPlanIR.cpp
// ============================================================================
// IR Builder: converts CanonicalModelGraph -> ExecutionPlanIR
// ============================================================================

#include "ExecutionPlanIR.hpp"
#include <iostream>

namespace RawrXD {

std::unique_ptr<ExecutionPlanIR> IRBuilder::Build(const CanonicalModelGraph& graph) {
    auto ir = std::make_unique<ExecutionPlanIR>();
    
    ir->numLayers = graph.numLayers;
    ir->hiddenSize = graph.hiddenSize;
    ir->isMoE = graph.isMoE;
    ir->numExperts = graph.numExperts;
    ir->numActiveExperts = graph.numActiveExperts;
    
    // Create input value (token ids)
    IRValue inputVal;
    inputVal.kind = IRValue::ValueKind::InputTensor;
    inputVal.name = "input_tokens";
    inputVal.dims[0] = 1; inputVal.dims[1] = graph.maxContext;
    inputVal.numDims = 2;
    inputVal.dtype = sovereign::TensorDesc::DataType::I32;
    ir->entryValue = ir->AddValue(inputVal);
    
    // Create embedding output
    IRValue embedVal;
    embedVal.kind = IRValue::ValueKind::Intermediate;
    embedVal.name = "embeddings";
    embedVal.dims[0] = 1; embedVal.dims[1] = graph.maxContext; 
    embedVal.dims[2] = graph.hiddenSize;
    embedVal.numDims = 3;
    embedVal.dtype = sovereign::TensorDesc::DataType::F32;
    uint32_t embedId = ir->AddValue(embedVal);
    
    // Embedding lookup op
    IROp embedOp;
    embedOp.type = IROp::OpType::EmbeddingLookup;
    embedOp.opName = "embedding";
    embedOp.inputs = {ir->entryValue};
    embedOp.outputs = {embedId};
    ir->AddOp(embedOp);
    
    // Build each transformer layer
    for (uint32_t layer = 0; layer < graph.numLayers; ++layer) {
        BuildTransformerLayer(*ir, graph, layer);
    }
    
    // Final norm
    IRValue finalNormOut;
    finalNormOut.kind = IRValue::ValueKind::Intermediate;
    finalNormOut.name = "final_norm_out";
    finalNormOut.dims[0] = 1; finalNormOut.dims[1] = graph.hiddenSize;
    finalNormOut.numDims = 2;
    uint32_t finalNormId = ir->AddValue(finalNormOut);
    
    IROp finalNormOp;
    finalNormOp.type = IROp::OpType::FinalNorm;
    finalNormOp.opName = "final_norm";
    finalNormOp.layerId = graph.numLayers;
    // Input is the output of the last layer (we'd track this properly)
    finalNormOp.inputs = {embedId}; // placeholder
    finalNormOp.outputs = {finalNormId};
    ir->AddOp(finalNormOp);
    
    // LM head
    IRValue logitsVal;
    logitsVal.kind = IRValue::ValueKind::Intermediate;
    logitsVal.name = "logits";
    logitsVal.dims[0] = 1; logitsVal.dims[1] = graph.vocabSize;
    logitsVal.numDims = 2;
    uint32_t logitsId = ir->AddValue(logitsVal);
    
    IROp lmHeadOp;
    lmHeadOp.type = IROp::OpType::LMHead;
    lmHeadOp.opName = "lm_head";
    lmHeadOp.inputs = {finalNormId};
    lmHeadOp.outputs = {logitsId};
    ir->AddOp(lmHeadOp);
    
    // Sampling
    IRValue outputVal;
    outputVal.kind = IRValue::ValueKind::Intermediate;
    outputVal.name = "output_token";
    outputVal.dims[0] = 1;
    outputVal.numDims = 1;
    outputVal.dtype = sovereign::TensorDesc::DataType::I32;
    ir->exitValue = ir->AddValue(outputVal);
    
    IROp sampleOp;
    sampleOp.type = IROp::OpType::Sampling;
    sampleOp.opName = "sampling";
    sampleOp.inputs = {logitsId};
    sampleOp.outputs = {ir->exitValue};
    sampleOp.floatAttrs["temperature"] = 0.7f;
    sampleOp.floatAttrs["top_p"] = 0.9f;
    sampleOp.intAttrs["top_k"] = 40;
    ir->AddOp(sampleOp);
    
    std::cout << "[IRBuilder] Built IR: " << ir->ops.size() << " ops, " 
              << ir->values.size() << " values" << std::endl;
    
    return ir;
}

void IRBuilder::BuildTransformerLayer(ExecutionPlanIR& ir,
                                       const CanonicalModelGraph& graph,
                                       uint32_t layerId)
{
    std::string prefix = "blk." + std::to_string(layerId) + ".";
    
    // Pre-attention RMSNorm
    IRValue normOut;
    normOut.kind = IRValue::ValueKind::Intermediate;
    normOut.name = prefix + "attn_norm_out";
    normOut.dims[0] = 1; normOut.dims[1] = graph.hiddenSize;
    normOut.numDims = 2;
    uint32_t normId = ir.AddValue(normOut);
    
    IROp normOp;
    normOp.type = IROp::OpType::RMSNorm;
    normOp.opName = prefix + "attn_norm";
    normOp.layerId = layerId;
    normOp.floatAttrs["eps"] = graph.rmsNormEps;
    normOp.outputs = {normId};
    ir.AddOp(normOp);
    
    // QKV projection
    IRValue qkvOut;
    qkvOut.kind = IRValue::ValueKind::Intermediate;
    qkvOut.name = prefix + "qkv_out";
    qkvOut.dims[0] = 1; qkvOut.dims[1] = graph.numHeads * graph.headDim * 3;
    qkvOut.numDims = 2;
    uint32_t qkvId = ir.AddValue(qkvOut);
    
    IROp qkvOp;
    qkvOp.type = IROp::OpType::QKVProjection;
    qkvOp.opName = prefix + "qkv_proj";
    qkvOp.layerId = layerId;
    qkvOp.inputs = {normId};
    qkvOp.outputs = {qkvId};
    qkvOp.canFuseWithPrev = true; // Can fuse with RMSNorm
    ir.AddOp(qkvOp);
    
    // RoPE
    IRValue ropeOut;
    ropeOut.kind = IRValue::ValueKind::Intermediate;
    ropeOut.name = prefix + "rope_out";
    ropeOut.dims[0] = 1; ropeOut.dims[1] = graph.numHeads * graph.headDim * 3;
    ropeOut.numDims = 2;
    uint32_t ropeId = ir.AddValue(ropeOut);
    
    IROp ropeOp;
    ropeOp.type = IROp::OpType::RoPE;
    ropeOp.opName = prefix + "rope";
    ropeOp.layerId = layerId;
    ropeOp.inputs = {qkvId};
    ropeOp.outputs = {ropeId};
    ropeOp.floatAttrs["theta"] = graph.ropeTheta;
    ir.AddOp(ropeOp);
    
    // Self-attention
    IRValue attnOut;
    attnOut.kind = IRValue::ValueKind::Intermediate;
    attnOut.name = prefix + "attn_out";
    attnOut.dims[0] = 1; attnOut.dims[1] = graph.hiddenSize;
    attnOut.numDims = 2;
    uint32_t attnId = ir.AddValue(attnOut);
    
    IROp attnOp;
    attnOp.type = IROp::OpType::SelfAttention;
    attnOp.opName = prefix + "self_attn";
    attnOp.layerId = layerId;
    attnOp.inputs = {ropeId};
    attnOp.outputs = {attnId};
    attnOp.intAttrs["num_heads"] = graph.numHeads;
    attnOp.intAttrs["num_kv_heads"] = graph.numKVHeads;
    attnOp.intAttrs["head_dim"] = graph.headDim;
    ir.AddOp(attnOp);
    
    // Attention output projection + residual
    IRValue attnResidOut;
    attnResidOut.kind = IRValue::ValueKind::Intermediate;
    attnResidOut.name = prefix + "attn_resid_out";
    attnResidOut.dims[0] = 1; attnResidOut.dims[1] = graph.hiddenSize;
    attnResidOut.numDims = 2;
    uint32_t attnResidId = ir.AddValue(attnResidOut);
    
    IROp attnOutOp;
    attnOutOp.type = IROp::OpType::AttentionOutput;
    attnOutOp.opName = prefix + "attn_out_proj";
    attnOutOp.layerId = layerId;
    attnOutOp.inputs = {attnId};
    attnOutOp.outputs = {attnResidId};
    ir.AddOp(attnOutOp);
    
    IROp residOp;
    residOp.type = IROp::OpType::ResidualAdd;
    residOp.opName = prefix + "attn_residual";
    residOp.layerId = layerId;
    residOp.inputs = {attnResidId};
    residOp.outputs = {attnResidId};
    ir.AddOp(residOp);
    
    // Pre-FFN norm
    IRValue ffnNormOut;
    ffnNormOut.kind = IRValue::ValueKind::Intermediate;
    ffnNormOut.name = prefix + "ffn_norm_out";
    ffnNormOut.dims[0] = 1; ffnNormOut.dims[1] = graph.hiddenSize;
    ffnNormOut.numDims = 2;
    uint32_t ffnNormId = ir.AddValue(ffnNormOut);
    
    IROp ffnNormOp;
    ffnNormOp.type = IROp::OpType::RMSNorm;
    ffnNormOp.opName = prefix + "ffn_norm";
    ffnNormOp.layerId = layerId;
    ffnNormOp.floatAttrs["eps"] = graph.rmsNormEps;
    ffnNormOp.inputs = {attnResidId};
    ffnNormOp.outputs = {ffnNormId};
    ir.AddOp(ffnNormOp);
    
    // FFN (MoE or dense)
    if (graph.isMoE && layerId >= 3) { // DeepSeek: first 3 layers are dense
        BuildMoELayer(ir, graph, layerId);
    } else {
        BuildDenseFFN(ir, graph, layerId);
    }
}

void IRBuilder::BuildMoELayer(ExecutionPlanIR& ir,
                                const CanonicalModelGraph& graph,
                                uint32_t layerId)
{
    std::string prefix = "blk." + std::to_string(layerId) + ".moe.";
    
    // MoE routing
    IRValue routeOut;
    routeOut.kind = IRValue::ValueKind::Intermediate;
    routeOut.name = prefix + "route_out";
    routeOut.dims[0] = 1; routeOut.dims[1] = graph.numExperts;
    routeOut.numDims = 2;
    uint32_t routeId = ir.AddValue(routeOut);
    
    IROp routeOp;
    routeOp.type = IROp::OpType::MoERoute;
    routeOp.opName = prefix + "route";
    routeOp.layerId = layerId;
    routeOp.intAttrs["num_experts"] = graph.numExperts;
    routeOp.intAttrs["top_k"] = graph.numActiveExperts;
    routeOp.outputs = {routeId};
    ir.AddOp(routeOp);
    
    // Expert FFNs (one per active expert)
    std::vector<uint32_t> expertOutputs;
    for (uint32_t e = 0; e < graph.numActiveExperts; ++e) {
        IRValue expertOut;
        expertOut.kind = IRValue::ValueKind::Intermediate;
        expertOut.name = prefix + "expert_" + std::to_string(e) + "_out";
        expertOut.dims[0] = 1; expertOut.dims[1] = graph.hiddenSize;
        expertOut.numDims = 2;
        expertOut.isExpert = true;
        expertOut.expertId = e;
        uint32_t expertOutId = ir.AddValue(expertOut);
        expertOutputs.push_back(expertOutId);
        
        IROp expertOp;
        expertOp.type = IROp::OpType::ExpertFFN;
        expertOp.opName = prefix + "expert_" + std::to_string(e);
        expertOp.layerId = layerId;
        expertOp.intAttrs["expert_id"] = e;
        expertOp.inputs = {routeId};
        expertOp.outputs = {expertOutId};
        expertOp.memHint = IROp::MemoryHint::Prefetch; // Prefetch expert weights
        ir.AddOp(expertOp);
    }
    
    // Combine expert outputs
    IRValue combineOut;
    combineOut.kind = IRValue::ValueKind::Intermediate;
    combineOut.name = prefix + "combine_out";
    combineOut.dims[0] = 1; combineOut.dims[1] = graph.hiddenSize;
    combineOut.numDims = 2;
    uint32_t combineId = ir.AddValue(combineOut);
    
    IROp combineOp;
    combineOp.type = IROp::OpType::ExpertCombine;
    combineOp.opName = prefix + "combine";
    combineOp.layerId = layerId;
    combineOp.inputs = expertOutputs;
    combineOp.outputs = {combineId};
    ir.AddOp(combineOp);
    
    // Post-FFN residual
    IROp ffnResidOp;
    ffnResidOp.type = IROp::OpType::ResidualAdd;
    ffnResidOp.opName = prefix + "ffn_residual";
    ffnResidOp.layerId = layerId;
    ffnResidOp.inputs = {combineId};
    ffnResidOp.outputs = {combineId};
    ir.AddOp(ffnResidOp);
}

void IRBuilder::BuildDenseFFN(ExecutionPlanIR& ir,
                                const CanonicalModelGraph& graph,
                                uint32_t layerId)
{
    std::string prefix = "blk." + std::to_string(layerId) + ".ffn.";
    
    // Gate projection (SiLU)
    IRValue gateOut;
    gateOut.kind = IRValue::ValueKind::Intermediate;
    gateOut.name = prefix + "gate_out";
    gateOut.dims[0] = 1; gateOut.dims[1] = graph.intermediateSize;
    gateOut.numDims = 2;
    uint32_t gateId = ir.AddValue(gateOut);
    
    IROp gateOp;
    gateOp.type = IROp::OpType::FFN;
    gateOp.opName = prefix + "gate";
    gateOp.layerId = layerId;
    gateOp.strAttrs["variant"] = "gate_silu";
    gateOp.outputs = {gateId};
    gateOp.canFuseWithNext = true;
    ir.AddOp(gateOp);
    
    // Up projection
    IRValue upOut;
    upOut.kind = IRValue::ValueKind::Intermediate;
    upOut.name = prefix + "up_out";
    upOut.dims[0] = 1; upOut.dims[1] = graph.intermediateSize;
    upOut.numDims = 2;
    uint32_t upId = ir.AddValue(upOut);
    
    IROp upOp;
    upOp.type = IROp::OpType::FFN;
    upOp.opName = prefix + "up";
    upOp.layerId = layerId;
    upOp.strAttrs["variant"] = "up";
    upOp.outputs = {upId};
    upOp.canFuseWithNext = true;
    ir.AddOp(upOp);
    
    // Down projection
    IRValue downOut;
    downOut.kind = IRValue::ValueKind::Intermediate;
    downOut.name = prefix + "down_out";
    downOut.dims[0] = 1; downOut.dims[1] = graph.hiddenSize;
    downOut.numDims = 2;
    uint32_t downId = ir.AddValue(downOut);
    
    IROp downOp;
    downOp.type = IROp::OpType::FFN;
    downOp.opName = prefix + "down";
    downOp.layerId = layerId;
    downOp.strAttrs["variant"] = "down";
    downOp.inputs = {gateId, upId};
    downOp.outputs = {downId};
    ir.AddOp(downOp);
    
    // Residual
    IROp residOp;
    residOp.type = IROp::OpType::ResidualAdd;
    residOp.opName = prefix + "residual";
    residOp.layerId = layerId;
    residOp.inputs = {downId};
    residOp.outputs = {downId};
    ir.AddOp(residOp);
}

void IRBuilder::BuildSampling(ExecutionPlanIR& ir,
                                const CanonicalModelGraph& graph)
{
    // Sampling op is already added in Build()
    (void)ir; (void)graph;
}

} // namespace RawrXD