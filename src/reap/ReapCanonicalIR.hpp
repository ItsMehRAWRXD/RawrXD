// ReapCanonicalIR.hpp — REAP-AutoFit R02
//
// Canonical intermediate representation that separates PHYSICAL tensor identity
// (one entry per GGUF tensor, never duplicated) from LOGICAL execution visits
// ((pass, layer) pairs produced by a recurrent loop). A recurrent block visits
// the same physical weights on every pass, so the IR must never clone physical
// allocations per visit.
//
// Header-only, dependency-free. Consumes the architecture metadata extracted by
// reap_tensor_enum.cpp (R01) plus a tensor list, and produces:
//   - ModelGeometry  : discovered architecture (embedding, blocks, heads,
//                      experts, loop metadata)
//   - PhysicalTensor : one per physical tensor, tagged with its layer index
//   - LogicalVisit   : (pass, ordinal, physicalLayer) schedule
//
// loop_count is the TOTAL number of passes; NormalizeLoop reconciles raw end conventions.

#pragma once

#include "reap/ReapVisitSchedule.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>

namespace reap {

struct ModelGeometry {
    std::string architecture;
    uint64_t embeddingLength   = 0;
    uint64_t blockCount        = 0;   // physical layers
    uint64_t contextLength     = 0;
    uint64_t expertCount       = 0;   // experts per MoE layer (0 = dense)
    uint64_t expertUsedCount   = 0;   // experts routed per token
    uint64_t attentionHeadCount    = 0;
    uint64_t attentionHeadCountKV  = 0;
    // Recurrent loop metadata (0 / absent => single pass, no recurrence).
    uint64_t loopCount   = 0;         // TOTAL passes (>=1 once normalized)
    uint64_t loopStart   = 0;         // inclusive first physical layer in loop
    uint64_t loopEnd     = 0;         // raw end; normalized by architecture
    uint64_t loopGateRank = 0;
};

// One physical tensor. `layerIndex` is the physical layer (0..blockCount-1) or
// UINT32_MAX for global tensors (embedding, output head, norms).
struct PhysicalTensor {
    std::string name;
    std::string family;
    uint32_t    type = 0;
    std::vector<uint64_t> dims;
    uint64_t    sizeBytes = 0;
    uint32_t    shardId = 0;
    uint64_t    fileOffset = 0;
    uint64_t    tensorOffset = 0;
    uint64_t    expertCount = 0;
    uint32_t    layerIndex = UINT32_MAX;   // UINT32_MAX = global
};

struct CanonicalIR {
    ModelGeometry geometry;
    std::vector<PhysicalTensor> tensors;   // physical identity (unique)
    std::vector<LogicalVisit>   visits;    // logical schedule (may exceed tensors)

    uint64_t PhysicalLayerCount() const { return geometry.blockCount; }
    uint64_t LogicalVisitCount()  const { return visits.size(); }
};

// Extract the physical layer index from a GGUF tensor name.
// Recognises "blk.<N>." and "layers.<N>." prefixes; returns UINT32_MAX if the
// tensor is global (no layer component).
inline uint32_t ParseLayerIndex(const std::string& name) {
    auto startsWith = [&](const char* p) {
        const size_t n = std::char_traits<char>::length(p);
        return name.compare(0, n, p) == 0;
    };
    size_t pos = std::string::npos;
    if (startsWith("blk."))       pos = 4;
    else if (startsWith("layers.")) pos = 7;
    if (pos == std::string::npos) return UINT32_MAX;
    uint64_t value = 0;
    size_t i = pos;
    for (; i < name.size() && name[i] >= '0' && name[i] <= '9'; ++i)
        value = value * 10 + static_cast<uint64_t>(name[i] - '0');
    if (i == pos) return UINT32_MAX;   // no digits -> global
    return static_cast<uint32_t>(value);
}

// Normalize the discovered loop metadata and include all non-recurrent layers.
inline LoopSchedule ModelLoop(const ModelGeometry& g) {
    return NormalizeLoop(g.architecture, g.blockCount, g.loopCount, g.loopStart, g.loopEnd);
}
inline std::vector<LogicalVisit> BuildVisitSchedule(const ModelGeometry& g) {
    return BuildLayerVisits(ModelLoop(g));
}

// Build the full canonical IR: assign layer indices to tensors and expand the
// logical visit schedule. Physical tensors are NEVER duplicated by visits.
inline CanonicalIR BuildCanonicalIR(const ModelGeometry& geometry,
                                    std::vector<PhysicalTensor> tensors) {
    CanonicalIR ir;
    ir.geometry = geometry;
    for (auto& t : tensors) {
        if (t.layerIndex == UINT32_MAX && !t.name.empty())
            t.layerIndex = ParseLayerIndex(t.name);
        ir.tensors.push_back(std::move(t));
    }
    ir.visits = BuildVisitSchedule(geometry);
    return ir;
}

// Compact diagnostic: physical tensors vs logical visits (proves no cloning).
inline std::string Describe(const CanonicalIR& ir) {
    std::ostringstream os;
    os << "arch=" << ir.geometry.architecture
       << " blocks=" << ir.geometry.blockCount
       << " experts=" << ir.geometry.expertCount
       << " loops=" << (ir.geometry.loopCount ? ir.geometry.loopCount : 1)
       << " physical_tensors=" << ir.tensors.size()
       << " logical_visits=" << ir.visits.size();
    return os.str();
}

} // namespace reap