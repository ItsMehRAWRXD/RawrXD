//=============================================================================
// ModelGenome - Method Implementations
// RAWRXD_MODEL_GENIE_HEADER_EXPORT_001
//=============================================================================

#include "ModelGenome.hpp"
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Deep2 {
namespace ModelGenie {

std::string ModelGenome::computeCanonicalHash() const {
    std::stringstream ss;
    ss << modelName << "|" << static_cast<int>(architecture) << "|" << blockCount << "|" 
       << tensorCount << "|" << exactParams << "|" << encodedWeightBytes << "|";
    
    // Include tensor fingerprints
    for (const auto& t : tensors) {
        ss << t.tensorId << ":" << t.name << ":" << t.encodedBytes << ":" << t.fileOffset << ";";
    }
    ss << "|";
    
    // Include block fingerprints
    for (const auto& b : blocks) {
        ss << b.blockIndex << ":";
        if (b.attnNorm) ss << "an=" << *b.attnNorm << ";";
        if (b.ffnNorm) ss << "fn=" << *b.ffnNorm << ";";
        if (b.attnKvANorm) ss << "akn=" << *b.attnKvANorm << ";";
        if (b.attnKvAMqa) ss << "akm=" << *b.attnKvAMqa << ";";
        if (b.attnKvB) ss << "akb=" << *b.attnKvB << ";";
        if (b.attnOutput) ss << "ao=" << *b.attnOutput << ";";
        if (b.attnQ) ss << "aq=" << *b.attnQ << ";";
        if (b.ffnDown) ss << "fd=" << *b.ffnDown << ";";
        if (b.ffnGate) ss << "fg=" << *b.ffnGate << ";";
        if (b.ffnUp) ss << "fu=" << *b.ffnUp << ";";
        if (b.ffnDownExps) ss << "fde=" << *b.ffnDownExps << ";";
        if (b.ffnGateExps) ss << "fge=" << *b.ffnGateExps << ";";
        if (b.ffnUpExps) ss << "fue=" << *b.ffnUpExps << ";";
        if (b.ffnGateInp) ss << "fgi=" << *b.ffnGateInp << ";";
        if (b.ffnDownShExp) ss << "fdse=" << *b.ffnDownShExp << ";";
        if (b.ffnGateShExp) ss << "fgse=" << *b.ffnGateShExp << ";";
        if (b.ffnUpShExp) ss << "fuse=" << *b.ffnUpShExp << ";";
    }
    ss << "|";
    
    // Include expert bank fingerprints
    for (const auto& bank : expertBanks) {
        ss << bank.blockIndex << ":"
           << bank.routedExpertCount << ":" << bank.activeExpertCount << ":"
           << bank.sharedExpertCount << ":" << bank.routerTensorId << ":"
           << std::fixed << std::setprecision(6) << bank.expertRomSharePercent << ";";
    }
    ss << "|";
    
    // Include execution op fingerprints
    for (const auto& op : executionOps) {
        ss << op.opId << ":" << static_cast<int>(op.opcode) << ":"
           << static_cast<int>(op.requiredPrimitive) << ":";
        for (uint32_t i : op.inputTensorIds) ss << i << ",";
        ss << ":";
        for (uint32_t w : op.weightTensorIds) ss << w << ",";
        ss << ":" << op.outputTensorId << ":" << op.blockIndex << ";";
    }
    ss << "|";
    
    // Include capability manifest
    for (auto p : capabilities.requiredPrimitives) ss << static_cast<int>(p) << ",";
    ss << "|";
    for (auto p : capabilities.availablePrimitives) ss << static_cast<int>(p) << ",";
    ss << "|";
    for (auto p : capabilities.unimplementedPrimitives) ss << static_cast<int>(p) << ",";
    ss << "|" << static_cast<int>(capabilities.firstUnimplementedPrimitive) << "|"
       << (capabilities.runtimeExecutable ? "1" : "0") << "|";
    
    // Include residency bounds
    ss << residencyBounds.maxPinnedTensorBytes << "|"
       << residencyBounds.minBlockBytes << "|"
       << residencyBounds.meanBlockBytes << "|"
       << residencyBounds.maxBlockBytes << "|"
       << (residencyBounds.uniformTensorSlotsSufficient ? "1" : "0") << "|"
       << (residencyBounds.meanBlockCapacitySafe ? "1" : "0") << "|"
       << residencyBounds.expertRomSharePercent << "|"
       << residencyBounds.expertRomBytes << "|"
       << residencyBounds.maxExpertBlockBytes;
    
    // Simple hash (FNV-1a 64-bit)
    std::string str = ss.str();
    uint64_t hash = 1469598103934665603ULL; // FNV offset basis
    for (char c : str) {
        hash ^= static_cast<unsigned char>(c);
        hash *= 1099511628211ULL; // FNV prime
    }
    
    std::stringstream hex;
    hex << std::hex << std::setw(16) << std::setfill('0') << hash;
    return hex.str();
}

} // namespace ModelGenie
} // namespace Deep2
} // namespace RawrXD