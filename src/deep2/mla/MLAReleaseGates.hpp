#pragma once
#include <array>
#include <string>
#include <cstdint>
#include <ostream>
#include <utility>
namespace rawrxd::mla {
enum class Verdict : uint8_t { NotRun, Fail, Pass };
enum class Gate : uint8_t {
    TensorMapping, GeometryValidation, QueryProjection, CompressedKV, LatentNorm,
    Rope, KeyAbsorption, LatentAttention, ValueExpansion, LayerParity,
    TransactionalKV, SingleGpuParity, DualGpuOwnership, CrossDeviceParity,
    ConcurrentThroughput, Count
};
struct Evidence {
    Verdict verdict = Verdict::NotRun;
    std::string commit, executableHash, modelHash, receiptHash;
    bool measured = false;
};
class ReleaseGates {
public:
    static constexpr size_t Count = static_cast<size_t>(Gate::Count);
    bool record(Gate gate, Evidence evidence) {
        const size_t i = static_cast<size_t>(gate);
        if (i >= Count) return false;
        if (evidence.verdict == Verdict::Pass) {
            if (!evidence.measured || evidence.commit.empty() || evidence.executableHash.empty() ||
                evidence.modelHash.empty() || evidence.receiptHash.empty()) return false;
        }
        gates_[i] = std::move(evidence); return true;
    }
    size_t passed() const noexcept {
        size_t count = 0;
        for (const auto& g : gates_) if (g.verdict == Verdict::Pass) ++count;
        return count;
    }
    bool certified(const std::string& commit, const std::string& exeHash, const std::string& modelHash) const {
        if (commit.empty() || exeHash.empty() || modelHash.empty()) return false;
        for (const auto& g : gates_) {
            if (g.verdict != Verdict::Pass || !g.measured || g.commit != commit ||
                g.executableHash != exeHash || g.modelHash != modelHash || g.receiptHash.empty()) return false;
        }
        return true;
    }
    void emit(std::ostream& out, const std::string& commit, const std::string& exeHash, const std::string& modelHash) const {
        static constexpr const char* names[] = {
            "TENSOR_MAPPING","GEOMETRY_VALIDATION","QUERY_PROJECTION","COMPRESSED_KV","LATENT_NORM",
            "ROPE","KEY_ABSORPTION","LATENT_ATTENTION","VALUE_EXPANSION","LAYER_PARITY",
            "TRANSACTIONAL_KV","SINGLE_GPU_PARITY","DUAL_GPU_OWNERSHIP","CROSS_DEVICE_PARITY","CONCURRENT_THROUGHPUT"
        };
        for (size_t i = 0; i < Count; ++i) {
            const auto v = gates_[i].verdict;
            out << "GATE_" << i + 1 << "_" << names[i] << "="
                << (v == Verdict::Pass ? "PASS" : v == Verdict::Fail ? "FAIL" : "NOT_RUN") << '\n';
        }
        const bool ok = certified(commit, exeHash, modelHash);
        out << "GATES_PASSED=" << passed() << "/" << Count << '\n';
        out << "CERTIFIED=" << int(ok) << '\n';
        out << "PROMOTE=" << int(ok) << '\n';
        out << "RELEASE=" << (ok ? "ELIGIBLE" : "HELD") << '\n';
    }
private:
    std::array<Evidence, Count> gates_{};
};
}