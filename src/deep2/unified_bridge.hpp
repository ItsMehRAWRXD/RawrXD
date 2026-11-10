#pragma once
#include "imagined_conceived_loop.hpp"
#include "rainbow_concept.hpp"
#include "flash_frozen.hpp"
#include <mutex>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
#include <limits>

namespace rawrxd_bridge {
// A local coordinator, not an inference engine. All public operations serialize
// access to the legacy single-threaded components.
struct Evidence {
    std::string candidate;
    bool verified = false;
    std::string reason;
};
struct Receipt {
    uint64_t step = 0;
    size_t generated = 0;
    size_t accepted = 0;
    size_t rejected = 0;
    uint64_t snapshot_root = 0;
};
class Coordinator {
public:
    using Generate = rawrxd::RainbowConceptLoop::Imagine;
    using Verify = std::function<Evidence(const std::string&)>;
    Coordinator(std::string seed, Generate generator, Verify verifier,
                size_t limit = 10000)
      : verifier_(std::move(verifier)),
        graph_(std::move(generator), [this](const std::string& s) {
            Evidence e = verifier_(s);
            return e.verified && e.candidate == s;
        }, limit) {
        if (!graph_.seed(seed)) throw std::invalid_argument("invalid seed");
        if (!frozen_.publish(1, 0, encode(seed))) throw std::runtime_error("initial publish");
    }
    Receipt advance() {
        std::lock_guard<std::mutex> guard(mu_);
        auto r = graph_.step();
        if (step_ == std::numeric_limits<uint64_t>::max()) throw std::overflow_error("step overflow");
        ++step_;
        // Only verified concept text enters the frozen stream. Index pages are
        // deterministic and content-addressed by exact text, not hash alone.
        std::string record = "step=" + std::to_string(step_) + ";nodes=" +
            std::to_string(graph_.size()) + ";accepted=" + std::to_string(r.conceived);
        if (!frozen_.publish(1, step_, encode(record))) throw std::runtime_error("version conflict");
        auto snap = frozen_.freeze();
        if (!rawrxd::FrozenStream::validate(snap)) throw std::runtime_error("snapshot invalid");
        return {step_, r.imagined, r.conceived, r.rejected, snap.root};
    }
    rawrxd::Frozen snapshot() const {
        std::lock_guard<std::mutex> guard(mu_);
        return frozen_.freeze();
    }
    bool contains(const std::string& text) const {
        std::lock_guard<std::mutex> guard(mu_);
        return graph_.contains(text);
    }
    // Read-only restoration of a frozen record into a separate consumer. This
    // does NOT restore the graph or authorize generation from unverified data.
    static std::map<uint64_t, rawrxd::Bytes> inspect(const rawrxd::Frozen& snap) {
        std::map<uint64_t, rawrxd::Bytes> pages;
        rawrxd::FrozenStream::replay(snap, [&](uint64_t id, uint64_t, const rawrxd::Bytes& b) {
            pages.emplace(id, b);
        });
        return pages;
    }
private:
    static rawrxd::Bytes encode(const std::string& s) { return {s.begin(), s.end()}; }
    mutable std::mutex mu_;
    Verify verifier_;
    rawrxd::RainbowConceptLoop graph_;
    rawrxd::FrozenStream frozen_;
    uint64_t step_ = 0;
};
// Contract for later Deep2 integration. No stubbed success paths are provided:
// callers must implement and test these against actual engine objects.
struct RuntimeAdapter {
    virtual ~RuntimeAdapter() = default;
    virtual bool validate_tensor_bytes(uint64_t tensor_id, const rawrxd::Bytes& bytes) = 0;
    virtual bool publish_kv_page(uint64_t session, uint64_t layer, uint64_t token,
                                 uint64_t expected_generation, const rawrxd::Bytes& bytes) = 0;
    virtual bool wait_for_gpu_consumers(uint64_t tensor_id, uint64_t generation) = 0;
    virtual bool persist_page_atomic(uint64_t page_id, uint64_t version,
                                     const rawrxd::Bytes& bytes) = 0;
};
} // namespace rawrxd_bridge
