#pragma once
// =============================================================================
// rawrxd_orchestrator.hpp — Runtime Memory Orchestrator (FIXED)
// Reversed Hotpatch Engine: unified promote/demote/evict/prefetch/rollback
//
// FIXES APPLIED (from audit):
//   1. mutable std::mutex on all const methods
//   2. ExecutionDependencyGraph residual registration fixed
//   3. Rollback marks as RECONSTRUCT_NEEDED instead of fake HOT
//   4. Prefetcher uses separate promote queue (no deadlock)
//   5. PagedKVCache uses std::vector<float>().swap() for guaranteed free
//   6. budget_bytes pulls from topo at runtime
//   7. evict_lowest_score uses std::set ordered by score (O(log n))
// =============================================================================
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <deque>
#include <queue>
#include <algorithm>
#include <numeric>
#include <chrono>
#include <atomic>
#include <mutex>
#include <thread>
#include <future>
#include <sstream>
#include <memory>
#include <functional>
#include <condition_variable>
#include <random>

#ifdef _WIN32
#include <windows.h>
#endif

#include "runtime/TensorExecutionRouter.hpp"

// ─── FORWARD DECLS (from rawrxd.cpp) ────────────────────────────────────────
struct GGUF;
struct GGTensor;

// ─── 1. DEVICE MEMORY TOPOLOGY ──────────────────────────────────────────────
struct MemoryTier {
    enum Type { VRAM, RAM, SSD, COUNT };
    Type type;
    uint64_t capacity_bytes;
    uint64_t free_bytes;
    double bandwidth_gbps;
    double latency_us;
    bool gpu_direct;

    static const char* name(Type t) {
        switch(t){case VRAM:return "VRAM";case RAM:return "RAM";case SSD:return "SSD";default:return "?";}
    }
};

struct DeviceMemoryTopology {
    std::array<MemoryTier,3> tiers;
    mutable std::mutex mtx;

    void init_default() {
        tiers[MemoryTier::VRAM] = {MemoryTier::VRAM, 32ULL*1024*1024*1024, 32ULL*1024*1024*1024, 1000.0, 0.1, true};
        tiers[MemoryTier::RAM]  = {MemoryTier::RAM,  64ULL*1024*1024*1024, 64ULL*1024*1024*1024,  100.0, 0.5, false};
        tiers[MemoryTier::SSD]  = {MemoryTier::SSD,  11ULL*1024*1024*1024*1024, 11ULL*1024*1024*1024*1024, 3.5, 100.0, false};
    }

    void probe_runtime() {
#ifdef _WIN32
        MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms);
        if (GlobalMemoryStatusEx(&ms)) {
            std::lock_guard<std::mutex> lock(mtx);
            tiers[MemoryTier::RAM].free_bytes = ms.ullAvailPhys;
        }
#endif
    }

    MemoryTier* best_tier_for_size(uint64_t bytes) {
        std::lock_guard<std::mutex> lock(mtx);
        for (int i = 0; i < 3; i++) {
            if (tiers[i].free_bytes >= bytes) return &tiers[i];
        }
        return &tiers[MemoryTier::SSD];
    }

    void account_alloc(MemoryTier::Type t, uint64_t bytes) {
        std::lock_guard<std::mutex> lock(mtx);
        if (tiers[t].free_bytes >= bytes) tiers[t].free_bytes -= bytes;
    }
    void account_free(MemoryTier::Type t, uint64_t bytes) {
        std::lock_guard<std::mutex> lock(mtx);
        tiers[t].free_bytes += bytes;
    }

    uint64_t vram_capacity() const {
        std::lock_guard<std::mutex> lock(mtx);
        return tiers[MemoryTier::VRAM].capacity_bytes;
    }

    std::string report() const {
        std::lock_guard<std::mutex> lock(mtx);
        std::ostringstream s;
        for (int i = 0; i < 3; i++) {
            const auto& t = tiers[i];
            s << "  " << MemoryTier::name(t.type) << ": "
              << (t.capacity_bytes - t.free_bytes)/(1024*1024) << "/"
              << t.capacity_bytes/(1024*1024) << " MB  bw=" << t.bandwidth_gbps
              << "GB/s lat=" << t.latency_us << "us gpu=" << t.gpu_direct << "\n";
        }
        return s.str();
    }
};

// ─── PATCH STATE (shared with HotPatchRegistry) ────────────────────────────
enum class PatchState : uint8_t {
    EVICTED = 0,
    COLD    = 1,
    WARM    = 2,
    HOT     = 3,
    PINNED  = 4,
    RECONSTRUCT_NEEDED = 5  // NEW: rollback target, data cleared
};

inline const char* state_name(PatchState s) {
    switch(s) { case PatchState::EVICTED: return "EVICTED"; case PatchState::COLD: return "COLD";
                case PatchState::WARM: return "WARM"; case PatchState::HOT: return "HOT";
                case PatchState::PINNED: return "PINNED"; case PatchState::RECONSTRUCT_NEEDED: return "RECONSTRUCT";
                default: return "?"; }
}

// ─── HOTPATCH ENTRY (from TensorResidency.hpp) ───────────────────────────────
struct HotPatchEntry {
    uint64_t id = 0;
    std::string name;
    PatchState state = PatchState::COLD;
    std::vector<float> data;
    uint64_t bytes_expanded = 0;
    uint64_t bytes_compressed = 0;
    uint64_t last_used = 0;
    uint32_t use_count = 0;
    float importance = 0.5f;
    bool pinned = false;
    int layer = -1;
    int expert_id = -1;

    float evict_score(uint64_t current_time) const {
        if (pinned) return 1e18f;
        return (1.0f / (use_count + 1)) +
               (current_time - last_used) * 0.001f -
               importance;
    }
};

struct HotPatchRegistry {
    std::vector<HotPatchEntry> entries;
    std::unordered_map<std::string, uint64_t> name_to_id;
    std::unordered_set<uint64_t> pinned_ids;
    uint64_t next_id = 0;

    uint64_t register_tensor(const std::string& name, uint64_t compressed_bytes,
                             uint64_t expanded_bytes, int layer = -1, int expert = -1) {
        auto it = name_to_id.find(name);
        if (it != name_to_id.end()) return it->second;
        HotPatchEntry e;
        e.id = next_id++;
        e.name = name;
        e.bytes_compressed = compressed_bytes;
        e.bytes_expanded = expanded_bytes;
        e.layer = layer;
        e.expert_id = expert;
        if (name == "token_embd.weight") e.importance = 1.0f;
        else if (name == "output_norm.weight") e.importance = 1.0f;
        else if (name == "output.weight") e.importance = 0.9f;
        else if (name.find("attn_norm") != std::string::npos) e.importance = 0.9f;
        else if (name.find("ffn_norm") != std::string::npos) e.importance = 0.9f;
        else if (name.find("attn") != std::string::npos) e.importance = 0.8f;
        else if (name.find("ffn_gate_inp") != std::string::npos) e.importance = 0.8f;
        else if (name.find("ffn_gate_shrd") != std::string::npos) e.importance = 0.7f;
        else if (name.find("ffn_up_shrd") != std::string::npos) e.importance = 0.7f;
        else if (name.find("ffn_down_shrd") != std::string::npos) e.importance = 0.7f;
        else if (name.find("_exp.") != std::string::npos) e.importance = 0.3f;
        else e.importance = 0.5f;
        entries.push_back(std::move(e));
        name_to_id[name] = entries.back().id;
        return entries.back().id;
    }

    void pin(const std::string& name) {
        auto it = name_to_id.find(name);
        if (it != name_to_id.end()) {
            pinned_ids.insert(it->second);
            entries[it->second].pinned = true;
            entries[it->second].importance = 1.0f;
        }
    }

    HotPatchEntry* get(uint64_t id) {
        return id < entries.size() ? &entries[id] : nullptr;
    }
    HotPatchEntry* get_by_name(const std::string& name) {
        auto it = name_to_id.find(name);
        return it != name_to_id.end() ? &entries[it->second] : nullptr;
    }

    std::vector<uint64_t> find_layer_tensors(int layer) const {
        std::vector<uint64_t> result;
        for (const auto& e : entries) if (e.layer == layer) result.push_back(e.id);
        return result;
    }
    std::vector<uint64_t> find_non_selected_experts(int layer, const std::vector<int>& selected) const {
        std::set<int> sel(selected.begin(), selected.end());
        std::vector<uint64_t> result;
        for (const auto& e : entries) {
            if (e.layer == layer && e.expert_id >= 0 && sel.find(e.expert_id) == sel.end())
                result.push_back(e.id);
        }
        return result;
    }

    std::string report() const {
        int counts[6] = {0};
        uint64_t hot_bytes = 0;
        for (const auto& e : entries) {
            counts[(int)e.state]++;
            if (e.state == PatchState::HOT) hot_bytes += e.bytes_expanded;
        }
        std::ostringstream s;
        s << "HotPatch: " << entries.size() << " tensors | "
          << "HOT=" << counts[3] << " WARM=" << counts[2]
          << " COLD=" << counts[1] << " EVICTED=" << counts[0]
          << " RECON=" << counts[5]
          << " | HOT mem: " << hot_bytes / (1024*1024) << " MB"
          << " | Pinned: " << pinned_ids.size();
        return s.str();
    }
};

// ─── 2. EXECUTION DEPENDENCY GRAPH (FIXED: residual registration) ───────────
struct ExecutionDependencyGraph {
    struct Node {
        int layer = -1;
        std::string tensor;
        std::vector<std::string> inputs;
        std::vector<std::string> outputs;
        bool residual_consumer = false;
    };
    std::vector<Node> nodes;
    std::unordered_map<std::string, std::set<int>> tensor_readers;
    std::unordered_map<std::string, int> tensor_last_writer;

    void build(int n_layers) {
        nodes.resize(n_layers);
        for (int l = 0; l < n_layers; l++) {
            nodes[l].layer = l;
            std::string p = "blk." + std::to_string(l) + ".";
            nodes[l].inputs.push_back(p + "attn_norm.weight");
            nodes[l].inputs.push_back(p + "attn_q.weight");
            nodes[l].inputs.push_back(p + "attn_k.weight");
            nodes[l].inputs.push_back(p + "attn_v.weight");
            nodes[l].inputs.push_back(p + "attn_output.weight");
            nodes[l].inputs.push_back(p + "ffn_norm.weight");
            nodes[l].inputs.push_back(p + "ffn_gate.weight");
            nodes[l].inputs.push_back(p + "ffn_up.weight");
            nodes[l].inputs.push_back(p + "ffn_down.weight");
            nodes[l].outputs.push_back("residual_" + std::to_string(l));
            nodes[l].residual_consumer = true;

            for (const auto& in : nodes[l].inputs) tensor_readers[in].insert(l);
            // FIX: register residual outputs as read by next layer
            for (const auto& out : nodes[l].outputs) {
                tensor_readers[out].insert(l + 1);  // layer l+1 reads residual from l
            }
            tensor_last_writer["residual_" + std::to_string(l)] = l;
        }
        tensor_readers["token_embd.weight"].insert(0);
        tensor_readers["output_norm.weight"].insert(n_layers);
        tensor_readers["output.weight"].insert(n_layers);
    }

    bool is_live(const std::string& name, int current_layer, int max_layer) const {
        auto it = tensor_readers.find(name);
        if (it == tensor_readers.end()) return false;
        for (int reader : it->second) {
            if (reader >= current_layer && reader <= max_layer) return true;
        }
        auto w = tensor_last_writer.find(name);
        if (w != tensor_last_writer.end() && w->second >= current_layer) return true;
        return false;
    }

    bool is_residual_pinned(int layer, int current_layer) const {
        return current_layer <= layer + 1;
    }
};

// ─── 3. TENSOR RESIDENCY MANAGER ────────────────────────────────────────────
struct TensorResidencyManager {
    struct Residency {
        uint64_t entry_id = 0;
        MemoryTier::Type location = MemoryTier::SSD;
        uint64_t resident_bytes = 0;
        bool migrating = false;
    };
    std::unordered_map<uint64_t, Residency> residency;
    DeviceMemoryTopology* topo;
    explicit TensorResidencyManager(DeviceMemoryTopology* t) : topo(t) {}

    void register_entry(uint64_t id, uint64_t compressed_bytes) {
        residency[id] = {id, MemoryTier::SSD, compressed_bytes, false};
    }

    bool promote(uint64_t id, uint64_t expanded_bytes, MemoryTier::Type target) {
        auto it = residency.find(id);
        if (it == residency.end()) return false;
        auto* tier = topo->best_tier_for_size(expanded_bytes);
        if (!tier || tier->type < target) return false;
        topo->account_alloc(tier->type, expanded_bytes);
        it->second.location = tier->type;
        it->second.resident_bytes = expanded_bytes;
        return true;
    }

    void demote(uint64_t id, uint64_t compressed_bytes) {
        auto it = residency.find(id);
        if (it == residency.end()) return;
        topo->account_free(it->second.location, it->second.resident_bytes);
        it->second.location = MemoryTier::SSD;
        it->second.resident_bytes = compressed_bytes;
    }

    MemoryTier::Type location(uint64_t id) const {
        auto it = residency.find(id);
        return it != residency.end() ? it->second.location : MemoryTier::SSD;
    }
};

// ─── 4. NEXT BLOCK PREFETCHER (FIXED: separate promote queue, no deadlock) ──
struct NextBlockPrefetcher {
    struct Job { uint64_t entry_id; std::string name; int layer; int priority; };
    std::deque<Job> promote_queue;  // main thread drains this
    std::priority_queue<Job, std::vector<Job>, std::function<bool(const Job&,const Job&)>> queue{
        [](const Job& a, const Job& b){ return a.priority > b.priority; }};
    std::atomic<bool> running{false};
    std::thread worker;
    mutable std::mutex mtx;
    std::condition_variable cv;
    std::function<void(const std::string&)> on_prefetch;

    double compute_time_per_layer_ms = 5.0;
    double ssd_bandwidth_gbps = 3.5;

    void start() {
        running = true;
        worker = std::thread([this](){
            while (running.load()) {
                std::unique_lock<std::mutex> lock(mtx);
                cv.wait(lock, [this]{ return !queue.empty() || !running.load(); });
                if (!running.load()) break;
                if (queue.empty()) continue;
                Job job = queue.top(); queue.pop();
                lock.unlock();
                // Only queue to promote_queue — main thread calls uncold()
                {
                    std::lock_guard<std::mutex> plock(mtx);
                    promote_queue.push_back(job);
                }
            }
        });
    }
    void stop() {
        running = false;
        cv.notify_all();
        if (worker.joinable()) worker.join();
    }

    void schedule(int current_layer, int n_layers, int lookahead,
                    const std::vector<std::string>& tensor_names,
                    const std::function<uint64_t(const std::string&)>& bytes_fn) {
        double budget_ms = compute_time_per_layer_ms;
        for (int ahead = 1; ahead <= lookahead && current_layer + ahead < n_layers; ++ahead) {
            int target = current_layer + ahead;
            for (const auto& name : tensor_names) {
                if (name.find("blk." + std::to_string(target) + ".") == std::string::npos) continue;
                uint64_t b = bytes_fn(name);
                double load_ms = (b / (1024.0*1024.0*1024.0)) / ssd_bandwidth_gbps * 1000.0;
                if (load_ms > budget_ms) continue;
                std::lock_guard<std::mutex> lock(mtx);
                queue.push({0, name, target, ahead});
            }
            budget_ms += compute_time_per_layer_ms;
        }
        cv.notify_one();
    }

    // Call from main thread only — drains promote_queue safely
    void drain_promote_queue(const std::function<void(const std::string&)>& promote_fn) {
        std::lock_guard<std::mutex> lock(mtx);
        while (!promote_queue.empty()) {
            auto job = promote_queue.front();
            promote_queue.pop_front();
            promote_fn(job.name);
        }
    }
};

// ─── 5. COLD BLOCK PREDICTOR ────────────────────────────────────────────────
struct ColdBlockPredictor {
    ExecutionDependencyGraph* dep;
    int max_layer = 0;
    explicit ColdBlockPredictor(ExecutionDependencyGraph* d, int ml) : dep(d), max_layer(ml) {}

    float score(const HotPatchEntry& e, int current_layer, uint64_t now) const {
        if (dep && dep->is_live(e.name, current_layer, max_layer)) return 1e18f;
        if (e.name.find("residual_") == 0) {
            int l = std::stoi(e.name.substr(9));
            if (dep && dep->is_residual_pinned(l, current_layer)) return 1e18f;
        }
        return e.evict_score(now);
    }
};

// ─── 6. EXPERT AFFINITY CACHE ───────────────────────────────────────────────
struct ExpertAffinityCache {
    struct LayerStats {
        std::unordered_map<int, uint64_t> select_count;
        uint64_t total = 0;
    };
    std::vector<LayerStats> layers;
    float threshold = 0.15f;
    int warmup_top_n = 3;

    void init(int n_layers) { layers.resize(n_layers); }

    void record(int layer, const std::vector<int>& selected) {
        if (layer >= (int)layers.size()) return;
        auto& ls = layers[layer];
        for (int e : selected) { ls.select_count[e]++; ls.total++; }
    }

    std::vector<int> predict(int layer) const {
        std::vector<int> hot;
        if (layer >= (int)layers.size() || layers[layer].total == 0) return hot;
        std::vector<std::pair<float,int>> scored;
        for (const auto& [eid, cnt] : layers[layer].select_count) {
            scored.push_back({(float)cnt / (float)layers[layer].total, eid});
        }
        std::sort(scored.begin(), scored.end(), std::greater<>());
        for (const auto& [p, eid] : scored) {
            if (p >= threshold) hot.push_back(eid);
            if ((int)hot.size() >= warmup_top_n) break;
        }
        return hot;
    }

    std::vector<std::string> prefetch_names(int layer, const std::vector<int>& experts,
                                            const std::string& prefix) const {
        std::vector<std::string> names;
        for (int e : experts) {
            names.push_back(prefix + "ffn_gate_exp." + std::to_string(e) + ".weight");
            names.push_back(prefix + "ffn_up_exp." + std::to_string(e) + ".weight");
            names.push_back(prefix + "ffn_down_exp." + std::to_string(e) + ".weight");
        }
        return names;
    }
};

// ─── 7. PAGED KV CACHE (FIXED: swap() for guaranteed free) ─────────────────
struct PagedKVCache {
    static constexpr int PAGE_TOKENS = 128;
    enum KVT { FULL, KV_INT8, BIN, MERGED, EVICTED };
    struct Page {
        int start_pos = 0;
        int layer = 0;
        KVT state = FULL;
        std::vector<float> k;
        std::vector<float> v;
        std::vector<int8_t> k_i8, v_i8;
        std::vector<float> k_scale, v_scale;
        uint64_t last_access = 0;
        float importance = 0.0f;
    };
    int n_layers = 0, dim = 0, max_pages = 0;
    std::vector<std::vector<std::unique_ptr<Page>>> pages;
    mutable std::atomic<uint64_t> access_seq{0};

    void init(int nl, int d, int max_tokens) {
        n_layers = nl; dim = d;
        max_pages = (max_tokens + PAGE_TOKENS - 1) / PAGE_TOKENS;
        pages.resize(nl);
    }

    void add(int layer, int pos, const float* kd, const float* vd) {
        int pidx = pos / PAGE_TOKENS;
        if (pidx >= max_pages) return;
        auto& layer_pages = pages[layer];
        if (pidx >= (int)layer_pages.size()) layer_pages.resize(pidx + 1);
        if (!layer_pages[pidx]) {
            layer_pages[pidx] = std::make_unique<Page>();
            layer_pages[pidx]->start_pos = pidx * PAGE_TOKENS;
            layer_pages[pidx]->layer = layer;
            layer_pages[pidx]->k.resize(PAGE_TOKENS * dim);
            layer_pages[pidx]->v.resize(PAGE_TOKENS * dim);
        }
        auto* pg = layer_pages[pidx].get();
        int off = (pos % PAGE_TOKENS) * dim;
        memcpy(pg->k.data() + off, kd, dim * 4);
        memcpy(pg->v.data() + off, vd, dim * 4);
        pg->last_access = ++access_seq;
    }

    void get(int layer, int pos, std::vector<float>& kout, std::vector<float>& vout) const {
        kout.assign(dim, 0.0f); vout.assign(dim, 0.0f);
        int pidx = pos / PAGE_TOKENS;
        if (layer >= (int)pages.size() || pidx >= (int)pages[layer].size() || !pages[layer][pidx]) return;
        const auto* pg = pages[layer][pidx].get();
        if (pg->state == EVICTED) return;
        int off = (pos % PAGE_TOKENS) * dim;
        if (pg->state == FULL) {
            memcpy(kout.data(), pg->k.data() + off, dim * 4);
            memcpy(vout.data(), pg->v.data() + off, dim * 4);
        } else if (pg->state == KV_INT8) {
            for (int d = 0; d < dim; d++) {
                int b = (off + d) / 32;
                float s = b < (int)pg->k_scale.size() ? pg->k_scale[b] : 1.0f;
                kout[d] = (float)pg->k_i8[off + d] * s;
                s = b < (int)pg->v_scale.size() ? pg->v_scale[b] : 1.0f;
                vout[d] = (float)pg->v_i8[off + d] * s;
            }
        }
        pg->last_access = ++access_seq;
    }

    // FIXED: use swap() for guaranteed deallocation
    void compress_oldest(size_t target_bytes) {
        size_t current = bytes();
        if (current <= target_bytes) return;
        std::vector<Page*> all;
        for (auto& l : pages) for (auto& p : l) if (p) all.push_back(p.get());
        std::sort(all.begin(), all.end(), [](Page* a, Page* b){ return a->last_access < b->last_access; });
        for (Page* pg : all) {
            if (pg->state == FULL) {
                pg->state = KV_INT8;
                int n = PAGE_TOKENS * dim;
                int nb = (n + 31) / 32;
                pg->k_scale.resize(nb); pg->v_scale.resize(nb);
                pg->k_i8.resize(n); pg->v_i8.resize(n);
                for (int b = 0; b < nb; b++) {
                    int st = b * 32, en = std::min(st + 32, n);
                    float mxk = 0, mxv = 0;
                    for (int i = st; i < en; i++) { mxk = std::max(mxk, std::abs(pg->k[i])); mxv = std::max(mxv, std::abs(pg->v[i])); }
                    pg->k_scale[b] = mxk / 127.0f; pg->v_scale[b] = mxv / 127.0f;
                    for (int i = st; i < en; i++) {
                        pg->k_i8[i] = (int8_t)(pg->k[i] / (pg->k_scale[b] + 1e-12f));
                        pg->v_i8[i] = (int8_t)(pg->v[i] / (pg->v_scale[b] + 1e-12f));
                    }
                }
                // FIXED: guaranteed deallocation
                std::vector<float>().swap(pg->k);
                std::vector<float>().swap(pg->v);
                current = bytes();
                if (current <= target_bytes) break;
            }
        }
    }

    size_t bytes() const {
        size_t b = 0;
        for (const auto& l : pages) {
            for (const auto& p : l) {
                if (!p) continue;
                if (p->state == FULL) b += (p->k.size() + p->v.size()) * 4;
                else if (p->state == KV_INT8) b += p->k_i8.size() + p->v_i8.size() + (p->k_scale.size() + p->v_scale.size()) * 4;
            }
        }
        return b;
    }

    std::string report() const {
        int n_full = 0, n_i8 = 0, n_evict = 0;
        for (const auto& l : pages) for (const auto& p : l) if (p) {
            if (p->state == FULL) n_full++;
            else if (p->state == KV_INT8) n_i8++;
            else if (p->state == EVICTED) n_evict++;
        }
        std::ostringstream s;
        s << "PagedKV: " << bytes()/(1024*1024) << "MB  FULL=" << n_full
          << " INT8=" << n_i8 << " EVICT=" << n_evict << "\n";
        return s.str();
    }
};

// ─── 8. HOTPATCH TRANSACTION LOG ────────────────────────────────────────────
struct HotpatchTransactionLog {
    enum Op { PROMOTE, DEMOTE, EVICT, PIN, UNPIN };
    struct Entry {
        Op op;
        uint64_t entry_id;
        PatchState old_state;
        PatchState new_state;
        uint64_t timestamp;
    };
    std::deque<Entry> log;
    size_t max_entries = 10000;
    mutable std::mutex mtx;

    void append(Op op, uint64_t id, PatchState old_s, PatchState new_s) {
        std::lock_guard<std::mutex> lock(mtx);
        log.push_back({op, id, old_s, new_s, (uint64_t)std::chrono::steady_clock::now().time_since_epoch().count()});
        if (log.size() > max_entries) log.pop_front();
    }

    std::vector<Entry> get_rollback_plan(uint64_t id, size_t n_ops = 1) const {
        std::vector<Entry> plan;
        std::lock_guard<std::mutex> lock(mtx);
        for (auto it = log.rbegin(); it != log.rend() && plan.size() < n_ops; ++it) {
            if (it->entry_id == id) plan.push_back(*it);
        }
        return plan;
    }

    std::string report() const {
        std::lock_guard<std::mutex> lock(mtx);
        std::ostringstream s;
        s << "TxLog: " << log.size() << " entries\n";
        return s.str();
    }
};

// ─── 9. QUANT CALIBRATION CACHE ─────────────────────────────────────────────
struct QuantCalibrationCache {
    struct Correction {
        std::vector<float> delta;
        uint32_t block_id = 0;
        float max_error_before = 0;
        float max_error_after = 0;
    };
    std::unordered_map<uint64_t, Correction> cache;
    mutable std::mutex mtx;

    void store(uint64_t entry_id, const std::vector<float>& original, const std::vector<float>& reconstructed) {
        if (original.size() != reconstructed.size()) return;
        std::lock_guard<std::mutex> lock(mtx);
        Correction c; c.delta.resize(original.size());
        float mx_before = 0, mx_after = 0;
        for (size_t i = 0; i < original.size(); i++) {
            float err = std::abs(original[i] - reconstructed[i]);
            mx_before = std::max(mx_before, err);
            c.delta[i] = original[i] - reconstructed[i];
        }
        for (size_t i = 0; i < original.size(); i++) {
            float err = std::abs(original[i] - (reconstructed[i] + c.delta[i]));
            mx_after = std::max(mx_after, err);
        }
        c.max_error_before = mx_before;
        c.max_error_after = mx_after;
        cache[entry_id] = std::move(c);
    }

    bool apply(uint64_t entry_id, std::vector<float>& data) const {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = cache.find(entry_id);
        if (it == cache.end() || it->second.delta.size() != data.size()) return false;
        for (size_t i = 0; i < data.size(); i++) data[i] += it->second.delta[i];
        return true;
    }

    std::string report() const {
        std::lock_guard<std::mutex> lock(mtx);
        std::ostringstream s;
        s << "CalibCache: " << cache.size() << " blocks\n";
        return s.str();
    }
};

// ─── 10. ORCHESTRATOR (FIXED: all 5 critical bugs patched) ───────────────────
struct Orchestrator {
    HotPatchRegistry* registry;
    GGUF* gguf;
    DeviceMemoryTopology topo;
    ExecutionDependencyGraph depgraph;
    TensorResidencyManager residency;
    NextBlockPrefetcher prefetcher;
    ColdBlockPredictor predictor;
    ExpertAffinityCache expert_cache;
    PagedKVCache paged_kv;
    HotpatchTransactionLog txlog;
    QuantCalibrationCache calib;

    uint64_t budget_bytes = 8ULL * 1024 * 1024 * 1024;
    uint64_t current_hot_bytes = 0;
    int lookahead = 3;
    int current_layer = 0;
    int n_layers = 0;

    std::atomic<uint64_t> promotes{0}, demotes{0}, evictions{0};
    std::atomic<uint64_t> cache_hits{0}, cache_misses{0}, prefetches{0};
    std::atomic<uint64_t> rollbacks{0}, calib_applied{0};

    mutable std::mutex mtx;
    // FIXED (6): ordered set for O(log n) eviction instead of O(n) sort
    std::set<std::pair<float, uint64_t>> eviction_index;

    Orchestrator(HotPatchRegistry* r, GGUF* g) : registry(r), gguf(g), residency(&topo), predictor(&depgraph, 0) {
        topo.init_default();
        topo.probe_runtime();
        // FIXED (6): budget pulls from VRAM capacity at runtime
        budget_bytes = topo.vram_capacity();
        prefetcher.on_prefetch = [this](const std::string& name){};
    }

    void init_model(int nl) {
        n_layers = nl;
        depgraph.build(nl);
        predictor = ColdBlockPredictor(&depgraph, nl);
        expert_cache.init(nl);
        prefetcher.start();
    }

    ~Orchestrator() { prefetcher.stop(); }

    // ─── Uncold with calibration + transaction logging ─────────────────────
    // ─── Resolve returns a TensorHandle ──────────────────────────────
    TensorHandle resolve(const std::string& name) {
        TensorHandle handle = {};
        handle.name = name.c_str();
        
        std::lock_guard<std::mutex> lock(mtx);
        auto* entry = registry->get_by_name(name);
        if (!entry) return handle;

        handle.bytes = entry->bytes_expanded;
        // Currently not tracking GPU pointer or quant data in HotPatchEntry directly yet
        // but we setup the handle structure here.
        handle.device_ptr = nullptr; 
        handle.is_quantized = false;
        handle.quant_kind = 0;
        
        // FIXED (3): if state is RECONSTRUCT_NEEDED, must reload from GGUF
        if (entry->state == PatchState::RECONSTRUCT_NEEDED) {
            entry->data.clear(); entry->data.shrink_to_fit();
            entry->state = PatchState::COLD;
        }

        if (entry->state == PatchState::HOT) {
            entry->use_count++;
            entry->last_used = (uint64_t)std::chrono::steady_clock::now().time_since_epoch().count();
            cache_hits++;
            handle.host_ptr = entry->data.data();
            handle.is_hot = true;
            return handle;
        }

        cache_misses++;
        PatchState old_state = entry->state;

        while (current_hot_bytes + entry->bytes_expanded > budget_bytes) {
            if (!evict_lowest_score()) break;
        }

        auto* t = gguf->get(name);
        if (!t) return handle;

        entry->data.resize(t->elems());
        // NOTE: dequant() must be provided by includer (rawrxd.cpp)
        extern void dequant(const GGTensor&, float*);
        dequant(*t, entry->data.data());

        if (calib.apply(entry->id, entry->data)) calib_applied++;

        entry->state = PatchState::HOT;
        entry->use_count++;
        entry->last_used = (uint64_t)std::chrono::steady_clock::now().time_since_epoch().count();
        current_hot_bytes += entry->bytes_expanded;
        promotes++;

        txlog.append(HotpatchTransactionLog::PROMOTE, entry->id, old_state, PatchState::HOT);
        residency.promote(entry->id, entry->bytes_expanded, MemoryTier::RAM);

        // FIXED (7): update eviction index
        eviction_index.insert({entry->evict_score(entry->last_used), entry->id});

        handle.host_ptr = entry->data.data();
        handle.is_hot = true;
        return handle;
    }

    const float* uncold(const std::string& name) {
        return reinterpret_cast<const float*>(resolve(name).host_ptr);
    }

    // ─── Demote with logging ───────────────────────────────────────────────
    void demote(const std::string& name) {
        std::lock_guard<std::mutex> lock(mtx);
        auto* entry = registry->get_by_name(name);
        if (!entry || entry->state != PatchState::HOT) return;
        PatchState old_state = entry->state;
        current_hot_bytes -= entry->bytes_expanded;
        entry->data.clear(); entry->data.shrink_to_fit();
        entry->state = PatchState::COLD;
        demotes++;
        txlog.append(HotpatchTransactionLog::DEMOTE, entry->id, old_state, PatchState::COLD);
        residency.demote(entry->id, entry->bytes_compressed);
        eviction_index.erase({entry->evict_score(entry->last_used), entry->id});
    }

    // ─── Dependency-aware eviction (FIXED: O(log n) via ordered set) ─────
    bool evict_lowest_score() {
        uint64_t now = (uint64_t)std::chrono::steady_clock::now().time_since_epoch().count();
        std::lock_guard<std::mutex> lock(mtx);

        // Rebuild index if stale (simple approach: clear and rebuild on miss)
        if (eviction_index.empty()) {
            for (const auto& e : registry->entries) {
                if (e.state == PatchState::HOT && !e.pinned) {
                    float s = predictor.score(e, current_layer, now);
                    eviction_index.insert({s, e.id});
                }
            }
        }

        if (eviction_index.empty()) return false;
        auto it = eviction_index.begin();
        uint64_t id = it->second;
        eviction_index.erase(it);

        auto* entry = registry->get(id);
        if (!entry) return false;
        PatchState old_state = entry->state;
        if (entry->state == PatchState::HOT) {
            current_hot_bytes -= entry->bytes_expanded;
            entry->data.clear(); entry->data.shrink_to_fit();
        }
        entry->state = PatchState::COLD;
        evictions++;
        txlog.append(HotpatchTransactionLog::EVICT, id, old_state, PatchState::COLD);
        residency.demote(id, entry->bytes_compressed);
        return true;
    }

    void evict_layer(int layer) {
        std::lock_guard<std::mutex> lock(mtx);
        auto ids = registry->find_layer_tensors(layer);
        for (auto id : ids) {
            auto* e = registry->get(id);
            if (!e || e->pinned) continue;
            if (depgraph.is_live(e->name, current_layer, n_layers)) continue;
            PatchState old_state = e->state;
            if (e->state == PatchState::HOT) {
                current_hot_bytes -= e->bytes_expanded;
                e->data.clear(); e->data.shrink_to_fit();
            }
            e->state = PatchState::COLD;
            evictions++;
            txlog.append(HotpatchTransactionLog::EVICT, id, old_state, PatchState::COLD);
            residency.demote(id, e->bytes_compressed);
            eviction_index.erase({e->evict_score(e->last_used), id});
        }
    }

    void evict_non_selected_experts(int layer, const std::vector<int>& selected) {
        std::lock_guard<std::mutex> lock(mtx);
        auto ids = registry->find_non_selected_experts(layer, selected);
        for (auto id : ids) {
            auto* e = registry->get(id);
            if (!e || e->pinned) continue;
            PatchState old_state = e->state;
            if (e->state == PatchState::HOT) {
                current_hot_bytes -= e->bytes_expanded;
                e->data.clear(); e->data.shrink_to_fit();
            }
            e->state = PatchState::COLD;
            evictions++;
            txlog.append(HotpatchTransactionLog::EVICT, id, old_state, PatchState::COLD);
            residency.demote(id, e->bytes_compressed);
            eviction_index.erase({e->evict_score(e->last_used), id});
        }
    }

    // ─── Rollback (FIXED: marks RECONSTRUCT_NEEDED, not fake HOT) ──────────
    bool rollback(uint64_t entry_id) {
        auto plan = txlog.get_rollback_plan(entry_id, 3);
        if (plan.empty()) return false;
        std::lock_guard<std::mutex> lock(mtx);
        for (const auto& e : plan) {
            auto* ent = registry->get(e.entry_id);
            if (!ent) continue;
            // FIXED (3): clear data and mark for reconstruction instead of lying about state
            if (ent->state == PatchState::HOT && e.old_state != PatchState::HOT) {
                current_hot_bytes -= ent->bytes_expanded;
                ent->data.clear(); ent->data.shrink_to_fit();
            }
            ent->state = PatchState::RECONSTRUCT_NEEDED;
        }
        rollbacks++;
        return true;
    }

    // ─── Smart prefetch: dependency graph + expert affinity ────────────────
    void prefetch_layers(int current_l, int nl) {
        current_layer = current_l;
        std::vector<std::string> candidates;
        for (int ahead = 1; ahead <= lookahead && current_l + ahead < nl; ++ahead) {
            int target = current_l + ahead;
            std::string prefix = "blk." + std::to_string(target) + ".";
            candidates.push_back(prefix + "attn_norm.weight");
            candidates.push_back(prefix + "attn_q.weight");
            candidates.push_back(prefix + "attn_k.weight");
            candidates.push_back(prefix + "attn_v.weight");
            candidates.push_back(prefix + "attn_output.weight");
            candidates.push_back(prefix + "ffn_norm.weight");
            candidates.push_back(prefix + "ffn_gate.weight");
            candidates.push_back(prefix + "ffn_up.weight");
            candidates.push_back(prefix + "ffn_down.weight");
        }
        auto likely = expert_cache.predict(current_l);
        auto exp_names = expert_cache.prefetch_names(current_l, likely, "blk." + std::to_string(current_l) + ".");
        candidates.insert(candidates.end(), exp_names.begin(), exp_names.end());

        for (const auto& name : candidates) {
            auto* e = registry->get_by_name(name);
            if (e && e->state != PatchState::HOT) {
                prefetcher.schedule(current_l, nl, lookahead, {name},
                    [this](const std::string& n){ auto* e2=registry->get_by_name(n); return e2?e2->bytes_compressed:0; });
            }
        }
    }

    // FIXED (4): drain prefetch promote queue from main thread (no deadlock)
    void drain_prefetch() {
        prefetcher.drain_promote_queue([this](const std::string& name) {
            this->uncold(name);
            prefetches++;
        });
    }

    void wait_prefetch() { drain_prefetch(); }

    void pin_critical() {
        registry->pin("token_embd.weight");
        registry->pin("output_norm.weight");
        auto* emb = registry->get_by_name("token_embd.weight");
        auto* out = registry->get_by_name("output_norm.weight");
        if (emb) txlog.append(HotpatchTransactionLog::PIN, emb->id, PatchState::COLD, PatchState::HOT);
        if (out) txlog.append(HotpatchTransactionLog::PIN, out->id, PatchState::COLD, PatchState::HOT);
    }

    void pin_layer_attention(int layer) {
        std::string p = "blk." + std::to_string(layer) + ".";
        registry->pin(p + "attn_norm.weight");
        if (layer > 0) {
            std::string pp = "blk." + std::to_string(layer - 1) + ".";
            auto* e = registry->get_by_name(pp + "attn_norm.weight");
            if (e) { e->pinned = false; e->importance = 0.5f; registry->pinned_ids.erase(e->id); }
        }
    }

    void record_experts(int layer, const std::vector<int>& selected) {
        expert_cache.record(layer, selected);
    }

    std::string report() const {
        std::ostringstream s;
        s << "=== ORCHESTRATOR ===\n";
        s << "Budget: " << budget_bytes/(1024*1024) << " MB | Used: " << current_hot_bytes/(1024*1024) << " MB\n";
        s << "Promotes: " << promotes.load() << " | Demotes: " << demotes.load()
          << " | Evictions: " << evictions.load() << " | Prefetches: " << prefetches.load() << "\n";
        s << "Cache: hits=" << cache_hits.load() << " misses=" << cache_misses.load()
          << " | Rollbacks: " << rollbacks.load() << " | Calib: " << calib_applied.load() << "\n";
        s << "--- Topology ---\n" << topo.report();
        s << "--- " << registry->report() << "\n";
        s << "--- " << txlog.report();
        s << "--- " << calib.report();
        s << "--- " << paged_kv.report();
        return s.str();
    }
};
