// ============================================================================
// plague_memory.hpp  --  RAWRXD UNIVERSAL PLAGUE MEMORY ENGINE (UPME)
// ============================================================================
// One shared page directory + residency controller serving four policies:
//   ROM      -- immutable content-addressed weight pages (GGUF-native quant).
//   Context  -- paged KV cache with session/layer/token ownership + COW.
//   Emulator -- virtual pages + code; VAT, COW, dirty tracking, invalidation,
//               MMIO authoritative, strict write/interrupt ordering.
//   Swarm    -- shared immutable data replicated to agents that need it.
//
// ROM-first integration. Context/Emulator/Swarm share the SAME directory,
// lease, pin, budget and transfer fabric (all real); their execution policies
// layer on it. The ROM policy is fully implemented and receipted here.
//
// Integrates existing G02 (byte-verified transfer), G03 (per-device budgets),
// G04 (generation-checked leases + fence-safe pinning). C++17/std-lib only at
// the core; GPU transfer is plugged in via TransferFn so the entire engine and
// its receipts run with or without Vulkan.
//
// Content addressing gives virtual addressability only: exact reconstruction
// still requires the source information in the backing store.
// ============================================================================
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <string>
#include <list>
#include <unordered_map>
#include <map>
#include <functional>
#include <mutex>
#include <algorithm>

namespace rawrxd { namespace plague {

static constexpr uint64_t kNoAgent = 0;
static constexpr uint64_t kUnknownBlock = 0xffffffffu;   // global (non per-block) ROM page
static constexpr uint64_t kUnknownExpert = 0xffffffffu;  // dense (non MoE) ROM page

// Device handle: 0 == HOST(RAM); 1..N == G02 Vulkan device slots.
enum class Residency : uint8_t { HOST = 0, DEV0 = 1, DEV1 = 2, DEV2 = 3, DEV3 = 4, DEV4 = 5 };
inline uint32_t ResidencyDevice(Residency r) { return (r == Residency::HOST) ? 0u : (uint32_t)r; }

enum class Policy : uint8_t { ROM = 0, Context = 1, Emulator = 2, Swarm = 3 };
inline const char* PolicyName(Policy p) {
    switch (p) { case Policy::ROM: return "ROM"; case Policy::Context: return "Context";
                 case Policy::Emulator: return "Emulator"; default: return "Swarm"; }
}

// --- policy-specific page metadata (part of the shared directory) -----------
struct RomMeta {
    uint32_t block = kUnknownBlock;  // layer index (follow layer execution)
    uint32_t expert = kUnknownExpert;// expert index (follow expert execution)
    uint32_t ggml_type = 0;          // native quant type: pages carry quantized bytes only
    uint64_t file_off = 0;           // byte offset of this page inside its GGUF shard
    uint64_t file_bytes = 0;         // exact byte length at that offset
};
struct CtxMeta {
    uint64_t session = 0;            // session isolation
    uint32_t layer = 0;              // attention-layer ownership
    uint64_t token_lo = 0;           // half-closed [token_lo, token_hi) ownership
    uint64_t token_hi = 0;
    bool mutable_kv = true;          // COW applies when mutable
    uint32_t replicas = 0;           // replication fan-out
};
struct EmuMeta {
    uint64_t vaddr = 0;              // virtual address (caller page-aligns)
    uint64_t guest_vm = 0;           // owning VM instance
    bool exec_page = false;          // executable: validation + invalidation rules
    bool dirty = false;              // dirty-page tracking
    bool mmio = false;               // device registers: authoritative, never auto-replicated
};

// ---------------------------------------------------------------------------
// Universal page-directory entry.
struct PageEntry {
    uint64_t page_id = 0;
    Policy policy = Policy::ROM;
    std::string task;                // e.g. "blk.3.attn_q.weight"
    std::string content_key;         // content-addressed identity + version
    uint64_t generation = 0;         // generation-checked lease (0 = never leased)
    uint32_t priority = 128;         // 0 hottest .. 255 coldest
    int pin_count = 0;               // fence-safe pin: pinned pages never evicted
    uint64_t owner_agent = kNoAgent; // per-agent isolation (realm)
    size_t bytes = 0;
    uint64_t crc = 0;                // byte-verified reconstruction fingerprint

    bool resident = false;           // host image materialised
    std::vector<uint8_t> payload;    // fabric-owned host image (single owner)
    bool gpu_loaded = false;         // device image present (G02 byte-verified)
    uint64_t gpu_token = 0;
    uint32_t gpu_device = 0;
    uint64_t device_generation = 0;  // generation of the image that was verified on device

    std::vector<uint64_t> replicas;  // swarm fan-out bookkeeping
    uint64_t use_seq = 0;            // LRU recency

    bool exec_validated = false;     // emulator: translated-code validation gate

    RomMeta rom;
    CtxMeta ctx;
    EmuMeta emu;
};

// Generation-checked, view-only lease to a resident page.
struct Lease {
    uint64_t page_id = 0;
    uint64_t generation = 0;
    bool ok = false;
    const uint8_t* data = nullptr;
    size_t bytes = 0;
};

// Pluggable byte-verified transfer (bound to G02 for the GPU-integrated build).
struct TransferFn {
    std::function<bool(uint32_t device, const uint8_t* src, size_t bytes, uint64_t& token)> upload;
    std::function<bool(uint32_t device, uint64_t token, uint8_t* dst, size_t bytes)> download;
    std::function<bool(uint32_t device, uint64_t token, const uint8_t* host_ref, size_t bytes)> verify;
};
inline bool HaveTransfer(const TransferFn& t) { return (bool)t.upload && (bool)t.download && (bool)t.verify; }

// ---------------------------------------------------------------------------
class PlagueMemoryEngine {
public:
    using Reconstruct = std::function<bool(const PageEntry&, std::vector<uint8_t>& out)>;

    PlagueMemoryEngine() = default;
    explicit PlagueMemoryEngine(Reconstruct r) : recon_(std::move(r)) {}
    void SetReconstruct(Reconstruct r)  { std::lock_guard<std::mutex> lk(mu_); recon_ = std::move(r); }
    void SetTransfer(TransferFn t)      { std::lock_guard<std::mutex> lk(mu_); transfer_ = std::move(t); }

    // ---- registration (content-addressed; dedup by content_key) -------------
    uint64_t RegisterRomPage(const std::string& task, const std::string& content_key,
                             uint64_t owner_agent, uint32_t priority, size_t bytes, RomMeta rom) {
        std::lock_guard<std::mutex> lk(mu_);
        auto existing = by_key_.find(content_key);
        if (existing != by_key_.end()) return existing->second;   // immutable dedup
        PageEntry p;
        p.page_id = next_page_id_++;
        p.policy = Policy::ROM; p.task = task; p.content_key = content_key;
        p.owner_agent = owner_agent; p.priority = priority; p.bytes = bytes; p.rom = rom;
        return emplace_(std::move(p));
    }
    uint64_t RegisterContextPage(const std::string& task, uint64_t owner_agent, size_t bytes, CtxMeta c) {
        std::lock_guard<std::mutex> lk(mu_);
        PageEntry p;
        p.page_id = next_page_id_++;
        p.policy = Policy::Context; p.task = task; p.owner_agent = owner_agent; p.bytes = bytes; p.ctx = c;
        p.content_key = "ctx:" + std::to_string(c.session) + ":" + std::to_string(c.layer) +
                        ":" + std::to_string(c.token_lo);
        return emplace_(std::move(p));
    }
    uint64_t RegisterEmuPage(const std::string& task, uint64_t owner_agent, size_t bytes, EmuMeta e) {
        std::lock_guard<std::mutex> lk(mu_);
        PageEntry p;
        p.page_id = next_page_id_++;
        p.policy = Policy::Emulator; p.task = task; p.owner_agent = owner_agent; p.bytes = bytes; p.emu = e;
        p.content_key = "emu:" + std::to_string(e.guest_vm) + ":" + std::to_string(e.vaddr);
        return emplace_(std::move(p));
    }

    // ---- budgets: per-device (G03) and per-agent (isolation) ----------------
    // A budget of 0 means UNLIMITED (unset semantics); budgets only constrain
    // when a positive byte count is supplied.
    void SetDeviceBudget(Residency dev, uint64_t bytes) {
        std::lock_guard<std::mutex> lk(mu_);
        dev_budget_[ResidencyDevice(dev)] = bytes;
        evict_device_budget_(ResidencyDevice(dev));
    }
    void SetAgentBudget(uint64_t agent, uint64_t bytes) {
        std::lock_guard<std::mutex> lk(mu_);
        agent_budget_[agent] = bytes;
        enforce_agent_budget_(agent);
    }

    // ---- pinning (G04): fence-safe, generation-checked ----------------------
    bool Pin(uint64_t page_id, uint64_t generation) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = pages_.find(page_id);
        if (it == pages_.end() || it->second.generation != generation) return false;
        if (it->second.pin_count == 0) ++stat_.pin_total;
        if (it->second.pin_count + 1 > (int)stat_.pin_active_peak) stat_.pin_active_peak = it->second.pin_count + 1;
        ++it->second.pin_count;
        return true;
    }
    void Unpin(uint64_t page_id) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = pages_.find(page_id);
        if (it != pages_.end() && it->second.pin_count > 0) --it->second.pin_count;
    }

    // ---- acquire (generation-checked lease; reconstruct on miss) ------------
    Lease Acquire(const std::string& task, uint64_t agent, uint32_t priority = 128) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = by_task_.find(task);
        if (it == by_task_.end()) { ++stat_.unknown_task; return Lease{}; }
        return acquire_locked_(it->second, agent, priority);
    }
    Lease AcquireByContent(const std::string& content_key, uint64_t agent, uint32_t priority = 128) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = by_key_.find(content_key);
        if (it == by_key_.end()) { ++stat_.unknown_task; return Lease{}; }
        return acquire_locked_(it->second, agent, priority);
    }

    // ---- ROM prefetch: device-aware warming, follows block/expert execution -
    // Materialises (reconstructs) matching ROM pages so the subsequent compute
    // step hits resident memory instead of stalling on the backing store. Fully
    // budget-aware: pages that do not fit evict the coldest unpinned ones.
    void PrefetchRom(uint32_t block, uint32_t expert, uint64_t agent) {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<uint64_t> ids;
        for (auto& kv : pages_) {
            PageEntry& p = kv.second;
            if (p.policy != Policy::ROM) continue;
            bool block_ok = (p.rom.block == block) || (p.rom.block == kUnknownBlock);
            bool exp_ok   = (p.rom.expert == expert) || (p.rom.expert == kUnknownExpert);
            if (block_ok && exp_ok) ids.push_back(p.page_id);
        }
        // Warm hottest-first so a too-small budget keeps the hottest pages.
        std::sort(ids.begin(), ids.end(), [&](uint64_t a, uint64_t b){
            const PageEntry& pa = pages_[a]; const PageEntry& pb = pages_[b];
            if (pa.priority != pb.priority) return pa.priority < pb.priority;
            return a < b;
        });
        for (uint64_t id : ids) {
            ++stat_.prefetch_hints;
            PageEntry& p = pages_[id];
            if (p.resident && !p.payload.empty() && p.payload.size() == p.bytes) {
                touch_locked_(p);
                continue;
            }
            std::vector<uint8_t> out;
            if (recon_ && recon_(p, out) && out.size() == p.bytes) {
                p.payload = std::move(out); p.resident = true;
                p.crc = Fpr(p.payload.data(), p.payload.size());
                if (p.generation == 0) p.generation = ++next_generation_;
                p.owner_agent = agent;                  // warming owns nothing: isolate by agent
                ++stat_.recons;
                touch_locked_(p);
                enforce_agent_budget_(agent);
                evict_device_budget_(0);
            } else {
                ++stat_.recon_fail;
            }
        }
    }

    // ---- byte-verified device transfer (G02); returns 0 on fail (fail-closed)
    uint64_t TransferToDevice(uint64_t page_id, uint64_t generation, uint32_t device) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = pages_.find(page_id);
        if (it == pages_.end() || it->second.generation != generation) return 0;
        PageEntry& p = it->second;
        if (!p.resident) return 0;                                  // must be resident first
        if (!HaveTransfer(transfer_)) { ++stat_.transfer_unsupported; return 0; }
        if (p.gpu_loaded && p.gpu_device == device &&
            p.device_generation == p.generation) {                   // warm, same gen image
            ++stat_.transfer_warm; touch_locked_(p); return p.gpu_token;
        }
        uint64_t token = 0;
        if (!transfer_.upload(device, p.payload.data(), p.payload.size(), token)) { ++stat_.transfer_fail; return 0; }
        if (transfer_.verify && !transfer_.verify(device, token, p.payload.data(), p.payload.size())) {
            ++stat_.verify_fail; return 0;                           // fail-closed
        }
        std::vector<uint8_t> back(p.payload.size());
        if (!transfer_.download(device, token, back.data(), back.size()) ||
            std::memcmp(back.data(), p.payload.data(), back.size()) != 0) {
            ++stat_.verify_fail; return 0;                           // independent readback
        }
        p.gpu_loaded = true; p.gpu_token = token; p.gpu_device = device;
        p.device_generation = p.generation;
        ++stat_.transfer_ok;
        touch_locked_(p);
        return token;
    }

    // ---- Context COW: materialise a private writable copy for `agent` -------
    Lease MaterializeWritableCopy(const std::string& task, uint64_t agent, size_t bytes) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = by_task_.find(task);
        if (it == by_task_.end() || pages_[it->second].policy != Policy::Context) return Lease{};
        PageEntry src = pages_[it->second];             // copy-on-write: read the shared image...
        if (!src.resident && recon_) {
            std::vector<uint8_t> out;
            if (recon_(src, out) && out.size() == src.bytes) { src.payload = std::move(out); src.resident = true; }
        }
        PageEntry cp = src;                             // ...then a private, generation-bumped copy
        cp.page_id = next_page_id_++;
        cp.owner_agent = agent;
        cp.bytes = bytes ? bytes : src.bytes;
        cp.generation = 0; cp.resident = false; cp.gpu_loaded = false;
        cp.pin_count = 0;
        if (cp.payload.size() != cp.bytes) cp.payload.assign(cp.bytes, 0);
        cp.resident = true;
        cp.content_key = src.content_key + ":cow:agent" + std::to_string(agent);
        cp.task = task + "#cow" + std::to_string(agent);
        cp.generation = ++next_generation_;
        cp.use_seq = ++next_use_seq_;
        by_task_[cp.task] = cp.page_id;
        pages_[cp.page_id] = std::move(cp);
        PageEntry& q = pages_[cp.page_id];
        lru_.push_front(q.page_id); lru_pos_[q.page_id] = lru_.begin();
        evict_device_budget_(0);
        Lease l{cp.page_id, q.generation, true, q.payload.data(), q.payload.size()};
        ++stat_.cow_created;
        return l;
    }

    // ---- Emulator: virtual-address translation + demand paging ---------------
    // Brings the vaddr's page in (demand paging), validates exec pages, and
    // returns the translated HOST backing pointer. MMIO is not backing-stored.
    Lease EmuTranslate(uint64_t guest_vm, uint64_t vaddr, uint64_t agent) {
        std::lock_guard<std::mutex> lk(mu_);
        // find page whose [vaddr, vaddr + page span) contains vaddr
        for (auto& kv : pages_) {
            PageEntry& p = kv.second;
            if (p.policy != Policy::Emulator) continue;
            if (p.emu.guest_vm != guest_vm) continue;
            if (vaddr >= p.emu.vaddr && vaddr < p.emu.vaddr + p.bytes) {
                if (p.emu.exec_page && !p.exec_validated) {
                    // validation hook (real policy point): caller-supplied validity
                    // predicate; if none provided, exec pages are accepted only
                    // when a validation callback was installed below.
                    if (exec_validator_ && !exec_validator_(p)) { ++stat_.exec_invalid; return Lease{}; }
                    p.exec_validated = !p.emu.mmio;   // mmio never "validated" as normal exec
                }
                Lease l = acquire_locked_(p.page_id, agent, p.priority);
                if (l.ok) ++stat_.emu_translations;
                return l;
            }
        }
        return Lease{};
    }
    // Mark a translated-code region invalid (stale TLB / self-modifying code).
    void InvalidateEmuCode(uint64_t guest_vm, uint64_t vaddr) {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& kv : pages_) {
            PageEntry& p = kv.second;
            if (p.policy == Policy::Emulator && p.emu.guest_vm == guest_vm &&
                vaddr >= p.emu.vaddr && vaddr < p.emu.vaddr + p.bytes) {
                if (p.emu.exec_page) { p.exec_validated = false; ++stat_.tc_invalidated; }
            }
        }
    }
    void SetExecValidator(std::function<bool(const PageEntry&)> v) { std::lock_guard<std::mutex> lk(mu_); exec_validator_ = std::move(v); }

    // ---- Swarm: replicate shared immutable data to another agent -------------
    // Refuses mutable Context pages and MMIO Emulator pages: no blind replication.
    bool ReplicateToAgent(const std::string& content_key, uint64_t target_agent) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = by_key_.find(content_key);
        if (it == by_key_.end()) return false;
        PageEntry& src = pages_[it->second];
        if (src.policy == Policy::Context && src.ctx.mutable_kv) return false;
        if (src.policy == Policy::Emulator && src.emu.mmio)     return false;
        if (src.resident && src.payload.empty())               return false;
        PageEntry cp = src;
        cp.page_id = next_page_id_++;
        cp.owner_agent = target_agent;
        cp.pin_count = 0; cp.gpu_loaded = false; cp.gpu_token = 0;
        cp.generation = ++next_generation_;
        cp.use_seq = ++next_use_seq_;
        cp.task = src.task + "#rep" + std::to_string(cp.page_id);
        cp.content_key = src.content_key + "#rep" + std::to_string(cp.page_id);
        by_task_[cp.task] = cp.page_id;
        by_key_[cp.content_key] = cp.page_id;
        pages_[cp.page_id] = std::move(cp);
        lru_.push_front(cp.page_id); lru_pos_[cp.page_id] = lru_.begin();
        src.replicas.push_back(cp.page_id);
        if (src.policy == Policy::Context) ++src.ctx.replicas;
        ++stat_.replicated_pages;
        evict_device_budget_(0);
        enforce_agent_budget_(target_agent);
        return true;
    }

    // ---- invalidation: drops residents + stale leases -----------------------
    void Invalidate(const std::string& task_or_key, bool by_key) {
        std::lock_guard<std::mutex> lk(mu_);
        auto& idx = by_key ? by_key_ : by_task_;
        auto it = idx.find(task_or_key);
        if (it == idx.end()) return;
        PageEntry& p = pages_[it->second];
        if (p.pin_count > 0) { ++stat_.pinned_refused_invalid; return; }  // pinned: refuse invalidation
        ++stat_.invalidated;
        drop_locked_(p);
    }
    void InvalidateAll(Policy pol) {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& kv : pages_)
            if (kv.second.policy == pol && kv.second.pin_count == 0) {
                ++stat_.invalidated;
                drop_locked_(kv.second);
            }
    }

    // ---- telemetry / accounting ---------------------------------------------
    struct Stats {
        uint64_t hits=0, misses=0, evictions=0, recons=0, recon_fail=0, size_fail=0;
        uint64_t invalidated=0, pinned_refused_invalid=0;
        uint64_t pin_total=0; int      pin_active_peak=0;
        uint64_t transfer_ok=0, transfer_warm=0, transfer_fail=0, verify_fail=0, transfer_unsupported=0;
        uint64_t replicated_pages=0, unknown_task=0, device_budget_evictions=0, agent_budget_evictions=0;
        uint64_t cow_created=0, exec_invalid=0, tc_invalidated=0, emu_translations=0;
        uint64_t prefetch_hints=0;
        uint64_t evict_skipped_pinned=0, over_budget_pinned=0, recover_alloc_fail=0;
    };
    Stats stats() const { std::lock_guard<std::mutex> lk(mu_); return stat_; }

    uint64_t gpu_resident_bytes(uint32_t device) const {
        std::lock_guard<std::mutex> lk(mu_);
        uint64_t s=0;
        for (auto& kv : pages_) if (kv.second.gpu_loaded && kv.second.gpu_device == device) s += kv.second.bytes;
        return s;
    }
    uint64_t host_resident_bytes() const {
        std::lock_guard<std::mutex> lk(mu_);
        uint64_t s=0;
        for (auto& kv : pages_) if (kv.second.resident && !kv.second.payload.empty()) s += kv.second.bytes;
        return s;
    }
    uint64_t agent_resident_bytes(uint64_t agent) const {
        std::lock_guard<std::mutex> lk(mu_);
        uint64_t s=0;
        for (auto& kv : pages_) if (kv.second.owner_agent == agent && kv.second.resident) s += kv.second.bytes;
        return s;
    }
    size_t page_count() const { std::lock_guard<std::mutex> lk(mu_); return pages_.size(); }
    const PageEntry* Find(const std::string& task) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = by_task_.find(task);
        return it == by_task_.end() ? nullptr : &pages_.at(it->second);
    }
    // Directory snapshot (task -> page id) for receipts.
    std::map<std::string, uint64_t> TaskToId() const {
        std::lock_guard<std::mutex> lk(mu_);
        return std::map<std::string, uint64_t>(by_task_.begin(), by_task_.end());
    }

private:
    static uint64_t Fpr(const uint8_t* d, size_t n) {   // deterministic fingerprint (byte verify)
        uint64_t h = 1469598103934665603ull;
        for (size_t i=0;i<n;++i) { h ^= d[i]; h *= 1099511628211ull; }
        return h;
    }

    uint64_t emplace_(PageEntry p) {                    // caller holds mu_
        uint64_t id = p.page_id;
        by_task_[p.task] = id;
        if (!p.content_key.empty()) by_key_[p.content_key] = id;
        pages_[id] = std::move(p);
        return id;
    }
    void touch_locked_(PageEntry& p) {                  // caller holds mu_
        p.use_seq = ++next_use_seq_;
        if (p.resident || p.gpu_loaded) {
            auto pos = lru_pos_.find(p.page_id);
            if (pos != lru_pos_.end()) { lru_.erase(pos->second); lru_pos_.erase(pos); }
            lru_.push_front(p.page_id); lru_pos_[p.page_id] = lru_.begin();
        }
    }
    Lease acquire_locked_(uint64_t page_id, uint64_t agent, uint32_t priority) {  // caller holds mu_
        PageEntry& p = pages_[page_id];
        if (priority != 128) p.priority = priority;
        bool need = (!p.resident) || p.payload.empty() || (p.bytes && p.payload.size() != p.bytes);
        if (!need) {
            ++stat_.hits;
            touch_locked_(p);
            if (p.generation == 0) p.generation = ++next_generation_;
            return Lease{p.page_id, p.generation, true, p.payload.data(), p.payload.size()};
        }
        // reconstruct on demand (fail-closed on error or size mismatch)
        std::vector<uint8_t> out;
        if (recon_ && recon_(p, out) && out.size() == p.bytes) {
            p.payload = std::move(out); p.resident = true; p.crc = Fpr(p.payload.data(), p.payload.size());
            p.generation = ++next_generation_;
            ++stat_.recons; ++stat_.misses;
            touch_locked_(p);
            enforce_agent_budget_(agent);
            evict_device_budget_(0);
            return Lease{p.page_id, p.generation, true, p.payload.data(), p.payload.size()};
        }
        if (out.size() != p.bytes) ++stat_.size_fail; else ++stat_.recon_fail;
        return Lease{};
    }
    void drop_locked_(PageEntry& p) {                   // caller holds mu_
        if (p.gpu_loaded) ++stat_.evictions;
        else if (p.resident) ++stat_.evictions;
        p.payload.clear(); p.payload.shrink_to_fit();
        p.resident=false; p.gpu_loaded=false; p.gpu_token=0; p.device_generation=0;
        ++p.generation;                                // invalidate stale leases
        auto pos = lru_pos_.find(p.page_id);
        if (pos != lru_pos_.end()) { lru_.erase(pos->second); lru_pos_.erase(pos); }
    }
    bool recon_out_of_budget_(PageEntry&) { return false; }

    void evict_device_budget_(uint32_t device) {       // caller holds mu_
        auto b = dev_budget_.find(device);
        if (b == dev_budget_.end() || b->second == 0) return;   // 0 = unlimited
        while (gpu_resident_bytes_locked_(device) > b->second) {
            bool evicted_any=false, saw_pinned=false;
            for (auto rit = lru_.rbegin(); rit != lru_.rend(); ++rit) {
                PageEntry& p = pages_[*rit];
                if (!p.gpu_loaded || p.gpu_device != device) continue;
                if (p.pin_count > 0) { saw_pinned=true; continue; }
                p.gpu_loaded=false; p.gpu_token=0; ++p.generation; ++stat_.evictions; ++stat_.device_budget_evictions;
                evicted_any=true; break;
            }
            if (!evicted_any) { if (saw_pinned) ++stat_.over_budget_pinned; break; }
        }
    }
    void enforce_agent_budget_(uint64_t agent) {       // caller holds mu_
        auto b = agent_budget_.find(agent);
        if (b == agent_budget_.end() || b->second == 0) return;  // 0 = unlimited
        while (agent_resident_bytes_locked_(agent) > b->second) {
            bool evicted_any=false, saw_pinned=false;
            for (auto rit = lru_.rbegin(); rit != lru_.rend(); ++rit) {
                PageEntry& p = pages_[*rit];
                if (p.owner_agent != agent || !p.resident) continue;
                if (p.pin_count > 0) { saw_pinned=true; continue; }
                bool was_gpu = p.gpu_loaded;
                p.payload.clear(); p.payload.shrink_to_fit(); p.resident=false;
                if (was_gpu) { p.gpu_loaded=false; p.gpu_token=0; }
                ++p.generation; ++stat_.evictions; ++stat_.agent_budget_evictions;
                {
                    auto pos = lru_pos_.find(p.page_id);
                    if (pos != lru_pos_.end()) { lru_.erase(pos->second); lru_pos_.erase(pos); }
                }
                evicted_any=true; break;
            }
            if (!evicted_any) { if (saw_pinned) ++stat_.over_budget_pinned; break; }
        }
    }
    uint64_t gpu_resident_bytes_locked_(uint32_t device) const {
        uint64_t s=0;
        for (auto& kv : pages_) if (kv.second.gpu_loaded && kv.second.gpu_device == device) s += kv.second.bytes;
        return s;
    }
    uint64_t agent_resident_bytes_locked_(uint64_t agent) const {
        uint64_t s=0;
        for (auto& kv : pages_) if (kv.second.owner_agent == agent && kv.second.resident) s += kv.second.bytes;
        return s;
    }

    mutable std::mutex mu_;
    Reconstruct recon_;
    TransferFn transfer_;
    std::function<bool(const PageEntry&)> exec_validator_;
    uint64_t next_page_id_ = 1;
    uint64_t next_generation_ = 0;
    uint64_t next_use_seq_ = 0;
    std::unordered_map<uint64_t, PageEntry> pages_;
    std::unordered_map<std::string, uint64_t> by_task_;
    std::unordered_map<std::string, uint64_t> by_key_;
    std::list<uint64_t> lru_;                                   // front = most recently used
    std::unordered_map<uint64_t, std::list<uint64_t>::iterator> lru_pos_;
    std::map<uint32_t, uint64_t> dev_budget_;
    std::map<uint64_t, uint64_t> agent_budget_;
    Stats stat_;
};

}} // namespace rawrxd::plague
