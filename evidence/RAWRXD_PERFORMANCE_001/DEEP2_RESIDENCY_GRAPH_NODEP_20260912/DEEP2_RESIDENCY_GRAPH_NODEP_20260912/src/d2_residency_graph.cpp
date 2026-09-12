#include "d2_residency_graph.h"
#include <cstring>
#include <limits>

namespace d2rg {

static constexpr std::uint32_t NEVER = 0xffffffffu;

ResidencyGraph::ResidencyGraph() noexcept {
    reset();
}

bool ResidencyGraph::reset() noexcept {
    std::memset(tensors_, 0, sizeof(tensors_));
    std::memset(nodes_, 0, sizeof(nodes_));
    std::memset(slots_, 0, sizeof(slots_));
    std::memset(actions_, 0, sizeof(actions_));
    tensor_count_ = node_count_ = action_count_ = 0;
    used_gpu0_ = used_gpu1_ = 0;
    cstats_ = {};
    rstats_ = {};
    compiled_ = false;
    return true;
}

bool ResidencyGraph::set_capacity(const Capacity& c) noexcept {
    if (compiled_) return false;
    if (c.reserve_gpu0_bytes > c.gpu0_bytes) return false;
    if (c.reserve_gpu1_bytes > c.gpu1_bytes) return false;
    cap_ = c;
    return true;
}

bool ResidencyGraph::bind_backend(const Backend& b) noexcept {
    if (!b.load_exact || !b.evict || !b.dispatch || !b.token_sync) return false;
    backend_ = b;
    backend_bound_ = true;
    return true;
}

std::int32_t ResidencyGraph::find_tensor(std::uint32_t id) const noexcept {
    for (std::uint32_t i = 0; i < tensor_count_; ++i)
        if (tensors_[i].present && tensors_[i].desc.id == id) return (std::int32_t)i;
    return -1;
}

std::int32_t ResidencyGraph::find_node(std::uint32_t id) const noexcept {
    for (std::uint32_t i = 0; i < node_count_; ++i)
        if (nodes_[i].id == id) return (std::int32_t)i;
    return -1;
}

bool ResidencyGraph::add_tensor(const TensorDesc& t) noexcept {
    if (compiled_ || tensor_count_ >= D2_RG_MAX_TENSORS || t.bytes == 0) return false;
    if (find_tensor(t.id) >= 0) return false;
    TensorState& s = tensors_[tensor_count_++];
    s = {};
    s.present = true;
    s.desc = t;
    s.first_use = NEVER;
    s.last_use = 0;
    s.slot_index = -1;
    return true;
}

bool ResidencyGraph::add_node(const NodeDesc& n) noexcept {
    if (compiled_ || node_count_ >= D2_RG_MAX_NODES) return false;
    if (n.input_count > D2_RG_MAX_NODE_INPUTS) return false;
    if (find_node(n.id) >= 0) return false;
    nodes_[node_count_++] = n;
    return true;
}

std::uint64_t ResidencyGraph::align256(std::uint64_t x) const noexcept {
    return (x + 255ull) & ~255ull;
}

std::uint64_t ResidencyGraph::tier_capacity(Tier t) const noexcept {
    if (t == Tier::GPU0) return cap_.gpu0_bytes - cap_.reserve_gpu0_bytes;
    if (t == Tier::GPU1) return cap_.gpu1_bytes - cap_.reserve_gpu1_bytes;
    return 0;
}

std::uint64_t ResidencyGraph::tier_used(Tier t) const noexcept {
    if (t == Tier::GPU0) return used_gpu0_;
    if (t == Tier::GPU1) return used_gpu1_;
    return 0;
}

Tier ResidencyGraph::choose_tier(const TensorDesc& t) const noexcept {
    if ((t.flags & TF_PREFER_GPU1) != 0 && cap_.gpu1_bytes) return Tier::GPU1;
    if ((t.flags & TF_PREFER_GPU0) != 0 && cap_.gpu0_bytes) return Tier::GPU0;

    const std::uint64_t free0 = tier_capacity(Tier::GPU0) - tier_used(Tier::GPU0);
    const std::uint64_t free1 = tier_capacity(Tier::GPU1) - tier_used(Tier::GPU1);
    return free0 >= free1 ? Tier::GPU0 : Tier::GPU1;
}

bool ResidencyGraph::plan_tensor_uses() noexcept {
    for (std::uint32_t i = 0; i < tensor_count_; ++i) {
        tensors_[i].first_use = NEVER;
        tensors_[i].last_use = 0;
    }

    for (std::uint32_t ni = 0; ni < node_count_; ++ni) {
        const NodeDesc& n = nodes_[ni];
        for (std::uint32_t j = 0; j < n.input_count; ++j) {
            const std::int32_t ti = find_tensor(n.inputs[j]);
            if (ti < 0) return false;
            TensorState& ts = tensors_[ti];
            if (ts.first_use == NEVER) ts.first_use = ni;
            ts.last_use = ni;
        }
        if (n.output != NEVER) {
            const std::int32_t ti = find_tensor(n.output);
            if (ti < 0) return false;
            TensorState& ts = tensors_[ti];
            if (ts.first_use == NEVER) ts.first_use = ni;
            ts.last_use = ni;
        }
    }
    return true;
}

bool ResidencyGraph::alloc_slot(
    Tier tier, std::uint64_t bytes, bool pinned,
    std::uint32_t tensor_id, std::int32_t* out_slot) noexcept {

    if (!out_slot || (tier != Tier::GPU0 && tier != Tier::GPU1)) return false;
    const std::uint64_t need = align256(bytes);
    const std::uint64_t cap = tier_capacity(tier);
    const std::uint64_t used = tier_used(tier);
    if (need > cap || used > cap - need) return false;

    for (std::uint32_t i = 0; i < D2_RG_MAX_GPU_SLOTS; ++i) {
        if (!slots_[i].used) {
            Slot& s = slots_[i];
            s = {};
            s.used = true;
            s.pinned = pinned;
            s.tier = tier;
            s.tensor_id = tensor_id;
            s.bytes = need;

            // Simple monotonic arena offset within each tier. Slots retain address identity.
            std::uint64_t max_end = 0;
            for (std::uint32_t k = 0; k < D2_RG_MAX_GPU_SLOTS; ++k) {
                if (k == i || !slots_[k].used || slots_[k].tier != tier) continue;
                const std::uint64_t end = slots_[k].offset + slots_[k].bytes;
                if (end > max_end) max_end = end;
            }
            s.offset = align256(max_end);
            if (s.offset + need > cap) {
                s = {};
                return false;
            }

            if (tier == Tier::GPU0) used_gpu0_ += need;
            else used_gpu1_ += need;

            *out_slot = (std::int32_t)i;
            return true;
        }
    }
    return false;
}

void ResidencyGraph::free_slot(std::int32_t slot) noexcept {
    if (slot < 0 || (std::uint32_t)slot >= D2_RG_MAX_GPU_SLOTS) return;
    Slot& s = slots_[slot];
    if (!s.used) return;

    if (s.tier == Tier::GPU0) used_gpu0_ -= s.bytes;
    else if (s.tier == Tier::GPU1) used_gpu1_ -= s.bytes;

    const std::int32_t ti = find_tensor(s.tensor_id);
    if (ti >= 0) {
        tensors_[ti].resident = false;
        tensors_[ti].slot_index = -1;
    }
    s = {};
}

bool ResidencyGraph::evict_one(Tier tier, std::uint32_t at_node) noexcept {
    std::int32_t victim = -1;
    std::uint32_t farthest_last = 0;

    // Prefer tensors whose final use is already behind us; otherwise evict
    // the evictable tensor with the farthest final use. Pinned tensors never move.
    for (std::uint32_t i = 0; i < D2_RG_MAX_GPU_SLOTS; ++i) {
        const Slot& s = slots_[i];
        if (!s.used || s.tier != tier || s.pinned) continue;
        const std::int32_t ti = find_tensor(s.tensor_id);
        if (ti < 0) continue;
        const TensorState& ts = tensors_[ti];
        if ((ts.desc.flags & TF_ALLOW_EVICT) == 0) continue;

        if (ts.last_use < at_node) {
            victim = (std::int32_t)i;
            break;
        }
        if (victim < 0 || ts.last_use > farthest_last) {
            victim = (std::int32_t)i;
            farthest_last = ts.last_use;
        }
    }

    if (victim < 0) return false;
    if (!backend_.evict(backend_.user, &slots_[victim].view)) return false;
    ++rstats_.evictions;
    free_slot(victim);
    return true;
}

bool ResidencyGraph::ensure_resident(std::uint32_t tensor_id, std::uint32_t node_index) noexcept {
    const std::int32_t ti = find_tensor(tensor_id);
    if (ti < 0) return false;
    TensorState& ts = tensors_[ti];
    if (ts.resident) {
        if (ts.slot_index >= 0) slots_[ts.slot_index].last_use_node = node_index;
        return true;
    }

    Tier tier = choose_tier(ts.desc);
    std::int32_t slot = -1;
    while (!alloc_slot(tier, ts.desc.bytes, (ts.desc.flags & TF_PINNED) != 0, tensor_id, &slot)) {
        if (!evict_one(tier, node_index)) {
            // One fallback to the other GPU if policy did not force a side.
            if ((ts.desc.flags & (TF_PREFER_GPU0 | TF_PREFER_GPU1)) != 0) return false;
            tier = (tier == Tier::GPU0) ? Tier::GPU1 : Tier::GPU0;
            if (tier_capacity(tier) == 0) return false;
            if (alloc_slot(tier, ts.desc.bytes, false, tensor_id, &slot)) break;
            if (!evict_one(tier, node_index)) return false;
        }
    }

    Slot& s = slots_[slot];
    s.last_use_node = node_index;
    PackedView view{};
    if (!backend_.load_exact(backend_.user, &ts.desc, tier, s.offset, &view)) {
        free_slot(slot);
        return false;
    }
    view.tensor_id = ts.desc.id;
    view.tier = tier;
    view.codec = ts.desc.codec;
    view.device_offset = s.offset;
    view.bytes = ts.desc.bytes;
    view.flags = ts.desc.flags;
    s.view = view;

    ts.resident = true;
    ts.slot_index = slot;

    ++rstats_.load_exact_calls;
    if (tier == Tier::GPU0) rstats_.bytes_loaded_gpu0 += ts.desc.bytes;
    else if (tier == Tier::GPU1) rstats_.bytes_loaded_gpu1 += ts.desc.bytes;
    return true;
}

bool ResidencyGraph::ensure_output(std::uint32_t tensor_id, Tier preferred) noexcept {
    const std::int32_t ti = find_tensor(tensor_id);
    if (ti < 0) return false;
    TensorState& ts = tensors_[ti];
    if (ts.resident) return true;

    Tier tier = preferred;
    if (tier != Tier::GPU0 && tier != Tier::GPU1) tier = choose_tier(ts.desc);

    std::int32_t slot = -1;
    if (!alloc_slot(tier, ts.desc.bytes, (ts.desc.flags & TF_PINNED) != 0, tensor_id, &slot))
        return false;

    Slot& s = slots_[slot];
    s.view.tensor_id = tensor_id;
    s.view.tier = tier;
    s.view.codec = ts.desc.codec;
    s.view.device_offset = s.offset;
    s.view.bytes = ts.desc.bytes;
    s.view.flags = ts.desc.flags;
    ts.resident = true;
    ts.slot_index = slot;
    return true;
}

bool ResidencyGraph::pin_static_working_set() noexcept {
    // Pin only explicitly pinned tensors. This allows the caller to choose
    // permanent target weights/KV/scratch independently from transient weights.
    for (std::uint32_t i = 0; i < tensor_count_; ++i) {
        TensorState& ts = tensors_[i];
        if ((ts.desc.flags & TF_PINNED) == 0) continue;
        if (!ensure_resident(ts.desc.id, 0)) return false;
        if (ts.slot_index < 0) return false;
        const Slot& s = slots_[ts.slot_index];
        if (s.tier == Tier::GPU0) {
            ++cstats_.pinned_gpu0;
            cstats_.pinned_gpu0_bytes += ts.desc.bytes;
        } else if (s.tier == Tier::GPU1) {
            ++cstats_.pinned_gpu1;
            cstats_.pinned_gpu1_bytes += ts.desc.bytes;
        }
    }
    return true;
}

bool ResidencyGraph::compile() noexcept {
    if (compiled_ || !backend_bound_ || node_count_ == 0 || tensor_count_ == 0) return false;
    if (!plan_tensor_uses()) return false;

    // Source tensors must be exact-range addressable. Activations/KV outputs may be generated.
    bool exact = true;
    for (std::uint32_t i = 0; i < tensor_count_; ++i) {
        const TensorDesc& t = tensors_[i].desc;
        if ((t.flags & TF_WEIGHT) != 0 && (t.flags & TF_EXACT_RANGE) == 0) exact = false;
    }

    cstats_ = {};
    cstats_.tensor_count = tensor_count_;
    cstats_.node_count = node_count_;
    cstats_.zero_token_heap = true;
    cstats_.exact_range_only = exact;

    if (!pin_static_working_set()) return false;

    // The runtime graph itself is the persistent execution graph. The action
    // list is diagnostic and can later be translated 1:1 into SsVk command templates.
    action_count_ = 0;
    for (std::uint32_t ni = 0; ni < node_count_; ++ni) {
        const NodeDesc& n = nodes_[ni];
        for (std::uint32_t j = 0; j < n.input_count; ++j) {
            const std::int32_t ti = find_tensor(n.inputs[j]);
            if (ti < 0) return false;
            if ((tensors_[ti].desc.flags & TF_PINNED) == 0) {
                if (action_count_ >= D2_RG_MAX_ACTIONS) return false;
                actions_[action_count_++] = {
                    ActionKind::LOAD_EXACT, Tier::NONE, 0, n.id, n.inputs[j]
                };
            }
        }
        if (action_count_ >= D2_RG_MAX_ACTIONS) return false;
        actions_[action_count_++] = { ActionKind::DISPATCH, Tier::NONE, 0, n.id, 0 };
    }
    if (action_count_ >= D2_RG_MAX_ACTIONS) return false;
    actions_[action_count_++] = { ActionKind::TOKEN_SYNC, Tier::NONE, 0, 0, 0 };

    cstats_.action_count = action_count_;
    compiled_ = true;
    return true;
}

const PackedView* ResidencyGraph::view(std::uint32_t tensor_id) const noexcept {
    const std::int32_t ti = find_tensor(tensor_id);
    if (ti < 0) return nullptr;
    const TensorState& ts = tensors_[ti];
    if (!ts.resident || ts.slot_index < 0) return nullptr;
    return &slots_[ts.slot_index].view;
}

bool ResidencyGraph::run_token(TokenContext* ctx) noexcept {
    if (!compiled_ || !backend_bound_ || !ctx) return false;

    for (std::uint32_t ni = 0; ni < node_count_; ++ni) {
        const NodeDesc& n = nodes_[ni];
        const PackedView* in[D2_RG_MAX_NODE_INPUTS]{};
        Tier preferred = Tier::NONE;

        for (std::uint32_t j = 0; j < n.input_count; ++j) {
            if (!ensure_resident(n.inputs[j], ni)) return false;
            in[j] = view(n.inputs[j]);
            if (!in[j]) return false;
            if (preferred == Tier::NONE && (in[j]->tier == Tier::GPU0 || in[j]->tier == Tier::GPU1))
                preferred = in[j]->tier;
        }

        PackedView* out = nullptr;
        if (n.output != NEVER) {
            if (!ensure_output(n.output, preferred)) return false;
            const std::int32_t ti = find_tensor(n.output);
            if (ti < 0 || tensors_[ti].slot_index < 0) return false;
            out = &slots_[tensors_[ti].slot_index].view;
        }

        if (!backend_.dispatch(backend_.user, &n, in, n.input_count, out, ctx))
            return false;
        ++rstats_.dispatches;

        // Reclaim transient tensors after their last graph use.
        for (std::uint32_t j = 0; j < n.input_count; ++j) {
            const std::int32_t ti = find_tensor(n.inputs[j]);
            if (ti < 0) return false;
            TensorState& ts = tensors_[ti];
            if (ts.last_use == ni &&
                (ts.desc.flags & TF_PINNED) == 0 &&
                (ts.desc.flags & TF_ALLOW_EVICT) != 0 &&
                ts.slot_index >= 0) {
                if (!backend_.evict(backend_.user, &slots_[ts.slot_index].view))
                    return false;
                ++rstats_.evictions;
                free_slot(ts.slot_index);
            }
        }
    }

    if (!backend_.token_sync(backend_.user, ctx)) return false;
    ++rstats_.token_syncs;
    ++rstats_.tokens;

    // This implementation never allocates in run_token.
    rstats_.per_token_heap_allocations = 0;
    return true;
}

} // namespace d2rg
