// deep2_ucf_four_object_smoke.cpp — compile + bounce RW++ / GenerationMismatch
#include "rawrxd_uncoherent_fabric.hpp"
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <vector>

using namespace rawrxd::ucf;

namespace {
struct Store {
    std::unordered_map<std::uintptr_t, std::vector<std::uint8_t>> blocks;
    std::uintptr_t next = 0x1000;
};
Store g;

Error Alloc(Node&, u64 bytes, PhysicalBlock& out) noexcept {
    const auto k = g.next++;
    g.blocks[k].assign(static_cast<size_t>(bytes), 0);
    out.handle = k;
    out.bytes = bytes;
    return Error::Ok;
}
void Free(Node&, PhysicalBlock b) noexcept { g.blocks.erase(b.handle); }
Error Copy(Node&, PhysicalBlock dst, const Node&, PhysicalBlock src,
           u64 bytes, Fence& f) noexcept {
    auto sit = g.blocks.find(src.handle);
    auto dit = g.blocks.find(dst.handle);
    if (sit == g.blocks.end() || dit == g.blocks.end()) return Error::CopyFailed;
    if (sit->second.size() < bytes || dit->second.size() < bytes)
        return Error::CopyFailed;
    std::memcpy(dit->second.data(), sit->second.data(),
                static_cast<size_t>(bytes));
    f.value = 1;
    return Error::Ok;
}
Error Wait(Node&, Fence) noexcept { return Error::Ok; }
Error Disp(Node&, PhysicalBlock, PhysicalBlock in, PhysicalBlock,
           void*, Fence& f) noexcept {
    auto it = g.blocks.find(in.handle);
    if (it == g.blocks.end() || it->second.empty()) return Error::DispatchFailed;
    it->second[0] = static_cast<std::uint8_t>(it->second[0] + 1);
    f.value = 1;
    return Error::Ok;
}

void Wire(Node& n, u64 id, NodeKind k) {
    n.objectId = id;
    n.kind = k;
    n.capabilities = CapCompute | CapDeviceMemory | CapAsyncCopy |
                     (k == NodeKind::Host ? CapHostMemory : 0);
    n.capacityBytes = 1ull << 30;
    n.usableBytes = 1ull << 30;
    n.backend = {Alloc, Free, Copy, Wait, Disp};
}
} // namespace

int main() {
    Fabric fab{};
    Node host{}, ga{}, gb{};
    Wire(host, 0xC001, NodeKind::Host);
    Wire(ga, 0xA11, NodeKind::Gpu);
    Wire(gb, 0xB22, NodeKind::Gpu);
    (void)fab.attach(host);
    (void)fab.attach(ga);
    (void)fab.attach(gb);

    Tensor act{};
    act.objectId = 0xA81;
    act.bytes = 64;
    Replica* r0 = nullptr;
    if (allocate_replica(act, ga, r0) != Error::Ok) return 2;
    r0->generation = act.generation();
    r0->present = 1;

    Tensor w0{}, w1{};
    w0.objectId = 0xD001;
    w0.bytes = 64;
    w1.objectId = 0xD002;
    w1.bytes = 64;
    Replica *rw0 = nullptr, *rw1 = nullptr;
    (void)allocate_replica(w0, ga, rw0);
    rw0->generation = w0.generation();
    rw0->present = 1;
    (void)allocate_replica(w1, gb, rw1);
    rw1->generation = w1.generation();
    rw1->present = 1;

    Layer layers[2] = {{&w0, nullptr}, {&w1, nullptr}};
    const u64 g0 = act.generation();
    ChainResult cr = dispatch_bounce_chain(fab, layers, 2, act);
    printf("BOUNCE err=%u layers=%u gen=%llu node=0x%llx\n",
           (unsigned)cr.error, cr.layer + 1,
           (unsigned long long)cr.generation,
           (unsigned long long)cr.nodeObjectId);
    if (cr.error != Error::Ok) return 3;
    if (act.generation() != g0 + 2) return 4;

    Lease bad{};
    Error e = begin_rw(fab, act, ga, g0, bad);
    printf("STALE_RW expect_mismatch=%u got=%u\n",
           (unsigned)Error::GenerationMismatch, (unsigned)e);
    if (e != Error::GenerationMismatch) return 5;

    printf("UCF_FOUR_OBJECT_SMOKE=PASS\n");
    return 0;
}
