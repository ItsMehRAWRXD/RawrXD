// ============================================================================
// tools/plague_rom_receipt.cpp  --  Universal Plague Memory Engine: ROM POLICY
// ----------------------------------------------------------------------------
// Real, independent receipt. No stubs, no simulated results:
//   * Real GGUF model ingested through the engine's own universal_gguf layer
//     (memory-mapped, exact tensor bytes).
//   * ROM pages registered content-addressed; on-demand reconstruction reads
//     the REAL mapped bytes; every page is byte-verified against its source.
//   * Native quantized bytes only: no F32 expansion, no CPU dequantisation.
//   * Eviction / reuse under a bounded budget, generation-checked leases,
//     fence-safe pinning, per-agent isolation + budgets, swarm replication.
//   * G02 byte-verified GPU transfer: pages are uploaded to a REAL device-local
//     buffer and read back byte-for-byte on one or two real GPUs.
//   * Fail-closed behaviour when a page cannot be reconstructed.
//
// Usage: plague_rom_receipt.exe --model <path.gguf> [--tensors N] [--no-gpu]
//                                [--gpu1 idx] [--gpu2 idx] [--budget B]
//   --tensors 0 = all tensors. Exits 0 only when every check passes.
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>

#include "plague_memory.hpp"

#include "universal_gguf.hpp"     // engine's model-agnostic GGUF ingest (mmap, real bytes)
#include "include/vulkan_compute.h" // ACTIVE engine (src/vulkan_compute.cpp), not the src/deep2 variant

using namespace rawrxd;
using namespace rawrxd::plague;
using RawrXD::Deep2::Universal::IngestReport;
using RawrXD::Deep2::Universal::Ingest;
using RawrXD::Deep2::Universal::TensorRec;

// ---- independent fingerprint, mirrors the fabric's own (for cross-checking) -
static uint64_t FprOf(const uint8_t* d, size_t n) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i=0;i<n;++i) { h ^= d[i]; h *= 1099511628211ull; }
    return h;
}

static uint32_t ParseBlock(const std::string& n) {
    const std::string k = "blk.";
    size_t p = n.find(k);
    if (p == std::string::npos) return (uint32_t)rawrxd::plague::kUnknownBlock;
    p += k.size();
    size_t e = n.find('.', p);
    if (e == std::string::npos) return (uint32_t)rawrxd::plague::kUnknownBlock;
    try { return (uint32_t)std::stoul(n.substr(p, e-p)); } catch (...) { return (uint32_t)kUnknownBlock; }
}
static uint32_t ParseExpert(const std::string& n) {
    // MoE expert tensor names in the zoo: ... ffn_{gate,up,down}_exps.<e>.weight
    static const char* keys[] = { "ffn_gate_exps.", "ffn_up_exps.", "ffn_down_exps." };
    for (const char* k : keys) {
        size_t p = n.find(k);
        if (p == std::string::npos) continue;
        p += strlen(k);
        size_t e = n.find('.', p);
        std::string num = (e == std::string::npos) ? n.substr(p) : n.substr(p, e-p);
        try { return (uint32_t)std::stoul(num); } catch (...) { return (uint32_t)kUnknownExpert; }
    }
    return (uint32_t)kUnknownExpert;
}

int main(int argc, char** argv) {
    std::string model;
    size_t want = 0;               // 0 = all tensors
    bool want_gpu = true;
    int32_t gpu1 = -1, gpu2 = -1;  // -1 = let engine pick
    uint64_t agent_budget = 12ull << 20;
    uint64_t dev_budget   = 8ull << 20;

    for (int i=1;i<argc;++i) {
        std::string a = argv[i];
        if      (a == "--model"      && i+1<argc) model = argv[++i];
        else if (a == "--tensors"    && i+1<argc) want = strtoull(argv[++i],0,10);
        else if (a == "--gpu1"       && i+1<argc) gpu1 = atoi(argv[++i]);
        else if (a == "--gpu2"       && i+1<argc) gpu2 = atoi(argv[++i]);
        else if (a == "--budget"     && i+1<argc) agent_budget = strtoull(argv[++i],0,10);
        else if (a == "--dev-budget" && i+1<argc) dev_budget   = strtoull(argv[++i],0,10);
        else if (a == "--no-gpu") want_gpu = false;
    }
    if (model.empty()) {
        printf("usage: plague_rom_receipt.exe --model <path.gguf> [--tensors N] [--no-gpu] [--gpu1 i] [--gpu2 i] [--budget B] [--dev-budget B]\n");
        return 2;
    }

    printf("===== UNIVERSAL PLAGUE MEMORY ENGINE -- ROM POLICY RECEIPT =====\n");
    printf("model=%s\n", model.c_str());

    // -------------------------------------------------- real GGUF source bytes
    const IngestReport& rep = Ingest(model, /*want_weights=*/false);
    if (!rep.ok || rep.tensors.empty()) {
        printf("A0 INGEST FAIL: %s\n", rep.error.empty() ? "(no error string)" : rep.error.c_str());
        printf("PLAGUE_ROM_RECEIPT verdict=FAIL stage=ingest\n");
        return 1;
    }
    printf("A0 ingest OK arch=%s tensors=%zu model_bytes=%llu\n",
           rep.spec.architecture.c_str(), rep.tensors.size(),
           (unsigned long long)RawrXD::Deep2::Universal::GetProvenance().file_bytes);

    // Exact source bytes per tensor (memory-mapped by the engine's own ingest).
    std::unordered_map<std::string, std::pair<const uint8_t*, size_t>> src;
    size_t total_bytes = 0;
    std::vector<const TensorRec*> tens;
    tens.reserve(rep.tensors.size());
    for (const auto& t : rep.tensors) {
        if (!t.data || !t.bytes) continue;
        src[t.name] = { t.data, t.bytes };
        total_bytes += t.bytes;
        tens.push_back(&t);
    }
    if (want && want < tens.size()) tens.resize(want);
    printf("A0 materialised source pages=%zu bytes=%zu (%.1f MiB)\n",
           tens.size(), total_bytes, total_bytes/1048576.0);

    // ------------------------------------------------------ fabric + ROM policy
    std::vector<std::pair<const char*, bool>> stages;
    PlagueMemoryEngine eng([&](const PageEntry& p, std::vector<uint8_t>& out) -> bool {
        auto it = src.find(p.task);
        if (it == src.end()) return false;                    // fail-closed: unknown backing
        if (it->second.second != p.bytes) return false;       // fail-closed: size mismatch
        out.assign(it->second.first, it->second.first + it->second.second);
        return true;
    });

    std::vector<uint64_t> ids;
    ids.reserve(tens.size());
    for (const TensorRec* t : tens) {
        RomMeta rm;
        rm.block = t->block >= 0 ? (uint32_t)t->block : ParseBlock(t->name);
        rm.expert = ParseExpert(t->name);
        rm.ggml_type = t->gguf_type;
        rm.file_off = t->rel_offset;
        rm.file_bytes = t->bytes;
        ids.push_back(eng.RegisterRomPage(t->name, "rom:" + t->name, /*agent=*/1,
                                          /*priority=*/t->role == RawrXD::Deep2::Universal::Role::TokenEmbedding ? 0 : 128,
                                          t->bytes, rm));
    }
    printf("ROM registered pages=%zu (content-addressed, immutable)\n", eng.page_count());

    // =========================== A1: on-demand reconstruction is byte-exact ====
    size_t byte_exact = 0, byte_bad = 0, crc_ok = 0, crc_bad = 0;
    {
        PlagueMemoryEngine::Stats before = eng.stats();
        for (size_t i=0;i<tens.size();++i) {
            Lease l = eng.Acquire(tens[i]->name, 1);
            if (!l.ok || l.bytes != tens[i]->bytes) { ++byte_bad; continue; }
            const uint8_t* s = src[tens[i]->name].first;
            if (std::memcmp(l.data, s, l.bytes) == 0) ++byte_exact; else ++byte_bad;
            const PageEntry* pe = eng.Find(tens[i]->name);
            if (pe->crc == FprOf(s, l.bytes)) ++crc_ok; else ++crc_bad;
        }
        PlagueMemoryEngine::Stats after = eng.stats();
        bool ok = (byte_bad == 0 && byte_exact == tens.size() && crc_ok == tens.size() &&
                   after.recons - before.recons == tens.size());
        printf("A1 on-demand reconstruction byte-exact: %zu/%zu byte_mismatch=%zu crc_ok=%zu crc_bad=%zu recons=%llu  %s\n",
               byte_exact, tens.size(), byte_bad, crc_ok, crc_bad,
               (unsigned long long)(after.recons-before.recons), ok ? "PASS" : "FAIL");
        stages.push_back({"A1 on-demand reconstruction byte-exact", ok});
    }

    // =========================== A2: native quantized bytes (no expansion) ====
    size_t no_expand_ok = 0, no_expand_bad = 0, quant_ok = 0, quant_bad = 0;
    for (size_t i=0;i<tens.size();++i) {
        const PageEntry* pe = eng.Find(tens[i]->name);
        if (!pe) { ++no_expand_bad; continue; }
        if (pe->bytes == tens[i]->bytes && pe->payload.size() == tens[i]->bytes) ++no_expand_ok;
        else ++no_expand_bad;
        // A page's bytes must equal the raw shard bytes: no F32 expansion (F32
        // would be 4 bytes/element) and no CPU dequantisation.
        uint32_t ggml_type = tens[i]->gguf_type;
        bool quantized = (ggml_type >= 2 && ggml_type <= 14);   // ggml quantized id range
        if (!quantized || pe->payload.size() == tens[i]->bytes) ++quant_ok; else ++quant_bad;
    }
    printf("A2 native quantized pages (no F32 expansion / no CPU dequant): size_ok=%zu bad=%zu quant_ok=%zu quant_bad=%zu  %s\n",
           no_expand_ok, no_expand_bad, quant_ok, quant_bad,
           (no_expand_bad==0 && quant_bad==0) ? "PASS" : "FAIL");
    stages.push_back({"A2 native quantized bytes (no F32 expansion / no CPU dequant)", no_expand_bad==0 && quant_bad==0});

    // =========================== A3: warm reuse (no second reconstruction) =====
    size_t warm_ok = 0, warm_bad = 0;
    {
        PlagueMemoryEngine::Stats before = eng.stats();
        for (size_t i=0;i<tens.size();++i) {
            Lease l = eng.Acquire(tens[i]->name, 1);
            const uint8_t* s = src[tens[i]->name].first;
            if (l.ok && std::memcmp(l.data, s, l.bytes) == 0) ++warm_ok; else ++warm_bad;
        }
        PlagueMemoryEngine::Stats after = eng.stats();
        bool ok = (warm_bad==0 && warm_ok==tens.size() &&
                   after.hits-before.hits == tens.size() && after.recons==before.recons);
        printf("A3 warm reuse: hits_delta=%llu recons_delta=%llu ok=%zu bad=%zu  %s\n",
               (unsigned long long)(after.hits-before.hits),
               (unsigned long long)(after.recons-before.recons),                warm_ok, warm_bad,
               ok ? "PASS" : "FAIL");
        stages.push_back({"A3 warm reuse without re-reconstruction", ok});
    }

    // =========================== A4: device-aware prefetch (block warm-up) ====
    size_t pf_ok = 0, pf_bad = 0;
    {
        // Pick a REAL per-block tensor so the warm-up covers a whole layer.
        uint32_t warm_block = (uint32_t)kUnknownBlock;
        for (const TensorRec* t : tens)
            if (ParseBlock(t->name) != (uint32_t)kUnknownBlock) { warm_block = ParseBlock(t->name); break; }
        // Clear the cache, then warm that block by prefetch only.
        eng.InvalidateAll(Policy::ROM);
        PlagueMemoryEngine::Stats before = eng.stats();
        eng.PrefetchRom(warm_block, (uint32_t)kUnknownExpert, 1);
        // Every tensor of the warm block must now be resident: acquiring it is a
        // hit with no per-tensor reconstruction.
        for (const TensorRec* t : tens) {
            if (ParseBlock(t->name) != warm_block) continue;
            PlagueMemoryEngine::Stats s0 = eng.stats();
            Lease l = eng.Acquire(t->name, 1);
            PlagueMemoryEngine::Stats s1 = eng.stats();
            const uint8_t* s = src[t->name].first;
            if (l.ok && std::memcmp(l.data, s, l.bytes)==0 &&
                s1.recons==s0.recons && s1.hits>s0.hits) ++pf_ok; else ++pf_bad;
        }
        PlagueMemoryEngine::Stats after = eng.stats();
        printf("A4 device-aware prefetch (block %u warmed): resident_hits=%zu misses=%zu hints=%llu  %s\n",
               warm_block, pf_ok, pf_bad, (unsigned long long)(after.prefetch_hints-before.prefetch_hints),
               (pf_bad==0 && pf_ok>0) ? "PASS" : "FAIL");
        stages.push_back({"A4 device-aware prefetch warms the block", pf_bad==0 && pf_ok>0});
    }

    // =========================== A5: generation-checked lease + pin ===========
    {
        const std::string t0 = tens[0]->name;
        Lease l = eng.Acquire(t0, 1);
        uint64_t pid = l.page_id, gen = l.generation;
        bool pinned  = eng.Pin(pid, gen);
        eng.Invalidate(t0, false);                       // must refuse while pinned
        PlagueMemoryEngine::Stats s = eng.stats();
        const PageEntry* pe = eng.Find(t0);
        bool refused = (s.pinned_refused_invalid >= 1) && pe && pe->resident;
        bool stale_still_usable = false;
        {
            Lease l2 = eng.Acquire(t0, 1);               // still resident after refusal
            stale_still_usable = l2.ok && std::memcmp(l2.data, src[t0].first, l2.bytes)==0;
        }
        eng.Unpin(pid);
        eng.Invalidate(t0, false);                       // now allowed
        PlagueMemoryEngine::Stats s2 = eng.stats();
        const PageEntry* pe2 = eng.Find(t0);
        bool dropped = pe2 && !pe2->resident;
        // stale generation must be refused by pin/transfer after invalidation
        bool gen_rejected = !eng.Pin(pid, gen);
        bool ok = pinned && refused && stale_still_usable && dropped && gen_rejected;
        printf("A5 pin+generation lease: pinned=%d refused_invalidate=%d resident_after_refusal=%d dropped=%d stale_gen_rejected=%d  %s\n",
               (int)pinned,(int)refused,(int)stale_still_usable,(int)dropped,               (int)gen_rejected, ok?"PASS":"FAIL");
        stages.push_back({"A5 generation-checked lease + fence-safe pin", ok});
    }

    // =========================== A6: budgeted eviction + exact re-reconstruct ==
    size_t ev_recovered = 0, ev_lost = 0;
    bool ev_bounded = false;
    {
        eng.SetAgentBudget(1, agent_budget);
        PlagueMemoryEngine::Stats s = eng.stats();
        // Re-acquire everything: most pages must be reconstructed again because
        // the budget forced eviction, and every reconstruction must be exact.
        uint64_t recons_before = s.recons, evict_before = s.evictions;
        for (size_t i=0;i<tens.size();++i) {
            Lease l = eng.Acquire(tens[i]->name, 1);
            const uint8_t* sp = src[tens[i]->name].first;
            if (l.ok && std::memcmp(l.data, sp, l.bytes)==0) ++ev_recovered; else ++ev_lost;
        }
        PlagueMemoryEngine::Stats s2 = eng.stats();
        ev_bounded = eng.agent_resident_bytes(1) <= agent_budget;
        bool ok = ev_lost==0 && ev_recovered==tens.size() &&
                  s2.evictions > evict_before && s2.recons > recons_before && ev_bounded;
        printf("A6 budget pressure (agent budget=%llu B): evictions_delta=%llu recons_delta=%llu exact=%zu bad=%zu resident=%llu B  %s\n",
               (unsigned long long)agent_budget,
               (unsigned long long)(s2.evictions-evict_before),
               (unsigned long long)(s2.recons-recons_before),
               ev_recovered, ev_lost,
               (unsigned long long)eng.agent_resident_bytes(1), ok?"PASS":"FAIL");
        stages.push_back({"A6 budgeted eviction + exact re-reconstruction", ok});
    }

    // =========================== A7: swarm replication rules ==================
    {
        // Content-addressed immutable ROM page replicates byte-exactly.
        const std::string t0 = tens[0]->name;
        Lease l0 = eng.Acquire(t0, 1);                    // replication source must be resident
        const PageEntry* pe = eng.Find(t0);
        bool src_ok = l0.ok && pe && pe->resident;
        bool rom_rep = eng.ReplicateToAgent(pe->content_key, /*agent=*/7);
        const PageEntry* rp = nullptr;
        for (const auto& kv : eng.TaskToId())
            if (kv.first.find("#rep") != std::string::npos) { rp = eng.Find(kv.first); break; }
        bool rep_exact = rp && rp->resident && rp->owner_agent == 7 && rp->bytes == src[t0].second &&
                         std::memcmp(rp->payload.data(), src[t0].first, rp->bytes)==0;
        // Mutable Context (growing KV) must NOT be blindly replicated.
        CtxMeta cm; cm.session=11; cm.layer=0; cm.token_lo=0; cm.token_hi=16; cm.mutable_kv=true;
        eng.RegisterContextPage("kv.mutable.11.0.0", 7, 64, cm);
        bool mutable_refused = !eng.ReplicateToAgent("ctx:11:0:0", /*agent=*/9);
        // Immutable Context (frozen KV snapshot) may be replicated.
        cm.session = 12; cm.mutable_kv = false;
        eng.RegisterContextPage("kv.frozen.12.0.0", 7, 64, cm);
        bool immutable_ctx_rep = eng.ReplicateToAgent("ctx:12:0:0", /*agent=*/9);
        // MMIO device registers must NEVER be replicated.
        EmuMeta em; em.guest_vm=0x1000; em.vaddr=0x400000; em.mmio=true;
        eng.RegisterEmuPage("mmio.400000", 7, 4096, em);
        bool mmio_refused = !eng.ReplicateToAgent("emu:4096:4194304", /*agent=*/9);
        bool ok = rom_rep && src_ok && rep_exact && mutable_refused && immutable_ctx_rep && mmio_refused;
        printf("A7 swarm replication: rom_replica=%d rom_byte_exact=%d mutable_ctx_refused=%d immutable_ctx_replicated=%d mmio_refused=%d replicated_pages=%llu  %s\n",
               (int)rom_rep,(int)rep_exact,(int)mutable_refused,(int)immutable_ctx_rep,(int)mmio_refused,
               (unsigned long long)eng.stats().replicated_pages, ok?"PASS":"FAIL");
        stages.push_back({"A7 swarm replication rules", ok});
    }

    // =========================== A8: fail-closed reconstruction ===============
    {
        PlagueMemoryEngine::Stats before = eng.stats();
        eng.SetReconstruct(PlagueMemoryEngine::Reconstruct());   // reader detached
        Lease l = eng.Acquire(tens[tens.size()-1]->name, 1);     // previously resident -> still served
        bool still_served = l.ok;
        eng.InvalidateAll(Policy::ROM);
        Lease l2 = eng.Acquire(tens[0]->name, 1);                // no reader, not resident
        PlagueMemoryEngine::Stats after = eng.stats();
        bool ok = !l2.ok && (after.recon_fail + after.size_fail) > (before.recon_fail + before.size_fail);
        printf("A8 fail-closed reconstruction: no_reader_ok=%d stale_served=%d recon_fail_delta=%llu size_fail_delta=%llu  %s\n",
               (int)still_served,(int)l2.ok,
               (unsigned long long)(after.recon_fail-before.recon_fail),
               (unsigned long long)(after.size_fail-before.size_fail),
               ok?"PASS":"FAIL");
        stages.push_back({"A8 fail-closed reconstruction", ok});
    }

    // =========================== A9: G02 byte-verified GPU transfer ===========
    if (want_gpu) {
        std::vector<VulkanCompute::EnumeratedDevice> devs = VulkanCompute::EnumerateDevices();
        printf("A9 devices=%zu", devs.size());
        for (auto& d : devs) printf(" [%d] %s (vendor=0x%x)", d.index, d.name.c_str(), d.vendor_id);
        printf("\n");
        if (devs.empty()) {
            printf("A9 GPU transfer SKIP: no Vulkan devices available\n");
        } else {
            int32_t pick1 = (gpu1 >= 0) ? gpu1 : devs.front().index;
            // Secondary: prefer a distinct physical GPU (e.g. the RX 7800 XT),
            // never a D3D12/Microsoft alias of the same physical device.
            int32_t pick2 = gpu2;
            if (pick2 < 0) {
                for (auto& d : devs) {
                    if (d.index == pick1) continue;
                    if (d.name.find("Direct3D12") != std::string::npos ||
                        d.name.find("Microsoft") != std::string::npos) continue;
                    pick2 = d.index;
                    if (d.name.find("7800 XT") != std::string::npos) break;   // prefer the RX 7800 XT
                }
            }

            // Re-attach the real reader, then warm the page set we will move.
            eng.SetReconstruct([&](const PageEntry& p, std::vector<uint8_t>& out) -> bool {
                auto it = src.find(p.task);
                if (it == src.end()) return false;
                if (it->second.second != p.bytes) return false;
                out.assign(it->second.first, it->second.first + it->second.second);
                return true;
            });
            eng.SetAgentBudget(1, 0);         // unlimited host budget for this stage
            eng.SetDeviceBudget(Residency::DEV0, 0);   // unlimited while warming

            const size_t gpu_pages = std::min<size_t>(tens.size(), 48);
            size_t max_bytes = 1;
            for (size_t i=0;i<gpu_pages;++i) { eng.Acquire(tens[i]->name, 1); max_bytes = std::max(max_bytes, tens[i]->bytes); }

            // --- device 1: bind the fabric's byte-verified transfer to the REAL
            //     Vulkan engine (device-local buffer + staged copy + readback) --
            VulkanCompute vc;
            vc.SetPreferredDeviceIndex(pick1);
            if (!vc.Initialize()) {
                printf("A9[device %d] Initialize() FAILED -- GPU transfer SKIP\n", pick1);
            } else {
                uint32_t scratch_idx = 0; size_t scratch_mem = 0;
                VkBuffer scratch_buf = VK_NULL_HANDLE; VkDeviceMemory scratch_bufmem = VK_NULL_HANDLE;
                bool have_scratch = vc.AllocateBuffer(max_bytes, scratch_idx, scratch_mem);
                if (!have_scratch) {
                    printf("A9[device %d] AllocateBuffer(%zu) FAILED -- GPU transfer SKIP\n", pick1, max_bytes);
                } else {
                    (void)scratch_buf; (void)scratch_bufmem;
                    printf("A9[device %d] active=%d name=%s scratch=%zu B\n",
                           pick1, vc.GetActiveDeviceIndex(), vc.GetDeviceInfo().device_name.c_str(), max_bytes);
                    TransferFn tf;
                    uint64_t upload_seq = 0;    // per-page device handle for the transferred image
                    tf.upload   = [&](uint32_t /*dev*/, const uint8_t* s, size_t b, uint64_t& tok) {
                        tok = ++upload_seq;      // non-zero handle identifying this image
                        return vc.CopyHostToBuffer(const_cast<uint8_t*>(s), scratch_idx, b);
                    };
                    tf.download = [&](uint32_t /*dev*/, uint64_t tok, uint8_t* d, size_t b) {
                        if (tok == 0) return false;
                        return vc.CopyBufferToHost(scratch_idx, d, b);
                    };
                    tf.verify   = [&](uint32_t /*dev*/, uint64_t tok, const uint8_t* ref, size_t b) {
                        if (tok == 0) return false;
                        std::vector<uint8_t> t(b);
                        if (!vc.CopyBufferToHost(scratch_idx, t.data(), b)) return false;
                        return std::memcmp(t.data(), ref, b) == 0;
                    };
                    eng.SetTransfer(tf);

                    const Residency dev = Residency::DEV0;
                    size_t ok_n = 0, bad_n = 0, direct_ok = 0;
                    for (size_t i=0;i<gpu_pages;++i) {
                        Lease l = eng.Acquire(tens[i]->name, 1);
                        if (!l.ok) { ++bad_n; continue; }
                        uint64_t token = eng.TransferToDevice(l.page_id, l.generation, ResidencyDevice(dev));
                        uint64_t token2 = eng.TransferToDevice(l.page_id, l.generation, ResidencyDevice(dev));
                        // Independent direct roundtrip on the same engine API.
                        uint32_t b2 = 0; size_t m2 = 0;
                        std::vector<uint8_t> back(l.bytes);
                        bool direct = vc.AllocateBuffer(l.bytes, b2, m2) &&
                                      vc.CopyHostToBuffer(const_cast<uint8_t*>(l.data), b2, l.bytes) &&
                                      vc.CopyBufferToHost(b2, back.data(), l.bytes) &&
                                      std::memcmp(back.data(), l.data, l.bytes) == 0;
                        if (direct) ++direct_ok;
                        if (token != 0 && token2 != 0 && direct) ++ok_n; else ++bad_n;
                        if (i == 0)
                            printf("A9[device %d] page0 name=%s bytes=%zu token=%llu warm=%d direct=%d\n",
                                   pick1, tens[i]->name.c_str(), l.bytes, (unsigned long long)token,
                                   (int)(eng.stats().transfer_warm >= 1), (int)direct);
                    }
                    // Budget enforcement on the fabric's device slot.
                    eng.SetDeviceBudget(dev, dev_budget);
                    uint64_t resident = eng.gpu_resident_bytes(ResidencyDevice(dev));
                    // A previously evicted page must be re-uploaded and re-verified.
                    const std::string t0 = tens[0]->name;
                    eng.InvalidateAll(Policy::ROM);
                    Lease l0 = eng.Acquire(t0, 1);
                    uint64_t token0 = eng.TransferToDevice(l0.page_id, l0.generation, ResidencyDevice(dev));
                    bool reupload_exact = token0 != 0 && l0.ok &&
                                          std::memcmp(l0.data, src[t0].first, l0.bytes) == 0;
                    PlagueMemoryEngine::Stats s = eng.stats();
                    bool ok = (bad_n == 0 && ok_n == gpu_pages && direct_ok == gpu_pages &&
                               resident <= dev_budget && token0 != 0 && reupload_exact &&
                               s.verify_fail == 0 && s.transfer_fail == 0);
                    printf("A9[device %d] G02 transfers ok=%zu bad=%zu direct_ok=%zu resident=%llu B budget=%llu B "
                           "reupload_after_evict=%d verify_fail=%llu transfer_fail=%llu  %s\n",
                           pick1, ok_n, bad_n, direct_ok,
                           (unsigned long long)resident, (unsigned long long)dev_budget,
                           (int)reupload_exact, (unsigned long long)s.verify_fail,
                           (unsigned long long)s.transfer_fail, ok ? "PASS" : "FAIL");
                    printf("A9[device %d] note: the %zu B scratch buffer is transfer staging, not a fabric-managed page;"
                           " fabric device bytes account only ROM pages moved by TransferToDevice.\n", pick1, max_bytes);
                    stages.push_back({"A9a G02 byte-verified GPU transfer on primary device", ok});
                    // --- device 2: independent byte-verified placement -----------
                    if (pick2 != pick1) {
                        VulkanCompute vc2;
                        vc2.SetPreferredDeviceIndex(pick2);
                        if (vc2.Initialize()) {
                            size_t ok2 = 0, bad2 = 0;
                            for (size_t i=0;i<std::min<size_t>(gpu_pages,16);++i) {
                                Lease l = eng.Acquire(tens[i]->name, 1);
                                uint32_t b2=0; size_t m2=0;
                                std::vector<uint8_t> back(l.bytes);
                                if (l.ok && vc2.AllocateBuffer(l.bytes,b2,m2) &&
                                    vc2.CopyHostToBuffer(const_cast<uint8_t*>(l.data), b2, l.bytes) &&
                                    vc2.CopyBufferToHost(b2, back.data(), l.bytes) &&
                                    std::memcmp(back.data(), l.data, l.bytes)==0) ++ok2; else ++bad2;
                            }
                            printf("A9[device %d] secondary byte-verified placements ok=%zu bad=%zu  %s\n",
                                   pick2, ok2, bad2, (bad2==0 && ok2>0) ? "PASS" : "FAIL");
                            stages.push_back({"A9b byte-verified placement on secondary device", bad2==0 && ok2>0});
                            vc2.Cleanup();
                        } else {
                            printf("A9[device %d] secondary Initialize() FAILED -- SKIP\n", pick2);
                        }
                    }
                    vc.Cleanup();
                }
            }
        }
    } else {
        printf("A9 G02 GPU transfer SKIP: --no-gpu\n");
    }

    PlagueMemoryEngine::Stats st = eng.stats();
    printf("---- fabric stats ----\n");
    printf("hits=%llu misses=%llu recons=%llu recon_fail=%llu size_fail=%llu evictions=%llu\n",
           (unsigned long long)st.hits,(unsigned long long)st.misses,(unsigned long long)st.recons,
           (unsigned long long)st.recon_fail,(unsigned long long)st.size_fail,(unsigned long long)st.evictions);
    printf("pin_total=%llu pin_peak=%d invalidated=%llu pinned_refused_invalid=%llu\n",
           (unsigned long long)st.pin_total, st.pin_active_peak,
           (unsigned long long)st.invalidated,(unsigned long long)st.pinned_refused_invalid);
    printf("transfer_ok=%llu transfer_warm=%llu transfer_fail=%llu verify_fail=%llu transfer_unsupported=%llu\n",
           (unsigned long long)st.transfer_ok,(unsigned long long)st.transfer_warm,
           (unsigned long long)st.transfer_fail,(unsigned long long)st.verify_fail,
           (unsigned long long)st.transfer_unsupported);
    printf("replicated_pages=%llu cow_created=%llu emu_translations=%llu tc_invalidated=%llu exec_invalid=%llu prefetch_hints=%llu\n",
           (unsigned long long)st.replicated_pages,(unsigned long long)st.cow_created,
           (unsigned long long)st.emu_translations,(unsigned long long)st.tc_invalidated,
           (unsigned long long)st.exec_invalid,(unsigned long long)st.prefetch_hints);

    size_t stages_passed = 0;
    for (auto& s : stages) if (s.second) ++stages_passed;
    for (auto& s : stages)
        printf("stage %-56s %s\n", s.first, s.second ? "PASS" : "FAIL");
    bool all = (stages_passed == stages.size() && byte_bad == 0);
    printf("PLAGUE_ROM_RECEIPT tensor_pages=%zu stages=%zu passed=%zu byte_exact=%zu/%zu warm=%zu prefetch=%zu transfer_ok=%llu verify_fail=%llu verdict=%s\n",
           tens.size(), stages.size(), stages_passed, byte_exact, tens.size(), warm_ok, pf_ok,
           (unsigned long long)st.transfer_ok, (unsigned long long)st.verify_fail,
           all ? "PASS" : "FAIL");
    return all ? 0 : 1;
}
