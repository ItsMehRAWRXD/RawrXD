// R04 regression: synthetic MoE GGUF -> expert prune -> verify.
// Asserts: retained experts bit-identical, pruned dims rewritten, shared
// experts untouched, expert_count metadata patched, output strictly smaller.
#include "reap/NativeExpertPruner.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

using namespace RawrXD::REAP;

static int g_fail = 0;
static void Check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++g_fail;
}
// Hang/crash localization: flushed checkpoints at each major operation.
#define R04_CHECKPOINT(msg) do { std::fprintf(stderr, "[R04] %s\n", msg); std::fflush(stderr); } while (0)

static void PutU32(std::vector<uint8_t>& v, uint32_t x) { const uint8_t* p = reinterpret_cast<const uint8_t*>(&x); v.insert(v.end(), p, p+4); }
static void PutU64(std::vector<uint8_t>& v, uint64_t x) { const uint8_t* p = reinterpret_cast<const uint8_t*>(&x); v.insert(v.end(), p, p+8); }
static void PutStr(std::vector<uint8_t>& v, const std::string& s) { PutU64(v, s.size()); v.insert(v.end(), s.begin(), s.end()); }

struct SynTensor { std::string name; std::vector<uint64_t> dims; std::vector<uint8_t> data; };

static std::vector<uint8_t> BuildGGUF(const std::vector<SynTensor>& ts) {
    std::vector<uint8_t> h;
    PutU32(h, 0x46554747u); PutU32(h, 3u);
    PutU64(h, ts.size()); PutU64(h, 4u);
    PutStr(h, "general.architecture"); PutU32(h, 8); PutStr(h, "llama");
    PutU32(h, 4); PutU32(h, 32u);   // placeholder alignment, fixed below
    // (rebuild with correct KVs: architecture, alignment, expert_count, expert_used_count)
    h.clear();
    PutU32(h, 0x46554747u); PutU32(h, 3u);
    PutU64(h, ts.size()); PutU64(h, 4u);
    auto kv_str = [&](const std::string& k, const std::string& v) { PutStr(h, k); PutU32(h, 8); PutStr(h, v); };
    auto kv_u32 = [&](const std::string& k, uint32_t v) { PutStr(h, k); PutU32(h, 4); PutU32(h, v); };
    kv_str("general.architecture", "llama");
    kv_u32("general.alignment", 32u);
    kv_u32("llama.expert_count", 4u);
    kv_u32("llama.expert_used_count", 4u);
    uint64_t cursor = 0;
    std::vector<uint64_t> offsets(ts.size());
    for (size_t i = 0; i < ts.size(); ++i) {
        offsets[i] = (cursor + 31) & ~(uint64_t)31;
        cursor = offsets[i] + ts[i].data.size();
    }
    for (size_t i = 0; i < ts.size(); ++i) {
        const auto& t = ts[i];
        PutStr(h, t.name); PutU32(h, (uint32_t)t.dims.size());
        for (uint64_t d : t.dims) PutU64(h, d);
        PutU32(h, 0); PutU64(h, offsets[i]);
    }
    const uint64_t data_start = (h.size() + 31) & ~(uint64_t)31;
    h.resize(static_cast<size_t>(data_start), 0);
    for (size_t i = 0; i < ts.size(); ++i) {
        const uint64_t pos = data_start + offsets[i];
        if (h.size() < pos) h.resize(static_cast<size_t>(pos), 0);
        h.insert(h.end(), ts[i].data.begin(), ts[i].data.end());
    }
    return h;
}

// Minimal GGUF reader: names/dims/types/offsets + expert_count + data start.
struct LoadedGGUF {
    std::vector<std::string> names;
    std::vector<std::vector<uint64_t>> dims;
    std::vector<uint32_t> types;
    std::vector<uint64_t> offs;
    uint64_t data_start = 0;
    uint32_t expert_count = 0;
    uint32_t expert_used_count = 0;
};
static bool LoadGGUF(const std::string& path, LoadedGGUF& g) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    uint32_t magic=0, version=0; uint64_t nt=0, nk=0;
    in.read(reinterpret_cast<char*>(&magic),4); in.read(reinterpret_cast<char*>(&version),4);
    in.read(reinterpret_cast<char*>(&nt),8); in.read(reinterpret_cast<char*>(&nk),8);
    if (magic != 0x46554747) return false;
    static const uint8_t sz[]={1,1,2,2,4,4,4,1,0,0,8,8,8};
    auto rd_name = [&](std::string& s) { uint64_t n=0; if(!in.read(reinterpret_cast<char*>(&n),8)||n>(1ULL<<20)) return false; s.resize(n); return n==0 || (bool)in.read(&s[0], n); };
    for (uint64_t i = 0; i < nk; ++i) {
        std::string key; uint32_t type=0;
        if (!rd_name(key) || !in.read(reinterpret_cast<char*>(&type),4)) return false;
        if (type == 8) { uint64_t vn=0; if(!in.read(reinterpret_cast<char*>(&vn),8)||vn>(1ULL<<26)) return false; std::string v(vn,'\0'); if (vn && !in.read(&v[0], vn)) return false; }
        else if (type == 9) { uint32_t el=0; uint64_t c=0; if(!in.read(reinterpret_cast<char*>(&el),4)||!in.read(reinterpret_cast<char*>(&c),8)||el>12||el==9) return false; if (el==8) { for (uint64_t k=0;k<c;++k) { std::string s; if(!rd_name(s)) return false; } } else { if (el==9 || !sz[el]) return false; in.seekg(c*sz[el], std::ios::cur); } }
        else { if (type > 12 || !sz[type]) return false; if (type == 4) { uint32_t v=0; in.read(reinterpret_cast<char*>(&v),4); if (key == "llama.expert_count") g.expert_count = v; if (key == "llama.expert_used_count") g.expert_used_count = v; } else in.seekg(sz[type], std::ios::cur); }
        if (!in) return false;
    }
    for (uint64_t i = 0; i < nt; ++i) {
        std::string name; uint32_t nd=0;
        if (!rd_name(name) || !in.read(reinterpret_cast<char*>(&nd),4) || nd==0 || nd>8) return false;
        std::vector<uint64_t> d(nd);
        for (auto& x : d) if (!in.read(reinterpret_cast<char*>(&x),8)) return false;
        uint32_t type=0; uint64_t off=0;
        if (!in.read(reinterpret_cast<char*>(&type),4) || !in.read(reinterpret_cast<char*>(&off),8)) return false;
        g.names.push_back(name); g.dims.push_back(std::move(d)); g.types.push_back(type); g.offs.push_back(off);
    }
    const uint64_t meta_end = (uint64_t)in.tellg();
    g.data_start = (meta_end + 31) & ~(uint64_t)31;
    return true;
}

static std::vector<uint8_t> ReadAt(const std::string& path, uint64_t data_start, uint64_t off, uint64_t bytes) {
    std::ifstream f(path, std::ios::binary);
    f.seekg(static_cast<std::streamoff>(data_start + off), std::ios::beg);
    std::vector<uint8_t> b(bytes);
    if (bytes && !f.read(reinterpret_cast<char*>(b.data()), static_cast<std::streamsize>(bytes))) b.clear();
    return b;
}

int main() {
    const std::string src = "reap_prune_src.gguf";
    const std::string dst = "reap_prune_dst.gguf";
    std::vector<SynTensor> ts;
    const uint32_t E = 4, EMB = 8, FF = 4;
    for (uint32_t L = 0; L < 2; ++L) {
        const std::string p = "blk." + std::to_string(L) + ".";
        { SynTensor t; t.name = p + "ffn_gate_inp.weight"; t.dims = {EMB, E}; t.data.resize(EMB*E*4);
          for (uint32_t e = 0; e < E; ++e) for (uint32_t r = 0; r < EMB; ++r) { float v = (float)(r + 1) * (float)(e + 1); std::memcpy(t.data.data() + (e*EMB + r)*4, &v, 4); }
          ts.push_back(std::move(t)); }
        const char* names[3] = { "ffn_gate_exps.weight", "ffn_up_exps.weight", "ffn_down_exps.weight" };
        for (int g = 0; g < 3; ++g) {
            SynTensor t; t.name = p + names[g]; t.dims = {EMB, FF, E}; t.data.resize(EMB*FF*E*4);
            for (uint32_t e = 0; e < E; ++e) for (uint32_t i = 0; i < EMB*FF; ++i) { float v = (float)((e + 1) * 1000 + i); std::memcpy(t.data.data() + (e*EMB*FF + i)*4, &v, 4); }
            ts.push_back(std::move(t)); }
        { SynTensor t; t.name = p + "ffn_shared.weight"; t.dims = {EMB, FF}; t.data.resize(EMB*FF*4);
          for (size_t i = 0; i < t.data.size(); i += 4) { float v = (float)(i / 4); std::memcpy(t.data.data()+i, &v, 4); }
          ts.push_back(std::move(t)); }
        { SynTensor n; n.name = p + "attn_norm.weight"; n.dims = {EMB}; n.data.assign(EMB*4, 0);
          for (uint32_t i = 0; i < EMB; ++i) { float v = 1.0f; std::memcpy(n.data.data()+i*4, &v, 4); }
          ts.push_back(std::move(n)); }
    }
    { std::ofstream f(src, std::ios::binary | std::ios::trunc);
      const auto bytes = BuildGGUF(ts);
      f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())); }
    R04_CHECKPOINT("built synthetic GGUF");
    std::printf("R04 prune regression: experts=%u keep_ratio=0.5 (top-2 per layer by router norm)\n", E);

    PruneRequest req; req.keep_ratio = 0.5;
    PruneReport rep;
    const PruneError err = PruneGGUF(src, dst, req, rep);
    R04_CHECKPOINT("pruned");
    static const char* kErrName[] = {"None","Input","Format","Unsupported","Overflow","Output","NoExperts"};
    std::printf("F: PruneGGUF err=%d (%s) layers=%zu input=%llu output=%llu experts_removed=%llu\n",
                (int)err, kErrName[(int)err], rep.layers.size(),
                (unsigned long long)rep.input_bytes, (unsigned long long)rep.output_bytes,
                (unsigned long long)rep.experts_removed);
    for (const auto& l : rep.layers)
        std::printf("F: layer %s kept=[%u,%u] before=%llu after=%llu\n", l.tensor.c_str(),
                    l.kept.size() > 0 ? l.kept[0] : 0, l.kept.size() > 1 ? l.kept[1] : 0,
                    (unsigned long long)l.bytes_before, (unsigned long long)l.bytes_after);
    std::fflush(stdout);
    Check(err == PruneError::None, "PruneGGUF succeeded");
    Check(rep.experts_removed == 12, "experts removed = 12 (6 exps tensors x 2)");
    Check(rep.bytes_saved > 0, "bytes saved > 0 (real reduction)");
    Check(rep.output_bytes < rep.input_bytes, "output strictly smaller than input");

    LoadedGGUF gs, gd;
    Check(LoadGGUF(src, gs), "source re-parsed");
    R04_CHECKPOINT("source parsed");
    Check(LoadGGUF(dst, gd), "pruned output re-parsed");
    R04_CHECKPOINT("output parsed");
    Check(gd.expert_count == 2, "expert_count metadata rewritten to 2");
    Check(gd.expert_used_count == 2, "expert_used_count clamped to 2 (min(4,2))");
    Check(gd.names.size() == gs.names.size(), "tensor count unchanged");
    R04_CHECKPOINT("verify begin");
    std::printf("F: gs.tensors=%zu gd.tensors=%zu gs.dims=%zu gd.dims=%zu\n",
                gs.names.size(), gd.names.size(), gs.dims.size(), gd.dims.size());
    std::fflush(stdout);
    if (gd.dims.size() != gs.dims.size() || gd.offs.size() != gs.offs.size()) {
        std::printf("R04_RESULT=FAIL (parsed tensor-count mismatch; gd parse incomplete)\n");
        return 1;
    }

    // expected kept experts per layer: router norm = (e+1)*sqrt(sum r^2) -> top-2 = {2,3}
    bool dims_ok = true, shared_ok = true, kept_ok = true, router_ok = true;
    const uint64_t slice = EMB * FF * 4;
    const uint64_t router_slice = EMB * 4;   // F32 router column (n_embd values)
    for (size_t i = 0; i < gs.names.size(); ++i) {
        const bool is_router = (gs.dims[i].size() == 2 && gs.dims[i][1] == 4 &&
                                gd.dims[i].size() == 2 && gd.dims[i][1] == 2);
        const bool is_exps = gd.dims[i].size() == 3 && gd.dims[i][2] == 2 &&
            gs.dims[i].size() == 3 && gs.dims[i][2] == 4;
        if (is_router) {
            if (!(gd.dims[i] == std::vector<uint64_t>({EMB, 2}))) router_ok = false;
            for (uint32_t k = 0; k < 2; ++k) {
                const uint32_t e = (k == 0) ? 2u : 3u;
                const auto want = ReadAt(src, gs.data_start, gs.offs[i] + (uint64_t)e * router_slice, router_slice);
                const auto got  = ReadAt(dst, gd.data_start, gd.offs[i] + (uint64_t)k * router_slice, router_slice);
                if (want.size() != router_slice || got != want) {
                    router_ok = false;
                    size_t j = 0; while (j < want.size() && j < got.size() && want[j] == got[j]) ++j;
                    std::printf("F: router mismatch src_expert=%u first_diff=%zu\n", e, j);
                }
            }
        } else if (is_exps) {
            if (!(gd.dims[i] == std::vector<uint64_t>({EMB, FF, 2}))) dims_ok = false;
            // kept experts {2,3} (ascending) must be bit-identical
            for (uint32_t k = 0; k < 2; ++k) {
                const uint32_t e = (k == 0) ? 2u : 3u;
                const auto want = ReadAt(src, gs.data_start, gs.offs[i] + (uint64_t)e * slice, slice);
                const auto got  = ReadAt(dst, gd.data_start, gd.offs[i] + (uint64_t)k * slice, slice);
                if (want.size() != slice || got != want) {
                    kept_ok = false;
                    size_t j = 0; while (j < want.size() && j < got.size() && want[j] == got[j]) ++j;
                    std::printf("F: mismatch tensor=%s src_expert=%u slot=%u sizes=%zu/%zu first_diff_byte=%zu\n",
                                gs.names[i].c_str(), e, k, want.size(), got.size(), j);
                }
            }
        } else {
            if (!(gd.dims[i] == gs.dims[i])) dims_ok = false;
            const auto a = ReadAt(src, gs.data_start, gs.offs[i], gs.dims[i].empty() ? 0 : 0);
            (void)a;
            // full tensor bytes
            uint64_t sb = 0;
            { const auto& d = gs.dims[i]; sb = d.size() ? d[0] : 0; for (size_t x = 1; x < d.size(); ++x) sb *= d[x]; sb *= 4; }
            const auto want = ReadAt(src, gs.data_start, gs.offs[i], sb);
            const auto got  = ReadAt(dst, gd.data_start, gd.offs[i], sb);
            if (want.size() != sb || got != want) shared_ok = false;
        }
    }
    Check(dims_ok, "dims rewritten for exps; non-exps dims unchanged");
    Check(router_ok, "router compacted to 2 experts with retained columns bit-identical");
    Check(kept_ok, "retained experts (2,3) bit-identical to source");
    Check(shared_ok, "shared experts / router / norm bit-identical");
    Check(rep.output_bytes < rep.input_bytes && rep.bytes_saved == rep.input_bytes - rep.output_bytes,
          "bytes_saved == input - output");

    std::printf("R04_RESULT=%s (failures=%d)\n", g_fail == 0 ? "PASS" : "FAIL", g_fail);
    return g_fail == 0 ? 0 : 1;
}