#pragma once
// R04: native expert pruning over GGUF. Architecture-aware per-layer expert
// selection with physical removal of whole experts from MoE *_exps tensors
// (slowest-dimension slices, block-aligned), router expert_count metadata
// rewrite, and byte-identical retention of every other tensor. This is a real
// transformation: the output artifact is smaller than the input.
//
// Importance calibration: per-expert L2 norm of the router row
// (blk.N.ffn_gate_inp.weight, F32/F16). Shared experts and non-exps tensors
// are never pruned. Retained expert bytes are copied bit-identically; pruned
// expert bytes never appear in the output.
#include "NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstring>
#include <map>
#include <set>
#include <sstream>

namespace RawrXD { namespace REAP {

enum class PruneError { None, Input, Format, Unsupported, Overflow, Output, NoExperts };

struct PruneRequest {
    double keep_ratio = 0.5;      // fraction of experts retained per layer
    uint32_t min_experts = 1;
};

struct PruneLayerReport {
    std::string tensor;
    uint32_t experts_before = 0;
    uint32_t experts_after = 0;
    uint64_t bytes_before = 0;
    uint64_t bytes_after = 0;
    std::vector<uint32_t> kept;   // retained expert indices (ascending)
};

struct PruneReport {
    std::vector<PruneLayerReport> layers;
    uint64_t input_bytes = 0;
    uint64_t output_bytes = 0;
    uint64_t experts_removed = 0;
    uint64_t bytes_saved = 0;
};

inline bool IsExpsTensor(const std::string& name, const std::vector<uint64_t>& dims) {
    return dims.size() >= 2 && dims.back() >= 2 &&
        name.find("_exps.") != std::string::npos;
}

struct PruneTensor {
    std::string name;
    std::vector<uint64_t> dims;
    uint32_t type = 0;
    uint64_t offset = 0;          // relative to aligned data start
    uint64_t bytes = 0;
    uint64_t old_bytes = 0;
    bool pruned = false;
    std::vector<uint32_t> kept;
    uint64_t slice_bytes = 0;
};

// Minimal fp16 -> fp32 (IEEE 754 binary16).
inline float PruneHalfToFloat(uint16_t h) {
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    uint32_t mant = h & 0x03FFu, exp = (h >> 10) & 0x1Fu;
    uint32_t bits;
    if (exp == 0) {
        if (mant == 0) bits = sign;
        else {
            exp = 127 - 15 + 1;
            while ((mant & 0x0400u) == 0) { mant <<= 1; --exp; }
            mant &= 0x03FFu;
            bits = sign | (exp << 23) | (mant << 13);
        }
    } else if (exp == 31) bits = sign | 0x7F800000u | (mant << 13);
    else bits = sign | ((exp - 15 + 127) << 23) | (mant << 13);
    float f; std::memcpy(&f, &bits, 4);
    return f;
}

inline bool EndsWith(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
        s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

struct PruneKV {
    uint64_t kv_start = 0;        // file offset of the whole KV entry
    uint64_t value_pos = 0;       // file offset of the value bytes
    uint64_t value_size = 0;
    std::string key;
    uint32_t type = 0;
};

// Per-expert L2 importance from the router tensor (F32/F16; else uniform).
inline bool RouterImportance(const std::vector<uint8_t>& bytes, uint32_t type,
                             uint64_t n_embd, uint32_t n_expert,
                             std::vector<double>& out) {
    out.assign(n_expert, 1.0);
    const uint64_t esz = (type == 0) ? 4 : (type == 1 ? 2 : 0);
    if (!esz) return false;
    const uint64_t col_bytes = n_embd * esz;
    if (bytes.size() < col_bytes * n_expert) return false;
    for (uint32_t e = 0; e < n_expert; ++e) {
        const uint8_t* p = bytes.data() + (uint64_t)e * col_bytes;
        double s = 0.0;
        for (uint64_t i = 0; i < n_embd; ++i) {
            float v = 0.0f;
            if (type == 0) std::memcpy(&v, p + i * 4, 4);
            else { uint16_t h; std::memcpy(&h, p + i * 2, 2); v = PruneHalfToFloat(h); }
            s += (double)v * (double)v;
        }
        out[e] = std::sqrt(s);
    }
    return true;
}

inline PruneError PruneGGUF(const std::string& input,
                            const std::string& output,
                            const PruneRequest& req,
                            PruneReport& report) {
    if (input == output) return PruneError::Output;
    if (!(req.keep_ratio > 0.0 && req.keep_ratio <= 1.0) || !req.min_experts)
        return PruneError::Unsupported;
    std::ifstream in(input, std::ios::binary);
    if (!in) return PruneError::Input;
    uint32_t magic = 0, version = 0;
    uint64_t tensorCount = 0, kvCount = 0;
    if (!ReadU32(in, magic) || !ReadU32(in, version) ||
        !ReadU64(in, tensorCount) || !ReadU64(in, kvCount) ||
        magic != 0x46554747 || (version != 2 && version != 3) ||
        tensorCount > (1ULL << 20) || kvCount > (1ULL << 20))
        return PruneError::Format;

    uint64_t alignment = 32;
    std::string arch;
    bool have_expert_count = false;
    uint32_t expert_count_old = 0, expert_used_old = 0;
    bool have_expert_used = false;
    uint64_t new_expert_count = 0;
    std::set<std::string> keys;
    std::vector<PruneKV> kvs;
    static const uint8_t sizes[] = {1,1,2,2,4,4,4,1,0,0,8,8,8};
    for (uint64_t i = 0; i < kvCount; ++i) {
        const auto kv_start = in.tellg();
        if (kv_start < 0) return PruneError::Format;
        PruneKV kv;
        kv.kv_start = static_cast<uint64_t>(kv_start);
        if (!ReadName(in, kv.key) || kv.key.empty() || !keys.insert(kv.key).second ||
            !ReadU32(in, kv.type)) return PruneError::Format;
        kv.value_pos = static_cast<uint64_t>(in.tellg());
        uint32_t type = kv.type;
        if (type > 12) return PruneError::Format;
        if (type == 8) {
            uint64_t n=0; if(!ReadU64(in,n)||n>(1ULL<<26)) return PruneError::Format;
            kv.value_size = 8 + n;
            in.seekg(static_cast<std::streamoff>(n), std::ios::cur);
            if (kv.key == "general.architecture") {
                in.clear(); in.seekg(static_cast<std::streamoff>(kv.value_pos), std::ios::beg);
                if (!ReadName(in, arch)) return PruneError::Format;
            }
        } else if (type == 9) {
            uint32_t elem=0; uint64_t count=0;
            if(!ReadU32(in,elem)||!ReadU64(in,count)||elem>12||elem==9||count>(1ULL<<24)) return PruneError::Format;
            kv.value_size = 12;
            for (uint64_t k=0;k<count;++k) {
                if (elem == 8) { std::string s; uint32_t t0=0; if(!ReadName(in,s)||!ReadU32(in,t0)||t0>12) return PruneError::Format; uint64_t n=0; if(!ReadU64(in,n)||n>(1ULL<<26)) return PruneError::Format; in.seekg(static_cast<std::streamoff>(n), std::ios::cur); kv.value_size += 8 + n + 4 + 8; }
                else { if (elem==9 || sizes[elem]==0) return PruneError::Format; in.seekg(sizes[elem], std::ios::cur); kv.value_size += sizes[elem]; }
            }
        } else {
            kv.value_size = sizes[type];
            if (type == 4) {
                uint32_t v = 0;
                in.read(reinterpret_cast<char*>(&v), 4);
                if (!EndsWith(kv.key, "expert_used_count")) { if (EndsWith(kv.key, "expert_count")) expert_count_old = v; }
                else { expert_used_old = v; have_expert_used = true; }
            } else in.seekg(static_cast<std::streamsize>(kv.value_size), std::ios::cur);
        }
        if (!in) return PruneError::Format;
        if (kv.key == "general.alignment") {
            uint32_t v = 0;
            in.clear(); in.seekg(static_cast<std::streamoff>(kv.value_pos), std::ios::beg);
            if (!ReadU32(in, v) || v < 8 || v > 4096 || (v & (v - 1))) return PruneError::Format;
            alignment = v;
        }
        if (kv.key == arch + ".expert_count") { have_expert_count = true; }
        kvs.push_back(std::move(kv));
    }
    const uint64_t metadataEnd = static_cast<uint64_t>(in.tellg());

    // ---- tensor directory ----
    std::vector<PruneTensor> tensors;
    tensors.reserve(static_cast<size_t>(tensorCount));
    std::set<std::string> names;
    for (uint64_t i = 0; i < tensorCount; ++i) {
        PruneTensor t;
        uint32_t nd = 0;
        if (!ReadName(in, t.name) || t.name.empty() || !names.insert(t.name).second ||
            !ReadU32(in, nd) || nd == 0 || nd > 8) return PruneError::Format;
        t.dims.resize(nd);
        uint64_t count = 1;
        for (auto& d : t.dims) if (!ReadU64(in, d) || !d || !CheckedMultiply(count, d, count)) return PruneError::Format;
        uint64_t block=0, bb=0;
        if (!ReadU32(in, t.type) || !ReadU64(in, t.offset) ||
            !StorageLayout(t.type, block, bb) || count % block ||
            !CheckedMultiply(count/block, bb, t.bytes)) return PruneError::Unsupported;
        t.old_bytes = t.bytes;
        tensors.push_back(std::move(t));
    }
    const uint64_t dirEnd = static_cast<uint64_t>(in.tellg());
    const uint64_t dataStart = (dirEnd + alignment - 1) & ~(alignment - 1);

    // ---- importance + selection (per layer) ----
    uint32_t pruned_layers = 0;
    uint32_t global_expert_count = 0;
    bool global_set = false;
    for (auto& t : tensors) {
        if (!IsExpsTensor(t.name, t.dims)) continue;
        const uint32_t n_expert = static_cast<uint32_t>(t.dims.back());
        if (!global_set) { global_expert_count = n_expert; global_set = true; }
        // All expert tensors of a layer (gate/up/down) share the layer router.
        const std::string blk_prefix = t.name.substr(0, t.name.find("ffn_"));   // "blk.N."
        const std::string router_name = blk_prefix + "ffn_gate_inp.weight";
        const PruneTensor* router = nullptr;
        for (const auto& o : tensors) if (o.name == router_name) { router = &o; break; }
        std::vector<uint8_t> rbytes;
        if (router) {
            rbytes.resize(static_cast<size_t>(router->bytes));
            in.clear();
            in.seekg(static_cast<std::streamoff>(dataStart + router->offset), std::ios::beg);
            if (!in.read(reinterpret_cast<char*>(rbytes.data()), static_cast<std::streamsize>(rbytes.size())))
                return PruneError::Format;
        }
        std::vector<double> imp;
        bool have_imp = false;
        if (router && (router->type == 0 || router->type == 1))
            have_imp = RouterImportance(rbytes, router->type, router->dims[0], n_expert, imp);
        if (!have_imp) imp.assign(n_expert, 1.0);   // uniform fallback (first K)
        uint32_t k = (uint32_t)std::ceil(n_expert * req.keep_ratio);
        if (k < req.min_experts) k = req.min_experts;
        if (k >= n_expert) {
            report.layers.push_back({t.name, n_expert, n_expert, t.bytes, t.bytes, {}});
            continue;
        }
        std::vector<uint32_t> order(n_expert);
        for (uint32_t e = 0; e < n_expert; ++e) order[e] = e;
        std::stable_sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b){ return imp[a] > imp[b]; });
        order.resize(k);
        std::sort(order.begin(), order.end());
        t.pruned = true;
        t.kept = order;
        // physical bytes per retained expert: the slowest-dim slice
        uint64_t slice_elems = 1;
        for (size_t d = 0; d + 1 < t.dims.size(); ++d) slice_elems *= t.dims[d];
        uint64_t block=0, bb=0;
        StorageLayout(t.type, block, bb);
        // Fail closed: an expert slice that does not fill whole quantization
        // blocks cannot be pruned physically (silent truncation would corrupt).
        if (slice_elems % block) return PruneError::Unsupported;
        t.slice_bytes = (slice_elems / block) * bb;
        uint64_t after_bytes = 0;
        for (uint32_t e : order) {
            if (after_bytes > UINT64_MAX - t.slice_bytes) return PruneError::Overflow;
            after_bytes += t.slice_bytes;
        }
        if (after_bytes > t.old_bytes) return PruneError::Format;
        t.bytes = after_bytes;
        report.layers.push_back({t.name, n_expert, k, t.old_bytes, t.bytes, order});
        ++pruned_layers;
        report.experts_removed += (n_expert - k);
        report.bytes_saved += t.slice_bytes * (n_expert - k);
    }
    if (pruned_layers == 0) return PruneError::NoExperts;

    // ---- router compaction: shrink each layer router's expert axis with the
    // SAME kept indices as its expert tensors, so routing and expert weights
    // stay consistent (no dangling expert indices after pruning).
    for (auto& t : tensors) {
        if (t.pruned || t.dims.size() != 2) continue;
        if (t.name.find("ffn_gate_inp.weight") == std::string::npos) continue;
        const std::string blk = t.name.substr(0, t.name.find("ffn_"));
        const std::string gate_name = blk + "ffn_gate_exps.weight";
        const PruneTensor* gate = nullptr;
        for (const auto& o : tensors) if (o.name == gate_name) { gate = &o; break; }
        if (!gate || !gate->pruned) continue;
        const uint32_t esz = (t.type == 0) ? 4u : (t.type == 1 ? 2u : 0u);
        // Fail closed: a pruned layer's router must be compactable (F32/F16);
        // silently keeping a 4-output router over 2 experts is inconsistent.
        if (!esz) return PruneError::Unsupported;
        t.slice_bytes = t.dims[0] * esz;
        uint64_t after_bytes = 0;
        for (uint32_t e : gate->kept) {
            if (after_bytes > UINT64_MAX - t.slice_bytes) return PruneError::Overflow;
            after_bytes += t.slice_bytes;
        }
        if (after_bytes > t.old_bytes) return PruneError::Format;
        t.pruned = true;
        t.kept = gate->kept;
        t.bytes = after_bytes;
        report.bytes_saved += t.old_bytes - after_bytes;   // router columns removed
    }

    new_expert_count = 0;
    for (const auto& l : report.layers) if (l.experts_after) { new_expert_count = l.experts_after; break; }
    if (have_expert_count && new_expert_count == 0) return PruneError::Format;

    // ---- write transformed GGUF ----
    std::ofstream out(output, std::ios::binary | std::ios::trunc);
    if (!out) return PruneError::Output;
    { std::vector<uint8_t> h(24); std::memcpy(h.data(), &magic, 4); std::memcpy(h.data()+4, &version, 4);
      std::memcpy(h.data()+8, &tensorCount, 8); std::memcpy(h.data()+16, &kvCount, 8);
      if (!out.write(reinterpret_cast<const char*>(h.data()), h.size())) return PruneError::Output; }
    // metadata: replay KV region with the expert_count value patched
    in.clear(); in.seekg(24, std::ios::beg);
    uint64_t cursor = 24;
    for (const auto& kv : kvs) {
        if (!CopyRange(in, out, cursor, kv.kv_start - cursor)) return PruneError::Output;
        cursor = kv.kv_start;
        std::string key; uint32_t type = 0;
        in.clear(); in.seekg(static_cast<std::streamoff>(kv.kv_start), std::ios::beg);
        if (!ReadName(in, key) || !ReadU32(in, type)) return PruneError::Output;
        if (!WriteName(out, key) || !WriteU32(out, type)) return PruneError::Output;
        if (have_expert_count && EndsWith(kv.key, "expert_count") && type == 4) {
            if (!WriteU32(out, new_expert_count)) return PruneError::Output;
        } else if (have_expert_used && EndsWith(kv.key, "expert_used_count") && type == 4) {
            // expert_used_count (top-k) must never exceed the pruned expert count.
            const uint32_t uv = (expert_used_old < new_expert_count) ? expert_used_old : new_expert_count;
            if (!WriteU32(out, uv)) return PruneError::Output;
        } else {
            if (!CopyRange(in, out, kv.value_pos, kv.value_size)) return PruneError::Output;
        }
        cursor = kv.value_pos + kv.value_size;
    }
    if (!CopyRange(in, out, cursor, metadataEnd - cursor)) return PruneError::Output;

    // tensor directory (rewritten dims/offsets)
    std::vector<uint64_t> new_offsets(tensors.size());
    uint64_t cursor2 = 0;   // new relative data offset
    for (size_t i = 0; i < tensors.size(); ++i) {
        const uint64_t aligned = (cursor2 + alignment - 1) & ~(alignment - 1);
        new_offsets[i] = aligned;
        cursor2 = aligned + tensors[i].bytes;
    }
    for (size_t i = 0; i < tensors.size(); ++i) {
        const auto& t = tensors[i];
        if (!WriteName(out, t.name) || !WriteU32(out, (uint32_t)t.dims.size())) return PruneError::Output;
        for (size_t d = 0; d < t.dims.size(); ++d) {
            const uint64_t v = (t.pruned && d + 1 == t.dims.size()) ? (uint64_t)t.kept.size() : t.dims[d];
            if (!WriteU64(out, v)) return PruneError::Output;
        }
        if (!WriteU32(out, t.type) || !WriteU64(out, new_offsets[i])) return PruneError::Output;
    }
    if (!PadTo(out, alignment)) return PruneError::Output;
    const uint64_t out_data_start = static_cast<uint64_t>(out.tellp());
    for (size_t i = 0; i < tensors.size(); ++i) {
        const auto& t = tensors[i];
        const auto pos = out.tellp();
        if (pos < 0) return PruneError::Output;
        const uint64_t target = out_data_start + new_offsets[i];
        const uint64_t absolute = static_cast<uint64_t>(pos);
        if (absolute > target) return PruneError::Format;
        uint64_t padding = target - absolute;
        const char zeros[4096] = {};
        while (padding) {
            const auto chunk = static_cast<std::streamsize>(std::min<uint64_t>(padding, sizeof(zeros)));
            if (!out.write(zeros, chunk)) return PruneError::Output;
            padding -= (uint64_t)chunk;
        }
        if (!t.pruned) {
            if (!CopyRange(in, out, dataStart + t.offset, t.old_bytes)) return PruneError::Output;
        } else {
            // copy only the retained expert slices (slowest-dim contiguous)
            const uint64_t slice_off = dataStart + t.offset;
            for (uint32_t e : t.kept) {
                if (!CopyRange(in, out, slice_off + (uint64_t)e * t.slice_bytes, t.slice_bytes))
                    return PruneError::Output;
            }
        }
    }
    out.flush();
    { std::ifstream f(input, std::ios::binary | std::ios::ate); if (f) report.input_bytes = (uint64_t)f.tellg(); }
    { std::ifstream f(output, std::ios::binary | std::ios::ate); if (f) report.output_bytes = (uint64_t)f.tellg(); }
    return out ? PruneError::None : PruneError::Output;
}

}} // namespace RawrXD::REAP