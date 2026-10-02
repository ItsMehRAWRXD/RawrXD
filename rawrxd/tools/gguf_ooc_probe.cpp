// ============================================================================
// gguf_ooc_probe.cpp — RAWRXD_GGUF_OOC_PROBE_001
//
// An experimental architecture built from scratch, deliberately independent of
// Deep2, for exactly one question:
//
//     Does a 578 GB MoE model stream out-of-core on this machine, and what are
//     its real tensor names?
//
// WHY NOT Deep2. Deep2's admission gate rejects Kimi K2 with
// "4 required tensor role(s) absent; first: attn_q". attn_q does not appear in
// any role table in the live source. Rather than delete a fail-closed gate --
// which turns a precise rejection into a wild pointer inside a GEMV kernel --
// this probe reads the file directly and reports what is ACTUALLY there. If the
// MLA names exist and differ, the gate is wrong and the fix is in the table. If
// they do not exist, the file is not what it claims to be. Either way the answer
// comes from bytes, not from a name someone guessed.
//
// WHAT IT MEASURES, SEPARATELY, BECAUSE THEY ARE NOT THE SAME THING:
//   mapping cost    CreateFileMapping + MapViewOfFile -> virtual ranges only
//   residency       physical pages actually resident after touching
//   faults          page faults, the only direct count of disk-to-RAM work
//
// The GGUF format details encoded here were each established by a measured
// failure, not from a spec:
//   * magic 0x46554747 ("GGUF"), NOT a filename
//   * BOOL value type is ONE byte (reading 4 desyncs the parse)
//   * ARRAY is u32 elem_type + u64 count (u32 count desyncs by 4)
//   * tensor descriptor ends with a u64 OFFSET (omitting it desyncs the table)
//
// Builds with no dependency on Deep2, so it cannot inherit Deep2's assumptions.
// ============================================================================
#define WIN32_LEAN_AND_MEAN
// <windows.h> defines max/min as MACROS. Without NOMINMAX, std::max(a, b)
// expands to std::(((a) > (b)) ? (a) : (b)) and fails to parse. This is the same
// class of failure as any other header that reuses standard-library names.
#define NOMINMAX
#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
static constexpr u32 GGUF_MAGIC_LE = 0x46554747u;

namespace {

struct Shard {
    fs::path path;
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE mapping = nullptr;
    const std::uint8_t* base = nullptr;
    u64 size = 0;
    int index = 1;
    int expected = 1;
};

// ---- little-endian POD reader over a raw mapping, with bounds checks -------
// Every read is bounds-checked. A probe that trusts the file is a probe that
// will be killed by a malformed file, which is the opposite of informative.
struct Cursor {
    const std::uint8_t* p = nullptr;
    const std::uint8_t* end = nullptr;
    bool bad = false;

    bool raw(void* dst, std::size_t n) {
        if (bad || static_cast<std::size_t>(end - p) < n) { bad = true; return false; }
        std::memcpy(dst, p, n);
        p += n;
        return true;
    }
    bool u32v(u32& v) { return raw(&v, 4); }
    bool u64v(u64& v) { return raw(&v, 8); }
    bool str(std::string& s, std::size_t cap = 4096) {
        u64 n = 0;
        if (!u64v(n)) return false;
        if (n > cap || static_cast<std::size_t>(end - p) < n) { bad = true; return false; }
        s.assign(reinterpret_cast<const char*>(p), static_cast<std::size_t>(n));
        p += n;
        return true;
    }
};

const char* TypeName(u32 t) {
    switch (t) {
        case 0: return "F32";   case 1: return "F16";    case 2: return "Q4_0";
        case 3: return "Q4_1";  case 6: return "Q5_0";   case 7: return "Q5_1";
        case 8: return "Q8_0";  case 9: return "Q8_1";   case 10: return "Q2_K";
        case 11: return "Q3_K"; case 12: return "Q4_K";  case 13: return "Q5_K";
        case 14: return "Q6_K"; case 15: return "Q8_K";  case 16: return "IQ2_XXS";
        case 17: return "IQ2_XS"; case 18: return "IQ3_XXS"; case 19: return "IQ1_S";
        case 20: return "IQ4_NL"; case 30: return "BF16";
        default: return "UNKNOWN";
    }
}

// A mapped tensor, located in GLOBAL data space.
struct TensorInfo {
    std::string name;
    u64 globalOffset = 0;   // relative to the start of tensor_data
    u64 bytes = 0;
    u32 type = 0;
    std::vector<u64> shape;
    int shard = 1;          // which shard holds the BYTES
};

std::size_t TypeBytes(u32 t) {
    switch (t) {
        case 0: case 1: case 30: return 2;   // F32 is 4; fixed below by shape
        default: return 0;                    // computed from shape+type properly below
    }
}

// Quantised row sizes in bytes per 256-element block, by ggml type.
bool BlockSizeFor(u32 t, std::size_t& blockBytes, std::size_t& perBlock) {
    switch (t) {
        case 0:  blockBytes = 4 * perBlock; return true;                 // F32
        case 1:  blockBytes = 2 * perBlock; return true;                 // F16
        case 30: blockBytes = 2 * perBlock; return true;                 // BF16
        case 2:  blockBytes = 18; perBlock = 32; return true;             // Q4_0
        case 3:  blockBytes = 20; perBlock = 32; return true;             // Q4_1
        case 6:  blockBytes = 22; perBlock = 32; return true;             // Q5_0
        case 7:  blockBytes = 24; perBlock = 32; return true;             // Q5_1
        case 8:  blockBytes = 34; perBlock = 32; return true;             // Q8_0
        case 9:  blockBytes = 36; perBlock = 32; return true;             // Q8_1
        case 10: blockBytes = 84;  perBlock = 256; return true;           // Q2_K
        case 11: blockBytes = 110; perBlock = 256; return true;           // Q3_K
        case 12: blockBytes = 144; perBlock = 256; return true;           // Q4_K
        case 13: blockBytes = 176; perBlock = 256; return true;           // Q5_K
        case 14: blockBytes = 210; perBlock = 256; return true;           // Q6_K
        case 15: blockBytes = 292; perBlock = 256; return true;           // Q8_K
        case 16: blockBytes = 66;  perBlock = 256; return true;           // IQ2_XXS
        case 17: blockBytes = 74;  perBlock = 256; return true;           // IQ2_XS
        case 18: blockBytes = 98;  perBlock = 256; return true;           // IQ3_XXS
        case 19: blockBytes = 50;  perBlock = 256; return true;           // IQ1_S
        case 20: blockBytes = 18;  perBlock = 32;  return true;           // IQ4_NL
        default: return false;
    }
}

bool TensorBytes(const TensorInfo& t, u64& out) {
    if (t.shape.empty()) return false;
    u64 elems = 1;
    for (u64 d : t.shape) {
        if (d == 0 || elems > (~0ull) / d) return false;
        elems *= d;
    }
    std::size_t block = 256, bytesPerBlock = 0;
    // F32/F16/BF16 are unquantised: no 256-block structure.
    if (t.type == 0 || t.type == 1 || t.type == 30) {
        const std::size_t w = (t.type == 0) ? 4 : 2;
        out = elems * w;
        return true;
    }
    if (!BlockSizeFor(t.type, block, bytesPerBlock)) return false;
    out = (elems / block) * bytesPerBlock;
    return true;
}

struct Residency {
    u64 workingSet = 0, privateBytes = 0, mappedBytes = 0, regions = 0, faults = 0;
};

Residency Measure() {
    Residency r;
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(),
                             reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                             sizeof(pmc))) {
        r.workingSet = pmc.WorkingSetSize;
        r.privateBytes = pmc.PrivateUsage;
        r.faults = pmc.PageFaultCount;
    }
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    MEMORY_BASIC_INFORMATION mbi{};
    auto c = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
    const auto lim = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
    while (c < lim) {
        if (VirtualQuery(reinterpret_cast<LPCVOID>(c), &mbi, sizeof(mbi)) == 0) break;
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_MAPPED) {
            r.regions++;
            r.mappedBytes += mbi.RegionSize;
        }
        const auto next = c + mbi.RegionSize;
        if (next <= c) break;
        c = next;
    }
    return r;
}

const double GB = 1024.0 * 1024.0 * 1024.0;

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: gguf_ooc_probe <file.gguf | directory> [--touch N]\n");
        return 2;
    }
    const fs::path target = argv[1];
    std::size_t touchCount = 64;
    for (int i = 2; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], "--touch") == 0) touchCount = std::strtoull(argv[i + 1], nullptr, 10);
    }

    std::printf("=== RAWRXD_GGUF_OOC_PROBE_001 ===\n");
    std::printf("TARGET=%s\n", target.string().c_str());
    std::printf("DEPENDENCY=none (reads bytes directly; Deep2 not involved)\n");

    // ---- 1. Collect shards -------------------------------------------------
    std::vector<Shard> shards;
    if (fs::is_directory(target)) {
        std::vector<fs::path> files;
        // RECURSIVE. Kimi K2's 13 shards are not in the top-level directory; a
        // non-recursive walk found 2 files totalling 0.00 GB and then bailed on
        // the first non-GGUF file, which is how a 578 GB model looks like an
        // empty one.
        for (const auto& e : fs::recursive_directory_iterator(target)) {
            if (!e.is_regular_file()) continue;
            files.push_back(e.path());
        }
        // Shards are identified by MAGIC, never by name or extension. Ollama
        // blobs carry no .gguf suffix, and a directory also contains manifests,
        // .git objects and settings files.
        std::sort(files.begin(), files.end());
        for (const auto& f : files) {
            std::ifstream probe(f, std::ios::binary);
            if (!probe) continue;
            char m[4] = {0, 0, 0, 0};
            probe.read(m, 4);
            if (probe.gcount() != 4) continue;
            if (std::memcmp(m, "GGUF", 4) != 0) continue;
            const std::string stem = f.stem().string();
            const std::size_t of = stem.rfind("-of-");
            Shard s;
            s.path = f;
            if (of != std::string::npos && of >= 6 && stem.size() == of + 8) {
                s.index = std::atoi(stem.substr(of - 5, 5).c_str());
                s.expected = std::atoi(stem.substr(of + 4, 5).c_str());
            } else {
                s.index = 1;
                s.expected = 1;
            }
            shards.push_back(s);
        }
        std::sort(shards.begin(), shards.end(), [](const Shard& a, const Shard& b) {
            return a.index < b.index;
        });
    } else {
        Shard s;
        s.path = target;
        shards.push_back(s);
    }
    std::printf("SHARDS_FOUND=%zu\n", shards.size());

    const Residency before = Measure();
    std::printf("resident_before_map_gb=%.3f\n", before.workingSet / GB);

    // ---- 2. Map every shard. Virtual ranges only. --------------------------
    const auto tMapStart = GetTickCount64();
    bool mapOk = true;
    u64 totalBytes = 0;
    for (Shard& s : shards) {
        s.file = CreateFileW(s.path.wstring().c_str(), GENERIC_READ,
                             FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
        if (s.file == INVALID_HANDLE_VALUE) {
            std::printf("MAP_FAIL=%s\n", s.path.string().c_str());
            mapOk = false;
            continue;
        }
        LARGE_INTEGER li{};
        GetFileSizeEx(s.file, &li);
        s.size = static_cast<u64>(li.QuadPart);
        totalBytes += s.size;
        s.mapping = CreateFileMappingW(s.file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!s.mapping) { mapOk = false; continue; }
        s.base = static_cast<const std::uint8_t*>(
            MapViewOfFile(s.mapping, FILE_MAP_READ, 0, 0, 0));
        if (!s.base) { mapOk = false; continue; }
    }
    const u64 mapMs = GetTickCount64() - tMapStart;
    const Residency afterMap = Measure();
    std::printf("mapped_all_shards=%d\n", mapOk ? 1 : 0);
    std::printf("total_file_gb=%.2f\n", totalBytes / GB);
    std::printf("MAP_TIME_MS=%llu\n", (unsigned long long)mapMs);
    std::printf("mapped_virtual_gb=%.2f in %llu regions\n",
                afterMap.mappedBytes / GB, (unsigned long long)afterMap.regions);
    std::printf("resident_after_map_gb=%.3f\n", afterMap.workingSet / GB);
    std::printf("faults_for_map_only=%llu\n",
                (unsigned long long)(afterMap.faults - before.faults));
    std::printf("MAP_VERDICT=%s\n", afterMap.mappedBytes > (totalBytes / 2)
                                       ? "MAPPING_IS_VIRTUAL_NOT_RESIDENT"
                                       : "MAPPING_INCOMPLETE");

    // ---- 3. Parse the header from shard 1 ----------------------------------
    if (shards.empty() || !shards[0].base) {
        std::printf("FATAL=no_first_shard_mapping\n");
        return 3;
    }
    Cursor c{shards[0].base, shards[0].base + shards[0].size, false};
    u32 magic = 0, version = 0;
    u64 tensorCount = 0, kvCount = 0;
    if (!c.u32v(magic) || magic != GGUF_MAGIC_LE) {
        std::printf("FATAL=bad_magic\n");
        return 3;
    }
    c.u32v(version);
    c.u64v(tensorCount);
    c.u64v(kvCount);
    std::printf("gguf_version=%u\nTENSOR_COUNT=%llu\nKV_COUNT=%llu\n", version,
                (unsigned long long)tensorCount, (unsigned long long)kvCount);

    u64 alignment = 32;
    std::map<std::string, std::string> kv;
    for (u64 i = 0; i < kvCount && !c.bad; ++i) {
        std::string key;
        u32 type = 0;
        if (!c.str(key) || !c.u32v(type)) { c.bad = true; break; }
        // std::function, not a bare lambda: this recurses through ARRAY elements,
        // and a lambda cannot appear in its own initializer.
        const std::function<bool(u32, int)> skipValue = [&](u32 t, int depth) -> bool {
            if (depth > 8) return false;
            switch (t) {
                case 0: case 1: case 7: { std::uint8_t v; return c.raw(&v, 1); }  // BOOL IS 1 BYTE
                case 2: case 3: { std::uint16_t v; return c.raw(&v, 2); }
                case 4: case 5: { u32 v; return c.u32v(v); }
                case 6: { float v; return c.raw(&v, 4); }
                case 8: { std::string s; return c.str(s, 1 << 20); }
                case 9: {                                                   // ARRAY
                    u32 et = 0; u64 n = 0;
                    if (!c.u32v(et) || !c.u64v(n)) return false;            // COUNT IS u64
                    if (n > (1ull << 26)) return false;
                    for (u64 k = 0; k < n; ++k) if (!skipValue(et, depth + 1)) return false;
                    return true;
                }
                case 10: case 11: { u64 v; return c.u64v(v); }
                case 12: { double v; return c.raw(&v, 8); }
                default: return false;
            }
        };
        if (type == 8) {
            std::string v;
            if (!c.str(v, 1 << 20)) { c.bad = true; break; }
            kv[key] = v;
        } else if (type == 4) {
            u32 v = 0;
            if (!c.u32v(v)) { c.bad = true; break; }
            kv[key] = std::to_string(v);
        } else if (!skipValue(type, 0)) {
            c.bad = true;
            break;
        }
    }
    std::printf("KV_PARSE_ERROR=%d\n", c.bad ? 1 : 0);
    if (kv.count("general.architecture")) std::printf("ARCH=%s\n", kv["general.architecture"].c_str());
    if (kv.count("general.name")) std::printf("MODEL_NAME=%s\n", kv["general.name"].c_str());
    auto it = kv.find("general.alignment");
    if (it != kv.end()) alignment = std::strtoull(it->second.c_str(), nullptr, 10);
    std::printf("ALIGNMENT=%llu\n", (unsigned long long)alignment);

    // ---- 4. Read the tensor table ------------------------------------------
    std::vector<TensorInfo> table;
    table.reserve(static_cast<std::size_t>(tensorCount));
    for (u64 i = 0; i < tensorCount && !c.bad; ++i) {
        TensorInfo t;
        u32 dims = 0, type = 0;
        u64 off = 0;
        if (!c.str(t.name, 256)) { c.bad = true; break; }
        if (!c.u32v(dims) || dims == 0 || dims > 8) { c.bad = true; break; }
        for (u32 d = 0; d < dims; ++d) { u64 ne = 0; if (!c.u64v(ne)) { c.bad = true; break; } t.shape.push_back(ne); }
        if (c.bad) break;
        if (!c.u32v(type) || !c.u64v(off)) { c.bad = true; break; }   // type THEN u64 offset
        t.type = type;
        t.globalOffset = off;
        TensorBytes(t, t.bytes);
        table.push_back(std::move(t));
    }
    std::printf("TENSOR_TABLE_ERROR=%d\n", c.bad ? 1 : 0);
    std::printf("TENSORS_PARSED=%zu of %llu\n", table.size(),
                (unsigned long long)tensorCount);

    // ---- 5. THE ACTUAL PAYLOAD: what are the real tensor names? --------------
    //
    // This is the whole reason this program exists. It answers, from bytes:
    // does this model carry attn_q, or does it carry MLA names instead?
    struct Probe { const char* needle; };
    static const char* kRoleNeedles[] = {
        "attn_q", "attn_q_a", "attn_q_b", "attn_kv_a", "attn_kv_a_mqa",
        "attn_kv_a_mqa", "attn_kv_b", "attn_k", "attn_v", "attn_output",
        "attn_norm", "ffn_up", "ffn_down", "ffn_gate", "ffn_up_exps",
        "ffn_down_exps", "token_embd", "output_norm", "output", "attn_norm_q",
        "attn_norm_k", "attn_q_proj", "q_proj", "kv_a_proj"
    };
    std::printf("\n--- ROLE PRESENCE (measured from tensor names in the file) ---\n");
    for (const char* needle : kRoleNeedles) {
        std::size_t hits = 0;
        std::string example;
        for (const TensorInfo& t : table) {
            if (t.name.find(needle) != std::string::npos) {
                ++hits;
                if (example.empty()) example = t.name;
            }
        }
        std::printf("ROLE %-18s count=%-6zu example=%s\n", needle, hits, example.c_str());
    }

    // Distinct leading token families, so an unexpected naming scheme is visible.
    std::map<std::string, std::size_t> stems;
    for (const TensorInfo& t : table) {
        std::string s = t.name;
        const std::size_t dot = s.rfind('.');
        if (dot != std::string::npos) s = s.substr(0, dot);
        stems[s]++;
    }
    std::printf("\n--- DISTINCT TENSOR STEMS (%zu) ---\n", stems.size());
    std::size_t shown = 0;
    for (const auto& kv2 : stems) {
        if (shown++ >= 40) { std::printf("  ... %zu more\n", stems.size() - 40); break; }
        std::printf("  %-42s x%zu\n", kv2.first.c_str(), kv2.second);
    }

    // ---- 6. Global layout: which shard holds each tensor ---------------------
    //
    // tensor_data begins after shard 1's table, and the offsets are GLOBAL across
    // the whole set. Assigning each tensor to the shard whose byte range contains
    // it is the step that decides whether a sharded model can be paged at all.
    const u64 tableEnd = static_cast<u64>(c.p - shards[0].base);
    u64 dataStart = (tableEnd + alignment - 1) / alignment * alignment;
    u64 cursor = dataStart;
    u64 assigned = 0, oversized = 0, unassigned = 0;
    for (TensorInfo& t : table) {
        const u64 abs = dataStart + t.globalOffset;
        u64 so = 0;
        for (const Shard& s : shards) {
            if (abs >= so && abs + t.bytes <= so + s.size) { t.shard = s.index; break; }
            so += s.size;
        }
        if (t.shard == 0) ++unassigned;
        else ++assigned;
        if (t.bytes == 0) ++oversized;
        cursor = std::max(cursor, abs + t.bytes);
    }
    std::printf("\n--- SHARD PLACEMENT ---\n");
    std::printf("data_start_in_shard1=0x%llx\n", (unsigned long long)dataStart);
    std::printf("tensors_placed=%llu unplaced=%llu\n",
                (unsigned long long)assigned, (unsigned long long)unassigned);
    std::printf("tensor_bytes_span=%.2f GB\n", (cursor / GB));
    std::printf("shard_bytes_total=%.2f GB\n", (totalBytes / GB));

    // ---- 7. Fault a bounded sample. Proof of out-of-core paging --------------
    if (!table.empty()) {
        const Residency pre = Measure();
        volatile u64 sink = 0;
        std::size_t touched = 0;
        for (std::size_t i = 0; i < table.size() && touched < touchCount; ++i) {
            const TensorInfo& t = table[i];
            if (t.bytes == 0) continue;
            // Sample a byte from the middle of each tensor: enough to fault the
            // page, not enough to read the model into RAM.
            const Shard& s = shards[static_cast<std::size_t>(t.shard) - 1];
            u64 so = 0;
            for (int k = 1; k < t.shard; ++k) so += shards[static_cast<std::size_t>(k) - 1].size;
            const u64 abs = dataStart + t.globalOffset;
            if (abs < so || abs >= so + s.size || !s.base) continue;
            sink += s.base[abs - so];
            ++touched;
        }
        const Residency post = Measure();
        std::printf("\n--- FAULT SAMPLE ---\n");
        std::printf("tensors_touched=%zu\n", touched);
        std::printf("faults=%llu\n", (unsigned long long)(post.faults - pre.faults));
        std::printf("resident_delta_mb=%.1f\n",
                    (post.workingSet - pre.workingSet) / (1024.0 * 1024.0));
        std::printf("OOC_VERDICT=%s\n",
                    (post.workingSet - pre.workingSet) < 64ull * 1024 * 1024
                        ? "PAGING_WORKS_TOUCH_COSTS_NO_RESIDENCY"
                        : "TOUCH_PULLED_RESIDENT_MEMORY");
        (void)sink;
    }

    // ---- 8. Drop residency, keep the mapping -------------------------------
    EmptyWorkingSet(GetCurrentProcess());
    const Residency dropped = Measure();
    std::printf("\n--- AFTER EmptyWorkingSet ---\n");
    std::printf("resident_gb=%.3f\n", dropped.workingSet / GB);
    std::printf("mapped_gb=%.2f in %llu regions\n", dropped.mappedBytes / GB,
                (unsigned long long)dropped.regions);
    std::printf("MAPPING_SURVIVED=%d\n", dropped.regions > 0 ? 1 : 0);

    std::printf("\nPROBE_RESULT=COMPLETE\n");
    for (Shard& s : shards) {
        if (s.base) UnmapViewOfFile(s.base);
        if (s.mapping) CloseHandle(s.mapping);
        if (s.file != INVALID_HANDLE_VALUE) CloseHandle(s.file);
    }
    return 0;
}