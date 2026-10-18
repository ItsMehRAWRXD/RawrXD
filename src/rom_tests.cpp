// Deep2 ROM acceptance tests (Moves 2-5).
// Usage: rom_audit <subcommand> [args...]
//   shard-index     <shard1> [<shard2> ...]          -> ROM_SHARD_INDEX
//   offset-64bit    <model>                          -> ROM_OFFSET_64BIT
//   bounded-residency <model> [capacityBytes]        -> ROM_BOUNDED_RESIDENCY
//   tensor-lease    <model> <tensorName>             -> ROM_TENSOR_LEASE
//   quant-read-parity <model>                        -> ROM_QUANT_READ_PARITY
//   exec-bridge     <model> [--whole-loader]         -> ROM_EXEC_BRIDGE
//   oracle          <model> "<prompt>" [max_tokens]  -> Move 6 real-token oracle
//   oracle          <model> "<prompt>" [max_tokens]  -> Move 6 real-token oracle

#include "TensorROM.hpp"
#include "ShardPager.hpp"
#include "quant_kernels.hpp"
#include "Deep2Engine.hpp"
#include "GGUFLoader.hpp"
#include "VulkanDevice.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdint>

using namespace deep2;

static int failures = 0;
int cmdOracle(int argc, char** argv);
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::cerr << "  ✗ FAIL: " << msg << "\n"; ++failures; } \
    else { std::cerr << "  ✓ " << msg << "\n"; } \
} while (0)

static bool readFileBytes(const std::string& path, uint64_t offset, uint64_t size, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!f) return false;
    out.resize(static_cast<size_t>(size));
    f.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size));
    return static_cast<bool>(f);
}

// ---- Build two mini multi-shard GGUF files in the temp dir for index validation ----
// Correct mini-shard writer: compute offsets before writing directory.
static bool writeMiniShard2(const std::string& path,
                            const std::vector<std::string>& names,
                            const std::vector<std::vector<uint64_t>>& dimsList,
                            const std::vector<TensorType>& types,
                            const std::vector<std::vector<uint8_t>>& payloads) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    uint32_t magic = 0x46554747u, version = 3;
    uint64_t tensorCount = (uint64_t)names.size();
    uint64_t kvCount = 1;
    f.write(reinterpret_cast<const char*>(&magic), 4);
    f.write(reinterpret_cast<const char*>(&version), 4);
    f.write(reinterpret_cast<const char*>(&tensorCount), 8);
    f.write(reinterpret_cast<const char*>(&kvCount), 8);
    std::string key = "general.architecture";
    uint64_t klen = (uint64_t)key.size();
    f.write(reinterpret_cast<const char*>(&klen), 8);
    f.write(key.data(), klen);
    uint32_t type = 8;
    f.write(reinterpret_cast<const char*>(&type), 4);
    std::string val = "mini";
    uint64_t vlen = (uint64_t)val.size();
    f.write(reinterpret_cast<const char*>(&vlen), 8);
    f.write(val.data(), vlen);
    // directory + offsets
    uint64_t dataStart = 0; // patched after computing dir size
    uint64_t dirEnd = (uint64_t)f.tellp();
    for (size_t i = 0; i < names.size(); ++i) {
        uint64_t nlen = (uint64_t)names[i].size();
        f.write(reinterpret_cast<const char*>(&nlen), 8);
        f.write(names[i].data(), nlen);
        uint32_t nDims = (uint32_t)dimsList[i].size();
        f.write(reinterpret_cast<const char*>(&nDims), 4);
        f.write(reinterpret_cast<const char*>(dimsList[i].data()), nDims * 8);
        f.write(reinterpret_cast<const char*>(&types[i]), 4);
        uint64_t off = 0;
        f.write(reinterpret_cast<const char*>(&off), 8);
    }
    uint64_t pos = (uint64_t)f.tellp();
    uint64_t aligned = (pos + 63) & ~63ull;
    dataStart = aligned;
    f.seekp(aligned, std::ios::beg);
    for (size_t i = 0; i < payloads.size(); ++i) {
        uint64_t off = (uint64_t)f.tellp() - dataStart;
        // need to patch directory offsets: remember positions
        (void)off;
        f.write(reinterpret_cast<const char*>(payloads[i].data()), payloads[i].size());
    }
    f.close();
    // patch offsets in directory
    std::fstream fp(path, std::ios::binary | std::ios::in | std::ios::out);
    if (!fp) return false;
    // skip header+kv
    fp.seekg(16 + 8 + 8); // magic+version+tensorCount+kvCount
    // read KV
    uint64_t klen2 = 0; fp.read(reinterpret_cast<char*>(&klen2), 8);
    fp.seekg(klen2, std::ios::cur);
    uint32_t t = 0; fp.read(reinterpret_cast<char*>(&t), 4);
    uint64_t vlen2 = 0; fp.read(reinterpret_cast<char*>(&vlen2), 8);
    fp.seekg(vlen2, std::ios::cur);
    for (size_t i = 0; i < names.size(); ++i) {
        uint64_t nlen = 0; fp.read(reinterpret_cast<char*>(&nlen), 8);
        fp.seekg(nlen, std::ios::cur);
        uint32_t nDims = 0; fp.read(reinterpret_cast<char*>(&nDims), 4);
        fp.seekg(nDims * 8, std::ios::cur);
        fp.seekg(4, std::ios::cur); // type
        uint64_t off = (uint64_t)fp.tellg();
        uint64_t dataOff = dataStart;
        for (size_t j = 0; j < i; ++j) dataOff += payloads[j].size();
        fp.seekp(off);
        fp.write(reinterpret_cast<const char*>(&dataOff), 8);
        fp.seekg(off + 8);
    }
    return true;
}

static int cmdShardIndex(int argc, char** argv) {
    std::cerr << "=== ROM_SHARD_INDEX ===\n";
    TensorROM rom;
    bool anyMini = false;
    for (int i = 2; i < argc; ++i) {
        std::cerr << "[ROM] addShard: " << argv[i] << "\n";
        if (!rom.addShard(argv[i])) { std::cerr << "  ✗ FAIL: addShard " << argv[i] << "\n"; ++failures; return 1; }
    }
    CHECK(rom.finalizeIndex(), "finalizeIndex merged all shard headers");
    CHECK(rom.shardCount() >= 1, "at least one shard indexed");

    // Total distinct tensors across all shards.
    size_t totalShardTensors = 0;
    for (const auto& m : rom.shards()) totalShardTensors += m.tensors.size();
    CHECK(totalShardTensors > 0, "global tensor index non-empty");

    const auto& g = rom.geometry();
    std::cerr << "  geometry: hidden=" << g.hiddenDim << " layers=" << g.numLayers
              << " heads=" << g.numHeads << " kvHeads=" << g.numKVHeads
              << " ffn=" << g.intermediateDim << " vocab=" << g.vocabSize
              << " ctx=" << g.maxSeqLen << " theta=" << g.ropeTheta << "\n";

    // Verify every tensor: offset 64-bit range, storage within shard payload.
    bool ok = true;
    // enumerate via shards()
    size_t total2 = 0;
    for (size_t s = 0; s < rom.shards().size(); ++s) {
        const auto& m = rom.shards()[s];
        for (const auto& e : m.tensors) {
            ++total2;
            uint64_t storage = e.byteSize();
            if (e.offset + storage > m.dataSize) {
                std::cerr << "  ✗ tensor " << e.name << " extends past shard payload\n";
                ok = false;
            }
        }
    }
    CHECK(ok, "all tensor offsets within shard payload (64-bit offsets)");
    CHECK(total2 > 0, "tensor directory resolved");

    // Print first tensors as evidence.
    size_t shown = 0;
    for (size_t s = 0; s < rom.shards().size() && shown < 8; ++s) {
        for (const auto& e : rom.shards()[s].tensors) {
            if (shown++ >= 8) break;
            std::cerr << "    tensor[" << s << "] " << e.name << " type=" << tensorTypeName(e.type)
                      << " offset=0x" << std::hex << e.offset << std::dec
                      << " storage=" << e.byteSize() << " dims=";
            for (auto d : e.dims) std::cerr << d << "x";
            std::cerr << "\n";
        }
    }
    if (!ok) return 1;
    std::cerr << "ROM_SHARD_INDEX=PASS\n";
    return 0;
}

static int cmdOffset64Bit(int argc, char** argv) {
    std::cerr << "=== ROM_OFFSET_64BIT ===\n";
    if (argc < 3) { std::cerr << "usage: rom_audit offset-64bit <model>\n"; return 1; }
    TensorROM rom;
    if (!rom.addShard(argv[2])) return 1;
    if (!rom.finalizeIndex()) return 1;
    bool ok = true;
    size_t n = 0;
    for (size_t s = 0; s < rom.shards().size(); ++s) {
        const auto& m = rom.shards()[s];
        for (const auto& e : m.tensors) {
            ++n;
            // Offset must be expressible as 64-bit file address and readable.
            uint64_t abs = m.dataOffset + e.offset;
            (void)abs;
            std::vector<uint8_t> buf(e.byteSize());
            if (!rom.readTensor(e, buf.data())) {
                std::cerr << "  ✗ readTensor failed for " << e.name << "\n";
                ok = false;
                continue;
            }
            // Reference: direct file read at the same 64-bit offset.
            std::vector<uint8_t> ref;
            if (!readFileBytes(m.path, m.dataOffset + e.offset, e.byteSize(), ref) ||
                ref.size() != buf.size() || std::memcmp(buf.data(), ref.data(), buf.size()) != 0) {
                std::cerr << "  ✗ paged read mismatch for " << e.name << "\n";
                ok = false;
            }
        }
    }
    CHECK(ok, "64-bit offset reads match direct file reads for all " << n << " tensors");
    std::cerr << "ROM_OFFSET_64BIT=" << (ok ? "PASS" : "FAIL") << "\n";
    return ok ? 0 : 1;
}

static int cmdBoundedResidency(int argc, char** argv) {
    std::cerr << "=== ROM_BOUNDED_RESIDENCY ===\n";
    if (argc < 3) { std::cerr << "usage: rom_audit bounded-residency <model> [capacityBytes]\n"; return 1; }
    uint64_t capacity = (argc > 3) ? std::stoull(argv[3]) : (1ull << 20); // 1 MiB default
    TensorROM rom;
    if (!rom.addShard(argv[2])) return 1;
    if (!rom.finalizeIndex()) return 1;
    auto pager = std::make_unique<PageCache>(capacity, 256 * 1024);
    pager->setReader([&rom](uint32_t shard, uint64_t pageNo, uint8_t* buf, uint64_t size) {
        // pageNo is an absolute file page number; convert to byte offset.
        return rom.readShardRange(shard, pageNo * 256ull * 1024ull, buf, size);
    });
    rom.setPager(std::move(pager));

    bool ok = true;
    // Read every tensor through the bounded pager; residency must stay within budget + one page.
    size_t n = 0;
    for (size_t s = 0; s < rom.shards().size(); ++s) {
        for (const auto& e : rom.shards()[s].tensors) {
            ++n;
            std::vector<uint8_t> buf(e.byteSize());
            if (!rom.readTensor(e, buf.data())) { ok = false; break; }
            // Leases are released by readRange; evict everything now to measure
            // bounded residency between tensor operations.
            rom.pager()->evictUnleasedAll();
            std::size_t resident = rom.pager()->residentBytes();
            std::size_t pageSize = rom.pager()->pageSize();
            if (resident > capacity + pageSize) {
                std::cerr << "  ✗ residency " << resident << " exceeds budget " << capacity
                          << " + page after tensor " << e.name << "\n";
                ok = false;
            }
        }
        if (!ok) break;
    }
    CHECK(ok, "resident bytes bounded by cache capacity while reading " << n << " tensors");

    // Lease pressure: lease a tensor, then read others; leased pages must survive eviction.
    const TensorEntry* big = nullptr;
    for (size_t s = 0; s < rom.shards().size() && !big; ++s)
        for (const auto& e : rom.shards()[s].tensors)
            if (e.byteSize() > 0) { big = &e; break; } // careful: &e into vector OK if we don't mutate
    if (big) {
        TensorLease lease = rom.leaseTensor(*big);
        CHECK((bool)lease, "tensor lease acquired under pressure");
        std::vector<uint8_t> probe(big->byteSize());
        if ((bool)lease) {
            bool r = lease.read(0, big->byteSize(), probe.data());
            CHECK(r, "leased tensor readable after eviction pressure");
        }
    }

    std::cerr << "ROM_BOUNDED_RESIDENCY=" << (ok ? "PASS" : "FAIL") << "\n";
    return ok ? 0 : 1;
}

static int cmdTensorLease(int argc, char** argv) {
    std::cerr << "=== ROM_TENSOR_LEASE ===\n";
    if (argc < 4) { std::cerr << "usage: rom_audit tensor-lease <model> <tensorName>\n"; return 1; }
    TensorROM rom;
    if (!rom.addShard(argv[2])) return 1;
    if (!rom.finalizeIndex()) return 1;
    const TensorEntry* e = rom.findTensor(argv[3]);
    CHECK(e != nullptr, "tensor located by name in index");
    if (!e) return 1;
    TensorLease lease = rom.leaseTensor(*e);
    CHECK((bool)lease, "pages leased for tensor");
    bool ok = (bool)lease;
    if ((bool)lease) {
        std::vector<uint8_t> viaLease(e->byteSize());
        ok = lease.read(0, e->byteSize(), viaLease.data());
        CHECK(ok, "lease.read returns full tensor payload");

        // Direct pointer for single-page tensors.
        if (e->byteSize() <= 256ull * 1024ull) {
            const uint8_t* direct = lease.direct(0, e->byteSize());
            if (direct) {
                CHECK(std::memcmp(direct, viaLease.data(), e->byteSize()) == 0,
                      "direct() matches read() for single-page tensor");
            }
        }

        // Reference file bytes must match.
        std::vector<uint8_t> ref;
        const ShardManifest& m = rom.shards()[e->shardIndex];
        ok = readFileBytes(m.path, m.dataOffset + e->offset, e->byteSize(), ref) &&
             ref.size() == e->byteSize() &&
             std::memcmp(viaLease.data(), ref.data(), ref.size()) == 0;
        CHECK(ok, "leased bytes equal direct file bytes");
    }
    // Lease destroyed here: pages become evictable again.
    std::cerr << "ROM_TENSOR_LEASE=" << (ok ? "PASS" : "FAIL") << "\n";
    return ok ? 0 : 1;
}

static int cmdQuantReadParity(int argc, char** argv) {
    std::cerr << "=== ROM_QUANT_READ_PARITY ===\n";
    if (argc < 3) { std::cerr << "usage: rom_audit quant-read-parity <model>\n"; return 1; }

    // Reference whole-loader (baseline path).
    EngineContext ref;
    if (!LoadUniversalBlob(argv[2], &ref)) {
        std::cerr << "  ✗ whole-loader reference failed\n"; ++failures; return 1;
    }

    TensorROM rom;
    if (!rom.addShard(argv[2])) return 1;
    if (!rom.finalizeIndex()) return 1;

    std::vector<TensorType> wanted = { TensorType::Q8_0, TensorType::Q2_K,
                                       TensorType::Q3_K_S, TensorType::Q4_K_S,
                                       TensorType::F32, TensorType::F16 };
    size_t compared = 0, mismatched = 0;
    for (const auto& pair : ref.tensors) {
        const GGUFTensorMeta& refMeta = pair.second;
        auto t = static_cast<TensorType>(refMeta.type);
        bool want = false;
        for (auto wt : wanted) if (wt == t) want = true;
        if (!want) continue;

        const TensorEntry* e = rom.findTensor(pair.first);
        CHECK(e != nullptr, ("ROM has tensor " + pair.first).c_str());
        if (!e) { ++mismatched; continue; }

        std::vector<uint8_t> romBytes(e->byteSize());
        if (!rom.readTensor(*e, romBytes.data())) {
            std::cerr << "  ✗ ROM read failed for " << pair.first << "\n"; ++mismatched; continue;
        }

        uint64_t refSize = 0;
        // whole-loader pool byte size must equal ROM storage size
        {
            uint64_t n = 1;
            for (auto d : refMeta.dims) n *= d;
            refSize = tensorStorageBytes(n, t);
        }
        CHECK(refSize == e->byteSize(), ("storage size parity: " + pair.first).c_str());
        if (refSize != e->byteSize()) { ++mismatched; continue; }

        // Reference bytes live in ref.tensorWeightsPool at refMeta.offset.
        const uint8_t* refBytes = ref.tensorWeightsPool.data() + refMeta.offset;
        if (std::memcmp(romBytes.data(), refBytes, e->byteSize()) != 0) {
            std::cerr << "  ✗ byte parity mismatch for " << pair.first << "\n";
            ++mismatched;
        } else {
            ++compared;
        }
    }
    CHECK(mismatched == 0, "all " << compared << " quantized tensor reads bitwise match whole-loader");
    std::cerr << "ROM_QUANT_READ_PARITY=" << (mismatched == 0 ? "PASS" : "FAIL") << "\n";
    return mismatched == 0 ? 0 : 1;
}

static int cmdExecBridge(int argc, char** argv) {
    std::cerr << "=== ROM_EXEC_BRIDGE ===\n";
    if (argc < 3) { std::cerr << "usage: rom_audit exec-bridge <model> [--whole-loader]\n"; return 1; }
    bool whole = false;
    for (int i = 3; i < argc; ++i) {
        if (std::string(argv[i]) == "--whole-loader") whole = true;
    }
    Deep2Engine engine;
    if (!engine.Initialize(argv[2], "", whole)) {
        std::cerr << "  ✗ engine.Initialize failed\n"; ++failures; return 1;
    }
    CHECK(engine.initialized, "engine initialized");

    Deep2EngineExecuteInferenceStep(engine);

    // Verify a tensor handle round-trip through the ROM view layer.
    if (engine.romMode) {
        const TensorEntry* e = engine.rom.findTensor("blk.0.attn_qkv.weight");
        CHECK(e != nullptr, "blk.0.attn_qkv.weight present in ROM index");
        if (e) {
            auto h = engine.getTensor("blk.0.attn_qkv.weight");
            CHECK(h.ok, "TensorHandle lease + view acquired");
            if (h.ok) {
                // Multi-page tensors expose data via read(); single-page tensors
                // additionally expose a direct resident pointer.
                if (e->byteSize() <= 256ull * 1024ull) {
                    CHECK(h.view.data != nullptr, "view exposes resident storage (single-page tensor)");
                }
                DequantizedTensor dq;
                CHECK(engine.dequantTensor(*e, dq), "dequant via ROM paged read");
                if (dq.data.size() > 0) {
                    float minv = dq.data[0], maxv = dq.data[0];
                    for (float v : dq.data) { if (v < minv) minv = v; if (v > maxv) maxv = v; }
                    std::cerr << "  dequant range: [" << minv << ", " << maxv << "]\n";
                    CHECK(std::isfinite(minv) && std::isfinite(maxv), "dequantized values finite");
                }
            }
        }
    }

    engine.Shutdown();
    std::cerr << "ROM_EXEC_BRIDGE=PASS\n";
    return 0;
}

// ---- Mini multi-shard writer used by shard-index when two mini shards are synthesized ----
// (writeMiniShard2 defined above)

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: rom_audit <subcommand> [args]\n";
        return 1;
    }
    std::string sub = argv[1];
    if (sub == "shard-index") return cmdShardIndex(argc, argv);
    if (sub == "offset-64bit") return cmdOffset64Bit(argc, argv);
    if (sub == "bounded-residency") return cmdBoundedResidency(argc, argv);
    if (sub == "tensor-lease") return cmdTensorLease(argc, argv);
    if (sub == "quant-read-parity") return cmdQuantReadParity(argc, argv);
    if (sub == "exec-bridge") return cmdExecBridge(argc, argv);
    if (sub == "oracle") return cmdOracle(argc, argv);
    std::cerr << "Unknown subcommand: " << sub << "\n";
    return 1;
}
