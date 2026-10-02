// ============================================================================
// rawr_dog_harness.cpp
// RAWRXD_DOG_TELEMETRY_001
//
// Reverse-engineered to the engine that ACTUALLY EXISTS.
//
// Three prior versions of this harness declared a C-API that is not in this
// tree and therefore could never link:
//
//     deep2_core.lib                     does not exist
//     deep2_engine_init_raw              0 occurrences
//     deep2_engine_decode_step           0 occurrences
//     deep2_engine_create / _load_shards
//     / deep2_generate_stream / _destroy 0 occurrences
//
// The real interface, read from src/deep2/Deep2Engine.h:376 and :433, is C++:
//
//     using TokenCallback = std::function<bool(int32_t, const std::string&)>;
//     bool Deep2Engine::loadModel(const std::string& ggufPath, ModelLoadDiag*);
//     GenerationResult Deep2Engine::generateStream(prompt, options, callback);
//     void Deep2Engine::unloadModel();
//
// It links against InferenceEngine.lib, which is the same linkage
// deep2_streamer_cert uses -- and that harness is what proves 4 models stream.
//
// ---------------------------------------------------------------------------
// WHY THE "I/O Rate" COLUMN IS NOT PAGE FAULTS
//
// The previous version computed disk traffic as PageFaultCount * 4096. That is
// not I/O. PageFaultCount includes minor faults served entirely from the page
// cache (zero disk traffic), copy-on-write faults, stack guard pages and
// instruction fetches. Dividing by token latency and labelling the result
// "I/O Rate" produces a confident, specific number for transfers that never
// touched the drive -- an instrument that cannot disagree with the thing it
// claims to measure.
//
// This version reports both, separately and honestly:
//
//     page_faults   raw fault-count delta            (NOT bytes)
//     read_MB       measured disk read bytes          (the real I/O number)
//     resident_MB   working set                       (what mmap actually costs)
//
// READ is measured via GetProcessIoCounters().ReadTransferCount, which is the
// OS's own accounting of bytes delivered by storage.
//
// ---------------------------------------------------------------------------
// PRIORITY
//
// This defaults to NORMAL. The previous version pinned REALTIME_PRIORITY_CLASS
// with THREAD_PRIORITY_TIME_CRITICAL on a thread that performs blocking file
// I/O. A realtime thread that blocks on I/O without yielding can starve the
// scheduler hard enough that the machine stops responding and requires a hard
// power-cycle, and because the thread is pinned realtime you may not get a
// debugger back in. Set DOG_PRIORITY=realtime to reproduce that deliberately.
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "deep2/Deep2Engine.h"

namespace fs = std::filesystem;

namespace {

struct Telemetry {
    PROCESS_MEMORY_COUNTERS_EX pmcPrev{};
    IO_COUNTERS              ioPrev{};
    std::chrono::steady_clock::time_point lastTok{};
    int  tokenCount = 0;
    int  maxTokens  = 32;
    bool sawFaults  = false;
    bool sawIo      = false;
    SIZE_T majorFaults = 0;      // out-of-core signal: pages that needed DISK
    SIZE_T minorFaults = 0;      // served from page cache: NOT disk traffic
    double readMBTotal  = 0.0;
};

void Snap(PROCESS_MEMORY_COUNTERS_EX& pmc, IO_COUNTERS& io) {
    GetProcessMemoryInfo(GetCurrentProcess(),
                         reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc));
    if (!GetProcessIoCounters(GetCurrentProcess(), &io)) {
        // Older SDKs / restricted sessions can refuse. Leave zeroed rather than
        // reporting a fabricated zero as "measured no I/O".
        std::memset(&io, 0, sizeof(io));
    }
}

double DeltaMB(unsigned long long d) {
    return static_cast<double>(d) / (1024.0 * 1024.0);
}

// Executed by Deep2 for every decoded token. Returning false halts the stream.
bool OnToken(int32_t tokenId, const std::string& token, void* user) {
    auto* t = static_cast<Telemetry*>(user);
    const auto now = std::chrono::steady_clock::now();

    PROCESS_MEMORY_COUNTERS_EX pmc{};
    IO_COUNTERS io{};
    Snap(pmc, io);

    const double latMs =
        std::chrono::duration<double, std::milli>(now - t->lastTok).count();

    const SIZE_T dFault =
        pmc.PageFaultCount - t->pmcPrev.PageFaultCount;
    const unsigned long long dRead =
        io.ReadTransferCount - t->ioPrev.ReadTransferCount;

    // Out-of-core discriminator.
    //
    // NOTE: PROCESS_MEMORY_COUNTERS_EX exposes only a COMBINED PageFaultCount.
    // It does NOT expose the major/minor split, so a "major faults" column
    // cannot be produced honestly from this API. An earlier draft of this file
    // computed one from OtherPageFaultCount, which is a different counter
    // entirely -- that would have been a fabricated metric printed next to a
    // real one. The split needs ETW or \Process(*)\Major Faults/sec.
    //
    // What IS authoritative here and is used instead:
    //   read_MB      measured disk bytes (GetProcessIoCounters)
    //   residency    resident_MB / mapped_set_GB
    // read_MB == 0 with residency climbing means the page cache is absorbing
    // everything; read_MB > 0 means the disk is genuinely involved.
    (void)dFault;

    std::string safe = token.substr(0, 48);
    for (auto& c : safe) {
        if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126) {
            c = '.';
        }
    }

    // read_MB is the only column here that is measured disk traffic.
    const double readMB   = DeltaMB(dRead);
    const double readMBps = (latMs > 0.0) ? (readMB / (latMs / 1000.0)) : 0.0;

    std::printf("[Tok %2d] id=%-7d lat=%8.2f ms  faults=%-6llu  read_MB=%-9.2f  read_MBps=%-9.2f  resident_MB=%-7zu  \"%s\"\n",
                t->tokenCount, tokenId, latMs,
                static_cast<unsigned long long>(dFault),
                readMB, readMBps,
                static_cast<std::size_t>(pmc.WorkingSetSize / (1024 * 1024)),
                safe.c_str());

    if (dFault) t->sawFaults = true;
    if (dRead)  t->sawIo = true;
    t->readMBTotal += readMB;

    t->pmcPrev = pmc;
    t->ioPrev  = io;
    t->lastTok = now;
    ++t->tokenCount;
    return t->tokenCount < t->maxTokens;   // cap
}

// The logical model size, summed across the whole shard set.
//
// Reporting only the entry shard mislabeled Kimi K2 as 43.12 GB when its set is
// 578.58 GB -- wrong by 13x. Any bandwidth or capacity arithmetic keyed off
// that number is wrong, so the set is summed and the shard count is printed
// next to it. The denominator for every rate in this harness is this value.
struct ModelExtent {
    uint64_t totalBytes = 0;
    int      shards = 0;
    std::string entry;
};

ModelExtent MeasureSet(const fs::path& target, const std::string& entry) {
    ModelExtent e;
    e.entry = entry;

    if (fs::is_regular_file(target)) {
        WIN32_FILE_ATTRIBUTE_DATA fa{};
        if (GetFileAttributesExA(entry.c_str(), GetFileExInfoStandard, &fa)) {
            e.totalBytes = (static_cast<uint64_t>(fa.nFileSizeHigh) << 32) | fa.nFileSizeLow;
            e.shards = 1;
        }
        return e;
    }

    std::error_code ec;
    for (const auto& en : fs::recursive_directory_iterator(target, ec)) {
        if (ec) break;
        if (!en.is_regular_file(ec)) continue;
        if (en.path().extension() != ".gguf") continue;
        const uintmax_t sz = en.file_size(ec);
        if (ec) continue;
        e.totalBytes += static_cast<uint64_t>(sz);
        ++e.shards;
    }
    return e;
}

std::string Gb(uint64_t b) {
    char buf[48];
    std::snprintf(buf, sizeof(buf), "%.2f", b / (1024.0 * 1024 * 1024));
    return buf;
}

std::string FirstGguf(const fs::path& p) {
    if (fs::is_regular_file(p)) return p.string();

    // A sharded GGUF is ONE model, and the loader must be handed member 00001.
    // Returning whichever file the filesystem enumerates first would hand it an
    // arbitrary fragment -- typically shard 7 of 13 -- which is not a model.
    std::error_code ec;
    std::string fallback;
    for (const auto& e : fs::recursive_directory_iterator(p, ec)) {
        if (ec) break;
        if (!e.is_regular_file(ec)) continue;
        if (e.path().extension() != ".gguf") continue;
        const std::string name = e.path().filename().string();
        if (name.find("-00001-of-") != std::string::npos) {
            return e.path().string();
        }
        if (fallback.empty()) fallback = e.path().string();
    }
    return fallback;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: rawr_dog <file.gguf | model_dir>\n");
        return 1;
    }

    if (const char* pr = std::getenv("DOG_PRIORITY")) {
        if (std::strcmp(pr, "realtime") == 0) {
            SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
            std::printf("[!] REALTIME priority enabled. A realtime thread doing\n"
                        "    blocking I/O can starve the scheduler. This is deliberate.\n\n");
        } else if (std::strcmp(pr, "above") == 0) {
            SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
        }
    }

    const fs::path target = argv[1];
    const std::string model = FirstGguf(target);
    if (model.empty()) {
        std::printf("[FATAL] no .gguf found under %s\n", target.string().c_str());
        return 2;
    }

    LARGE_INTEGER fsz{};
    {
        HANDLE h = CreateFileA(model.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            std::printf("[FATAL] cannot open %s (win32=%lu)\n", model.c_str(), GetLastError());
            return 2;
        }
        GetFileSizeEx(h, &fsz);
        CloseHandle(h);
    }

    const ModelExtent ext = MeasureSet(target, model);

    std::printf("RAWRXD_DOG_TELEMETRY_001\n");
    std::printf("MODEL=%s\n", model.c_str());
    std::printf("FILE_BYTES=%llu\n", (unsigned long long)ext.totalBytes);
    std::printf("SHARDS=%d\n", ext.shards);
    std::printf("SET_GB=%s\n", Gb(ext.totalBytes).c_str());
    std::printf("api       = Deep2::Deep2Engine::loadModel + generateStream (real)\n\n");

    Deep2::Deep2Engine engine;
    Deep2::ModelLoadDiag diag;

    // DOG_VULKAN=1 enables the GPU backend. This is the decisive test for the
    // MLA suspension: the engine has no CPU MLA branch, but it DOES have a GPU
    // one (computeMLAAttentionGpu). Whether an MLA model is genuinely blocked
    // or merely unreachable because this harness never turned the GPU on is a
    // question that must be answered by measurement, not assumed.
    if (const char* vk = std::getenv("DOG_VULKAN")) {
        const bool on = std::strcmp(vk, "0") != 0;
        engine.enableVulkan(on);
        std::printf("DOG_VULKAN=%d\n", on ? 1 : 0);
    }

    const auto t0 = std::chrono::steady_clock::now();
    const bool loaded = engine.loadModel(model, &diag);
    const auto t1 = std::chrono::steady_clock::now();

    if (!loaded) {
        std::printf("[FATAL] loadModel failed stage=%d name=%s msg=%s\n",
                    diag.stageCode, diag.stageName.c_str(), diag.message.c_str());
        return 3;
    }
    const double loadMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
    std::printf("[+] loadModel returned in %.1f ms\n", loadMs);
    std::printf("    NOTE: this is mmap construction. It is NOT bytes read.\n");
    std::printf("          The read_MB column below is the measured traffic.\n\n");

    Deep2::GenerationOptions opt;
    opt.maxTokens   = 32;
    opt.temperature = 0.0f;   // deterministic
    opt.topP        = 1.0f;
    opt.topK        = 1;
    opt.seed        = 1234;

    Telemetry tel;
    if (const char* mt = std::getenv("DOG_TOKENS")) {
        tel.maxTokens = std::atoi(mt);
        opt.maxTokens = static_cast<std::uint32_t>(tel.maxTokens);
    }

    Snap(tel.pmcPrev, tel.ioPrev);
    tel.lastTok = std::chrono::steady_clock::now();

    std::printf("Streaming (max %d tokens), per-token telemetry:\n", tel.maxTokens);
    std::printf("--------------------------------------------------------------------------------\n");

    const Deep2::GenerationResult r =
        engine.generateStream("The capital of France is", opt,
            [&tel](int32_t id, const std::string& piece) {
                return OnToken(id, piece, &tel);
            });

    std::printf("--------------------------------------------------------------------------------\n");
    std::printf("callbacks=%d  engine_generatedTokens=%llu  status=%d  cancelled=%d\n",
                tel.tokenCount,
                static_cast<unsigned long long>(r.generatedTokens),
                static_cast<int>(r.status), r.cancelled ? 1 : 0);
    if (!r.failureDetail.empty()) {
        std::printf("failureDetail=%s\n", r.failureDetail.c_str());
    }

    engine.unloadModel();

    std::printf("\nVERDICT=%s\n",
                (tel.tokenCount > 0 && tel.tokenCount == r.generatedTokens)
                    ? "STREAM_TELEMETRY_OK" : "STREAM_TELEMETRY_MISMATCH");
    std::printf("TOKENS_GENERATED=%llu\n",
                static_cast<unsigned long long>(r.generatedTokens));
    std::printf("READ_BYTES_TOTAL=%llu\n",
                static_cast<unsigned long long>(tel.readMBTotal * 1024.0 * 1024.0));
    std::printf("RESIDENT_AFTER_TOKENS_MB=%zu\n", static_cast<std::size_t>(
                tel.pmcPrev.WorkingSetSize / (1024 * 1024)));
    if (ext.totalBytes > 0) {
        std::printf("RESIDENCY_RATIO=%.4f\n",
            (double)(tel.pmcPrev.WorkingSetSize) / (double)ext.totalBytes);
    }
    std::printf("disk_read_observed=%s  page_faults_observed=%s\n",
                tel.sawIo ? "YES" : "NO", tel.sawFaults ? "YES" : "NO");
    std::printf("FAIL_CLASS=%s\n",
                (tel.tokenCount > 0) ? "NONE"
                : (static_cast<int>(r.status) == 3 ? "STRUCTURAL_REJECTION"
                : (static_cast<int>(r.status) == 4 ? "FORWARD_FAILURE"
                : (static_cast<int>(r.status) == 5 ? "INTERNAL_ERROR"
                : "UNKNOWN"))));
    if (!tel.sawIo) {
        std::printf("  -> NO storage reads were counted. Whatever the model produced was\n"
                    "     served from cache or memory. Load time is therefore not I/O.\n");
    }
    return 0;
}
