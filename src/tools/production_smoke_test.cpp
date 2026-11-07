#include "../Win32RomEmulator.hpp"
#include "../PrefetchQueue.hpp"
#include "../PerformanceProfiler.hpp"
#include <iostream>
#include <cassert>
#include <cerrno>
#include <climits>
#include <cwchar>
#include <unordered_map>

using namespace Deep2Engine::Emulator;
using namespace Deep2Rom;

void run_production_stress_test(const std::wstring& rom_path, const std::wstring& base_shard_path, uint32_t shards) {
    std::cout << "======================================================================\n";
    std::cout << "          DEEP2ENGINE PRODUCTION VALIDATION & STRESS SUITE            \n";
    std::cout << "======================================================================\n";

    if (shards == 0) {
        std::cerr << "[-] Invalid test configuration: shard count must be positive.\n";
        std::exit(2);
    }

    // 1. Assert ROM Loader initialization boundaries
    Win32RomLoader loader;
    if (!loader.map_rom_to_virtual_space(rom_path)) {
        std::cerr << "[-] CRITICAL: ROM Manifest Loader initialization failed.\n";
        std::exit(1);
    }
    std::cout << "[✓] Gate 1: Zero-Copy ROM Loader Mapping -> PASS\n";

    // 2. Instantiate and fill out the shard handle file table
    MultiShardFlickerManager flicker;
    std::unordered_map<uint32_t, uint64_t> shard_file_sizes;
    for (uint32_t i = 0; i < shards; ++i) {
        wchar_t current_shard[MAX_PATH] = {};
        const int shardPathChars = swprintf_s(current_shard, MAX_PATH,
                                             L"%ls.gguf.%02u", base_shard_path.c_str(), i);
        if (shardPathChars < 0 || shardPathChars >= MAX_PATH) {
            std::cerr << "[-] Gate 2 FAIL: shard path exceeds MAX_PATH.\n";
            std::exit(1);
        }
        uint64_t file_size = 0;
        {
            HANDLE h = ::CreateFileW(current_shard, GENERIC_READ, FILE_SHARE_READ,
                                     nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER sz;
                if (::GetFileSizeEx(h, &sz) && sz.QuadPart > 0)
                    file_size = static_cast<uint64_t>(sz.QuadPart);
                ::CloseHandle(h);
            }
        }
        if (file_size == 0) {
            std::wcerr << L"[-] Gate 2 FAIL: shard is missing, unreadable, or empty: "
                       << current_shard << L"\n";
            std::exit(1);
        }
        shard_file_sizes[i] = file_size;
        if (!flicker.register_shard(i, current_shard, file_size)) {
            std::wcout << L"[-] CRITICAL: Shard file missing or locked: " << current_shard << L"\n";
            std::exit(1);
        }
    }
    std::cout << "[✓] Gate 2: Shard Handle Map Allocation -> PASS (" << shards << " files linked)\n";

    // 3. Register tensor descriptors with the prefetch queue for real shard resolution
    PrefetchQueue prefetch(flicker);
    const auto* tensors = loader.get_tensors();
    size_t tensor_count = loader.get_tensor_count();
    for (size_t i = 0; i < tensor_count; ++i) {
        const auto& desc = tensors[i];
        TensorPrefetchInfo info;
        info.shard_id = desc.shard_id;
        info.absolute_offset = desc.absolute_offset;
        info.tensor_bytes = desc.tensor_bytes;
        auto sit = shard_file_sizes.find(desc.shard_id);
        info.file_size = (sit != shard_file_sizes.end()) ? sit->second : 0;
        if (desc.tensor_bytes == 0 || sit == shard_file_sizes.end() ||
            desc.absolute_offset > info.file_size ||
            desc.tensor_bytes > info.file_size - desc.absolute_offset) {
            std::cerr << "[-] Gate 3 FAIL: tensor " << i
                      << " exceeds its registered shard bounds.\n";
            std::exit(1);
        }
        prefetch.register_tensor_info(i, info);
    }
    std::cout << "[✓] Gate 3: Tensor descriptors registered for prefetch -> PASS\n";
    std::cout << "    Tensor descriptors registered: " << tensor_count << "\n";

    // 4. Fire high-frequency virtual memory operations to assert structural bounds stability
    std::cout << "[*] Injecting localized memory-mapping lease bursts...\n";
    size_t test_iterations = 500;
    bool memory_leaks_detected = false;

    if (tensor_count == 0) {
        std::cerr << "[-] Gate 4 FAIL: ROM manifest has no tensors; page lease test was not executed.\n";
        std::exit(1);
    } else {
        for (size_t iter = 0; iter < test_iterations; ++iter) {
            size_t target_idx = iter % tensor_count;
            prefetch.submit_prefetch(target_idx, true);

            if (target_idx < tensor_count) {
                const auto& desc = tensors[target_idx];
                auto sit = shard_file_sizes.find(desc.shard_id);
                uint64_t file_size = (sit != shard_file_sizes.end()) ? sit->second : 0;
                auto view = flicker.acquire_tensor(
                    desc.shard_id, target_idx,
                    desc.absolute_offset, desc.tensor_bytes,
                    file_size);
                if (!view.valid()) {
                    std::cerr << "[-] Gate 4 FAIL at iter " << iter
                              << " tensor " << target_idx
                              << " (shard " << desc.shard_id
                              << ", offset " << desc.absolute_offset
                              << ", bytes " << desc.tensor_bytes
                              << ", file_size " << file_size << ")\n";
                    memory_leaks_detected = true;
                    break;
                }
            }
        }
    }

    if (!memory_leaks_detected) {
        std::cout << "[✓] Gate 4: " << test_iterations << " Page Lease Attempts -> PASS (no invalid views observed)\n";
    } else {
        std::cerr << "[-] CRITICAL: Memory virtualization tracking failure during lease burst.\n";
        std::exit(1);
    }

    // 5. Print hardware profiler telemetry (baseline)
    HardwareProfiler profiler;
    std::cout << "[✓] Gate 5: Hardware Profiler constructed -> PASS\n";

    std::cout << "----------------------------------------------------------------------\n";
    std::cout << "STATUS: FIVE SMOKE CHECKS COMPLETED; NOT A FULL ENGINE CERTIFICATION.\n";
    std::cout << "======================================================================\n";
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 4) {
        std::wcout << L"Usage: production_smoke_test.exe <manifest.rom> <base_shard_path> <total_shards>\n";
        std::wcout << L"Example: production_smoke_test.exe model.rom G:\\~dev\\rawrxd\\models\\DeepSeek-R1 11\n";
        return 1;
    }
    errno = 0;
    wchar_t* end = nullptr;
    const unsigned long parsed = std::wcstoul(argv[3], &end, 10);
    if (errno != 0 || !end || *end != L'\0' || parsed == 0 || parsed > UINT32_MAX) {
        std::wcerr << L"Invalid shard count: expected a positive uint32 integer.\n";
        return 2;
    }
    run_production_stress_test(argv[1], argv[2], static_cast<uint32_t>(parsed));
    return 0;
}
