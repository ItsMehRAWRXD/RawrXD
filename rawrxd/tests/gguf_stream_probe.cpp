// gguf_stream_probe.cpp — streams the real 10.36 GB DeepSeek-V2-Lite model and
// reports the working-set ceiling. The point of this gate is NOT throughput; it
// is that peak memory is bounded by the window, not by the file.

#include "deep2/GGUFLoader.hpp"
#include "deep2/QuantKernelRegistry.hpp"
#include "deep2/GGUFStream.hpp"

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1] : "";
    const std::uint64_t windowBlocks = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 4096;

    std::printf("RAWRXD_GGUF_STREAM_001\n");
    std::printf("file: %s\n", path.c_str());

    Deep2::GGUFLoader L;
    const auto t0 = std::chrono::steady_clock::now();
    if (!L.load(path)) { std::printf("LOAD_FAILED\n"); return 1; }
    const auto t1 = std::chrono::steady_clock::now();
    std::printf("mapped in %.1f ms  (no whole-file copy)\n",
                std::chrono::duration<double, std::milli>(t1 - t0).count());

    auto names = L.listTensors();
    std::printf("tensors: %zu\n", names.size());

    auto& reg = Deep2::QuantKernelRegistry::Instance();
    reg.RegisterBuiltins();      // populate the dequant table (Q4_K=12, Q6_K=14, Q8_0=8, ...)
    std::printf("dequant kernels registered\n");
    Deep2::GGUFStream S(reg);
    S.setWindow(windowBlocks);

    std::uint64_t totalBlocks = 0, totalElems = 0, totalBytes = 0, totalSlices = 0;
    std::size_t maxWindow = 0, unaligned = 0, failed = 0;
    std::string firstErr;
    double checksum = 0.0;

    const auto t2 = std::chrono::steady_clock::now();
    for (const auto& n : names) {
        std::string err;
        if (!S.open(L, n, &err)) {
            ++failed;
            if (firstErr.empty()) firstErr = n + " -> " + err;
            continue;
        }
        if (!S.rowAligned()) ++unaligned;
        maxWindow = std::max(maxWindow, S.workingSetBytes());

        Deep2::GGUFStream::Slice sl;
        while (S.next(sl)) {
            // consume every decoded element: this is the real work, not a stub
            double acc = 0.0;
            for (std::uint64_t i = 0; i < sl.elements; ++i) acc += double(sl.data[i]);
            checksum += acc;
            ++totalSlices;
        }
        totalBlocks += S.blocksServed();
        totalElems += S.elementsServed();
        totalBytes += S.bytesTouched();
    }
    const auto t3 = std::chrono::steady_clock::now();
    const double secs = std::chrono::duration<double>(t3 - t2).count();

    std::printf("\nstreamed %zu tensors (%zu failed to open)\n", names.size() - failed, failed);
    std::printf("  quant blocks decoded : %llu\n", (unsigned long long)totalBlocks);
    std::printf("  elements decoded     : %llu\n", (unsigned long long)totalElems);
    std::printf("  tensor bytes touched : %llu  (%.2f GB)\n",
                (unsigned long long)totalBytes, double(totalBytes) / 1e9);
    std::printf("  slices               : %llu (window=%llu blocks)\n",
                (unsigned long long)totalSlices, (unsigned long long)windowBlocks);
    std::printf("  tensors NOT row-aligned (must slice by block) : %zu\n", unaligned);
    std::printf("  PEAK DECODE WINDOW   : %.2f MB\n", double(maxWindow) / (1024.0 * 1024.0));
    std::printf("  working set / data ratio : %.9f\n",
                double(maxWindow) / (double(totalBytes) + 1.0));
    std::printf("  elapsed              : %.2f s  (%.2f GB/s)\n",
                secs, double(totalBytes) / 1e9 / (secs > 0 ? secs : 1));
    std::printf("  checksum             : %.6g  (proves elements were really decoded)\n", checksum);

    // Physical impossibilities. A stream cannot decode more bytes than the file
    // contains, nor more elements than the tensors declare. "Did I decode
    // anything" cannot catch a counter bug -- an earlier run reported 1863 GB
    // touched from a 10.36 GB file and still printed PASS.
    const double fileGB  = double(std::size_t(L.mappedBytes())) / 1e9;
    const double windowMB = double(maxWindow) / (1024.0 * 1024.0);
    std::uint64_t declaredElems = 0;
    for (const auto& n : names) {
        const auto* t = L.getTensor(n);
        if (t) declaredElems += t->numElements();
    }
    const bool touchedWithinFile =
        (totalBytes <= std::uint64_t(L.mappedBytes()) + (1ull << 20));
    const bool elemsWithinDeclared = (totalElems <= declaredElems);
    const bool allElementsServed  = (declaredElems > 0) && (totalElems == declaredElems);

    std::printf("\n--- gate conditions ---\n");
    std::printf("  decoded_some_elements        : %d (%llu elements)\n",
                (totalElems > 0 && checksum != 0.0) ? 1 : 0, (unsigned long long)totalElems);
    std::printf("  checksum_nonzero            : %d (%.6g)\n", checksum != 0.0 ? 1 : 0, checksum);
    std::printf("  no_tensor_open_failures      : %d (%zu failed)\n", (failed == 0) ? 1 : 0, failed);
    std::printf("  window_nonzero_under_32mb    : %d (%.3f MB)\n",
                (windowMB > 0.0 && windowMB < 32.0) ? 1 : 0, windowMB);
    std::printf("  touched_bytes_within_file    : %d (%llu vs file %llu)\n",
                touchedWithinFile ? 1 : 0, (unsigned long long)totalBytes,
                (unsigned long long)L.mappedBytes());
    std::printf("  elements_within_declared     : %d (%llu vs %llu)\n",
                elemsWithinDeclared ? 1 : 0, (unsigned long long)totalElems,
                (unsigned long long)declaredElems);
    std::printf("  every_element_served_once    : %d\n", allElementsServed ? 1 : 0);
    if (!firstErr.empty()) std::printf("  first_open_failure           : %s\n", firstErr.c_str());

    const bool pass = (totalElems > 0) && (checksum != 0.0) && (failed == 0)
                      && (windowMB > 0.0) && (windowMB < 32.0)
                      && touchedWithinFile && elemsWithinDeclared && allElementsServed;
    std::printf("\nSTREAMING_BOUNDED_MEMORY=%s\n", pass ? "PASS" : "FAIL");
    std::printf("  file is %.2f GB; peak decode window is %.3f MB\n", fileGB, windowMB);
    return pass ? 0 : 1;
}
