#include <cstdio>
#include <cstdint>
#include <cmath>
#include <limits>
#include <vector>

int main() {
    const char* path = "G:\\~dev\\rawrxd\\models\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    const std::int64_t offset = 293968800LL;
    const std::size_t nbytes = 8192;
    const int nfloats = 2048;

    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || f == nullptr) {
        std::printf("ERROR: cannot open file: %s\n", path);
        return 1;
    }

    if (_fseeki64(f, offset, SEEK_SET) != 0) {
        std::printf("ERROR: cannot seek to offset %lld\n", (long long)offset);
        fclose(f);
        return 1;
    }

    std::vector<unsigned char> buf(nbytes);
    std::size_t got = fread(buf.data(), 1, nbytes, f);
    fclose(f);

    if (got != nbytes) {
        std::printf("ERROR: short read: %zu of %zu bytes (file may be smaller than offset)\n", got, nbytes);
        return 1;
    }

    const float* pf = reinterpret_cast<const float*>(buf.data());

    int nonfinite_count = 0;
    std::vector<int> nonfinite_idx;
    float min_fin = std::numeric_limits<float>::infinity();
    float max_fin = -std::numeric_limits<float>::infinity();

    for (int i = 0; i < nfloats; ++i) {
        float v = pf[i];
        if (!std::isfinite(v)) {
            ++nonfinite_count;
            nonfinite_idx.push_back(i);
        } else {
            if (v < min_fin) min_fin = v;
            if (v > max_fin) max_fin = v;
        }
    }

    std::printf("File: %s\n", path);
    std::printf("Offset: %lld decimal\n", (long long)offset);
    std::printf("Bytes read: %zu\n", got);
    std::printf("Float32 count: %d\n", nfloats);
    std::printf("Non-finite count: %d\n", nonfinite_count);

    std::printf("\nFirst 20 values:\n");
    for (int i = 0; i < 20; ++i) {
        float v = pf[i];
        const char* tag = std::isfinite(v) ? "" : (std::isnan(v) ? " (NaN)" : " (Inf)");
        std::printf("  [%3d] %12.6g%s\n", i, (double)v, tag);
    }

    std::printf("\nNon-finite indices:\n");
    if (nonfinite_idx.empty()) {
        std::printf("  (none)\n");
    } else {
        for (int idx : nonfinite_idx) {
            float v = pf[idx];
            const char* tag = std::isnan(v) ? "NaN" : "Inf";
            std::printf("  [%d] %s (0x%08X)\n", idx, tag,
                *(reinterpret_cast<const std::uint32_t*>(&v)));
        }
    }

    if (nonfinite_count == nfloats) {
        std::printf("\nMin/Max finite: (no finite values present)\n");
    } else {
        std::printf("\nMin finite: %12.6g\n", (double)min_fin);
        std::printf("Max finite: %12.6g\n", (double)max_fin);
    }

    return 0;
}
