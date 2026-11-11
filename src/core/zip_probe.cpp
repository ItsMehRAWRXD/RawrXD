// Isolates the ZIP reader: reads a package and lists its entries.
#include "core/zip_reader.h"

#include <cstdio>
#include <fstream>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: zip_probe <file>\n"); return 2; }

    std::ifstream in(argv[1], std::ios::binary);
    if (!in) { printf("cannot open %s\n", argv[1]); return 1; }
    std::string blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    printf("archive: %zu bytes\n", blob.size());

    RawrXD::ZipReader reader;
    if (!reader.open(reinterpret_cast<const uint8_t*>(blob.data()), blob.size())) {
        printf("open failed\n");
        return 1;
    }
    printf("central directory: %zu entries\n", reader.entries().size());
    for (const auto& e : reader.entries()) {
        printf("  %-40s method=%u comp=%u uncomp=%u crc=%08X local=%u\n",
               e.name.c_str(), (unsigned)e.method, e.compressedSize,
               e.uncompressedSize, e.crc32, e.localHeaderOffset);
    }

    for (const auto& e : reader.entries()) {
        printf("extracting %s ... ", e.name.c_str());
        std::string content;
        bool ok = reader.extract(e.name, content);
        printf("%s (%zu bytes)\n", ok ? "ok" : "FAILED", content.size());
        if (ok && e.name.size() > 20) {
            printf("    first bytes: %.60s\n", content.c_str());
        }
    }
    return 0;
}
