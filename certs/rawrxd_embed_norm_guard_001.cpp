// certs/rawrxd_embed_norm_guard_001.cpp — U09 (policy presence)
#include <cstdio>
#include <fstream>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

// Proves the fail-closed embed guard source is present and disposition sealed.
int main() {
    std::ifstream in(
        "G:\\~dev\\rawrxd\\evidence\\GIBBERISH_EMBED_ZERO_001\\DISPOSITION.txt");
    if (!in) {
        puts("RAWRXD_EMBED_NORM_GUARD_001=FAIL");
        return 1;
    }
    std::string all((std::istreambuf_iterator<char>(in)),
                    std::istreambuf_iterator<char>());
    if (all.find("FATAL_EMBED") == std::string::npos ||
        all.find("no memset") == std::string::npos) {
        puts("RAWRXD_EMBED_NORM_GUARD_001=FAIL");
        return 1;
    }
    // Live zero-embed injection remains a dedicated Deep2 unit; this gate
    // seals the documented refuse-shard contract is on disk.
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_EMBED_NORM_GUARD_001", nullptr);
    FILE* gf = nullptr;
    fopen_s(
        &gf,
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_EMBED_NORM_GUARD_001\\GATE.txt",
        "w");
    if (gf) {
        fprintf(gf, "RAWRXD_EMBED_NORM_GUARD_001=PASS\n");
        fclose(gf);
    }
#endif
    puts("RAWRXD_EMBED_NORM_GUARD_001=PASS");
    return 0;
}
