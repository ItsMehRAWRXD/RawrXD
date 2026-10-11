// gguf_crash_iso.cpp - isolates where the universal reader fails.
#include "RawrXDGgufReader.hpp"
#include <cstdio>
using namespace rawrxd;

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 2) { printf("need file\n"); return 2; }
    printf("opening %s\n", argv[1]);

    GgufReader r;
    printf("calling Open...\n");
    const bool ok = r.Open(argv[1]);
    printf("Open returned %d why='%s'\n", ok ? 1 : 0, r.why().c_str());
    if (!ok) return 1;

    printf("version=%u tensors=%llu dataStart=%llu fileSize=%llu arch='%s'\n",
           r.version(), (unsigned long long)r.tensorCount(),
           (unsigned long long)r.dataStart(),
           (unsigned long long)r.fileSize(), r.architecture().c_str());

    printf("iterating tensors...\n");
    size_t i = 0;
    for (const auto& kv : r.tensors()) { (void)kv; if (++i % 100 == 0) printf("  %zu...\n", i); }
    printf("iterated %zu tensors\n", i);

    printf("blockIndices...\n");
    std::vector<int> b; r.blockIndices(b);
    printf("blocks=%zu\n", b.size());

    printf("capabilities ssm=%d attn=%d moe=%d\n",
           r.hasSsm() ? 1 : 0, r.hasAttention() ? 1 : 0, r.hasMoe() ? 1 : 0);

    printf("DONE\n");
    return 0;
}
