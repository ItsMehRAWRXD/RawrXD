#include "GGUFLoader.hpp"

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: deep2_shard_probe <first-shard.gguf> [...]\n");
        return 2;
    }
    int failures = 0;
    std::string dumpPath;
    bool dumpMeta = false;
    std::vector<std::string> paths;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--dump" && i + 1 < argc) {
            dumpPath = argv[++i];
            continue;
        }
        if (std::string(argv[i]) == "--meta") {
            dumpMeta = true;
            continue;
        }
        paths.emplace_back(argv[i]);
    }
    for (const auto& path : paths) {
        Deep2::GGUFLoader loader;
        if (!loader.load(path)) {
            std::printf("SHARD_PROBE_FAIL path=%s reason=%s\n", path.c_str(), loader.error().c_str());
            ++failures;
            continue;
        }
        std::printf("SHARD_PROBE_PASS path=%s shards=%u tensors=%zu mapped_bytes=%llu arch=%s\n",
                    path.c_str(), loader.shardCount(), loader.tensorCount(),
                    static_cast<unsigned long long>(loader.mappedBytes()),
                    loader.getMetaString("general.architecture", "unknown").c_str());
        if (dumpMeta) {
            for (const auto& kv : loader.getMetaAllStrings())
                std::printf("SHARD_PROBE_META %s=%s\n", kv.first.c_str(), kv.second.c_str());
        }
        if (!dumpPath.empty()) {
            std::ofstream out(dumpPath, std::ios::trunc);
            if (!out) {
                std::fprintf(stderr, "SHARD_PROBE_DUMP_FAIL path=%s\n", dumpPath.c_str());
                ++failures;
            } else {
                for (const auto& name : loader.listTensors()) {
                    const auto* t = loader.getTensor(name);
                    if (!t) continue;
                    out << static_cast<unsigned>(t->type) << "\t" << t->shardId << "\t"
                        << t->sizeBytes << "\t";
                    for (size_t d = 0; d < t->shape.size(); ++d) {
                        if (d) out << 'x';
                        out << t->shape[d];
                    }
                    out << "\t" << t->name << '\n';
                }
                std::printf("SHARD_PROBE_DUMP_PASS path=%s\n", dumpPath.c_str());
            }
            dumpPath.clear();
        }
    }
    return failures ? 1 : 0;
}
