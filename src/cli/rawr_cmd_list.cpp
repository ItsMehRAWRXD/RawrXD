// rawr_cmd_list.cpp — rawr list / show / paths
#include "rawr_commands.hpp"
#include "rawr_output_router.hpp"
#include "rawr_model_registry.hpp"
#include <cstdio>

namespace rawr {
namespace {

void PrintSize(uint64_t b) {
    if (b >= (1ull << 30))
        std::printf("%6.1f GB", (double)b / (double)(1ull << 30));
    else if (b >= (1ull << 20))
        std::printf("%6.1f MB", (double)b / (double)(1ull << 20));
    else
        std::printf("%6.1f KB", (double)b / 1024.0);
}

} // namespace

int CmdList(const CliArgs& a) {
    auto& reg = ModelRegistry::instance();
    reg.scan(a.refresh);
    if (a.verbose) {
        std::printf("%-28s %-8s %-8s %6s  %-10s %s\n", "NAME", "ARCH",
                    "QUANT", "SHARDS", "SIZE", "LOCATION");
    } else {
        std::printf("%-36s %-10s %s\n", "NAME", "ID", "SIZE");
    }
    for (const auto& e : reg.entries()) {
        if (!e.valid) continue;
        std::string label = e.name;
        if (!e.tag.empty() && e.tag != "latest") label += ":" + e.tag;
        if (a.verbose) {
            std::printf("%-28s %-8s %-8s %6u  ", label.c_str(),
                        e.architecture.c_str(), e.quantization.c_str(),
                        e.shardCount);
            PrintSize(e.sizeBytes);
            std::printf("  %s\n", e.path.c_str());
        } else {
            std::printf("%-36s %-10s ", label.c_str(),
                        e.id.size() > 8 ? e.id.substr(0, 8).c_str()
                                        : e.id.c_str());
            PrintSize(e.sizeBytes);
            std::printf("\n");
        }
    }
    return ExitCode::Ok;
}

int CmdShow(const CliArgs& a) {
    if (a.model.empty()) {
        PrintUsage();
        return ExitCode::Usage;
    }
    auto& reg = ModelRegistry::instance();
    reg.scan(a.refresh);
    ModelEntry e;
    if (!reg.inspect(a.model, e)) {
        Diag("rawr: model not found: %s\n", a.model.c_str());
        return ExitCode::ModelResolve;
    }
    std::printf("name\t%s\n", e.name.c_str());
    std::printf("tag\t%s\n", e.tag.c_str());
    std::printf("id\t%s\n", e.id.c_str());
    std::printf("path\t%s\n", e.path.c_str());
    std::printf("size\t%llu\n", (unsigned long long)e.sizeBytes);
    std::printf("arch\t%s\n", e.architecture.c_str());
    std::printf("quant\t%s\n", e.quantization.c_str());
    std::printf("shards\t%u\n", e.shardCount);
    std::printf("valid\t%d\n", e.valid ? 1 : 0);
    return ExitCode::Ok;
}

int CmdPaths(const CliArgs& /*a*/) {
    auto& reg = ModelRegistry::instance();
    reg.scan(false);
    for (const auto& r : reg.roots()) std::printf("%s\n", r.c_str());
    return ExitCode::Ok;
}

} // namespace rawr
