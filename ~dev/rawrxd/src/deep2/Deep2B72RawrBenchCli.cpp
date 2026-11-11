#include "Deep2B72RawrBenchCli.hpp"
#include <cstdlib>

namespace Deep2 {

B72BenchOptions B72RawrBenchCli::parse(const std::vector<std::string>& a) noexcept {
    B72BenchOptions o{};
    if(a.empty()) return o;

    size_t i=0;
    if(a[i]=="rawr") ++i;
    if(i>=a.size() || a[i]!="bench") return o;
    ++i;

    if(i<a.size() && (a[i]=="-h"||a[i]=="--help")) {
        o.valid=true;o.showHelp=true;return o;
    }
    if(i>=a.size()) return o;
    o.model=a[i++];

    while(i<a.size()) {
        const auto& x=a[i++];
        if(x=="--contract") {
            o.useContract=true;
            if(i<a.size() && !a[i].empty() && a[i][0]!='-')
                o.contractName=a[i++];
        } else if(x=="--tokens" && i<a.size()) {
            o.tokens=static_cast<uint32_t>(std::strtoul(a[i++].c_str(),nullptr,10));
        } else if(x=="--warmup" && i<a.size()) {
            o.warmupTokens=static_cast<uint32_t>(std::strtoul(a[i++].c_str(),nullptr,10));
        } else if(x=="--prompt" && i<a.size()) {
            o.prompt=a[i++];
        } else if(x=="--evidence-dir" && i<a.size()) {
            o.evidenceDir=a[i++];
        } else if(x=="--json") {
            o.json=true;
        } else if(x=="--quiet") {
            o.quiet=true;
        } else {
            return o;
        }
    }

    if(o.tokens<64 || o.warmupTokens>o.tokens) return o;
    o.valid=true;
    return o;
}

std::string B72RawrBenchCli::usage() {
    return
      "rawr bench <model> [--contract [name]] [--tokens N] [--warmup N]\\n"
      "           [--prompt TEXT] [--evidence-dir DIR] [--json] [--quiet]\\n";
}

} // namespace Deep2
