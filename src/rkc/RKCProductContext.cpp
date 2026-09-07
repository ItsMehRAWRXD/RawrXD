// RKCProductContext.cpp — product-path assemble (proof state, not tab stuffing)
#include "RKCProductContext.hpp"

namespace RawrXD {
namespace RKC {

ProductAssembleResult AssembleProductContext(const ProductAssembleInput& in) {
    ProductAssembleResult out;
    WorldObserveConfig cfg;
    cfg.modelPath = in.modelPath;
    cfg.probeOllama11434 = in.probeOllama;
    out.session = CompileQueryToProof(in.query, cfg);
    out.assembled = out.session.emitted;

    out.wantsPatch =
        out.session.proof.goal == "cancellation_path" ||
        in.query.find("implement") != std::string::npos ||
        in.query.find("Implement") != std::string::npos ||
        in.query.find("patch") != std::string::npos;

    if (out.wantsPatch && !in.selection.empty()) {
        out.assembled += "\n[PATCH_SITE]\n```\n";
        if (in.selection.size() > 2000)
            out.assembled += in.selection.substr(0, 2000) + "\n…\n";
        else
            out.assembled += in.selection + "\n";
        out.assembled += "```\n";
        out.includedSelection = true;
    }

    const std::size_t budget = in.byteBudget == 0 ? 12288 : in.byteBudget;
    if (out.assembled.size() > budget) {
        out.assembled.resize(budget > 16 ? budget - 16 : budget);
        out.assembled += "\n…[truncated]\n";
    }
    return out;
}

} // namespace RKC
} // namespace RawrXD
