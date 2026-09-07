#pragma once
#include "../context/context_engine.hpp"
#include "../repo/repo_scanner.hpp"
#include "../tools/tool_runtime.hpp"
#include "confidence.hpp"
#include "reflector.hpp"
#include "retry_policy.hpp"
#include <string>
namespace rawr::product {

struct LoopWit {
    int planned = 0;
    int scanned = 0;
    int contexted = 0;
    int patched = 0;
    int built = 0;
    int tested = 0;
    int retried = 0;
    int rolled = 0;
    int confident = 0;
};

struct CodingLoop {
    ContextEngine ctx;
    ToolRuntime tools;
    RetryPolicy retry;
    LoopWit wit{};

    bool run(const std::string& ws, const std::string& file,
             const std::string& want) {
        wit = {};
        wit.planned = 1;
        tools.box.workspace = ws;
        tools.box.perm.allow(Perm::Read);
        tools.box.perm.allow(Perm::Write);
        tools.box.perm.allow(Perm::Exec);
        RepoIndex idx;
        ScanRepo(ws, idx, 80);
        wit.scanned = idx.files.empty() ? 0 : 1;
        EditorSnap e{};
        e.path = file;
        e.prefix = want;
        e.language = "cpp";
        auto packed = ctx.assemble(e, CtxStrategy::Agent, {}, "fix");
        wit.contexted = packed.prompt.empty() ? 0 : 1;
        std::string orig;
        tools.readFile(file, orig);
        std::string next = orig.empty() ? want : (orig + want);
        if (!tools.writeFile(file, next)) return false;
        wit.patched = 1;
        std::string out;
        int rc = tools.execEcho("RAWR_PRODUCT_BUILD_OK", out);
        wit.built = (rc == 0 && out.find("RAWR_PRODUCT_BUILD_OK") != std::string::npos) ? 1 : 0;
        rc = tools.execEcho("RAWR_PRODUCT_TEST_OK", out);
        wit.tested = (rc == 0 && out.find("RAWR_PRODUCT_TEST_OK") != std::string::npos) ? 1 : 0;
        auto ref = ReflectOn(out, wit.built, wit.tested);
        if (ref.rollback && retry.again(ref.fail)) {
            wit.retried = 1;
            wit.rolled = tools.writeFile(file, orig) ? 1 : 0;
        }
        Confidence c{wit.scanned && wit.contexted, wit.tested, wit.built};
        wit.confident = c.shippable() ? 1 : 0;
        return wit.patched && wit.built && wit.tested && wit.confident;
    }
};

} // namespace rawr::product
