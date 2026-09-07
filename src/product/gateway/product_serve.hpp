#pragma once
#include "../complete/completion_scheduler.hpp"
#include "../context/context_engine.hpp"
#include "../win32/chrome.hpp"
#include "product_protocol.hpp"
#include <string>
#include <vector>
namespace rawr::product {

struct ProductServer {
    ContextEngine ctx;
    CompletionScheduler sch;
    InferFn infer = nullptr;
    EventBus bus;
    std::string lastCand;
    TaskStatus status{"idle", "idle", 0};

    ProductServer() {
        sch.db.delayMs = 0;
        sch.bus = &bus;
        ctx.budget.maxTokens = 2048;
    }

    std::string complete(const std::string& prompt, const EditorSnap& snap) {
        status = TaskStatus{"complete", "infer", 40};
        auto extra = std::vector<CtxItem>{};
        auto assembled = ctx.assemble(snap, CtxStrategy::Completion, extra, prompt);
        ExecutionRequest req{};
        req.prompt = assembled.prompt;
        sch.submit(req);
        auto xr = sch.run(infer);
        Candidate best = RankOne(xr.ok ? xr.text : "", 1);
        lastCand = best.text;
        status = TaskStatus{"complete", xr.ok ? "done" : "fail", xr.ok ? 100u : 0};
        bus.push(EvKind::Infer, sch.liveGen, "candidate", lastCand.c_str());
        if (!xr.ok) return std::string("ERR ") + xr.err;
        return std::string("CANDIDATE ") + lastCand;
    }

    std::string dispatch(const std::string& line, const EditorSnap* snap) {
        ProductCmd c = ParseProductCmd(line);
        if (c.verb == "PING" || c.verb == "CAPS" || c.verb == "STATUS" ||
            c.verb == "INDEX") {
            if (c.verb == "STATUS")
                return std::string(status.name) + ":" + StatusLine(status);
            return HandleProductCmd(c);
        }
        if (c.verb == "COMPLETE") {
            EditorSnap e;
            if (snap) e = *snap;
            e.prefix = c.arg.empty() ? e.prefix : c.arg;
            return complete(c.arg, e);
        }
        return "ERR unknown";
    }
};

} // namespace rawr::product
