#pragma once
#include "../runtime/event_bus.hpp"
#include "../runtime/task_queue.hpp"
#include "../runtime/telemetry.hpp"
#include "completion_job.hpp"
#include "debounce.hpp"
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
namespace rawr::product {

using InferFn = bool (*)(const char* prompt, char* out, size_t cap);

struct CompletionScheduler {
    TaskQueue q;
    Debounce db;
    CancelToken cancel;
    EventBus* bus = nullptr;
    uint64_t liveGen = 1;
    uint32_t lastMs = 0;

    uint64_t submit(const ExecutionRequest& req) {
        db.arm();
        cancel.clear();
        liveGen = q.bumpGen();
        q.dropStale(liveGen);
        ExecutionRequest r = req;
        r.gen = liveGen;
        CompletionJob job{};
        job.id = q.enqueue(TaskPri::High, "complete", r.prompt.c_str());
        job.gen = liveGen;
        job.req = r;
        job.cancel = &cancel;
        if (bus) bus->push(EvKind::Infer, liveGen, "submit", r.prompt.c_str());
        return job.id;
    }

    ExecutionResult run(InferFn infer) {
        ExecutionResult x{};
        x.gen = liveGen;
        DWORD t0 = GetTickCount();
        if (!db.ready()) {
            x.err = "debounce";
            return x;
        }
        if (cancel.requested()) {
            x.cancelled = 1;
            x.err = "cancel";
            return x;
        }
        Task t{};
        if (!q.pop(t) || t.stale) {
            x.stale = 1;
            x.err = "stale";
            return x;
        }
        char buf[2048];
        buf[0] = 0;
        bool ok = infer ? infer(t.payload.c_str(), buf, sizeof(buf)) : false;
        x.ok = ok ? 1 : 0;
        x.text = buf;
        x.tokensOut = (uint32_t)(x.text.size() / 4);
        x.cancelled = cancel.requested() ? 1 : 0;
        x.latencyMs = GetTickCount() - t0;
        lastMs = x.latencyMs;
        TelemetryFromResult(x, "complete");
        return x;
    }
};

} // namespace rawr::product
