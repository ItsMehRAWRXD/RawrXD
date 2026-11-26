// OllamaExecutor.hpp — RAWRXD_BLACKBOARD_REAL_EXECUTION_001
//
// Native WinHTTP Ollama executor compatible with blackboard_v5::ExecutorFn.
// Performs REAL /api/tags, /api/show and /api/generate requests and parses the
// authoritative token counts and durations. No fabricated measurements: on any
// failure it returns false and the blackboard accounts the failed attempt.
//
// Resource ownership: every WinHTTP handle is closed on every path (RAII).
// Timeouts: resolve/connect/send/receive are bounded via WinHttpSetTimeouts.
// Cancellation: RequestCancel() sets a process-global flag checked before each
// request and between response chunks; a blocking receive is bounded by the
// receive timeout, so cancellation cannot hang indefinitely.
#pragma once
#include "AdaptiveBlackboardIntelligenceV5.hpp"
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <atomic>
#include <cstdlib>
#include <thread>

namespace rawrxd {
namespace ollama {

static std::atomic<bool> g_cancel{false};
inline void RequestCancel() { g_cancel.store(true); }
inline void ClearCancel()   { g_cancel.store(false); }

// RAII wrapper for a WinHTTP handle so cleanup is exception/early-return safe.
namespace detail {
struct Handle {
    HINTERNET h = nullptr;
    ~Handle() { if (h) WinHttpCloseHandle(h); }
    Handle() = default;
    explicit Handle(HINTERNET v) : h(v) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    bool ok() const { return h != nullptr; }
    HINTERNET get() const { return h; }
};
} // namespace detail

// Perform a request with bounded timeouts. Returns body in `out`; sets ok.
inline std::string HttpDo(const wchar_t* method, const std::wstring& host, int port,
                          const std::wstring& path, const std::string& body, bool& ok) {
    ok = false;
    std::string out;
    if (g_cancel.load()) return out;

    detail::Handle hs(WinHttpOpen(L"Deep2Blackboard/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!hs.ok()) return out;
    detail::Handle hc(WinHttpConnect(hs.get(), host.c_str(), (INTERNET_PORT)port, 0));
    if (!hc.ok()) return out;

    DWORD flags = 0;   // plain HTTP for localhost
    detail::Handle hr(WinHttpOpenRequest(hc.get(), method, path.c_str(), nullptr,
                                         WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags));
    if (!hr.ok()) return out;

    // Bounded timeouts (ms): resolve, connect, send, receive.
    WinHttpSetTimeouts(hr.get(), 5000, 5000, 30000, 120000);

    const std::wstring hdr = L"Content-Type: application/json\r\n";
    BOOL sent;
    if (body.empty())
        sent = WinHttpSendRequest(hr.get(), hdr.c_str(), (DWORD)hdr.size(), nullptr, 0, 0, 0);
    else
        sent = WinHttpSendRequest(hr.get(), hdr.c_str(), (DWORD)hdr.size(),
                                  (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0);
    if (sent) sent = WinHttpReceiveResponse(hr.get(), nullptr);
    if (sent) {
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(hr.get(), &avail) && avail > 0) {
            if (g_cancel.load()) return out;           // cancellation between chunks
            std::string chunk(avail, '\0');
            DWORD read = 0;
            if (!WinHttpReadData(hr.get(), &chunk[0], avail, &read)) break;
            chunk.resize(read);
            out += chunk;
        }
        ok = true;
    }
    return out;
}

inline std::string HttpPost(const std::wstring& host, int port, const std::wstring& path,
                            const std::string& body, bool& ok) {
    return HttpDo(L"POST", host, port, path, body, ok);
}
inline std::string HttpGet(const std::wstring& host, int port, const std::wstring& path, bool& ok) {
    return HttpDo(L"GET", host, port, path, std::string(), ok);
}

// ---- minimal, robust JSON field extraction (no external deps) ---------------
inline long long JsonInt(const std::string& j, const std::string& needle) {
    const size_t p = j.find(needle);
    if (p == std::string::npos) return -1;
    return std::atoll(j.c_str() + p + needle.size());
}
// Find the first string value for a key like "\"name\":".
inline std::string JsonStr(const std::string& j, const std::string& key, size_t from = 0) {
    const std::string pat = key + ":\"";
    size_t p = j.find(pat, from);
    if (p == std::string::npos) return std::string();
    p += pat.size();
    size_t e = j.find('"', p);
    if (e == std::string::npos) return std::string();
    return j.substr(p, e - p);
}

// ---- model / hardware discovery ---------------------------------------------
struct ModelInfo { std::string name; };

inline std::vector<ModelInfo> ListModels() {
    std::vector<ModelInfo> out;
    bool ok = false;
    const std::string j = HttpGet(L"127.0.0.1", 11434, L"/api/tags", ok);
    if (!ok) return out;
    size_t from = 0;
    while (true) {
        const std::string nm = JsonStr(j, "\"name\"", from);
        if (nm.empty()) break;
        out.push_back(ModelInfo{nm});
        from = j.find("\"name\":", from) + 7;
        if (from == std::string::npos) break;
    }
    return out;
}

struct ShowInfo {
    std::string family, parameterSize, quantization;
    long long contextLength = 0;
    bool ok = false;
};

inline ShowInfo ShowModel(const std::string& model) {
    ShowInfo si;
    const std::string body = "{\"model\":\"" + model + "\"}";
    bool ok = false;
    const std::string j = HttpPost(L"127.0.0.1", 11434, L"/api/show", body, ok);
    if (!ok) return si;
    si.family = JsonStr(j, "\"family\"");
    si.parameterSize = JsonStr(j, "\"parameter_size\"");
    si.quantization = JsonStr(j, "\"quantization_level\"");
    si.contextLength = JsonInt(j, "context_length\":");   // matches "...context_length":
    si.ok = true;
    return si;
}

struct Hardware : public blackboard_v5::Bounds {
    int logicalCores = 1;
};

inline Hardware DiscoverHardware(const std::string& model) {
    Hardware hw;
    hw.logicalCores = (int)std::thread::hardware_concurrency();
    if (hw.logicalCores < 1) hw.logicalCores = 1;
    hw.maxThreads = std::min(32, hw.logicalCores);     // hardware-compatible thread bound
    hw.maxBatch = 512;                                 // batch upper bound (admission limit)
    hw.maxCtx = 4096;                                  // reference workload context
    const ShowInfo si = ShowModel(model);
    if (si.contextLength > 0) hw.maxCtx = (int)std::min<long long>(si.contextLength, 32768);
    return hw;
}

// ---- global execution configuration ----------------------------------------
inline std::string& ModelName() { static std::string m = "llama3.2:3b"; return m; }
inline void SetModel(const std::string& m) { ModelName() = m; }

inline bool OllamaExec(const blackboard_v5::Controls& c, blackboard_v5::Measured& m);

// Reference workload: a fixed prompt + token budget establishing the baseline and
// warming the model so measured TPS reflects steady-state, not model load.
inline bool ReferenceWorkload(blackboard_v5::Measured& m) {
    blackboard_v5::Controls c; c.batch = 32; c.threads = 8;
    return OllamaExec(c, m);
}

// blackboard_v5::ExecutorFn-compatible real Ollama inference.
inline bool OllamaExec(const blackboard_v5::Controls& c, blackboard_v5::Measured& m) {
    if (g_cancel.load()) return false;
    const std::string body =
        "{\"model\":\"" + ModelName() + "\","
        "\"prompt\":\"Explain how computer memory works in 200 words.\","
        "\"stream\":false,\"keep_alive\":\"10m\",\"options\":{\"num_batch\":" +
        std::to_string(c.batch) + ",\"num_ctx\":4096,\"num_thread\":" +
        std::to_string(c.threads) +
        ",\"num_predict\":256,\"temperature\":0,\"seed\":42}}";
    bool ok = false;
    const std::string resp = HttpPost(L"127.0.0.1", 11434, L"/api/generate", body, ok);
    if (!ok || resp.empty()) return false;
    const long long ec = JsonInt(resp, "\"eval_count\":");
    const long long ed = JsonInt(resp, "\"eval_duration\":");
    const long long pc = JsonInt(resp, "\"prompt_eval_count\":");
    const long long pd = JsonInt(resp, "\"prompt_eval_duration\":");
    if (ec <= 0 || ed <= 0) return false;                 // no valid measurement
    m.decodeTps  = (double)ec * 1e9 / (double)ed;
    m.prefillTps = (pd > 0) ? (double)pc * 1e9 / (double)pd : 0.0;
    m.tokens     = (int)ec;
    m.consistent = true; // single-shot consistency; V5 confirms via repeats
    m.valid      = true;
    return true;
}

} // namespace ollama
} // namespace rawrxd