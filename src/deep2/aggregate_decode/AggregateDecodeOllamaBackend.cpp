#include "AggregateDecodeOllamaBackend.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <chrono>
#include <sstream>
#include <string>
#include <vector>
#pragma comment(lib, "winhttp.lib")

namespace rawr::aggdec {
namespace {

uint64_t now_ns() {
    using clock = std::chrono::steady_clock;
    return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
               clock::now().time_since_epoch())
        .count();
}

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '"' || c == '\\') { o.push_back('\\'); o.push_back(c); }
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else o.push_back(c);
    }
    return o;
}

// Count eval tokens from Ollama stream NDJSON; fall back to response chunks.
bool parse_eval_count(const std::string& line, uint64_t* eval_out, bool* done) {
    auto pos = line.find("\"eval_count\"");
    if (pos != std::string::npos) {
        auto colon = line.find(':', pos);
        if (colon != std::string::npos) {
            *eval_out = (uint64_t)std::strtoull(line.c_str() + colon + 1, nullptr, 10);
        }
    }
    if (line.find("\"done\":true") != std::string::npos ||
        line.find("\"done\": true") != std::string::npos)
        *done = true;
    return line.find("\"response\"") != std::string::npos;
}

} // namespace

AggregateDecodeOllamaBackend::AggregateDecodeOllamaBackend(std::string host,
                                                           std::string model)
    : host_(std::move(host)), model_(std::move(model)) {}

bool AggregateDecodeOllamaBackend::open() {
    open_ = !host_.empty() && !model_.empty();
    return open_;
}

void AggregateDecodeOllamaBackend::close() { open_ = false; }

SessionMetrics AggregateDecodeOllamaBackend::decode(const DecodeRequest& req,
                                                    TokenEmitFn on_token) {
    SessionMetrics m{};
    m.session_id = req.session_id;
    m.backend = BackendKind::OllamaHttp;
    if (!open_) return m;

    std::ostringstream body;
    body << "{\"model\":\"" << json_escape(model_) << "\","
         << "\"prompt\":\"" << json_escape(req.prompt) << "\","
         << "\"stream\":true,"
         << "\"options\":{\"num_predict\":" << req.max_tokens
         << ",\"temperature\":0}}";
    const std::string payload = body.str();

    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t hostBuf[256]{}, pathBuf[256]{};
    uc.lpszHostName = hostBuf;
    uc.dwHostNameLength = 255;
    uc.lpszUrlPath = pathBuf;
    uc.dwUrlPathLength = 255;
    std::wstring url = widen(host_ + "/api/generate");
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) return m;

    HINTERNET ses = WinHttpOpen(L"AggregateDecode/1.0",
                                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                WINHTTP_NO_PROXY_NAME,
                                WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) return m;
    HINTERNET con = WinHttpConnect(ses, hostBuf, uc.nPort, 0);
    if (!con) { WinHttpCloseHandle(ses); return m; }
    HINTERNET reqh = WinHttpOpenRequest(
        con, L"POST", pathBuf, nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, (uc.nScheme == INTERNET_SCHEME_HTTPS)
                                          ? WINHTTP_FLAG_SECURE
                                          : 0);
    if (!reqh) {
        WinHttpCloseHandle(con);
        WinHttpCloseHandle(ses);
        return m;
    }

    const wchar_t* hdrs = L"Content-Type: application/json\r\n";
    const uint64_t t0 = now_ns();
    BOOL ok = WinHttpSendRequest(reqh, hdrs, (DWORD)-1L,
                                 (LPVOID)payload.data(), (DWORD)payload.size(),
                                 (DWORD)payload.size(), 0);
    if (!ok || !WinHttpReceiveResponse(reqh, nullptr)) {
        WinHttpCloseHandle(reqh);
        WinHttpCloseHandle(con);
        WinHttpCloseHandle(ses);
        return m;
    }

    uint64_t eval_count = 0;
    uint64_t emit_n = 0;
    uint64_t first_ns = 0;
    std::string buf;
    char chunk[4096];
    for (;;) {
        DWORD avail = 0, read = 0;
        if (!WinHttpQueryDataAvailable(reqh, &avail) || avail == 0) break;
        if (avail > sizeof(chunk)) avail = sizeof(chunk);
        if (!WinHttpReadData(reqh, chunk, avail, &read) || read == 0) break;
        buf.append(chunk, chunk + read);
        size_t nl;
        while ((nl = buf.find('\n')) != std::string::npos) {
            std::string line = buf.substr(0, nl);
            buf.erase(0, nl + 1);
            bool done = false;
            if (parse_eval_count(line, &eval_count, &done)) {
                if (first_ns == 0) first_ns = now_ns() - t0;
                ++emit_n;
                if (on_token && !on_token((uint32_t)emit_n)) done = true;
            }
            if (done) break;
        }
    }

    const uint64_t t1 = now_ns();
    m.wall_ns = (t1 > t0) ? (t1 - t0) : 0;
    m.first_token_ns = first_ns;
    m.generated_tokens = (eval_count > 0) ? eval_count : emit_n;
    m.tps = (m.wall_ns > 0)
                ? (double)m.generated_tokens / ((double)m.wall_ns / 1e9)
                : 0.0;
    m.ok = m.generated_tokens > 0;
    WinHttpCloseHandle(reqh);
    WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    return m;
}

} // namespace rawr::aggdec
