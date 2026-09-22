#include "rawrxd_screenpilot_agent_v2.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cwctype>
#include <filesystem>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#pragma comment(lib, "Bcrypt.lib")

namespace fs = std::filesystem;

namespace {

constexpr std::size_t kDefaultMaxBody   = 8u * 1024u * 1024u;
constexpr std::size_t kDefaultMaxPrompt = 4u * 1024u * 1024u;
constexpr std::uint32_t kDefaultApprovalTimeoutMs = 120000;

struct JobState {
    std::atomic_bool cancelled{false};
    std::mutex approval_mutex;
    std::condition_variable approval_cv;
    std::string approval_id;
    int approval_decision = -1; // -1 pending, 0 deny, 1 approve
};

struct State {
    std::uint16_t port = 0;
    fs::path workspace_root;
    bool allow_null_origin = false;
    std::size_t max_body_bytes = kDefaultMaxBody;
    std::size_t max_prompt_bytes = kDefaultMaxPrompt;
    std::uint32_t approval_timeout_ms = kDefaultApprovalTimeoutMs;

    RawrXD_SP_AuthorityV2 authority{};
    std::string session;
    std::atomic_bool initialized{false};

    std::mutex jobs_mutex;
    std::map<std::string, std::shared_ptr<JobState>> jobs;
};

State g;

std::string str(RawrXD_SP_StringV2 s) {
    return (s.data && s.size) ? std::string(s.data, s.size) : std::string{};
}

RawrXD_SP_StringV2 span(const std::string& s) {
    return RawrXD_SP_StringV2{s.data(), s.size()};
}

std::string lower_ascii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim(std::string s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    return s;
}

std::wstring widen(std::string_view s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    if (MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n) <= 0) {
        return {};
    }
    return out;
}

std::string narrow(std::wstring_view s) {
    if (s.empty()) return {};
    const int n = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<std::size_t>(n), '\0');
    if (WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr) <= 0) {
        return {};
    }
    return out;
}

std::wstring lower_w(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

bool path_is_under(const fs::path& root, const fs::path& child) {
    const fs::path r = root.lexically_normal();
    const fs::path c = child.lexically_normal();

    auto ri = r.begin();
    auto ci = c.begin();
    for (; ri != r.end(); ++ri, ++ci) {
        if (ci == c.end()) return false;
        if (lower_w(ri->wstring()) != lower_w(ci->wstring())) return false;
    }
    return true;
}

std::optional<fs::path> validate_workspace(std::string_view utf8) {
    try {
        const auto w = widen(utf8);
        if (w.empty()) return std::nullopt;
        const fs::path requested = fs::weakly_canonical(fs::path(w));
        const fs::path root = fs::weakly_canonical(g.workspace_root);

        if (!fs::exists(requested) || !fs::is_directory(requested)) return std::nullopt;
        if (!path_is_under(root, requested)) return std::nullopt;
        return requested;
    } catch (...) {
        return std::nullopt;
    }
}

std::string random_token(std::size_t bytes = 32) {
    std::vector<unsigned char> b(bytes);
    if (BCryptGenRandom(
            nullptr, b.data(), static_cast<ULONG>(b.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return {};
    }

    static constexpr char h[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes * 2);
    for (unsigned char v : b) {
        out.push_back(h[v >> 4]);
        out.push_back(h[v & 0x0f]);
    }
    return out;
}

bool constant_time_equal(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

bool exact_local_host(std::string host) {
    host = lower_ascii(trim(std::move(host)));
    const std::string p = std::to_string(g.port);
    return host == "127.0.0.1:" + p ||
           host == "localhost:" + p ||
           host == "[::1]:" + p;
}

bool allowed_origin(std::string origin) {
    origin = lower_ascii(trim(std::move(origin)));
    if (origin.empty()) return true; // non-browser local harness
    if (origin == "null") return g.allow_null_origin;

    const std::string p = std::to_string(g.port);
    return origin == "http://127.0.0.1:" + p ||
           origin == "http://localhost:" + p ||
           origin == "http://[::1]:" + p;
}

std::string json_escape(std::string_view s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b";  break;
            case '\f': o << "\\f";  break;
            case '\n': o << "\\n";  break;
            case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:
                if (c < 0x20) {
                    o << "\\u" << std::hex << std::setw(4)
                      << std::setfill('0') << static_cast<int>(c);
                } else {
                    o << static_cast<char>(c);
                }
        }
    }
    return o.str();
}

std::optional<std::string> json_string(std::string_view json, std::string_view key) {
    const std::string needle = "\"" + std::string(key) + "\"";
    std::size_t p = json.find(needle);
    if (p == std::string_view::npos) return std::nullopt;
    p = json.find(':', p + needle.size());
    if (p == std::string_view::npos) return std::nullopt;
    ++p;

    while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) ++p;
    if (p >= json.size() || json[p] != '"') return std::nullopt;
    ++p;

    std::string out;
    while (p < json.size()) {
        const char c = json[p++];
        if (c == '"') return out;

        if (c != '\\') {
            out.push_back(c);
            continue;
        }

        if (p >= json.size()) return std::nullopt;
        const char e = json[p++];
        switch (e) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
                if (p + 4 > json.size()) return std::nullopt;
                unsigned value = 0;
                for (int i = 0; i < 4; ++i) {
                    const char h = json[p++];
                    value <<= 4;
                    if      (h >= '0' && h <= '9') value |= unsigned(h - '0');
                    else if (h >= 'a' && h <= 'f') value |= unsigned(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') value |= unsigned(h - 'A' + 10);
                    else return std::nullopt;
                }

                if (value <= 0x7f) {
                    out.push_back(static_cast<char>(value));
                } else {
                    const wchar_t wc = static_cast<wchar_t>(value);
                    out += narrow(std::wstring_view(&wc, 1));
                }
                break;
            }
            default:
                return std::nullopt;
        }
    }
    return std::nullopt;
}

bool valid_mode(std::string_view m) {
    return m == "ask" || m == "plan" || m == "build" || m == "agent";
}

bool valid_id(std::string_view s) {
    if (s.empty() || s.size() > 128) return false;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.') continue;
        return false;
    }
    return true;
}

bool valid_model(std::string_view s) {
    if (s.empty() || s.size() > 512) return false;
    for (unsigned char c : s) {
        if (std::isalnum(c)) continue;
        switch (c) {
            case '.': case '_': case '-': case ':':
            case '/': case '\\': case '@': case '+':
                continue;
            default:
                return false;
        }
    }
    return true;
}

int add_header(const RawrXD_SP_HttpSinkV2* sink, const char* k, const char* v) {
    return sink->header ? sink->header(sink->user, k, v) : 1;
}

int begin_response(
    const RawrXD_SP_HttpSinkV2* sink,
    int code,
    const char* content_type,
    int chunked)
{
    if (!sink || !sink->begin || !sink->write || !sink->end) return 0;
    add_header(sink, "Cache-Control", "no-store");
    add_header(sink, "X-Content-Type-Options", "nosniff");
    add_header(sink, "Referrer-Policy", "no-referrer");
    add_header(sink, "Cross-Origin-Resource-Policy", "same-origin");
    return sink->begin(sink->user, code, content_type, chunked);
}

int sink_write(const RawrXD_SP_HttpSinkV2* sink, std::string_view text) {
    return sink->write(sink->user, text.data(), text.size());
}

int json_reply(const RawrXD_SP_HttpSinkV2* sink, int code, std::string_view body) {
    if (!begin_response(sink, code, "application/json; charset=utf-8", 0)) return 0;
    const int ok = sink_write(sink, body);
    sink->end(sink->user);
    return ok;
}

struct EmitContext {
    const RawrXD_SP_HttpSinkV2* sink = nullptr;
    std::shared_ptr<JobState> job;
    std::string request_id;
};

int emit_ndjson(void* user, const char* type, const char* data, std::size_t size) {
    auto* ctx = static_cast<EmitContext*>(user);
    if (!ctx || !ctx->sink || !ctx->job) return 0;
    if (ctx->job->cancelled.load(std::memory_order_acquire)) return 0;

    const std::string_view d(data ? data : "", data ? size : 0);
    const std::string line =
        "{\"type\":\"" + json_escape(type ? type : "output") +
        "\",\"requestId\":\"" + json_escape(ctx->request_id) +
        "\",\"data\":\"" + json_escape(d) + "\"}\n";

    if (!sink_write(ctx->sink, line)) {
        ctx->job->cancelled.store(true, std::memory_order_release);
        ctx->job->approval_cv.notify_all();
        return 0;
    }
    return 1;
}

int is_cancelled(void* user) {
    auto* job = static_cast<JobState*>(user);
    return job && job->cancelled.load(std::memory_order_acquire) ? 1 : 0;
}

std::string make_approval_id() {
    return random_token(16);
}

int request_approval(
    void* user,
    const char* tool_name,
    const char* summary,
    const char* risk,
    std::uint64_t permission_bit)
{
    auto* ctx = static_cast<EmitContext*>(user);
    if (!ctx || !ctx->job || !ctx->sink) return 0;

    auto& job = *ctx->job;
    if (job.cancelled.load(std::memory_order_acquire)) return 0;

    const std::string approval_id = make_approval_id();
    if (approval_id.empty()) return 0;

    {
        std::lock_guard<std::mutex> lock(job.approval_mutex);
        job.approval_id = approval_id;
        job.approval_decision = -1;
    }

    std::ostringstream payload;
    payload << "{"
            << "\"approvalId\":\"" << json_escape(approval_id) << "\","
            << "\"tool\":\"" << json_escape(tool_name ? tool_name : "unknown") << "\","
            << "\"summary\":\"" << json_escape(summary ? summary : "") << "\","
            << "\"risk\":\"" << json_escape(risk ? risk : "elevated") << "\","
            << "\"permissionBit\":" << permission_bit
            << "}";

    const std::string p = payload.str();
    if (!emit_ndjson(ctx, "approval_required", p.data(), p.size())) {
        return 0;
    }

    std::unique_lock<std::mutex> lock(job.approval_mutex);
    const bool signaled = job.approval_cv.wait_for(
        lock,
        std::chrono::milliseconds(g.approval_timeout_ms),
        [&] {
            return job.approval_decision != -1 ||
                   job.cancelled.load(std::memory_order_acquire);
        });

    if (!signaled || job.cancelled.load(std::memory_order_acquire)) {
        job.approval_id.clear();
        job.approval_decision = 0;
        return 0;
    }

    const int decision = job.approval_decision;
    job.approval_id.clear();
    job.approval_decision = -1;
    return decision == 1 ? 1 : 0;
}

std::uint64_t mode_permissions(std::string_view mode) {
    const std::uint64_t readonly =
        RAWRXD_SP_PERM_READ |
        RAWRXD_SP_PERM_SEARCH |
        RAWRXD_SP_PERM_GIT_READ;

    if (mode == "ask" || mode == "plan") {
        return readonly;
    }

    const std::uint64_t build =
        readonly |
        RAWRXD_SP_PERM_WORKSPACE_WRITE |
        RAWRXD_SP_PERM_BUILD |
        RAWRXD_SP_PERM_TEST;

    if (mode == "build") {
        return build;
    }

    if (mode == "agent") {
        return build |
               RAWRXD_SP_PERM_PROCESS_GENERAL |
               RAWRXD_SP_PERM_GIT_WRITE |
               RAWRXD_SP_PERM_GIT_REMOTE |
               RAWRXD_SP_PERM_NETWORK |
               RAWRXD_SP_PERM_MODEL_CONTROL |
               RAWRXD_SP_PERM_HOST_DESTRUCTIVE;
    }

    return 0;
}

std::uint64_t mode_approval_mask(std::string_view mode) {
    if (mode != "agent") return 0;
    return
        RAWRXD_SP_PERM_GIT_REMOTE |
        RAWRXD_SP_PERM_NETWORK |
        RAWRXD_SP_PERM_HOST_DESTRUCTIVE;
}

bool authorized_browser_request(const RawrXD_SP_HttpRequestV2* request) {
    return request &&
           exact_local_host(str(request->host)) &&
           allowed_origin(str(request->origin));
}

} // namespace

extern "C" {

std::uint64_t RawrXD_ScreenPilot_ModePermissionsV2(RawrXD_SP_StringV2 mode) {
    return mode_permissions(lower_ascii(str(mode)));
}

std::uint64_t RawrXD_ScreenPilot_ModeApprovalMaskV2(RawrXD_SP_StringV2 mode) {
    return mode_approval_mask(lower_ascii(str(mode)));
}

int RawrXD_ScreenPilot_InitializeV2(
    const RawrXD_SP_ConfigV2* config,
    const RawrXD_SP_AuthorityV2* authority)
{
    if (!config || !authority) return 0;
    if (config->abi_version != RAWRXD_SCREENPILOT_ABI_V2) return 0;
    if (authority->abi_version != RAWRXD_SCREENPILOT_ABI_V2) return 0;
    if (!authority->run_agent || !config->port) return 0;

    const std::string root_utf8 = str(config->workspace_root);
    if (root_utf8.empty()) return 0;

    try {
        const std::wstring root_w = widen(root_utf8);
        if (root_w.empty()) return 0;
        g.workspace_root = fs::weakly_canonical(fs::path(root_w));
        if (!fs::exists(g.workspace_root) || !fs::is_directory(g.workspace_root)) return 0;
    } catch (...) {
        return 0;
    }

    g.port = config->port;
    g.allow_null_origin = config->allow_null_origin != 0;
    g.max_body_bytes = config->max_body_bytes ? config->max_body_bytes : kDefaultMaxBody;
    g.max_prompt_bytes = config->max_prompt_bytes ? config->max_prompt_bytes : kDefaultMaxPrompt;
    g.approval_timeout_ms =
        config->approval_timeout_ms ? config->approval_timeout_ms : kDefaultApprovalTimeoutMs;

    if (g.max_prompt_bytes > g.max_body_bytes) return 0;
    if (g.max_body_bytes > 64u * 1024u * 1024u) return 0;
    if (g.approval_timeout_ms < 1000 || g.approval_timeout_ms > 30u * 60u * 1000u) return 0;

    g.authority = *authority;
    g.session = random_token();
    if (g.session.empty()) return 0;

    g.initialized.store(true, std::memory_order_release);
    return 1;
}

void RawrXD_ScreenPilot_ShutdownV2() {
    g.initialized.store(false, std::memory_order_release);

    std::vector<std::shared_ptr<JobState>> jobs;
    {
        std::lock_guard<std::mutex> lock(g.jobs_mutex);
        for (auto& [_, job] : g.jobs) jobs.push_back(job);
    }

    for (auto& job : jobs) {
        if (!job) continue;
        job->cancelled.store(true, std::memory_order_release);
        job->approval_cv.notify_all();
    }

    {
        std::lock_guard<std::mutex> lock(g.jobs_mutex);
        g.jobs.clear();
    }

    g.session.clear();
}

int RawrXD_ScreenPilot_ValidateBrowserSessionV2(
    RawrXD_SP_StringV2 host,
    RawrXD_SP_StringV2 origin,
    RawrXD_SP_StringV2 session_token)
{
    if (!g.initialized.load(std::memory_order_acquire)) return 0;
    if (!exact_local_host(str(host))) return 0;
    if (!allowed_origin(str(origin))) return 0;
    return constant_time_equal(str(session_token), g.session) ? 1 : 0;
}

int RawrXD_ScreenPilot_HandleHttpV2(
    const RawrXD_SP_HttpRequestV2* request,
    const RawrXD_SP_HttpSinkV2* sink)
{
    if (!g.initialized.load(std::memory_order_acquire) || !request || !sink) return 0;

    const std::string method = lower_ascii(str(request->method));
    const std::string path = str(request->path);

    const bool ours =
        path == "/api/v1/screenpilot/health" ||
        path == "/api/v1/screenpilot/session" ||
        path == "/api/v1/screenpilot/capabilities" ||
        path == "/api/v1/screenpilot/agent/run" ||
        path == "/api/v1/screenpilot/agent/cancel" ||
        path == "/api/v1/screenpilot/agent/approve";

    if (!ours) return 0;

    if (!authorized_browser_request(request)) {
        json_reply(sink, 403, R"({"ok":false,"error":"host/origin rejected"})");
        return 1;
    }

    const std::string body = str(request->body);
    if (body.size() > g.max_body_bytes) {
        json_reply(sink, 413, R"({"ok":false,"error":"request body too large"})");
        return 1;
    }

    if (method == "get" && path == "/api/v1/screenpilot/health") {
        const std::string payload =
            "{\"ok\":true,"
            "\"service\":\"RawrXD ScreenPilot\","
            "\"transport\":\"in-process\","
            "\"authority\":\"canonical\","
            "\"abi\":2,"
            "\"workspaceRoot\":\"" + json_escape(narrow(g.workspace_root.wstring())) + "\"}";
        json_reply(sink, 200, payload);
        return 1;
    }

    if (method == "post" && path == "/api/v1/screenpilot/session") {
        const std::string payload =
            "{\"ok\":true,\"token\":\"" + json_escape(g.session) + "\"}";
        json_reply(sink, 200, payload);
        return 1;
    }

    if (!constant_time_equal(str(request->session_token), g.session)) {
        json_reply(sink, 401, R"({"ok":false,"error":"invalid session"})");
        return 1;
    }

    if (method == "get" && path == "/api/v1/screenpilot/capabilities") {
        std::ostringstream o;
        o << "{"
          << "\"ok\":true,"
          << "\"modes\":[\"ask\",\"plan\",\"build\",\"agent\"],"
          << "\"streaming\":true,"
          << "\"cancel\":true,"
          << "\"approval\":true,"
          << "\"workspaceOnly\":true,"
          << "\"toolAuthority\":true,"
          << "\"transport\":\"in-process\","
          << "\"abi\":2"
          << "}";
        json_reply(sink, 200, o.str());
        return 1;
    }

    if (method == "post" && path == "/api/v1/screenpilot/agent/cancel") {
        auto id = json_string(body, "requestId");
        if (!id || !valid_id(*id)) {
            json_reply(sink, 400, R"({"ok":false,"error":"valid requestId required"})");
            return 1;
        }

        bool found = false;
        {
            std::lock_guard<std::mutex> lock(g.jobs_mutex);
            auto it = g.jobs.find(*id);
            if (it != g.jobs.end() && it->second) {
                found = true;
                it->second->cancelled.store(true, std::memory_order_release);
                it->second->approval_cv.notify_all();
            }
        }

        json_reply(
            sink, 200,
            found ? R"({"ok":true,"cancelled":true})"
                  : R"({"ok":true,"cancelled":false})");
        return 1;
    }

    if (method == "post" && path == "/api/v1/screenpilot/agent/approve") {
        auto id = json_string(body, "requestId");
        auto approval_id = json_string(body, "approvalId");
        auto decision = json_string(body, "decision");

        if (!id || !valid_id(*id) ||
            !approval_id || approval_id->empty() || approval_id->size() > 128 ||
            !decision || (*decision != "approve" && *decision != "deny")) {
            json_reply(sink, 400, R"({"ok":false,"error":"invalid approval response"})");
            return 1;
        }

        std::shared_ptr<JobState> job;
        {
            std::lock_guard<std::mutex> lock(g.jobs_mutex);
            auto it = g.jobs.find(*id);
            if (it != g.jobs.end()) job = it->second;
        }

        if (!job) {
            json_reply(sink, 404, R"({"ok":false,"error":"job not found"})");
            return 1;
        }

        {
            std::lock_guard<std::mutex> lock(job->approval_mutex);
            if (job->approval_id.empty() || job->approval_id != *approval_id) {
                json_reply(sink, 409, R"({"ok":false,"error":"approval id mismatch or expired"})");
                return 1;
            }
            job->approval_decision = (*decision == "approve") ? 1 : 0;
        }
        job->approval_cv.notify_all();

        json_reply(
            sink, 200,
            *decision == "approve"
                ? R"({"ok":true,"approved":true})"
                : R"({"ok":true,"approved":false})");
        return 1;
    }

    if (method == "post" && path == "/api/v1/screenpilot/agent/run") {
        auto id = json_string(body, "requestId");
        auto mode = json_string(body, "mode");
        auto model = json_string(body, "model");
        auto workspace = json_string(body, "workspace");
        auto prompt = json_string(body, "prompt");

        if (!id || !mode || !model || !workspace || !prompt) {
            json_reply(
                sink, 400,
                R"({"ok":false,"error":"requestId, mode, model, workspace, prompt required"})");
            return 1;
        }

        *mode = lower_ascii(*mode);
        if (!valid_id(*id) || !valid_mode(*mode) || !valid_model(*model) || prompt->empty()) {
            json_reply(sink, 400, R"({"ok":false,"error":"invalid request fields"})");
            return 1;
        }

        if (prompt->size() > g.max_prompt_bytes) {
            json_reply(sink, 413, R"({"ok":false,"error":"prompt too large"})");
            return 1;
        }

        auto canonical = validate_workspace(*workspace);
        if (!canonical) {
            json_reply(
                sink, 403,
                R"({"ok":false,"error":"workspace outside configured root or missing"})");
            return 1;
        }

        const std::uint64_t permissions = mode_permissions(*mode);
        const std::uint64_t approval_mask = mode_approval_mask(*mode);

        auto job = std::make_shared<JobState>();
        {
            std::lock_guard<std::mutex> lock(g.jobs_mutex);
            if (g.jobs.contains(*id)) {
                json_reply(sink, 409, R"({"ok":false,"error":"duplicate requestId"})");
                return 1;
            }
            g.jobs.emplace(*id, job);
        }

        if (!begin_response(sink, 200, "application/x-ndjson; charset=utf-8", 1)) {
            std::lock_guard<std::mutex> lock(g.jobs_mutex);
            g.jobs.erase(*id);
            return 1;
        }

        EmitContext emit_ctx{sink, job, *id};
        const std::string canonical_utf8 = narrow(canonical->wstring());

        std::ostringstream started;
        started << "{"
                << "\"mode\":\"" << json_escape(*mode) << "\","
                << "\"permissionMask\":" << permissions << ","
                << "\"approvalMask\":" << approval_mask << ","
                << "\"workspaceOnly\":true"
                << "}";
        const std::string started_payload = started.str();
        emit_ndjson(
            &emit_ctx, "started",
            started_payload.data(), started_payload.size());

        const RawrXD_SP_AgentRequestV2 agent_request{
            span(*id),
            span(*mode),
            span(*model),
            span(canonical_utf8),
            span(*prompt),
            permissions,
            approval_mask,
            1
        };

        int rc = -1;
        try {
            rc = g.authority.run_agent(
                g.authority.user,
                &agent_request,
                emit_ndjson,
                &emit_ctx,
                is_cancelled,
                job.get(),
                request_approval,
                &emit_ctx);
        } catch (const std::exception& e) {
            const std::string message = std::string("authority exception: ") + e.what();
            emit_ndjson(&emit_ctx, "error", message.data(), message.size());
            rc = -2;
        } catch (...) {
            const std::string message = "authority exception: unknown";
            emit_ndjson(&emit_ctx, "error", message.data(), message.size());
            rc = -3;
        }

        {
            std::lock_guard<std::mutex> lock(g.jobs_mutex);
            g.jobs.erase(*id);
        }

        if (!job->cancelled.load(std::memory_order_acquire)) {
            const std::string exit_code = std::to_string(rc);
            emit_ndjson(&emit_ctx, "exit", exit_code.data(), exit_code.size());
        }

        sink->end(sink->user);
        return 1;
    }

    json_reply(sink, 405, R"({"ok":false,"error":"method not allowed"})");
    return 1;
}

} // extern "C"
