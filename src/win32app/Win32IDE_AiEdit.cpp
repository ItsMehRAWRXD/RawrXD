// Win32IDE_AiEdit.cpp — live :11436/:11434 chat completions (no mock socket).
#include "Win32IDE_AiEdit.h"
#include "Win32IDE.h"
#include <richedit.h>
#include <cstdio>
#include <cstring>
#include <vector>

struct AiApplyPayload {
    long start;
    long end;
    std::string text;
};

#pragma comment(lib, "winhttp.lib")

void AiWinHttpCancelToken::Cancel() {
    m_cancelled.store(true);
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_hActiveRequest) {
        WinHttpCloseHandle(m_hActiveRequest);
        m_hActiveRequest = nullptr;
    }
}

void AiWinHttpCancelToken::RegisterRequest(HINTERNET hRequest) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_cancelled.load()) {
        if (hRequest) WinHttpCloseHandle(hRequest);
        return;
    }
    m_hActiveRequest = hRequest;
}

void AiWinHttpCancelToken::UnregisterRequest() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_hActiveRequest = nullptr;
}

std::string EscapeJsonString(const std::string& input) {
    std::string output;
    output.reserve(input.size() + 16);
    for (unsigned char c : input) {
        switch (c) {
            case '\"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    output += buf;
                } else {
                    output += static_cast<char>(c);
                }
        }
    }
    return output;
}

std::string BuildOpenAIChatPayload(const std::string& model, const std::string& userPrompt) {
    const std::string sys = EscapeJsonString("You are an expert C++ Win32 IDE assistant.");
    const std::string user = EscapeJsonString(userPrompt);
    const std::string m = EscapeJsonString(model);
    return std::string("{\"model\":\"") + m +
           "\",\"messages\":[{\"role\":\"system\",\"content\":\"" + sys +
           "\"},{\"role\":\"user\",\"content\":\"" + user +
           "\"}],\"temperature\":0.2,\"max_tokens\":2048,\"stream\":false}";
}

static std::string extractJsonStringField(const std::string& json, const char* key) {
    const std::string needle = std::string("\"") + key + "\"";
    size_t k = json.find(needle);
    if (k == std::string::npos) return {};
    k = json.find(':', k + needle.size());
    if (k == std::string::npos) return {};
    k = json.find('"', k + 1);
    if (k == std::string::npos) return {};
    ++k;
    std::string out;
    for (size_t i = k; i < json.size(); ++i) {
        char c = json[i];
        if (c == '\\' && i + 1 < json.size()) {
            char n = json[++i];
            if (n == 'n') out += '\n';
            else if (n == 't') out += '\t';
            else if (n == 'r') out += '\r';
            else if (n == '"' || n == '\\') out += n;
            else out += n;
            continue;
        }
        if (c == '"') break;
        out += c;
    }
    return out;
}

std::string ExtractOpenAIChatContent(const std::string& jsonResponse) {
    // Prefer choices[0].message.content (OpenAI) then message.content / response.
    size_t msg = jsonResponse.find("\"message\"");
    if (msg != std::string::npos) {
        std::string slice = jsonResponse.substr(msg);
        std::string c = extractJsonStringField(slice, "content");
        if (!c.empty() || slice.find("\"content\":\"\"") != std::string::npos)
            return c;
    }
    std::string c = extractJsonStringField(jsonResponse, "content");
    if (!c.empty()) return c;
    return extractJsonStringField(jsonResponse, "response");
}

std::string QueryOpenAIChatSync(const std::string& host, INTERNET_PORT port,
                                const std::string& model, const std::string& prompt,
                                AiWinHttpCancelToken* token) {
    if (token && token->IsCancelled()) return {};
    std::wstring whost(host.begin(), host.end());
    HINTERNET ses = WinHttpOpen(L"RawrXD-AIEdit/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) return {};
    WinHttpSetTimeouts(ses, 15000, 15000, 120000, 120000);
    HINTERNET con = WinHttpConnect(ses, whost.c_str(), port, 0);
    if (!con) { WinHttpCloseHandle(ses); return {}; }
    HINTERNET req = WinHttpOpenRequest(con, L"POST", L"/v1/chat/completions",
                                       nullptr, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!req) {
        WinHttpCloseHandle(con); WinHttpCloseHandle(ses); return {};
    }
    if (token) token->RegisterRequest(req);
    std::string body = BuildOpenAIChatPayload(model, prompt);
    WinHttpAddRequestHeaders(req,
        L"Content-Type: application/json\r\nX-Deep2-LivePath: 1\r\n",
        (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
    BOOL ok = WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 (LPVOID)body.data(), (DWORD)body.size(),
                                 (DWORD)body.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(req, nullptr);
    std::string resp;
    if (ok && !(token && token->IsCancelled())) {
        DWORD sz = 0;
        do {
            if (token && token->IsCancelled()) break;
            sz = 0;
            if (!WinHttpQueryDataAvailable(req, &sz) || !sz) break;
            std::vector<char> buf(sz);
            DWORD rd = 0;
            if (!WinHttpReadData(req, buf.data(), sz, &rd) || !rd) break;
            resp.append(buf.data(), rd);
        } while (sz > 0);
    }
    if (token) token->UnregisterRequest();
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    return ExtractOpenAIChatContent(resp);
}

AsyncAiTaskQueue::AsyncAiTaskQueue() {
    m_workerThread = std::thread(&AsyncAiTaskQueue::WorkerLoop, this);
}
AsyncAiTaskQueue::~AsyncAiTaskQueue() { Stop(); }

void AsyncAiTaskQueue::Enqueue(AiEditTask task) {
    { std::lock_guard<std::mutex> lock(m_mutex); m_taskQueue.push(std::move(task)); }
    m_cv.notify_one();
}

void AsyncAiTaskQueue::CancelAll() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_currentTaskToken) m_currentTaskToken->Cancel();
    std::queue<AiEditTask> empty;
    std::swap(m_taskQueue, empty);
}

void AsyncAiTaskQueue::Stop() {
    m_stop = true;
    CancelAll();
    m_cv.notify_all();
    if (m_workerThread.joinable()) m_workerThread.join();
}

void AsyncAiTaskQueue::WorkerLoop() {
    while (true) {
        AiEditTask task;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [&] { return !m_taskQueue.empty() || m_stop; });
            if (m_stop && m_taskQueue.empty()) return;
            task = std::move(m_taskQueue.front());
            m_taskQueue.pop();
            m_currentTaskToken = task.cancelToken;
        }
        ExecuteTask(task);
        { std::lock_guard<std::mutex> lock(m_mutex); m_currentTaskToken = nullptr; }
    }
}

void AsyncAiTaskQueue::ExecuteTask(AiEditTask& task) {
    if (task.cancelToken && task.cancelToken->IsCancelled()) {
        if (task.completionCallback) task.completionCallback(false, {});
        return;
    }
    // Live tip Deep2 first (:11436), then Ollama OpenAI-compat (:11434). No mocks.
    std::string model = "tinyllama-1.1b-chat-v1.0.Q4_K_M";
    char envModel[128] = {};
    if (GetEnvironmentVariableA("RAWRXD_MODEL", envModel, sizeof(envModel)) > 0)
        model = envModel;
    std::string result = QueryOpenAIChatSync("127.0.0.1", 11436, model, task.prompt,
                                             task.cancelToken.get());
    if (result.empty() && !(task.cancelToken && task.cancelToken->IsCancelled())) {
        model = "qwen3:8b";
        if (envModel[0]) model = envModel;
        result = QueryOpenAIChatSync("127.0.0.1", 11434, model, task.prompt,
                                     task.cancelToken.get());
    }
    const bool ok = !result.empty() &&
                    !(task.cancelToken && task.cancelToken->IsCancelled());
    if (task.completionCallback) task.completionCallback(ok, result);
}

static AsyncAiTaskQueue& AiEditQueue() {
    static AsyncAiTaskQueue q;
    return q;
}
static std::shared_ptr<AiWinHttpCancelToken> g_activeAiToken;

void Win32IDE::triggerAIEdit() {
    if (!m_hwndEditor) {
        if (m_hwndStatusBar)
            SendMessageW(m_hwndStatusBar, SB_SETTEXTW, 0, (LPARAM)L"AI Edit: no editor");
        return;
    }
    CHARRANGE sel{};
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&sel);
    const int len = GetWindowTextLengthA(m_hwndEditor);
    std::string all(static_cast<size_t>(len) + 1, '\0');
    GetWindowTextA(m_hwndEditor, all.data(), len + 1);
    all.resize(strlen(all.c_str()));
    long a = sel.cpMin, b = sel.cpMax;
    if (a < 0) a = 0;
    if (b < a) b = a;
    if (b > (long)all.size()) b = (long)all.size();
    std::string selected = (b > a) ? all.substr((size_t)a, (size_t)(b - a)) : all;
    if (selected.empty()) {
        if (m_hwndStatusBar)
            SendMessageW(m_hwndStatusBar, SB_SETTEXTW, 0, (LPARAM)L"AI Edit: empty buffer");
        return;
    }
    auto token = std::make_shared<AiWinHttpCancelToken>();
    g_activeAiToken = token;
    if (m_hwndStatusBar)
        SendMessageW(m_hwndStatusBar, SB_SETTEXTW, 0, (LPARAM)L"AI Edit: requesting…");
    HWND hwnd = m_hwndMain ? m_hwndMain : m_hwndEditor;
    long start = a, end = (b > a) ? b : (long)all.size();
    std::string prompt =
        "Repair or improve this C++ code. Return ONLY the replacement code.\n\n" + selected;
    AiEditTask task;
    task.taskId = "ai_edit";
    task.prompt = std::move(prompt);
    task.targetStart = start;
    task.targetEnd = end;
    task.cancelToken = token;
    task.completionCallback = [hwnd, start, end](bool ok, const std::string& text) {
        if (!ok || text.empty()) {
            PostMessageW(hwnd, WM_USER_AI_STREAM_CANCEL, 0, 0);
            return;
        }
        auto* payload = new AiApplyPayload{ start, end, text };
        PostMessageW(hwnd, WM_USER_AI_APPLY_EDIT, 0, (LPARAM)payload);
    };
    AiEditQueue().Enqueue(std::move(task));
}

void Win32IDE::applyAIEdit(long start, long end, const std::string& replacement) {
    if (!m_hwndEditor || replacement.empty()) return;
    CHARRANGE sel{ start, end };
    SendMessage(m_hwndEditor, EM_EXSETSEL, 0, (LPARAM)&sel);
    std::wstring w(replacement.begin(), replacement.end());
    SendMessageW(m_hwndEditor, EM_REPLACESEL, TRUE, (LPARAM)w.c_str());
    if (m_hwndStatusBar)
        SendMessageW(m_hwndStatusBar, SB_SETTEXTW, 0, (LPARAM)L"AI Edit: applied");
    g_activeAiToken.reset();
}

void Win32IDE::cancelAIEdit() {
    if (g_activeAiToken) {
        g_activeAiToken->Cancel();
        g_activeAiToken.reset();
    }
    AiEditQueue().CancelAll();
    if (m_hwndStatusBar)
        SendMessageW(m_hwndStatusBar, SB_SETTEXTW, 0, (LPARAM)L"AI Edit: cancelled");
}
