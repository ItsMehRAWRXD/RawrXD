#pragma once
// Win32IDE AI edit: live WinHTTP cancel + sequential queue (no mock Ollama).
#include <windows.h>
#include <winhttp.h>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <memory>

#ifndef WM_USER_AI_STREAM_CHUNK
#define WM_USER_AI_STREAM_CHUNK   (WM_USER + 0x5A01)
#define WM_USER_AI_STREAM_DONE   (WM_USER + 0x5A02)
#define WM_USER_AI_STREAM_CANCEL (WM_USER + 0x5A03)
#define WM_USER_AI_APPLY_EDIT    (WM_USER + 0x5A04)
#endif

class AiWinHttpCancelToken {
public:
    void Cancel();
    bool IsCancelled() const { return m_cancelled.load(); }
    void RegisterRequest(HINTERNET hRequest);
    void UnregisterRequest();

private:
    std::atomic<bool> m_cancelled{false};
    HINTERNET m_hActiveRequest{nullptr};
    mutable std::mutex m_mutex;
};

struct AiEditTask {
    std::string taskId;
    std::string prompt;
    std::wstring filePath;
    long targetStart = 0;
    long targetEnd = 0;
    std::shared_ptr<AiWinHttpCancelToken> cancelToken;
    std::function<void(bool, const std::string&)> completionCallback;
};

class AsyncAiTaskQueue {
public:
    AsyncAiTaskQueue();
    ~AsyncAiTaskQueue();
    void Enqueue(AiEditTask task);
    void CancelAll();
    void Stop();

private:
    void WorkerLoop();
    void ExecuteTask(AiEditTask& task);

    std::queue<AiEditTask> m_taskQueue;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::thread m_workerThread;
    std::atomic<bool> m_stop{false};
    std::shared_ptr<AiWinHttpCancelToken> m_currentTaskToken;
};

std::string EscapeJsonString(const std::string& input);
std::string BuildOpenAIChatPayload(const std::string& model, const std::string& userPrompt);
std::string ExtractOpenAIChatContent(const std::string& jsonResponse);
std::string QueryOpenAIChatSync(const std::string& host, INTERNET_PORT port,
                                const std::string& model, const std::string& prompt,
                                AiWinHttpCancelToken* token);
