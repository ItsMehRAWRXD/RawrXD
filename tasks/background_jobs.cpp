// background_jobs.cpp — Background Job Manager
#include "task_runner.hpp"
#include <queue>
#include <thread>
#include <chrono>

namespace RawrXD {
namespace Tasks {

// ============================================================================
// Background Job
// ============================================================================
struct BackgroundJob {
    std::string id;
    std::string label;
    std::string command;
    std::chrono::steady_clock::time_point startedAt;
    std::chrono::steady_clock::time_point completedAt;
    bool running = false;
    bool completed = false;
    int exitCode = -1;
    std::string output;
};

// ============================================================================
// Background Job Manager
// ============================================================================
class BackgroundJobManager {
public:
    static BackgroundJobManager& Get();

    // Start a background job
    std::string StartJob(const std::string& label, const std::string& command, const std::string& cwd = "");

    // Stop a background job
    bool StopJob(const std::string& jobId);

    // Get job status
    BackgroundJob* GetJob(const std::string& jobId);

    // List all jobs
    std::vector<BackgroundJob*> ListJobs() const;

    // List running jobs
    std::vector<BackgroundJob*> ListRunningJobs() const;

    // Clean up completed jobs
    void CleanupCompletedJobs(int maxAgeMinutes = 60);

    // Events
    using JobEventCallback = std::function<void(const std::string& jobId)>;
    void OnJobStarted(JobEventCallback callback) { m_onStarted = callback; }
    void OnJobCompleted(JobEventCallback callback) { m_onCompleted = callback; }

private:
    BackgroundJobManager() = default;
    std::string GenerateJobId();

    std::map<std::string, std::unique_ptr<BackgroundJob>> m_jobs;
    std::map<std::string, void*> m_processHandles;
    JobEventCallback m_onStarted;
    JobEventCallback m_onCompleted;
    std::atomic<uint64_t> m_jobCounter{0};
    mutable std::mutex m_mutex;
};

BackgroundJobManager& BackgroundJobManager::Get() {
    static BackgroundJobManager instance;
    return instance;
}

std::string BackgroundJobManager::StartJob(const std::string& label, const std::string& command, const std::string& cwd) {
    auto jobId = GenerateJobId();

    auto job = std::make_unique<BackgroundJob>();
    job->id = jobId;
    job->label = label;
    job->command = command;
    job->startedAt = std::chrono::steady_clock::now();
    job->running = true;

    // Store job
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_jobs[jobId] = std::move(job);
    }

    if (m_onStarted) m_onStarted(jobId);

    // Run in background thread
    std::thread([this, jobId, command, cwd]() {
        // Set up process
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
        HANDLE hStdoutRead, hStdoutWrite;
        CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0);
        SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOA si = { sizeof(STARTUPINFOA) };
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = hStdoutWrite;
        si.hStdError = hStdoutWrite;

        PROCESS_INFORMATION pi;
        std::string cmdLine = "cmd.exe /c " + command;
        std::string workDir = cwd.empty() ? std::filesystem::current_path().string() : cwd;

        if (CreateProcessA(nullptr, cmdLine.data(), nullptr, nullptr, TRUE,
                           CREATE_NO_WINDOW, nullptr, workDir.c_str(), &si, &pi)) {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_processHandles[jobId] = pi.hProcess;
            }

            // Read output
            char buffer[4096];
            DWORD bytesRead;
            std::string output;

            while (WaitForSingleObject(pi.hProcess, 100) == WAIT_TIMEOUT) {
                while (PeekNamedPipe(hStdoutRead, nullptr, 0, nullptr, &bytesRead, nullptr) && bytesRead > 0) {
                    if (ReadFile(hStdoutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr)) {
                        buffer[bytesRead] = '\0';
                        output += buffer;
                    }
                }
            }

            // Final read
            while (ReadFile(hStdoutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                output += buffer;
            }

            DWORD exitCode;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            CloseHandle(pi.hProcess);
            CloseHandle(hStdoutRead);
            CloseHandle(hStdoutWrite);

            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_jobs.count(jobId)) {
                    m_jobs[jobId]->output = output;
                    m_jobs[jobId]->exitCode = static_cast<int>(exitCode);
                    m_jobs[jobId]->completed = true;
                    m_jobs[jobId]->running = false;
                    m_jobs[jobId]->completedAt = std::chrono::steady_clock::now();
                    m_processHandles.erase(jobId);
                }
            }

            if (m_onCompleted) m_onCompleted(jobId);
        }
    }).detach();

    return jobId;
}

bool BackgroundJobManager::StopJob(const std::string& jobId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_processHandles.find(jobId);
    if (it == m_processHandles.end()) return false;

    TerminateProcess(it->second, 1);
    CloseHandle(it->second);
    m_processHandles.erase(it);

    if (m_jobs.count(jobId)) {
        m_jobs[jobId]->running = false;
        m_jobs[jobId]->completed = true;
        m_jobs[jobId]->exitCode = -1;
    }

    return true;
}

BackgroundJob* BackgroundJobManager::GetJob(const std::string& jobId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_jobs.find(jobId);
    return it != m_jobs.end() ? it->second.get() : nullptr;
}

std::vector<BackgroundJob*> BackgroundJobManager::ListJobs() const {
    std::vector<BackgroundJob*> jobs;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [id, job] : m_jobs) {
        jobs.push_back(job.get());
    }
    return jobs;
}

std::vector<BackgroundJob*> BackgroundJobManager::ListRunningJobs() const {
    std::vector<BackgroundJob*> jobs;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [id, job] : m_jobs) {
        if (job->running) jobs.push_back(job.get());
    }
    return jobs;
}

void BackgroundJobManager::CleanupCompletedJobs(int maxAgeMinutes) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto it = m_jobs.begin(); it != m_jobs.end(); ) {
        if (it->second->completed) {
            auto age = std::chrono::duration_cast<std::chrono::minutes>(now - it->second->completedAt).count();
            if (age >= maxAgeMinutes) {
                it = m_jobs.erase(it);
                continue;
            }
        }
        ++it;
    }
}

std::string BackgroundJobManager::GenerateJobId() {
    return "bg-" + std::to_string(++m_jobCounter);
}

} // namespace Tasks
} // namespace RawrXD
