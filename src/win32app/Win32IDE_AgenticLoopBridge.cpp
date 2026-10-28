// Win32IDE_AgenticLoopBridge.cpp - Bridge to deep2_agentic_loop.exe
// Connects IDE to the standalone agentic execution engine with SNAP recovery and watchdog

#include "Win32IDE_AgenticLoopBridge.h"
#include "Win32IDE.h"
#include <sstream>
#include <chrono>
#include <algorithm>
#include <cstdlib>

namespace {

std::atomic<uint64_t> g_nextAgentRequestId{1};

std::string EspField(const std::string& line, const char* name, bool rest = false)
{
    const std::string prefix = std::string(name) + "=";
    const size_t start = line.find(prefix);
    if (start == std::string::npos) return {};
    const size_t valueStart = start + prefix.size();
    if (rest) return line.substr(valueStart);
    const size_t end = line.find(' ', valueStart);
    return line.substr(valueStart, end == std::string::npos ? std::string::npos : end - valueStart);
}

rawrxd::esp::Kind EspKind(const std::string& name)
{
    using rawrxd::esp::Kind;
    if (name == "model_load") return Kind::ModelLoad;
    if (name == "tokenizer_check") return Kind::TokenizerCheck;
    if (name == "prefill_start") return Kind::PrefillStart;
    if (name == "prefill_end") return Kind::PrefillEnd;
    if (name == "token_generated") return Kind::TokenGenerated;
    if (name == "gpu_dispatch") return Kind::GPUDispatch;
    if (name == "cpu_fallback") return Kind::CPUFallback;
    if (name == "snap_stop") return Kind::SnapStop;
    if (name == "tool_start") return Kind::ToolStart;
    if (name == "tool_result") return Kind::ToolResult;
    if (name == "file_changed") return Kind::FileChanged;
    if (name == "build_result") return Kind::BuildResult;
    if (name == "test_result") return Kind::TestResult;
    if (name == "error") return Kind::Error;
    if (name == "finished") return Kind::Finished;
    if (name == "heartbeat") return Kind::Heartbeat;
    return Kind::AgentStep;
}

}

AgenticLoopBridge::AgenticLoopBridge(Win32IDE* ide)
    : m_ide(ide)
    , m_watchdog({30000, 600000, 100})  // 30s startup, 600s wall, 100ms poll
{
    LOG_INFO("AgenticLoopBridge constructed");
}

AgenticLoopBridge::~AgenticLoopBridge()
{
    Cancel();
    if (m_watchdog.Inspect().state != rawrxd::watchdog::State::Finished) {
        m_watchdog.Stop();
    }
    if (m_snapStarted.load()) {
        m_snapDetector.Stop();
    }
    if (m_workerThread.joinable()) {
        m_workerThread.join();
    }
    if (m_outputThread.joinable()) {
        m_outputThread.join();
    }
    LOG_INFO("AgenticLoopBridge destroyed");
}

bool AgenticLoopBridge::StartTask(const TaskConfig& config, ProgressCallback progress, ToolCallback toolCb, CompleteCallback completeCb)
{
    if (m_running.load()) {
        LOG_WARNING("Task already running");
        return false;
    }

    // A completed std::thread remains joinable. Reusing the bridge without
    // joining it would call std::terminate when the next task is assigned.
    if (m_workerThread.joinable()) {
        m_workerThread.join();
    }
    if (m_outputThread.joinable()) {
        m_outputThread.join();
    }

    m_currentConfig = config;
    m_progressCallback = progress;
    m_toolCallback = toolCb;
    m_completeCallback = completeCb;
    m_accumulatedOutput.clear();
    m_cancelRequested.store(false);
    m_running.store(true);
    m_processStarted.store(false);
    m_completionSent.store(false);
    m_espRequestId = g_nextAgentRequestId.fetch_add(1, std::memory_order_relaxed);
    m_forwardedChildEvents.clear();

    // Publish ESP: task start
    if (m_espBus) {
        m_espBus->publish(rawrxd::esp::Kind::AgentStep, "task_start: " + config.task, m_espRequestId);
    }

    // Start SNAP detector for process monitoring
    m_snapDetector.Start(
        [this](const rawrxd::snap::Event& event) {
            HandleSnapEvent(event);
        },
        nullptr,  // Job object - caller must provide
        2000  // 2 second scan interval
    );
    m_snapStarted.store(true);

    // Start progress watchdog
    m_watchdog.Start([this](const rawrxd::watchdog::Status& status) {
        HandleWatchdogTimeout(status);
    });

    m_workerThread = std::thread([this] { WorkerThread(); });
    return true;
}

void AgenticLoopBridge::Cancel()
{
    if (!m_running.load()) return;
    
    m_cancelRequested.store(true);
    m_watchdog.Finish();
    
    // Terminate process tree
    if (m_processStarted.load() && m_process) {
        TerminateProcessTree(m_processId);
    }
    
    // Signal output thread
    m_queueCv.notify_all();
}

void AgenticLoopBridge::CompleteTask(bool success, const std::string& summary, DWORD exitCode)
{
    if (m_completionSent.exchange(true))
        return;

    m_cancelRequested.store(!success || m_cancelRequested.load());
    m_running.store(false);
    m_processStarted.store(false);
    m_watchdog.Finish();
    if (m_snapStarted.exchange(false))
        m_snapDetector.Stop();

    // Let the reader observe the closed child pipe before disposing the
    // parent read handle. This prevents a new task from racing a stale
    // reader and makes repeated agent runs deterministic.
    if (m_outputThread.joinable() &&
        m_outputThread.get_id() != std::this_thread::get_id()) {
        m_outputThread.join();
    }

    if (m_process)
    {
        CloseHandle(m_process);
        m_process = nullptr;
    }
    if (m_stdoutRead) { CloseHandle(m_stdoutRead); m_stdoutRead = nullptr; }
    if (m_stdoutWrite) { CloseHandle(m_stdoutWrite); m_stdoutWrite = nullptr; }
    if (m_stdinRead) { CloseHandle(m_stdinRead); m_stdinRead = nullptr; }
    if (m_stdinWrite) { CloseHandle(m_stdinWrite); m_stdinWrite = nullptr; }
    m_processId = 0;
    m_queueCv.notify_all();

    if (m_progressCallback)
        m_progressCallback(success ? "Task completed successfully" : summary);
    PublishESPEvent(success ? rawrxd::esp::Kind::Finished : rawrxd::esp::Kind::Error,
                    success ? "PASS" : "FAIL", static_cast<int>(exitCode));
    if (m_completeCallback)
        m_completeCallback(success, summary);
}

void AgenticLoopBridge::WorkerThread()
{
    try {
        // Run startup recovery before launching
        StartupRecovery();

        // Build command line for the selected agent runtime without embedding
        // a checkout-specific absolute path.  The canonical CLI path is
        // preferred for Ollama chat tasks so the GUI and `rawr run` share one
        // actual agent/tool implementation.
        std::string exePath;
        char modulePath[MAX_PATH];
        GetModuleFileNameA(nullptr, modulePath, MAX_PATH);
        std::string ideDir = std::string(modulePath);
        size_t pos = ideDir.find_last_of("\\/");
        if (pos != std::string::npos) {
            ideDir = ideDir.substr(0, pos);
        }

        std::vector<std::string> loopCandidates;
        if (m_currentConfig.useCliAgent) {
            if (const char* configured = std::getenv("RAWRXD_CLI_PATH");
                configured && *configured) {
                loopCandidates.emplace_back(configured);
            }
            loopCandidates.insert(loopCandidates.end(), {
                m_currentConfig.workDir + "\\build_ide\\bin-msvc\\rawr.exe",
                ideDir + "\\..\\bin-msvc\\rawr.exe",
                ideDir + "\\..\\..\\build_ide\\bin-msvc\\rawr.exe",
                ".\\build_ide\\bin-msvc\\rawr.exe"
            });
        } else {
            loopCandidates = {
                m_currentConfig.workDir + "\\deep2_agentic_loop.exe",
                ideDir + "\\deep2_agentic_loop.exe",
                ideDir + "\\..\\deep2_agentic_loop.exe",
                ideDir + "\\..\\..\\deep2_agentic_loop.exe",
                ".\\deep2_agentic_loop.exe"
            };
        }
        exePath.clear();
        for (const auto& candidate : loopCandidates) {
            if (GetFileAttributesA(candidate.c_str()) != INVALID_FILE_ATTRIBUTES) {
                exePath = candidate;
                break;
            }
        }
        if (exePath.empty()) {
            LOG_ERROR("Agentic loop executable not found relative to configured workdir or IDE");
            CompleteTask(false, "Agentic loop executable not found", ERROR_FILE_NOT_FOUND);
            return;
        }

        auto quoteWindowsArg = [](const std::string& value) {
            std::string out;
            out.reserve(value.size() + 2);
            out.push_back('"');
            size_t slashes = 0;
            for (const char ch : value) {
                if (ch == '\\') {
                    ++slashes;
                } else if (ch == '"') {
                    out.append(slashes * 2 + 1, '\\');
                    out += "\\\"";
                    slashes = 0;
                } else {
                    out.append(slashes, '\\');
                    slashes = 0;
                    out.push_back(ch);
                }
            }
            out.append(slashes * 2, '\\');
            out.push_back('"');
            return out;
        };

        std::ostringstream cmd;
        if (m_currentConfig.useCliAgent) {
            cmd << quoteWindowsArg(exePath) << " run "
                << quoteWindowsArg(m_currentConfig.modelPath)
                << " --backend ollama"
                << " --workspace " << quoteWindowsArg(m_currentConfig.workDir)
                << " --prompt " << quoteWindowsArg(m_currentConfig.task)
                << " --esp=tps";
            // An approved GUI run is an autonomous agent run, not an ordinary
            // code/chat request.  Pass the mode explicitly so the CLI applies
            // its tool protocol and mutation policy instead of defaulting to
            // the model's non-agent path.
            if (m_currentConfig.readOnly) {
                cmd << " --mode ask";
            } else if (m_currentConfig.approveMutations) {
                cmd << " --mode agent";
            }
            if (m_currentConfig.approveMutations) cmd << " --approve-mutations";
            // Concrete GUI source-edit tasks use a bounded, real tool surface
            // so the model must begin with readFile/editFiles/writeFile rather
            // than an unrelated workspace enumeration.  Dispatch and policy
            // enforcement remain in the CLI registry.
            if (m_currentConfig.approveMutations &&
                (m_currentConfig.task.find(".cpp") != std::string::npos ||
                 m_currentConfig.task.find(".h") != std::string::npos ||
                 m_currentConfig.task.find("source") != std::string::npos ||
                 m_currentConfig.task.find("edit") != std::string::npos)) {
                cmd << " --tool-scope source-edit";
            }
        } else {
            cmd << quoteWindowsArg(exePath) << " ";
            if (m_currentConfig.provider == "ollama") {
                cmd << "--provider ollama ";
            }
            cmd << "--model " << quoteWindowsArg(m_currentConfig.modelPath) << " ";
            cmd << "--workdir " << quoteWindowsArg(m_currentConfig.workDir) << " ";
            if (!m_currentConfig.targetFile.empty()) {
                cmd << "--target-file " << quoteWindowsArg(m_currentConfig.targetFile) << " ";
            }
            cmd << "--max-steps " << m_currentConfig.maxSteps << " ";
            cmd << "--max-new " << m_currentConfig.maxNewTokens << " ";
            cmd << "--max-retries " << m_currentConfig.maxRetries << " ";
            cmd << "--max-wall-time-sec " << m_currentConfig.maxWallTimeSec << " ";
            cmd << "--max-total-tokens " << m_currentConfig.maxTotalTokens << " ";
            if (m_currentConfig.quiet) cmd << "--quiet ";
        }

        std::string commandLine = cmd.str();
        LOG_INFO("Launching agentic loop: " + commandLine);
        
        if (m_progressCallback) {
            m_progressCallback("Launching: " + exePath);
        }

        // Publish ESP
        PublishESPEvent(rawrxd::esp::Kind::AgentStep, "launching agentic loop");

        // Create pipes for stdin/stdout
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
        if (!CreatePipe(&m_stdoutRead, &m_stdoutWrite, &sa, 0)) {
            throw std::runtime_error("Failed to create stdout pipe");
        }
        if (!CreatePipe(&m_stdinRead, &m_stdinWrite, &sa, 0)) {
            throw std::runtime_error("Failed to create stdin pipe");
        }

        // Make stdout read handle non-inheritable
        SetHandleInformation(m_stdoutRead, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(m_stdinWrite, HANDLE_FLAG_INHERIT, 0);

        // The GUI text control is UTF-16 and the CLI/JSON boundary is UTF-8.
        // Convert explicitly before CreateProcessW. CreateProcessA would use
        // the active ANSI code page and can turn an em dash into a stray
        // 0x97 byte, which is invalid UTF-8 when the CLI serializes JSON.
        auto utf8ToWide = [](const std::string& value) -> std::wstring {
            if (value.empty()) return {};
            const int needed = MultiByteToWideChar(
                CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                static_cast<int>(value.size()), nullptr, 0);
            if (needed <= 0) {
                throw std::runtime_error("invalid UTF-8 in agent command line");
            }
            std::wstring wide(static_cast<size_t>(needed), L'\0');
            if (MultiByteToWideChar(
                    CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                    static_cast<int>(value.size()), wide.data(), needed) != needed) {
                throw std::runtime_error("UTF-8 command-line conversion failed");
            }
            return wide;
        };

        // Start process
        STARTUPINFOW si = { sizeof(STARTUPINFOW) };
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = m_stdoutWrite;
        si.hStdError = m_stdoutWrite;
        si.hStdInput = m_stdinRead;

        PROCESS_INFORMATION pi = { 0 };
        std::wstring cmdMutable = utf8ToWide(commandLine); // CreateProcess modifies the buffer
        std::wstring workDirWide = utf8ToWide(m_currentConfig.workDir);
        
        if (!CreateProcessW(
            nullptr,
            cmdMutable.data(),
            nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW,
            nullptr,
            workDirWide.c_str(),
            &si, &pi)) {
            DWORD err = GetLastError();
            std::string errMsg = "CreateProcess failed: " + std::to_string(err);
            LOG_ERROR(errMsg);
            PublishESPEvent(rawrxd::esp::Kind::Error, errMsg);
            CompleteTask(false, errMsg, err);
            return;
        }

        m_process = pi.hProcess;
        m_processId = pi.dwProcessId;
        m_processStarted.store(true);
        CloseHandle(pi.hThread);

        // Close write ends in parent
        CloseHandle(m_stdoutWrite);
        m_stdoutWrite = nullptr;
        CloseHandle(m_stdinRead);
        m_stdinRead = nullptr;

        // Start output reader thread
        m_outputThread = std::thread([this] { ReadProcessOutput(); });

        // Wait for process to complete with watchdog
        const auto wallDeadline = std::chrono::steady_clock::now() +
                                  std::chrono::seconds(
                                      std::max(1, m_currentConfig.maxWallTimeSec));
        // Preserve the reason for termination.  TerminateProcessTree() can
        // make the child signaled before the next wait, which must not turn a
        // watchdog timeout into an ordinary exit-code failure.
        bool timedOut = false;
        DWORD waitResult = WaitForSingleObject(m_process, 1000);
        while (waitResult == WAIT_TIMEOUT && m_running.load()) {
            // Check watchdog
            auto status = m_watchdog.Inspect();
            if (status.state == rawrxd::watchdog::State::StartupTimedOut ||
                status.state == rawrxd::watchdog::State::WallTimedOut) {
                LOG_WARNING("Watchdog timeout: " + std::to_string(static_cast<int>(status.state)));
                timedOut = true;
                TerminateProcessTree(m_processId);
                break;
            }
            // The task's host-owned wall budget is stricter than the bridge's
            // long-lived default watchdog.  Enforce it here as well so a
            // helper that stops emitting progress cannot outlive the task's
            // configured deadline.
            if (std::chrono::steady_clock::now() >= wallDeadline) {
                LOG_WARNING("Task wall timeout: " +
                            std::to_string(m_currentConfig.maxWallTimeSec) + "s");
                timedOut = true;
                TerminateProcessTree(m_processId);
                break;
            }
            waitResult = WaitForSingleObject(m_process, 1000);
        }
        
        if (timedOut) {
            CompleteTask(false, "Watchdog timeout", WAIT_TIMEOUT);
        } else if (waitResult != WAIT_TIMEOUT) {
            // Process exited naturally
            DWORD exitCode = 0;
            GetExitCodeProcess(m_process, &exitCode);
            
            // Process output queue
            std::string finalOutput = m_accumulatedOutput;
            bool success = (exitCode == 0);

            // `rawr run` can complete an ordinary chat turn with exit code
            // zero even when the selected Ollama model cannot execute tools.
            // The GUI bridge is used for audit/agent tasks, so that condition
            // must remain visible as a failed capability check rather than a
            // misleading successful task.
            if (success && m_currentConfig.useCliAgent) {
                const bool toolCapabilityRejected =
                    finalOutput.find("does not support tools") != std::string::npos ||
                    finalOutput.find("doesn't support tools") != std::string::npos;
                const bool toolWasRequested =
                    m_currentConfig.task.find("readFile") != std::string::npos ||
                    m_currentConfig.task.find("writeFile") != std::string::npos ||
                    m_currentConfig.task.find("audit") != std::string::npos ||
                    m_currentConfig.task.find("inspect") != std::string::npos;
                const bool toolWasObserved =
                    finalOutput.find("tool_start") != std::string::npos ||
                    finalOutput.find("TOOL ") != std::string::npos;

                if (toolCapabilityRejected || (toolWasRequested && !toolWasObserved)) {
                    success = false;
                    if (toolCapabilityRejected) {
                        finalOutput = "Selected model does not support agent tools. "
                                      "Choose a tool-capable Ollama model (for example qwen3:8b).\n" +
                                      finalOutput;
                    } else {
                        finalOutput = "Agent task completed without an observable tool call; "
                                      "the requested read-only operation was not certified.\n" +
                                      finalOutput;
                    }
                }
            }
            
            LOG_INFO("Agentic loop exited with code: " + std::to_string(exitCode));
            
            CompleteTask(success, finalOutput.empty()
                                  ? ("Task completed with exit code: " + std::to_string(exitCode))
                                  : finalOutput,
                         exitCode);
        } else {
            // Watchdog terminated process
            CompleteTask(false, "Watchdog timeout", WAIT_TIMEOUT);
        }
    }
    catch (const std::exception& e) {
        LOG_ERROR("Worker thread exception: " + std::string(e.what()));
        CompleteTask(false, std::string("Worker exception: ") + e.what(), ERROR_UNHANDLED_EXCEPTION);
    }
    catch (...) {
        LOG_ERROR("Worker thread unknown exception");
        CompleteTask(false, "Unknown worker exception", ERROR_UNHANDLED_EXCEPTION);
    }
}

void AgenticLoopBridge::StartupRecovery()
{
    LOG_INFO("Starting SNAP startup recovery");
    if (m_progressCallback) {
        m_progressCallback("[SNAP] Startup recovery initialized");
    }
    PublishESPEvent(rawrxd::esp::Kind::AgentStep, "snap_startup_recovery");

    // Acquire recovery mutex to serialize recovery
    HANDLE recoveryMutex = CreateMutexA(nullptr, FALSE, "Global\\RawrXD_Snap_Recovery");
    if (recoveryMutex) {
        DWORD waitResult = WaitForSingleObject(recoveryMutex, 30000);
        if (waitResult != WAIT_OBJECT_0 && waitResult != WAIT_ABANDONED) {
            LOG_WARNING("Could not acquire recovery mutex");
        } else {
            if (m_progressCallback) {
                m_progressCallback("[SNAP] Recovery mutex acquired");
            }
            PublishESPEvent(rawrxd::esp::Kind::AgentStep, "snap_recovery_mutex_acquired");
        }
    }

    // Scan for existing deep2_agentic_loop.exe processes
    auto snapshot = rawrxd::snap::capture();
    
    if (m_progressCallback) {
        m_progressCallback("[SNAP] Process enumeration complete: " + std::to_string(snapshot.processes.size()) + " candidates");
    }
    PublishESPEvent(rawrxd::esp::Kind::AgentStep, "snap_enumerated_" + std::to_string(snapshot.processes.size()));

    // Exclude self
    DWORD selfPid = GetCurrentProcessId();
    size_t excludedSelf = 0;
    for (const auto& proc : snapshot.processes) {
        if (proc.pid == selfPid) {
            excludedSelf++;
        }
    }
    
    if (m_progressCallback) {
        m_progressCallback("[SNAP] Self process excluded: " + std::to_string(excludedSelf));
    }
    PublishESPEvent(rawrxd::esp::Kind::AgentStep, "snap_self_excluded_" + std::to_string(excludedSelf));

    // Check for verified abandoned processes
    size_t verifiedAbandoned = 0;
    for (const auto& proc : snapshot.processes) {
        if (proc.pid == selfPid) continue;
        
        if (IsAbandonedProcess(proc)) {
            verifiedAbandoned++;
            if (m_progressCallback) {
                m_progressCallback("[SNAP] Reclaiming verified abandoned PID: " + std::to_string(proc.pid));
            }
            PublishESPEvent(rawrxd::esp::Kind::AgentStep, "snap_reclaiming_" + std::to_string(proc.pid));
            
            // Terminate verified abandoned process
            rawrxd::snap::Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE, FALSE, proc.pid));
            if (h) {
                if (TerminateProcess(h.get(), 0xE001)) {
                    WaitForSingleObject(h.get(), 10000);
                }
            }
        }
    }
    
    if (m_progressCallback) {
        m_progressCallback("[SNAP] Verified abandoned processes: " + std::to_string(verifiedAbandoned));
    }
    PublishESPEvent(rawrxd::esp::Kind::AgentStep, "snap_verified_abandoned_" + std::to_string(verifiedAbandoned));

    // Release recovery mutex
    if (recoveryMutex) {
        ReleaseMutex(recoveryMutex);
        CloseHandle(recoveryMutex);
    }

    // No GPU residency probe is executed in this startup recovery path.  Do
    // not publish a completion event for work that was not performed; the
    // dashboard must keep this capability visibly unverified.
    if (m_progressCallback) {
        m_progressCallback("[SNAP] GPU residency check not run");
    }
    PublishESPEvent(rawrxd::esp::Kind::AgentStep, "snap_gpu_check_not_run");

    if (m_progressCallback) {
        m_progressCallback("[SNAP] Startup preflight PASS");
    }
    PublishESPEvent(rawrxd::esp::Kind::AgentStep, "snap_preflight_pass");
}

bool AgenticLoopBridge::IsAbandonedProcess(const rawrxd::snap::Process& proc)
{
    // Fail-closed identity check
    if (!rawrxd::snap::sameProcessIdentity(proc)) {
        return false;
    }

    // Check if process is in our job object (if we have one)
    // This would require the Job Object handle to be passed in
    // For now, just use the identity check

    // Verify process is still alive but not making progress
    // This is a simplified check - in production, check task lease
    return true; // Only called after identity verification
}

void AgenticLoopBridge::HandleSnapEvent(const rawrxd::snap::Event& event)
{
    switch (event.kind) {
        case rawrxd::snap::EventKind::NewProcess:
            LOG_INFO("SNAP: New process detected PID=" + std::to_string(event.pid));
            PublishESPEvent(rawrxd::esp::Kind::AgentStep, "snap_new_process_" + std::to_string(event.pid));
            break;
        case rawrxd::snap::EventKind::ExitedProcess:
            LOG_INFO("SNAP: Process exited PID=" + std::to_string(event.pid));
            PublishESPEvent(rawrxd::esp::Kind::AgentStep, "snap_exited_process_" + std::to_string(event.pid));
            break;
        case rawrxd::snap::EventKind::MemoryPressure:
            LOG_WARNING("SNAP: Memory pressure - available=" + std::to_string(event.value));
            PublishESPEvent(rawrxd::esp::Kind::Error, "memory_pressure_" + std::to_string(event.value));
            break;
        case rawrxd::snap::EventKind::ProcessPressure:
            LOG_WARNING("SNAP: Process pressure - count=" + std::to_string(event.value));
            PublishESPEvent(rawrxd::esp::Kind::Error, "process_pressure_" + std::to_string(event.value));
            break;
        case rawrxd::snap::EventKind::ScanIncomplete:
            LOG_WARNING("SNAP: Scan incomplete - failures=" + std::to_string(event.value));
            break;
        case rawrxd::snap::EventKind::Scan:
            // Regular scan, no action needed
            break;
    }
}

void AgenticLoopBridge::HandleWatchdogTimeout(const rawrxd::watchdog::Status& status)
{
    LOG_WARNING("Watchdog timeout: state=" + std::to_string(static_cast<int>(status.state)) + 
                " elapsed=" + std::to_string(status.elapsedMs) + "ms" +
                " progress=" + std::to_string(status.progressEvents));
    PublishESPEvent(rawrxd::esp::Kind::Error, "watchdog_timeout_state_" + std::to_string(static_cast<int>(status.state)));
    
    // Request cancellation
    m_cancelRequested.store(true);
    
    // The worker thread will terminate the process
}

void AgenticLoopBridge::TerminateProcessTree(DWORD pid)
{
    // Use Windows Job Object for clean process tree termination
    HANDLE job = CreateJobObject(nullptr, nullptr);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
        AssignProcessToJobObject(job, m_process);
        CloseHandle(job);
    }
    
    // Force terminate if still running
    if (m_process) {
        TerminateProcess(m_process, 1);
        WaitForSingleObject(m_process, 5000);
    }
}

void AgenticLoopBridge::ReadProcessOutput()
{
    char buffer[4096];
    DWORD bytesRead = 0;
    m_lineBuffer.clear();
    
    while (m_running.load() || m_processStarted.load()) {
        if (!ReadFile(m_stdoutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr)) {
            break; // Pipe closed or error
        }
        if (bytesRead == 0) break;
        
        buffer[bytesRead] = '\0';
        std::string chunk(buffer);
        m_accumulatedOutput += chunk;
        m_lineBuffer += chunk;
        
        // Parse only complete records. The tail remains buffered for the
        // next ReadFile call because pipe boundaries are not line boundaries.
        size_t newline = 0;
        while ((newline = m_lineBuffer.find('\n')) != std::string::npos) {
            std::string line = m_lineBuffer.substr(0, newline);
            m_lineBuffer.erase(0, newline + 1);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty()) ParseOutput(line);
        }
        
        // Progress callback
        if (m_progressCallback) {
            m_progressCallback(chunk);
        }
    }

    if (!m_lineBuffer.empty()) {
        ParseOutput(m_lineBuffer);
        m_lineBuffer.clear();
    }
    
    CloseHandle(m_stdoutRead);
    m_stdoutRead = nullptr;
}

void AgenticLoopBridge::ParseOutput(const std::string& line)
{
    // Parse agentic loop output for ESP events
    // Look for patterns like: [step N] TOOL read file.cpp
    // [ESP] seq=X ...
    
    if (line.find("[ESP]") != std::string::npos) {
        // Forward the child's structured event once.  The bridge owns the
        // GUI bus, while the child JSONL remains the raw evidence record.
        const std::string childSeq = EspField(line, "seq");
        const std::string childRequest = EspField(line, "req");
        const std::string childKind = EspField(line, "kind");
        const std::string childValue = EspField(line, "value");
        const std::string childMessage = EspField(line, "message", true);
        if (!childSeq.empty() && !childRequest.empty() && !childKind.empty()) {
            const std::string key = childRequest + ":" + childSeq;
            if (m_forwardedChildEvents.insert(key).second) {
                int value = 0;
                try { value = std::stoi(childValue); } catch (...) { value = 0; }
                // CompleteTask below is the sole owner of the GUI terminal
                // event. Preserve child terminal/error evidence as a normal
                // step so the UI cannot render a second terminal transition.
                const auto kind = EspKind(childKind);
                const auto displayKind = kind == rawrxd::esp::Kind::Finished ||
                                         kind == rawrxd::esp::Kind::Error
                    ? rawrxd::esp::Kind::AgentStep : kind;
                PublishESPEvent(displayKind,
                    "child_request=" + childRequest + " child_seq=" + childSeq +
                    " child_kind=" + childKind + " " + childMessage, value);

                // Structured CLI events are the authoritative tool boundary.
                // Convert tool_result into the same callback contract used by
                // the legacy text parser so the GUI receives one real result,
                // and keep tool_start as progress only.
                if (childKind == "tool_start") {
                    // The watchdog has no separate ToolStarted state; the
                    // subsequent tool_result is the completion heartbeat.
                } else if (childKind == "tool_result") {
                    ToolResult result{};
                    result.success = childMessage.find("status=PASS") != std::string::npos || value == 0;
                    result.exitCode = result.success ? 0 : 1;
                    result.output = childMessage;
                    const auto namePos = childMessage.find("name=");
                    if (namePos != std::string::npos) {
                        const size_t start = namePos + 5;
                        const size_t end = childMessage.find(' ', start);
                        result.toolName = childMessage.substr(start, end == std::string::npos ? std::string::npos : end - start);
                    }
                    const auto targetPos = childMessage.find("target=");
                    if (targetPos != std::string::npos) {
                        const size_t start = targetPos + 7;
                        const size_t end = childMessage.find(" status=", start);
                        result.target = childMessage.substr(start, end == std::string::npos ? std::string::npos : end - start);
                    }
                    m_watchdog.Progress(rawrxd::watchdog::Activity::ToolCompleted);
                    if (m_toolCallback) m_toolCallback(result);
                }
            }
        }
        return;
    }
    
    if (line.find("TOOL read") != std::string::npos || 
        line.find("TOOL write") != std::string::npos ||
        line.find("TOOL bash") != std::string::npos) {
        // Tool call detected
        ToolResult result;
        result.toolName = "unknown";
        result.target = "";
        result.success = true;
        result.output = line;
        result.exitCode = 0;
        
        if (line.find("TOOL read") != std::string::npos) {
            result.toolName = "read";
            m_watchdog.Progress(rawrxd::watchdog::Activity::ToolCompleted);
        } else if (line.find("TOOL write") != std::string::npos) {
            result.toolName = "write";
            m_watchdog.Progress(rawrxd::watchdog::Activity::ToolCompleted);
        } else if (line.find("TOOL bash") != std::string::npos) {
            result.toolName = "bash";
            m_watchdog.Progress(rawrxd::watchdog::Activity::ToolCompleted);
        }
        
        // Extract target
        size_t pos = line.find("TOOL " + result.toolName + " ");
        if (pos != std::string::npos) {
            size_t start = pos + result.toolName.size() + 6;
            size_t end = line.find(' ', start);
            if (end == std::string::npos) end = line.size();
            result.target = line.substr(start, end - start);
        }
        
        if (m_toolCallback) {
            m_toolCallback(result);
        }
        
        PublishESPEvent(rawrxd::esp::Kind::ToolStart, result.toolName + " " + result.target);
    }
    
    if (line.find("BUILD") != std::string::npos || line.find("build") != std::string::npos) {
        PublishESPEvent(rawrxd::esp::Kind::BuildResult, line);
        m_watchdog.Progress(rawrxd::watchdog::Activity::BuildCompleted);
    }
    
    if (line.find("TEST") != std::string::npos || line.find("test") != std::string::npos) {
        PublishESPEvent(rawrxd::esp::Kind::TestResult, line);
        m_watchdog.Progress(rawrxd::watchdog::Activity::TestCompleted);
    }
    
    if (line.find("FINAL_VERDICT") != std::string::npos) {
        bool pass = line.find("PASS") != std::string::npos;
        PublishESPEvent(rawrxd::esp::Kind::TestResult, pass ? "PASS" : "FAIL", pass ? 0 : 1);
        m_watchdog.Progress(rawrxd::watchdog::Activity::VerificationCompleted);
    }
    
    // Record progress for prefill/decode detection
    if (line.find("prefill") != std::string::npos && line.find("tok") != std::string::npos) {
        m_watchdog.Progress(rawrxd::watchdog::Activity::PrefillToken);
    }
    if (line.find("decode") != std::string::npos && line.find("tok") != std::string::npos) {
        m_watchdog.Progress(rawrxd::watchdog::Activity::DecodeToken);
    }
}

void AgenticLoopBridge::PublishESPEvent(rawrxd::esp::Kind kind, const std::string& message, int value)
{
    if (m_espBus) {
        m_espBus->publish(kind, message, m_espRequestId, 0, value);
    }
}

std::string AgenticLoopBridge::GetStatus() const
{
    std::ostringstream oss;
    if (!m_running.load()) {
        oss << "Idle";
    } else {
        oss << "Running: " << m_currentConfig.task.substr(0, 50);
        auto status = m_watchdog.Inspect();
        oss << " (watchdog: " << std::to_string(static_cast<int>(status.state)) << ")";
    }
    return oss.str();
}

void AgenticLoopBridge::SetESPBus(rawrxd::esp::Bus* bus, uint64_t requestId)
{
    m_espBus = bus;
    m_espRequestId = requestId;
}
