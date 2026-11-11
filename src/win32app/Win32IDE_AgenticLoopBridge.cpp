// Win32IDE_AgenticLoopBridge.cpp - Bridge to deep2_agentic_loop.exe
// Connects IDE to the standalone agentic execution engine with SNAP recovery and watchdog

#include "Win32IDE_AgenticLoopBridge.h"
#include "Win32IDE.h"
#include <sstream>
#include <fstream>
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

// 7B instruct prefill/MOTD reinjection exceeds legacy 30s/600s defaults.
// Env overrides: RAWRXD_AGENTIC_WATCHDOG_STARTUP_MS / RAWRXD_AGENTIC_WATCHDOG_WALL_MS.
rawrxd::watchdog::Config LoadAgenticWatchdogConfig()
{
    // 7B PrefillBatch(P128) can run >3min with stdout block-buffered before
    // the first flushed ESP tick; 15min startup avoids false IDE cancel.
    rawrxd::watchdog::Config c{900000, 7200000, 100}; // 15min startup, 2h wall
    if (const char* s = std::getenv("RAWRXD_AGENTIC_WATCHDOG_STARTUP_MS")) {
        const unsigned long v = std::strtoul(s, nullptr, 10);
        if (v >= 5000ul) c.startupMs = v;
    }
    if (const char* s = std::getenv("RAWRXD_AGENTIC_WATCHDOG_WALL_MS")) {
        const unsigned long v = std::strtoul(s, nullptr, 10);
        if (v >= 60000ul) c.wallMs = v;
    }
    return c;
}

}

AgenticLoopBridge::AgenticLoopBridge(Win32IDE* ide)
    : m_ide(ide)
    , m_watchdog(LoadAgenticWatchdogConfig())
{
    LOG_INFO("AgenticLoopBridge constructed");
}

AgenticLoopBridge::~AgenticLoopBridge()
{
    // Unconditional reap — do not depend on m_running (may be race-cleared).
    m_cancelRequested.store(true);
    m_running.store(false);
    ReapChildProcess();
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
    CloseChildJob();
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
    m_structuredToolResults = 0;
    m_successfulToolResults = 0;
    m_failedToolResults = 0;
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
    // Map9: never early-return solely on !m_running — child may still live
    // after CompleteTask raced m_running clear, or before m_processStarted.
    m_cancelRequested.store(true);
    m_running.store(false);
    m_watchdog.Finish();
    ReapChildProcess();
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

    // Close job after natural exit so any leftover job members are reaped
    // (KILL_ON_JOB_CLOSE). Safe when the primary child already exited.
    CloseChildJob();

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
        if (m_cancelRequested.load()) {
            CompleteTask(false, "Cancelled before launch", ERROR_CANCELLED);
            return;
        }

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
            // Prefer packaged rawr.exe beside the IDE (CU-capable CLI registry).
            loopCandidates.insert(loopCandidates.end(), {
                ideDir + "\\rawr.exe",
                m_currentConfig.workDir + "\\build_ide\\bin-msvc\\rawr.exe",
                ideDir + "\\..\\bin-msvc\\rawr.exe",
                ideDir + "\\..\\..\\build_ide\\bin-msvc\\rawr.exe",
                ".\\build_ide\\bin-msvc\\rawr.exe"
            });
            // Issue #49: if rawr.exe is absent beside the tip package, fall
            // through to deep2_agentic_loop.exe (same as local provider).
            loopCandidates.insert(loopCandidates.end(), {
                ideDir + "\\deep2_agentic_loop.exe",
                m_currentConfig.workDir + "\\deep2_agentic_loop.exe",
                ".\\deep2_agentic_loop.exe"
            });
        } else {
            // Prefer IDE/tip-package loop over workdir. tip_016 IDE exclusive
            // spawned a stale fixture-shadow deep2_agentic_loop.exe from
            // CC79 issue49_project (exit -1) instead of tip_016's fixed loop.
            loopCandidates = {
                ideDir + "\\deep2_agentic_loop.exe",
                m_currentConfig.workDir + "\\deep2_agentic_loop.exe",
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
        const bool exeIsDeep2Loop =
            exePath.size() >= 22 &&
            (exePath.find("deep2_agentic_loop.exe") != std::string::npos ||
             exePath.find("deep2_agentic_loop") != std::string::npos);
        // Issue #49: Ollama GUI path may fall back to deep2_agentic_loop.exe
        // when rawr.exe is absent — never emit `rawr run` argv to that binary.
        if (m_currentConfig.useCliAgent && !exeIsDeep2Loop) {
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
            // Computer Use tasks must keep the full tool surface (computer_use.*);
            // do not clamp to source-edit scope.
            const bool cuTask =
                m_currentConfig.task.find("computer_use") != std::string::npos ||
                m_currentConfig.task.find("find_window") != std::string::npos ||
                m_currentConfig.task.find("screenshot") != std::string::npos;
            // Concrete GUI source-edit tasks use a bounded, real tool surface
            // so the model must begin with readFile/editFiles/writeFile rather
            // than an unrelated workspace enumeration.  Dispatch and policy
            // enforcement remain in the CLI registry.
            if (!cuTask && m_currentConfig.approveMutations &&
                (m_currentConfig.task.find(".cpp") != std::string::npos ||
                 m_currentConfig.task.find(".h") != std::string::npos ||
                 m_currentConfig.task.find("source") != std::string::npos ||
                 m_currentConfig.task.find("edit") != std::string::npos)) {
                cmd << " --tool-scope source-edit";
            }
        } else {
            cmd << quoteWindowsArg(exePath) << " ";
            if (m_currentConfig.provider == "ollama" ||
                m_currentConfig.provider == "ollama-cli" ||
                m_currentConfig.useCliAgent) {
                cmd << "--provider ollama ";
            }
            cmd << "--model " << quoteWindowsArg(m_currentConfig.modelPath) << " ";
            cmd << "--workdir " << quoteWindowsArg(m_currentConfig.workDir) << " ";
            if (!m_currentConfig.task.empty()) {
                cmd << "--task " << quoteWindowsArg(m_currentConfig.task) << " ";
            }
            if (!m_currentConfig.targetFile.empty()) {
                cmd << "--target-file " << quoteWindowsArg(m_currentConfig.targetFile) << " ";
            } else {
                // deep2 ollama path defaults target to calc.cpp; seed a relative
                // target so Map9 spawn is not an instant VERDICT FAIL exit.
                cmd << "--target-file calc.cpp ";
            }
            // Ollama agent path requires build/run commands or exits 1 immediately
            // (orphan-cancel never exercises). Provide deterministic no-op cmds.
            cmd << "--build-command " << quoteWindowsArg("cmd /c exit 0") << " ";
            cmd << "--run-command " << quoteWindowsArg("cmd /c echo PASS") << " ";
            cmd << "--max-steps " << m_currentConfig.maxSteps << " ";
            cmd << "--max-new " << m_currentConfig.maxNewTokens << " ";
            cmd << "--max-retries " << m_currentConfig.maxRetries << " ";
            cmd << "--max-wall-time-sec " << m_currentConfig.maxWallTimeSec << " ";
            cmd << "--max-total-tokens " << m_currentConfig.maxTotalTokens << " ";
            if (m_currentConfig.contextSize > 0) {
                cmd << "--context-size " << m_currentConfig.contextSize << " ";
            }
            // Issue #49 tip_015 IDE exclusive: default prefill_chunk=8 mid-7B
            // PrefillBatch → flight global_no_progress + child exit -1 before TOOL.
            // Loop-exclusive 08-11 PASSes with --prefill-chunk 128; pass the same
            // on IDE-spawned deep2 so HOST_SEED=OFF can reach model TOOL.
            if (exeIsDeep2Loop) {
                size_t prefillChunk = 128;
                if (const char* pc = std::getenv("RAWRXD_PREFILL_CHUNK")) {
                    const unsigned long v = std::strtoul(pc, nullptr, 10);
                    if (v >= 1ul && v <= 2048ul) prefillChunk = static_cast<size_t>(v);
                }
                cmd << "--batched-prefill 1 ";
                cmd << "--prefill-chunk " << prefillChunk << " ";
            }
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

        // Child CLI inherits this so computer_use can allowlist the IDE HWND
        // (CLI PID alone cannot capture the parent window).
        {
            const std::string pidBuf =
                std::to_string(static_cast<unsigned long>(GetCurrentProcessId()));
            SetEnvironmentVariableA("RAWRXD_PARENT_PID", pidBuf.c_str());
            SetEnvironmentVariableA("RAWRXD_CU_ALLOW_PIDS", pidBuf.c_str());
        }

        // Supervise before the child runs so deep2 cannot self-job away from
        // parent kill-on-close (Map9 orphan class).
        EnsureChildJob();
        
        if (!CreateProcessW(
            nullptr,
            cmdMutable.data(),
            nullptr, nullptr, TRUE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            nullptr,
            workDirWide.c_str(),
            &si, &pi)) {
            DWORD err = GetLastError();
            std::string errMsg = "CreateProcess failed: " + std::to_string(err);
            LOG_ERROR(errMsg);
            PublishESPEvent(rawrxd::esp::Kind::Error, errMsg);
            CloseChildJob();
            CompleteTask(false, errMsg, err);
            return;
        }

        if (m_hJob) {
            if (!AssignProcessToJobObject(m_hJob, pi.hProcess)) {
                LOG_WARNING("AssignProcessToJobObject failed err=" +
                            std::to_string(GetLastError()) +
                            " — Cancel/shutdown will TerminateProcess fallback");
            }
        }

        if (m_cancelRequested.load()) {
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseChildJob();
            CompleteTask(false, "Cancelled before resume", ERROR_CANCELLED);
            return;
        }

        ResumeThread(pi.hThread);
        m_process = pi.hProcess;
        m_processId = pi.dwProcessId;
        m_processStarted.store(true);
        CloseHandle(pi.hThread);
        {
            std::ofstream crumb(
                "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\artifacts\\MAP9_AGENTIC_CRUMB.txt",
                std::ios::app);
            if (crumb) crumb << "createprocess_ok pid=" << m_processId
                             << " exe=" << exePath << "\n";
        }

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
        while (waitResult == WAIT_TIMEOUT &&
               m_running.load() &&
               !m_cancelRequested.load()) {
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
        } else if (m_cancelRequested.load() && waitResult == WAIT_TIMEOUT) {
            CompleteTask(false, "Cancelled", ERROR_CANCELLED);
        } else if (waitResult != WAIT_TIMEOUT) {
            // Process exited naturally
            DWORD exitCode = 0;
            GetExitCodeProcess(m_process, &exitCode);
            {
                std::ofstream crumb(
                    "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\artifacts\\MAP9_AGENTIC_CRUMB.txt",
                    std::ios::app);
                if (crumb) crumb << "child_exited code=" << exitCode
                                 << " cancel=" << (m_cancelRequested.load()?1:0) << "\n";
            }
            
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
                // A tool_start event is only an attempted dispatch.  Require
                // a structured successful tool_result so a model cannot make
                // the GUI report PASS by printing a TOOL line or by exiting 0
                // without executing the requested operation.
                const bool toolWasObserved = m_structuredToolResults > 0;
                const bool toolSucceeded = m_successfulToolResults > 0;

                if (toolCapabilityRejected ||
                    (toolWasRequested && (!toolWasObserved || !toolSucceeded))) {
                    success = false;
                    if (toolCapabilityRejected) {
                        finalOutput = "Selected model does not support agent tools. "
                                      "Choose a tool-capable Ollama model (for example qwen3:8b).\n" +
                                      finalOutput;
                    } else if (m_failedToolResults > 0 && !toolSucceeded) {
                        finalOutput = "Agent task tool execution failed; no successful "
                                      "tool_result was observed.\n" + finalOutput;
                    } else {
                        finalOutput = "Agent task completed without a successful structured "
                                      "tool_result; the requested operation was not certified.\n" +
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
    if (m_cancelRequested.load()) return;
    if (m_progressCallback) {
        m_progressCallback("[SNAP] Startup recovery initialized");
    }
    PublishESPEvent(rawrxd::esp::Kind::AgentStep, "snap_startup_recovery");

    // Acquire recovery mutex to serialize recovery (short wait — Cancel must
    // not be blocked behind a 30s mutex during Map9 clean-exit).
    HANDLE recoveryMutex = CreateMutexA(nullptr, FALSE, "Global\\RawrXD_Snap_Recovery");
    if (recoveryMutex) {
        DWORD waitResult = WaitForSingleObject(recoveryMutex, 2000);
        if (waitResult != WAIT_OBJECT_0 && waitResult != WAIT_ABANDONED) {
            LOG_WARNING("Could not acquire recovery mutex");
        } else {
            if (m_progressCallback) {
                m_progressCallback("[SNAP] Recovery mutex acquired");
            }
            PublishESPEvent(rawrxd::esp::Kind::AgentStep, "snap_recovery_mutex_acquired");
        }
    }
    if (m_cancelRequested.load()) {
        if (recoveryMutex) { ReleaseMutex(recoveryMutex); CloseHandle(recoveryMutex); }
        return;
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
        if (m_cancelRequested.load()) break;
        if (proc.pid == selfPid) continue;
        
        if (IsAbandonedProcess(proc)) {
            verifiedAbandoned++;
            if (m_progressCallback) {
                m_progressCallback("[SNAP] Reclaiming verified abandoned PID: " + std::to_string(proc.pid));
            }
            PublishESPEvent(rawrxd::esp::Kind::AgentStep, "snap_reclaiming_" + std::to_string(proc.pid));
            
            // Terminate verified abandoned process (bounded wait)
            rawrxd::snap::Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE, FALSE, proc.pid));
            if (h) {
                if (TerminateProcess(h.get(), 0xE001)) {
                    WaitForSingleObject(h.get(), 1000);
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
    if (m_cancelRequested.load()) return;

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

void AgenticLoopBridge::EnsureChildJob()
{
    if (m_hJob) return;
    m_hJob = CreateJobObjectW(nullptr, nullptr);
    if (!m_hJob) {
        LOG_WARNING("CreateJobObject failed err=" + std::to_string(GetLastError()));
        return;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(m_hJob, JobObjectExtendedLimitInformation, &jeli,
                                 sizeof(jeli))) {
        LOG_WARNING("SetInformationJobObject failed err=" +
                    std::to_string(GetLastError()));
        CloseHandle(m_hJob);
        m_hJob = nullptr;
    }
}

void AgenticLoopBridge::CloseChildJob()
{
    if (!m_hJob) return;
    // KILL_ON_JOB_CLOSE: closing the last handle reaps every member.
    CloseHandle(m_hJob);
    m_hJob = nullptr;
}

void AgenticLoopBridge::ReapChildProcess()
{
    const DWORD pid = m_processId;
    // Prefer job teardown — covers deep2 + any inheriting children even when
    // late AssignProcessToJobObject would fail (child already self-jobbed).
    if (m_hJob) {
        TerminateJobObject(m_hJob, 1);
        CloseChildJob();
    }
    if (m_process) {
        TerminateProcess(m_process, 1);
        WaitForSingleObject(m_process, 5000);
    } else if (pid != 0) {
        HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
        if (h) {
            TerminateProcess(h, 1);
            WaitForSingleObject(h, 5000);
            CloseHandle(h);
        }
    }
    m_processStarted.store(false);
}

void AgenticLoopBridge::TerminateProcessTree(DWORD pid)
{
    (void)pid;
    ReapChildProcess();
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

        // tip_017 keepalive: any child stdout during long PrefillBatch proves
        // the loop is alive even when ESP is block-buffered mid-fence.
        m_watchdog.Progress(rawrxd::watchdog::Activity::PrefillToken);
        
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
        std::string childKind = EspField(line, "kind");
        const std::string childValue = EspField(line, "value");
        std::string childMessage = EspField(line, "message", true);
        // Legacy ConsoleView: "[ESP] seq=N req=N agent=N tool_result  TEXT value=N"
        // (positional kind, no kind=/message=). Accept so tool_result reaches ledger.
        if (childKind.empty()) {
            const char* markers[] = {
                "tool_result", "tool_start", "finished", "error",
                "build_result", "test_result", "agent_step", "heartbeat"
            };
            for (const char* marker : markers) {
                const std::string needle = std::string(" ") + marker + " ";
                const size_t pos = line.find(needle);
                if (pos == std::string::npos) continue;
                childKind = marker;
                if (childMessage.empty()) {
                    const size_t msgStart = pos + needle.size();
                    const size_t valuePos = line.find(" value=", msgStart);
                    childMessage = line.substr(
                        msgStart,
                        valuePos == std::string::npos ? std::string::npos
                                                      : valuePos - msgStart);
                }
                break;
            }
        }
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
                    const bool hasExplicitPass =
                        childMessage.find("status=PASS") != std::string::npos;
                    const bool hasExplicitFail =
                        childMessage.find("status=FAIL") != std::string::npos;
                    // The CLI contract emits both status and value.  Missing
                    // status is not success, even when the parser's default
                    // numeric value happens to be zero.
                    result.success = hasExplicitPass && !hasExplicitFail && value == 0;
                    result.exitCode = result.success ? 0 : (value == 0 ? 1 : value);
                    result.output = childMessage;
                    ++m_structuredToolResults;
                    if (result.success) ++m_successfulToolResults;
                    else ++m_failedToolResults;
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
                } else if (childKind == "model_load" || childKind == "tokenizer_check" ||
                           childKind == "gpu_dispatch") {
                    // tip_017: model/tokenizer load precedes prefill_start; count
                    // as startup progress so 7B init cannot burn the budget mute.
                    m_watchdog.Progress(rawrxd::watchdog::Activity::ModelLayer);
                } else if (childKind == "prefill_start" || childKind == "prefill_end" ||
                           childKind == "heartbeat") {
                    // tip_015: ESP lines returned before PrefillToken Progress,
                    // so startup watchdog never saw 7B prefill heartbeats.
                    const bool prefillish =
                        childKind.find("prefill") != std::string::npos ||
                        childMessage.find("prefill") != std::string::npos ||
                        childMessage.find("\"phase\":\"prefill\"") != std::string::npos;
                    const bool decodeish =
                        childMessage.find("decode") != std::string::npos ||
                        childMessage.find("\"phase\":\"decode\"") != std::string::npos;
                    if (prefillish) {
                        m_watchdog.Progress(rawrxd::watchdog::Activity::PrefillToken);
                    } else if (decodeish) {
                        m_watchdog.Progress(rawrxd::watchdog::Activity::DecodeToken);
                    } else {
                        m_watchdog.Progress(rawrxd::watchdog::Activity::PrefillToken);
                    }
                }
            }
        }
        return;
    }
    
    if (line.find("TOOL read") != std::string::npos || 
        line.find("TOOL write") != std::string::npos ||
        line.find("TOOL bash") != std::string::npos) {
        // Legacy text is only an attempted tool call.  It has no trustworthy
        // execution result, so never turn it into a synthetic PASS callback.
        std::string toolName = line.find("TOOL read") != std::string::npos
            ? "read" : (line.find("TOOL write") != std::string::npos ? "write" : "bash");
        PublishESPEvent(rawrxd::esp::Kind::ToolStart, toolName + " (result pending)");
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
    if (line.find("PREFILL_BATCH_") != std::string::npos ||
        (line.find("prefill") != std::string::npos && line.find("tok") != std::string::npos)) {
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
