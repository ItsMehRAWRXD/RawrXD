#include "centralized_exception_handler.h"
<<<<<<< HEAD
#include "agentic_observability.h"
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

<<<<<<< HEAD
static const char* kComponent = "CentralizedExceptionHandler";

=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#ifdef _WIN32
#include <windows.h>
#endif

namespace RawrXD {

CentralizedExceptionHandler& CentralizedExceptionHandler::instance() {
    static CentralizedExceptionHandler handler;
    return handler;
}

CentralizedExceptionHandler::CentralizedExceptionHandler()
    : installed_(false)
    , autoRecovery_(false)
    , previousTerminate_(nullptr)
#ifdef _WIN32
    , previousFilter_(nullptr)
#endif
{
}

CentralizedExceptionHandler::~CentralizedExceptionHandler() = default;

void CentralizedExceptionHandler::installHandler() {
    if (installed_.exchange(true)) {
        return;
    }

    previousTerminate_ = std::set_terminate(&CentralizedExceptionHandler::terminateHandler);
#ifdef _WIN32
    previousFilter_ = reinterpret_cast<void*>(SetUnhandledExceptionFilter(&CentralizedExceptionHandler::unhandledExceptionFilter));
#endif
<<<<<<< HEAD

    auto& obs = AgenticObservability::instance();
    obs.logInfo(kComponent, "Exception handler installed (terminate + SEH)");
    obs.incrementCounter("exception_handler.installs", 1);
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void CentralizedExceptionHandler::uninstallHandler() {
    if (!installed_.exchange(false)) {
        return;
    }

    if (previousTerminate_) {
        std::set_terminate(previousTerminate_);
    }
#ifdef _WIN32
    if (previousFilter_) {
        SetUnhandledExceptionFilter(reinterpret_cast<LPTOP_LEVEL_EXCEPTION_FILTER>(previousFilter_));
    }
#endif
}

void CentralizedExceptionHandler::enableAutomaticRecovery(bool enabled) {
    autoRecovery_.store(enabled);
}

bool CentralizedExceptionHandler::isAutomaticRecoveryEnabled() const {
    return autoRecovery_.load();
}

void CentralizedExceptionHandler::reportException(const std::exception& ex) noexcept {
<<<<<<< HEAD
    auto& obs = AgenticObservability::instance();
    obs.incrementCounter("exception_handler.exceptions_reported", 1);
    obs.logError(kComponent, std::string("C++ exception: ") + ex.what());

=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::string details = "Exception: ";
    details += ex.what();
    handleUnhandledException(details);
}

void CentralizedExceptionHandler::reportError(const std::string& message, const std::string& context, const std::string& metadata_json) noexcept {
<<<<<<< HEAD
    auto& obs = AgenticObservability::instance();
    obs.incrementCounter("exception_handler.errors_reported", 1);
    obs.logError(kComponent, "Error [" + context + "]: " + message);

=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::string details = "Error: " + message + " | Context: " + context;
    if (!metadata_json.empty() && metadata_json != "{}") {
        details += " | Metadata: " + metadata_json;
    }
    handleUnhandledException(details);
}

void CentralizedExceptionHandler::handleTerminate() noexcept {
<<<<<<< HEAD
    auto& obs = AgenticObservability::instance();
    obs.incrementCounter("exception_handler.terminate_calls", 1);
    obs.logCritical(kComponent, "std::terminate called — unhandled C++ exception");

=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::string message = "Unhandled C++ exception detected.";
    handleUnhandledException(message);
    std::abort();
}

void CentralizedExceptionHandler::handleUnhandledException(const std::string& message) noexcept {
    std::filesystem::path baseDir = std::filesystem::current_path();
#ifdef _WIN32
    char pathBuffer[MAX_PATH] = {};
    DWORD len = GetModuleFileNameA(nullptr, pathBuffer, MAX_PATH);
    if (len > 0) {
        baseDir = std::filesystem::path(pathBuffer).parent_path();
    }
#endif

    const std::filesystem::path logDir = baseDir / "logs";
    std::error_code ec;
    std::filesystem::create_directories(logDir, ec);

    const std::filesystem::path logPath = logDir / "exceptions.log";
    std::ofstream ofs(logPath.string(), std::ios::app);
    if (ofs.is_open()) {
        const auto now = std::chrono::system_clock::now();
        const auto t = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
#ifdef _WIN32
        localtime_s(&tm, &t);
#else
        tm = *std::localtime(&t);
#endif
        ofs << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << " | " << message << "\n";
    }


}

void CentralizedExceptionHandler::terminateHandler() noexcept {
    CentralizedExceptionHandler::instance().handleTerminate();
}

#ifdef _WIN32
LONG WINAPI CentralizedExceptionHandler::unhandledExceptionFilter(EXCEPTION_POINTERS* exceptionInfo) {
    (void)exceptionInfo;
<<<<<<< HEAD
    auto& obs = AgenticObservability::instance();
    obs.incrementCounter("exception_handler.seh_exceptions", 1);
    obs.logCritical(kComponent, "Windows SEH exception caught");

=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    CentralizedExceptionHandler::instance().handleUnhandledException(
        "Windows structured exception detected.");
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

} // namespace RawrXD

