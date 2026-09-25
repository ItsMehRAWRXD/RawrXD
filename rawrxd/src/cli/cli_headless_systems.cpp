#include "cli_headless_systems.hpp"
#include <thread>
#include <mutex>
#include <map>
#include <atomic>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#endif

namespace rawrxd::cli {

class CLIHeadlessSystems::Impl {
public:
    mutable std::mutex mutex_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> shutdown_requested_{false};
    std::map<std::string, HeadlessService> services_;
    std::map<std::string, bool> service_states_;
    HeadlessHealth last_health_;
    CLIHeadlessSystems::ShutdownCallback shutdown_cb_;
    CLIHeadlessSystems::HealthChangeCallback health_cb_;

    static CLIHeadlessSystems* g_instance;
};

CLIHeadlessSystems* CLIHeadlessSystems::Impl::g_instance = nullptr;

CLIHeadlessSystems::CLIHeadlessSystems() : impl_(std::make_unique<Impl>()) {
    Impl::g_instance = this;
}
CLIHeadlessSystems::~CLIHeadlessSystems() {
    StopAllServices();
    Impl::g_instance = nullptr;
}

bool CLIHeadlessSystems::Initialize(const std::string& /*config_path*/) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->services_["inference"] = HeadlessService{"inference", "tcp://127.0.0.1:9001", true, 32, {}};
    impl_->services_["training"] = HeadlessService{"training", "tcp://127.0.0.1:9002", false, 4, {}};
    impl_->services_["bridge"] = HeadlessService{"bridge", "tcp://127.0.0.1:9003", true, 16, {}};
    impl_->initialized_.store(true);
    return true;
}

bool CLIHeadlessSystems::StartAllServices() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    bool all_ok = true;
    for (auto& [name, svc] : impl_->services_) {
        if (svc.auto_start) {
            impl_->service_states_[name] = true;
        }
    }
    return all_ok;
}

bool CLIHeadlessSystems::StopAllServices() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (auto& [name, _] : impl_->service_states_) {
        impl_->service_states_[name] = false;
    }
    return true;
}

bool CLIHeadlessSystems::IsInitialized() const {
    return impl_->initialized_.load();
}

bool CLIHeadlessSystems::StartService(const std::string& name) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->services_.find(name);
    if (it == impl_->services_.end()) return false;
    impl_->service_states_[name] = true;
    return true;
}

bool CLIHeadlessSystems::StopService(const std::string& name) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->service_states_.find(name);
    if (it == impl_->service_states_.end()) return false;
    it->second = false;
    return true;
}

bool CLIHeadlessSystems::IsServiceRunning(const std::string& name) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->service_states_.find(name);
    if (it == impl_->service_states_.end()) return false;
    return it->second;
}

std::vector<std::string> CLIHeadlessSystems::ListServices() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<std::string> out;
    for (const auto& [name, _] : impl_->services_) out.push_back(name);
    return out;
}

HeadlessHealth CLIHeadlessSystems::GetHealthSnapshot() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    HeadlessHealth h;
    h.active_connections = 0;
    h.total_requests_served = 0;
    h.memory_usage_mb = 0.0f;
    h.cpu_percent = 0.0f;
    for (const auto& [name, running] : impl_->service_states_) {
        if (!running) {
            h.all_services_healthy = false;
            h.unhealthy_services.push_back(name);
        }
    }
    impl_->last_health_ = h;
    return h;
}

bool CLIHeadlessSystems::IsHealthy() const {
    return GetHealthSnapshot().all_services_healthy;
}

void CLIHeadlessSystems::InstallSignalHandlers() {
#ifdef _WIN32
    SetConsoleCtrlHandler([](DWORD sig) -> BOOL {
        if (sig == CTRL_C_EVENT || sig == CTRL_BREAK_EVENT) {
            if (Impl::g_instance) Impl::g_instance->RequestGracefulShutdown();
            return TRUE;
        }
        return FALSE;
    }, TRUE);
#else
    struct sigaction sa;
    sa.sa_handler = [](int) {
        if (Impl::g_instance) Impl::g_instance->RequestGracefulShutdown();
    };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
#endif
}

void CLIHeadlessSystems::RequestGracefulShutdown() {
    impl_->shutdown_requested_.store(true);
    if (impl_->shutdown_cb_) impl_->shutdown_cb_();
}

bool CLIHeadlessSystems::IsShutdownRequested() const {
    return impl_->shutdown_requested_.load();
}

bool CLIHeadlessSystems::SendMessageToService(const std::string& /*service*/, const std::string& /*message*/) {
    return true;
}

std::optional<std::string> CLIHeadlessSystems::ReadMessageFromService(const std::string& /*service*/, uint32_t /*timeout_ms*/) {
    return std::nullopt;
}

void CLIHeadlessSystems::SetShutdownCallback(ShutdownCallback cb) {
    impl_->shutdown_cb_ = std::move(cb);
}

void CLIHeadlessSystems::SetHealthChangeCallback(HealthChangeCallback cb) {
    impl_->health_cb_ = std::move(cb);
}

} // namespace rawrxd::cli
