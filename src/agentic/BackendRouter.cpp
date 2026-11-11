// =============================================================================
// BackendRouter.cpp — Inference Backend Router Implementation
// =============================================================================
#include "BackendRouter.h"
#include <algorithm>

namespace RawrXD {
namespace Agent {

BackendRouter::BackendRouter() = default;
BackendRouter::~BackendRouter() { Shutdown(); }

bool BackendRouter::Initialize(const RouterConfig& config) {
    if (m_initialized.load()) return true;

    m_config = config;

    // Initialize Deep2 backend (primary)
    BackendConfig deep2_cfg;
    deep2_cfg.kind     = BackendKind::Deep2;
    deep2_cfg.endpoint = config.primary_endpoint;
    deep2_cfg.model    = config.primary_model;
    if (deep2_cfg.model.empty()) deep2_cfg.model = "deep2-native";
    deep2_cfg.temperature  = 0.2f;
    deep2_cfg.top_p        = 0.9f;
    deep2_cfg.max_tokens   = 4096;
    deep2_cfg.num_ctx      = 32768;
    deep2_cfg.timeout_ms   = 120000;
    deep2_cfg.use_gpu      = true;
    deep2_cfg.num_gpu      = 99;

    m_deep2 = std::make_unique<Deep2Backend>();
    m_deep2->Initialize(deep2_cfg);

    // Initialize Ollama backend (fallback)
    BackendConfig ollama_cfg;
    ollama_cfg.kind     = BackendKind::Ollama;
    ollama_cfg.endpoint = config.fallback_endpoint;
    ollama_cfg.model    = config.fallback_model;
    if (ollama_cfg.model.empty()) ollama_cfg.model = "qwen2.5-coder:32b";
    ollama_cfg.temperature  = 0.2f;
    ollama_cfg.top_p        = 0.9f;
    ollama_cfg.max_tokens   = 4096;
    ollama_cfg.num_ctx      = 8192;
    ollama_cfg.timeout_ms   = 120000;
    ollama_cfg.use_gpu      = true;
    ollama_cfg.num_gpu      = 99;

    m_ollama = std::make_unique<OllamaBackend>();
    m_ollama->Initialize(ollama_cfg);

    // Determine active backend based on mode
    {
        std::lock_guard<std::mutex> lock(m_active_mtx);
        if (config.mode == BackendMode::Ollama) {
            m_active_kind = BackendKind::Ollama;
            m_active_model = ollama_cfg.model;
            m_active_endpoint = ollama_cfg.endpoint;
        } else {
            // Default: primary (Deep2)
            m_active_kind = BackendKind::Deep2;
            m_active_model = deep2_cfg.model;
            m_active_endpoint = deep2_cfg.endpoint;
        }
    }

    // Start health check thread
    m_health_running.store(true);
    m_health_thread = std::thread([this]() {
        while (m_health_running.load()) {
            m_deep2->CheckHealth();
            m_ollama->CheckHealth();
            std::unique_lock<std::mutex> lock(m_health_cv_mtx);
            m_health_cv.wait_for(lock, std::chrono::seconds(m_config.health_check_interval_s));
        }
    });

    m_initialized.store(true);
    return true;
}

void BackendRouter::Shutdown() {
    m_health_running.store(false);
    m_health_cv.notify_all();
    if (m_health_thread.joinable()) {
        m_health_thread.join();
    }
    if (m_deep2)   m_deep2->Shutdown();
    if (m_ollama)  m_ollama->Shutdown();
    m_initialized.store(false);
}

void BackendRouter::SetMode(BackendMode mode) {
    m_mode.store(mode);

    // Update active backend based on mode
    {
        std::lock_guard<std::mutex> lock(m_active_mtx);
        if (mode == BackendMode::Ollama) {
            m_active_kind = BackendKind::Ollama;
            m_active_model = m_config.fallback_model;
            m_active_endpoint = m_config.fallback_endpoint;
        } else {
            m_active_kind = BackendKind::Deep2;
            m_active_model = m_config.primary_model;
            m_active_endpoint = m_config.primary_endpoint;
        }
    }

    Cancel();
}

void BackendRouter::SetPrimaryModel(const std::string& model) {
    m_config.primary_model = model;
    if (m_deep2) {
        auto cfg = m_deep2->GetConfig();
        cfg.model = model;
        m_deep2->SetConfig(cfg);
    }
}

void BackendRouter::SetFallbackModel(const std::string& model) {
    m_config.fallback_model = model;
    if (m_ollama) {
        auto cfg = m_ollama->GetConfig();
        cfg.model = model;
        m_ollama->SetConfig(cfg);
    }
}

void BackendRouter::SetEndpoints(const std::string& primary, const std::string& fallback) {
    m_config.primary_endpoint = primary;
    m_config.fallback_endpoint = fallback;

    if (m_deep2) {
        auto cfg = m_deep2->GetConfig();
        cfg.endpoint = primary;
        m_deep2->SetConfig(cfg);
    }
    if (m_ollama) {
        auto cfg = m_ollama->GetConfig();
        cfg.endpoint = fallback;
        m_ollama->SetConfig(cfg);
    }
}

BackendHealth BackendRouter::GetPrimaryHealth() const {
    if (m_deep2) return m_deep2->GetHealth();
    BackendHealth h;
    h.last_error = "Deep2 backend not initialized";
    return h;
}

BackendHealth BackendRouter::GetFallbackHealth() const {
    if (m_ollama) return m_ollama->GetHealth();
    BackendHealth h;
    h.last_error = "Ollama backend not initialized";
    return h;
}

bool BackendRouter::CheckPrimaryHealth() {
    if (!m_deep2) return false;
    return m_deep2->CheckHealth();
}

bool BackendRouter::CheckFallbackHealth() {
    if (!m_ollama) return false;
    return m_ollama->CheckHealth();
}

std::vector<std::string> BackendRouter::ListModels(BackendKind preferred) {
    if (preferred == BackendKind::Ollama && m_ollama) {
        return m_ollama->ListModels();
    }
    if (preferred == BackendKind::Deep2 && m_deep2) {
        return m_deep2->ListModels();
    }
    // Default to primary
    if (m_deep2) return m_deep2->ListModels();
    if (m_ollama) return m_ollama->ListModels();
    return {};
}

BackendKind BackendRouter::SelectBackendForRequest(FailoverInfo* failover_info) {
    BackendMode mode = m_mode.load();

    if (mode == BackendMode::Ollama) {
        return BackendKind::Ollama;
    }
    if (mode == BackendMode::Deep2) {
        return BackendKind::Deep2;
    }
    if (mode == BackendMode::Manual) {
        // Use active backend
        std::lock_guard<std::mutex> lock(m_active_mtx);
        return m_active_kind;
    }

    // Auto mode: Deep2 first, Ollama fallback
    bool deep2_ok = m_deep2 && m_deep2->CheckHealth();
    if (deep2_ok) {
        return BackendKind::Deep2;
    }

    if (failover_info) {
        failover_info->did_failover     = true;
        failover_info->original_backend = BackendKind::Deep2;
        failover_info->failover_backend = BackendKind::Ollama;
        failover_info->failover_reason  = "Deep2 primary backend unavailable; routing to Ollama backup";
    }
    m_failovers.fetch_add(1);
    return BackendKind::Ollama;
}

void BackendRouter::RouteToBackend(BackendKind kind, const std::string& /*model*/) {
    std::lock_guard<std::mutex> lock(m_active_mtx);
    m_active_kind = kind;
    if (kind == BackendKind::Deep2) {
        m_active_model = m_config.primary_model;
        m_active_endpoint = m_config.primary_endpoint;
    } else {
        m_active_model = m_config.fallback_model;
        m_active_endpoint = m_config.fallback_endpoint;
    }
}

bool BackendRouter::IsBackendAvailable(BackendKind kind) {
    switch (kind) {
        case BackendKind::Deep2:
            return m_deep2 && m_deep2->CheckHealth();
        case BackendKind::Ollama:
            return m_ollama && m_ollama->CheckHealth();
        default:
            return false;
    }
}

InferenceResult BackendRouter::ChatSync(
    const std::vector<ChatMessage>& messages,
    const json& tools,
    FailoverInfo* failover_info) {

    if (!m_initialized.load()) {
        return InferenceResult::Error("BackendRouter not initialized");
    }

    m_total_requests.fetch_add(1);

    // Select backend
    BackendKind selected = SelectBackendForRequest(failover_info);

    // Route to selected backend
    InferenceBackend* backend = GetBackendPtr(selected);
    if (!backend) {
        // If auto mode and primary failed, try fallback
        if (m_mode.load() == BackendMode::Auto && selected == BackendKind::Deep2) {
            if (failover_info) {
                failover_info->did_failover = true;
                failover_info->original_backend = BackendKind::Deep2;
                failover_info->failover_backend = BackendKind::Ollama;
                failover_info->failover_reason = "Deep2 backend unavailable; routing to Ollama";
            }
            backend = GetBackendPtr(BackendKind::Ollama);
            selected = BackendKind::Ollama;
        }
        if (!backend) {
            return InferenceResult::Error("No backend available");
        }
    }

    RouteToBackend(selected, backend->GetConfig().model);
    return backend->ChatSync(messages, tools);
}

bool BackendRouter::ChatStream(
    const std::vector<ChatMessage>& messages,
    const json& tools,
    TokenCallback     on_token,
    ToolCallCallback  on_tool_call,
    DoneCallback      on_done,
    ErrorCallback     on_error,
    FailoverInfo*     failover_info) {

    if (!m_initialized.load()) {
        if (on_error) on_error("BackendRouter not initialized");
        return false;
    }

    m_total_requests.fetch_add(1);

    BackendKind selected = SelectBackendForRequest(failover_info);

    InferenceBackend* backend = GetBackendPtr(selected);
    if (!backend) {
        if (m_mode.load() == BackendMode::Auto && selected == BackendKind::Deep2) {
            if (failover_info) {
                failover_info->did_failover = true;
                failover_info->original_backend = BackendKind::Deep2;
                failover_info->failover_backend = BackendKind::Ollama;
                failover_info->failover_reason = "Deep2 backend unavailable; routing to Ollama";
            }
            backend = GetBackendPtr(BackendKind::Ollama);
            selected = BackendKind::Ollama;
        }
        if (!backend) {
            if (on_error) on_error("No backend available");
            return false;
        }
    }

    RouteToBackend(selected, backend->GetConfig().model);
    return backend->ChatStream(messages, tools, on_token, on_tool_call,
                               on_done, on_error);
}

InferenceResult BackendRouter::FIMSync(
    const std::string& prefix,
    const std::string& suffix,
    const std::string& filename,
    FailoverInfo* failover_info) {

    if (!m_initialized.load()) {
        return InferenceResult::Error("BackendRouter not initialized");
    }

    m_total_requests.fetch_add(1);

    BackendKind selected = SelectBackendForRequest(failover_info);

    InferenceBackend* backend = GetBackendPtr(selected);
    if (!backend) {
        if (m_mode.load() == BackendMode::Auto && selected == BackendKind::Deep2) {
            backend = GetBackendPtr(BackendKind::Ollama);
            selected = BackendKind::Ollama;
        }
        if (!backend) {
            return InferenceResult::Error("No backend available");
        }
    }

    RouteToBackend(selected, backend->GetConfig().model);
    return backend->FIMSync(prefix, suffix, filename);
}

bool BackendRouter::FIMStream(
    const std::string& prefix,
    const std::string& suffix,
    const std::string& filename,
    TokenCallback  on_token,
    DoneCallback   on_done,
    ErrorCallback  on_error,
    FailoverInfo*  failover_info) {

    if (!m_initialized.load()) {
        if (on_error) on_error("BackendRouter not initialized");
        return false;
    }

    m_total_requests.fetch_add(1);

    BackendKind selected = SelectBackendForRequest(failover_info);

    InferenceBackend* backend = GetBackendPtr(selected);
    if (!backend) {
        if (m_mode.load() == BackendMode::Auto && selected == BackendKind::Deep2) {
            backend = GetBackendPtr(BackendKind::Ollama);
            selected = BackendKind::Ollama;
        }
        if (!backend) {
            if (on_error) on_error("No backend available");
            return false;
        }
    }

    RouteToBackend(selected, backend->GetConfig().model);
    return backend->FIMStream(prefix, suffix, filename, on_token, on_done, on_error);
}

void BackendRouter::Cancel() {
    if (m_deep2)   m_deep2->Cancel();
    if (m_ollama)  m_ollama->Cancel();
}

bool BackendRouter::IsStreaming() const {
    if (m_deep2 && m_deep2->IsStreaming()) return true;
    if (m_ollama && m_ollama->IsStreaming()) return true;
    return false;
}

BackendKind BackendRouter::GetActiveBackendKind() const {
    std::lock_guard<std::mutex> lock(m_active_mtx);
    return m_active_kind;
}

std::string BackendRouter::GetActiveModel() const {
    std::lock_guard<std::mutex> lock(m_active_mtx);
    return m_active_model;
}

std::string BackendRouter::GetActiveEndpoint() const {
    std::lock_guard<std::mutex> lock(m_active_mtx);
    return m_active_endpoint;
}

InferenceBackend& BackendRouter::GetBackend(BackendKind kind) {
    switch (kind) {
        case BackendKind::Deep2:
            if (!m_deep2) throw std::runtime_error("Deep2 backend not initialized");
            return *m_deep2;
        case BackendKind::Ollama:
            if (!m_ollama) throw std::runtime_error("Ollama backend not initialized");
            return *m_ollama;
        default:
            throw std::runtime_error("Unknown backend kind");
    }
}

InferenceBackend* BackendRouter::GetBackendPtr(BackendKind kind) {
    switch (kind) {
        case BackendKind::Deep2:
            return m_deep2.get();
        case BackendKind::Ollama:
            return m_ollama.get();
        default:
            return nullptr;
    }
}

void BackendRouter::HealthCheckLoop() {
    // Background health checks handled in Initialize()
}

} // namespace Agent
} // namespace RawrXD
