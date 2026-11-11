#include "AdaptiveFusionEngine.h"
#include "../telemetry/FeedbackCollector.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#endif

namespace RawrXD::Fusion {

// UserPersona implementation
double UserPersona::get_confidence() const {
    if (total_interactions < 10) return 0.0;
    if (total_interactions < 50) return 0.3;
    if (total_interactions < 100) return 0.6;
    if (total_interactions < 500) return 0.8;
    return 1.0;
}

// Singleton implementation
AdaptiveFusionEngine& AdaptiveFusionEngine::instance() {
    static AdaptiveFusionEngine instance;
    return instance;
}

AdaptiveFusionEngine::AdaptiveFusionEngine() 
    : m_state(), m_config() {
    m_state.alpha = DEFAULT_ALPHA;
    m_persona.persona_id = "default";
    m_persona.avg_trie_preference = DEFAULT_ALPHA;
    m_persona.avg_semantic_preference = 1.0 - DEFAULT_ALPHA;
    m_persona.total_interactions = 0;
    m_persona.tab_accepts = 0;
    m_persona.dismissals = 0;
}

AdaptiveFusionEngine::~AdaptiveFusionEngine() {
    if (m_initialized.load()) {
        shutdown();
    }
}

bool AdaptiveFusionEngine::initialize(const AdaptiveFusionConfig& config) {
    if (m_initialized.exchange(true)) {
        return true; // Already initialized
    }
    
    m_config = config;
    
    // Set initial state from config
    m_state.alpha = config.initial_alpha;
    m_state.learning_rate = config.learning_rate;
    m_state.velocity = 0.0;
    m_state.update_count = 0;
    m_state.cumulative_reward = 0.0;
    
    // Load persisted state if available
    load_state();
    
    return true;
}

double AdaptiveFusionEngine::get_weight(const std::string& context_hash) const {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    return m_state.alpha;
}

double AdaptiveFusionEngine::get_weight_confident(bool& confidence_out) const {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    confidence_out = (m_persona.total_interactions >= m_config.confidence_threshold);
    return m_state.alpha;
}

void AdaptiveFusionEngine::update_from_signal(
    RawrXD::Telemetry::InteractionSignal signal,
    const std::string& context_hash,
    float trie_score,
    float semantic_score
) {
    if (!m_initialized.load()) {
        return;
    }
    
    double reward = signal_to_reward(signal);
    
    // Update persona statistics
    {
        std::lock_guard<std::mutex> lock(m_state_mutex);
        m_persona.total_interactions++;
        m_persona.last_updated = std::chrono::system_clock::now();
        
        if (signal == RawrXD::Telemetry::InteractionSignal::TAB_ACCEPT) {
            m_persona.tab_accepts++;
        } else if (signal == RawrXD::Telemetry::InteractionSignal::DISMISS ||
                   signal == RawrXD::Telemetry::InteractionSignal::IGNORE_5S) {
            m_persona.dismissals++;
        }
        
        // Update preference averages
        double trie_pref = (signal == RawrXD::Telemetry::InteractionSignal::TAB_ACCEPT) ? 1.0 : 0.0;
        double semantic_pref = (signal == RawrXD::Telemetry::InteractionSignal::TAB_ACCEPT) ? 0.0 : 1.0;
        
        double decay = 1.0 / std::sqrt(m_persona.total_interactions + 1.0);
        m_persona.avg_trie_preference = (1.0 - decay) * m_persona.avg_trie_preference + decay * trie_pref;
        m_persona.avg_semantic_preference = (1.0 - decay) * m_persona.avg_semantic_preference + decay * semantic_pref;
    }
    
    // Apply gradient descent update
    apply_update(reward);
    
    // Notify listeners
    notify_callbacks();
    
    // Periodic save (every 10 updates)
    if (m_state.update_count % 10 == 0) {
        save_state();
    }
}

double AdaptiveFusionEngine::signal_to_reward(RawrXD::Telemetry::InteractionSignal signal) {
    switch (signal) {
        case RawrXD::Telemetry::InteractionSignal::TAB_ACCEPT:
            return REWARD_ACCEPT;
        case RawrXD::Telemetry::InteractionSignal::DISMISS:
            return REWARD_DISMISS;
        case RawrXD::Telemetry::InteractionSignal::IGNORE_5S:
            return REWARD_IGNORE;
        case RawrXD::Telemetry::InteractionSignal::EDIT_AFTER_ACCEPT:
            return REWARD_EDIT_AFTER;
        default:
            return REWARD_IGNORE;
    }
}

UserPersona AdaptiveFusionEngine::get_persona() const {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    return m_persona;
}

FusionState AdaptiveFusionEngine::get_state() const {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    return m_state;
}

void AdaptiveFusionEngine::reset() {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    m_state.alpha = m_config.initial_alpha;
    m_state.velocity = 0.0;
    m_state.learning_rate = m_config.learning_rate;
    m_state.update_count = 0;
    m_state.cumulative_reward = 0.0;
    
    m_persona.total_interactions = 0;
    m_persona.tab_accepts = 0;
    m_persona.dismissals = 0;
    m_persona.avg_trie_preference = m_config.initial_alpha;
    m_persona.avg_semantic_preference = 1.0 - m_config.initial_alpha;
}

bool AdaptiveFusionEngine::save_state() {
    std::string path = m_config.weights_path.empty() 
        ? get_default_weights_path() 
        : m_config.weights_path;
    
    // Ensure directory exists
    size_t last_slash = path.find_last_of("/\\");
    if (last_slash != std::string::npos) {
        std::string dir = path.substr(0, last_slash);
#ifdef _WIN32
        CreateDirectoryA(dir.c_str(), nullptr);
#else
        mkdir(dir.c_str(), 0755);
#endif
    }
    
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(m_state_mutex);
    
    file << "{\n";
    file << "  \"version\": 1,\n";
    file << "  \"alpha\": " << std::fixed << std::setprecision(6) << m_state.alpha << ",\n";
    file << "  \"velocity\": " << m_state.velocity << ",\n";
    file << "  \"learning_rate\": " << m_state.learning_rate << ",\n";
    file << "  \"update_count\": " << m_state.update_count << ",\n";
    file << "  \"cumulative_reward\": " << m_state.cumulative_reward << ",\n";
    file << "  \"persona\": {\n";
    file << "    \"total_interactions\": " << m_persona.total_interactions << ",\n";
    file << "    \"tab_accepts\": " << m_persona.tab_accepts << ",\n";
    file << "    \"dismissals\": " << m_persona.dismissals << ",\n";
    file << "    \"avg_trie_preference\": " << m_persona.avg_trie_preference << ",\n";
    file << "    \"avg_semantic_preference\": " << m_persona.avg_semantic_preference << "\n";
    file << "  }\n";
    file << "}\n";
    
    return file.good();
}

void AdaptiveFusionEngine::on_weight_changed(std::function<void(double)> callback) {
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    m_callbacks.push_back(std::move(callback));
}

void AdaptiveFusionEngine::shutdown() {
    if (!m_initialized.exchange(false)) {
        return;
    }
    save_state();
}

void AdaptiveFusionEngine::load_state() {
    std::string path = m_config.weights_path.empty() 
        ? get_default_weights_path() 
        : m_config.weights_path;
    
    std::ifstream file(path);
    if (!file.is_open()) {
        return; // No saved state, use defaults
    }
    
    // Simple JSON parsing (in production, use a proper library)
    std::string line;
    while (std::getline(file, line)) {
        size_t pos = line.find("\"alpha\":");
        if (pos != std::string::npos) {
            m_state.alpha = std::stod(line.substr(pos + 8));
        }
        pos = line.find("\"velocity\":");
        if (pos != std::string::npos) {
            m_state.velocity = std::stod(line.substr(pos + 11));
        }
        pos = line.find("\"learning_rate\":");
        if (pos != std::string::npos) {
            m_state.learning_rate = std::stod(line.substr(pos + 16));
        }
        pos = line.find("\"update_count\":");
        if (pos != std::string::npos) {
            m_state.update_count = std::stoi(line.substr(pos + 15));
        }
    }
}

std::string AdaptiveFusionEngine::get_default_weights_path() const {
#ifdef _WIN32
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, path))) {
        return std::string(path) + "\\RawrXD\\adaptive_weights.json";
    }
    return "C:\\RawrXD\\adaptive_weights.json";
#else
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (home) {
        return std::string(home) + "/.config/rawrxd/adaptive_weights.json";
    }
    return "/tmp/rawrxd_adaptive_weights.json";
#endif
}

void AdaptiveFusionEngine::apply_update(double reward) {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    
    // Online gradient descent with momentum
    // v_{t+1} = β·v_t + η·(R - α_t)
    double gradient = reward - m_state.alpha;
    m_state.velocity = m_config.momentum * m_state.velocity + 
                       m_state.learning_rate * gradient;
    
    // α_{t+1} = clip(α_t + v_{t+1}, min, max)
    m_state.alpha += m_state.velocity;
    m_state.alpha = std::clamp(m_state.alpha, m_config.min_alpha, m_config.max_alpha);
    
    // Decay learning rate
    m_state.learning_rate *= m_config.decay_factor;
    m_state.learning_rate = std::max(m_state.learning_rate, 0.001); // Floor at 0.1%
    
    m_state.update_count++;
    m_state.cumulative_reward += reward;
}

void AdaptiveFusionEngine::notify_callbacks() {
    double current_alpha;
    {
        std::lock_guard<std::mutex> lock(m_state_mutex);
        current_alpha = m_state.alpha;
    }
    
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    for (auto& callback : m_callbacks) {
        try {
            callback(current_alpha);
        } catch (...) {
            // Ignore callback errors
        }
    }
}

} // namespace RawrXD::Fusion
