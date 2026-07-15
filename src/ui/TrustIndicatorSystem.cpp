#include "TrustIndicatorSystem.h"
#include "../lora/LoRAAdapterManager.h"
#include "../telemetry/FeedbackCollector.h"
#include <algorithm>

namespace RawrXD {

// TrustMetadata implementation
TrustIndicatorType TrustMetadata::get_indicator_type() const {
    if (is_learning) {
        return TrustIndicatorType::LEARNED;
    }
    if (is_personalized) {
        return TrustIndicatorType::PERSONALIZED;
    }
    if (lora_contribution > 0.3f) {
        return TrustIndicatorType::PERSONALIZED;
    }
    if (semantic_contribution > 0.7f) {
        return TrustIndicatorType::SEMANTIC;
    }
    if (trie_contribution > 0.7f) {
        return TrustIndicatorType::SYNTACTIC;
    }
    if (confidence_score > 0.9f) {
        return TrustIndicatorType::CONFIDENT;
    }
    if (confidence_score < 0.5f) {
        return TrustIndicatorType::EXPERIMENTAL;
    }
    return TrustIndicatorType::HYBRID;
}

std::string TrustMetadata::get_description() const {
    switch (get_indicator_type()) {
        case TrustIndicatorType::LEARNED:
            return "Learned from your feedback";
        case TrustIndicatorType::PERSONALIZED:
            return "Personalized: " + origin_description;
        case TrustIndicatorType::SEMANTIC:
            return "Semantic match (AI-powered)";
        case TrustIndicatorType::SYNTACTIC:
            return "Syntactic match (exact)";
        case TrustIndicatorType::HYBRID:
            return "Hybrid: " + std::to_string(static_cast<int>(trie_contribution * 100)) + 
                   "% syntax, " + std::to_string(static_cast<int>(semantic_contribution * 100)) + "% semantic";
        case TrustIndicatorType::CONFIDENT:
            return "High confidence prediction";
        case TrustIndicatorType::EXPERIMENTAL:
            return "Experimental suggestion";
        default:
            return "Standard suggestion";
    }
}

std::string TrustMetadata::get_css_class() const {
    switch (get_indicator_type()) {
        case TrustIndicatorType::LEARNED:
            return "badge-learned";
        case TrustIndicatorType::PERSONALIZED:
            return "badge-personalized";
        case TrustIndicatorType::SEMANTIC:
            return "badge-semantic";
        case TrustIndicatorType::SYNTACTIC:
            return "badge-syntactic";
        case TrustIndicatorType::HYBRID:
            return "badge-hybrid";
        case TrustIndicatorType::CONFIDENT:
            return "badge-confident";
        case TrustIndicatorType::EXPERIMENTAL:
            return "badge-experimental";
        default:
            return "badge-default";
    }
}

// Singleton implementation
TrustIndicatorSystem& TrustIndicatorSystem::instance() {
    static TrustIndicatorSystem inst;
    return inst;
}

TrustIndicatorSystem::~TrustIndicatorSystem() {
    if (m_initialized.load()) {
        shutdown();
    }
}

bool TrustIndicatorSystem::initialize() {
    if (m_initialized.exchange(true)) {
        return true;
    }
    
    // Initialize with default metadata
    std::lock_guard<std::mutex> lock(m_metadata_mutex);
    m_active_metadata = TrustMetadata();
    
    return true;
}

int TrustIndicatorSystem::register_observer(std::weak_ptr<ITrustIndicatorObserver> observer) {
    std::lock_guard<std::mutex> lock(m_observers_mutex);
    int id = m_next_observer_id++;
    m_observers.emplace_back(id, observer);
    return id;
}

void TrustIndicatorSystem::unregister_observer(int observer_id) {
    std::lock_guard<std::mutex> lock(m_observers_mutex);
    m_observers.erase(
        std::remove_if(m_observers.begin(), m_observers.end(),
            [observer_id](const auto& pair) { return pair.first == observer_id; }),
        m_observers.end()
    );
}

void TrustIndicatorSystem::report_completion(const CompletionReport& report) {
    if (!m_enabled.load()) return;
    
    // Update active metadata
    {
        std::lock_guard<std::mutex> lock(m_metadata_mutex);
        m_active_metadata = report.trust;
    }
    
    // Queue notification
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        Notification notif;
        notif.type = Notification::COMPLETION;
        notif.report = report;
        m_notification_queue.push(notif);
    }
    
    // Process immediately if on UI thread
    process_notifications();
}

void TrustIndicatorSystem::report_training_state(
    const std::string& adapter_id,
    bool is_training,
    float progress
) {
    if (!m_enabled.load()) return;
    
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        Notification notif;
        notif.type = Notification::TRAINING_STATE;
        notif.adapter_id = adapter_id;
        notif.is_training = is_training;
        notif.progress = progress;
        m_notification_queue.push(notif);
    }
    
    process_notifications();
}

void TrustIndicatorSystem::report_adapter_swap(
    const std::string& old_adapter,
    const std::string& new_adapter
) {
    if (!m_enabled.load()) return;
    
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        Notification notif;
        notif.type = Notification::ADAPTER_SWAP;
        notif.old_adapter = old_adapter;
        notif.new_adapter = new_adapter;
        m_notification_queue.push(notif);
    }
    
    process_notifications();
}

TrustMetadata TrustIndicatorSystem::get_active_metadata() const {
    std::lock_guard<std::mutex> lock(m_metadata_mutex);
    return m_active_metadata;
}

void TrustIndicatorSystem::shutdown() {
    m_enabled.store(false);
    m_initialized.store(false);
    
    std::lock_guard<std::mutex> lock(m_observers_mutex);
    m_observers.clear();
}

void TrustIndicatorSystem::process_notifications() {
    // Process all pending notifications
    std::queue<Notification> notifications;
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        std::swap(notifications, m_notification_queue);
    }
    
    while (!notifications.empty()) {
        const auto& notif = notifications.front();
        
        switch (notif.type) {
            case Notification::COMPLETION:
                notify_observers(notif.report);
                break;
            case Notification::TRAINING_STATE:
                notify_training_state(notif.adapter_id, notif.is_training, notif.progress);
                break;
            case Notification::ADAPTER_SWAP:
                notify_adapter_swap(notif.old_adapter, notif.new_adapter);
                break;
        }
        
        notifications.pop();
    }
}

void TrustIndicatorSystem::notify_observers(const CompletionReport& report) {
    std::lock_guard<std::mutex> lock(m_observers_mutex);
    
    for (auto& [id, weak_observer] : m_observers) {
        if (auto observer = weak_observer.lock()) {
            observer->on_completion_generated(report);
        }
    }
}

void TrustIndicatorSystem::notify_training_state(
    const std::string& adapter_id,
    bool is_training,
    float progress
) {
    std::lock_guard<std::mutex> lock(m_observers_mutex);
    
    for (auto& [id, weak_observer] : m_observers) {
        if (auto observer = weak_observer.lock()) {
            observer->on_training_state_changed(adapter_id, is_training, progress);
        }
    }
}

void TrustIndicatorSystem::notify_adapter_swap(
    const std::string& old_adapter,
    const std::string& new_adapter
) {
    std::lock_guard<std::mutex> lock(m_observers_mutex);
    
    for (auto& [id, weak_observer] : m_observers) {
        if (auto observer = weak_observer.lock()) {
            observer->on_adapter_swapped(old_adapter, new_adapter);
        }
    }
}

} // namespace RawrXD
