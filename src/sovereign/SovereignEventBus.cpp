#include "sovereign/SovereignEventBus.hpp"
#include <algorithm>

namespace Sovereign {

// Static member definitions
std::vector<SovereignEventBus::Subscription> SovereignEventBus::s_subscriptions;
std::vector<SovereignEvent> SovereignEventBus::s_eventQueue;
std::mutex SovereignEventBus::s_subscriptionsMutex;
std::mutex SovereignEventBus::s_queueMutex;
uint32_t SovereignEventBus::s_nextSubscriptionId = 1;

uint32_t SovereignEventBus::Subscribe(SovereignEventType type, SovereignEventHandler handler) {
    std::lock_guard<std::mutex> lock(s_subscriptionsMutex);
    
    Subscription sub;
    sub.id = s_nextSubscriptionId++;
    sub.type = type;
    sub.handler = std::move(handler);
    
    s_subscriptions.push_back(std::move(sub));
    return sub.id;
}

void SovereignEventBus::Unsubscribe(uint32_t subscriptionId) {
    std::lock_guard<std::mutex> lock(s_subscriptionsMutex);
    
    s_subscriptions.erase(
        std::remove_if(s_subscriptions.begin(), s_subscriptions.end(),
            [subscriptionId](const Subscription& sub) {
                return sub.id == subscriptionId;
            }),
        s_subscriptions.end()
    );
}

void SovereignEventBus::Publish(const SovereignEvent& event) {
    std::lock_guard<std::mutex> lock(s_queueMutex);
    s_eventQueue.push_back(event);
}

void SovereignEventBus::PublishBeacon(const Beacon& beacon) {
    SovereignEvent evt{};
    evt.type = SovereignEventType::BeaconismEvent;
    evt.beacon = beacon;
    evt.timestamp = beacon.timestamp;
    evt.payload = beacon.payload;
    
    Publish(evt);
}

void SovereignEventBus::ProcessEvents() {
    // Move events from queue to local vector
    std::vector<SovereignEvent> events;
    {
        std::lock_guard<std::mutex> lock(s_queueMutex);
        events.swap(s_eventQueue);
    }
    
    if (events.empty()) return;
    
    // Get subscriptions
    std::vector<Subscription> subs;
    {
        std::lock_guard<std::mutex> lock(s_subscriptionsMutex);
        subs = s_subscriptions;
    }
    
    // Dispatch events
    for (const auto& evt : events) {
        for (const auto& sub : subs) {
            if (sub.type == evt.type || sub.type == SovereignEventType::None) {
                sub.handler(evt);
            }
        }
    }
}

} // namespace Sovereign
