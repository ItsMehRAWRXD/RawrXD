#pragma once

#include <functional>
#include <vector>
#include <mutex>
#include "Beaconism.hpp"

namespace Sovereign {

/**
 * @brief Event types for the sovereign event bus
 */
enum class SovereignEventType : uint32_t {
    None = 0,
    BeaconismEvent = 1,
    TelemetryEvent = 2,
    ModelLoaded = 3,
    ModelError = 4,
    InferenceStart = 5,
    InferenceComplete = 6,
    HealthWarning = 7,
    HealthCritical = 8
};

/**
 * @brief Event structure for the sovereign event bus
 */
struct SovereignEvent {
    SovereignEventType type;
    Beacon beacon;
    uint64_t timestamp;
    uint32_t payload;
};

/**
 * @brief Event handler type
 */
using SovereignEventHandler = std::function<void(const SovereignEvent&)>;

/**
 * @brief Thread-safe event bus for sovereign subsystem communication
 * 
 * Used to broadcast events from Beaconism and other subsystems to
 * IDE panels and other listeners.
 */
class SovereignEventBus {
public:
    /**
     * @brief Subscribe to events of a specific type
     * @param type Event type to subscribe to
     * @param handler Callback function to invoke when event occurs
     * @return Subscription ID for unsubscribing
     */
    static uint32_t Subscribe(SovereignEventType type, SovereignEventHandler handler);

    /**
     * @brief Unsubscribe from events
     * @param subscriptionId ID returned by Subscribe
     */
    static void Unsubscribe(uint32_t subscriptionId);

    /**
     * @brief Publish an event to all subscribers
     * @param event The event to publish
     */
    static void Publish(const SovereignEvent& event);

    /**
     * @brief Publish a Beaconism event (convenience overload)
     * @param beacon The beacon to publish
     */
    static void PublishBeacon(const Beacon& beacon);

    /**
     * @brief Process pending events (call from main thread)
     */
    static void ProcessEvents();

private:
    struct Subscription {
        uint32_t id;
        SovereignEventType type;
        SovereignEventHandler handler;
    };

    static std::vector<Subscription> s_subscriptions;
    static std::vector<SovereignEvent> s_eventQueue;
    static std::mutex s_subscriptionsMutex;
    static std::mutex s_queueMutex;
    static uint32_t s_nextSubscriptionId;
};

} // namespace Sovereign
