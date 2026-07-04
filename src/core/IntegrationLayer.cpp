// ============================================================================
// RawrXD Integration Layer - Phase 4 Implementation
// Wires all subsystems together
// ============================================================================

#include "IntegrationLayer.hpp"
#include <cstdio>

namespace RawrXD {

IntegrationLayer& IntegrationLayer::Instance() {
    static IntegrationLayer instance;
    return instance;
}

bool IntegrationLayer::Initialize(ComponentType componentType) {
    if (m_initialized.load()) {
        printf("[IntegrationLayer] Already initialized\n");
        return true;
    }

    printf("[IntegrationLayer] Initializing...\n");

    // Set version info
    m_version = GetCurrentVersion(componentType);
    printf("[IntegrationLayer] Version: %s\n", m_version.ToString().c_str());

    // Initialize session state (Phase 1)
    m_sessionState = std::make_unique<UnifiedSessionState>();
    if (!m_sessionState->Initialize()) {
        printf("[IntegrationLayer] ERROR: Failed to initialize session state\n");
        return false;
    }

    // Initialize command queue (Phase 3)
    if (!g_CommandQueue.Initialize()) {
        printf("[IntegrationLayer] ERROR: Failed to initialize command queue\n");
        return false;
    }

    // Start worker thread
    if (!g_CommandQueue.StartWorker(ProcessCommand)) {
        printf("[IntegrationLayer] ERROR: Failed to start worker thread\n");
        return false;
    }

    m_initialized.store(true);
    printf("[IntegrationLayer] Initialization complete\n");
    return true;
}

void IntegrationLayer::Shutdown() {
    if (!m_initialized.load()) {
        return;
    }

    printf("[IntegrationLayer] Shutting down...\n");
    m_running.store(false);

    // Stop command queue worker
    g_CommandQueue.Shutdown();

    // Cleanup session state
    m_sessionState.reset();

    m_initialized.store(false);
    printf("[IntegrationLayer] Shutdown complete\n");
}

void IntegrationLayer::RunEventLoop() {
    if (!m_initialized.load()) {
        printf("[IntegrationLayer] ERROR: Not initialized\n");
        return;
    }

    m_running.store(true);
    printf("[IntegrationLayer] Event loop started\n");

    while (m_running.load()) {
        PollAndDispatch();
        
        // Small yield to prevent busy-waiting
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }

    printf("[IntegrationLayer] Event loop stopped\n");
}

bool IntegrationLayer::PollAndDispatch() {
    if (!m_sessionState) {
        return false;
    }

    // Poll for events from shared memory
    SharedEventFrame frame;
    if (m_sessionState->PopEvent(frame)) {
        // Dispatch to command queue
        g_CommandQueue.PushEvent(frame);
        
        // Call monitoring callback if set
        if (m_eventCallback) {
            m_eventCallback(frame);
        }
        
        return true;
    }

    return false;
}

bool IntegrationLayer::RegisterCommand(uint32_t hash, CommandHandler handler) {
    return g_CommandRouter.Register(hash, handler);
}

bool IntegrationLayer::PushEvent(uint32_t eventType, const void* payload, uint32_t len) {
    return g_CommandQueue.Push(eventType, payload, len);
}

void IntegrationLayer::ProcessCommand(CommandJob* job) {
    if (!job) return;

    // Route to handler via CommandRouter
    CommandContext ctx;
    ctx.eventId = job->commandHash;
    ctx.payload = job->payload;
    ctx.payloadLen = job->payloadLen;
    ctx.timestamp = job->timestamp;
    ctx.sourceComponent = job->sourceComponent;

    g_CommandRouter.Route(job->commandHash, ctx);
}

} // namespace RawrXD
