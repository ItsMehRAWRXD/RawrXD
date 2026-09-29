// ============================================================================
// RuntimeKernel.cpp — Universal execution kernel implementation
// ============================================================================
#include "RuntimeKernel.hpp"
#include <iostream>
#include <chrono>

namespace rawrxd::runtime {

bool RuntimeKernel::bootstrap() {
    state_.recordBoot();
    state_.mode.store(RuntimeMode::Boot, std::memory_order_release);
    return discover() && admit() && initialize();
}

CapabilityContext RuntimeKernel::createContext(const std::string& requestId) {
    CapabilityContext ctx;
    ctx.kernel = this;
    ctx.registry = &registry_;
    ctx.requestId = requestId;
    ctx.startTime = std::chrono::steady_clock::now();
    return ctx;
}

bool RuntimeKernel::runPhase(const char* phaseName,
                              bool (RuntimeCapability::*phase)(CapabilityContext&)) {
    auto caps = registry_.all();
    bool allPass = true;
    for (auto* cap : caps) {
        auto ctx = createContext(std::string(cap->name()) + "." + phaseName);
        bool ok = (cap->*phase)(ctx);
        emitEvidence(std::string(cap->name()), phaseName, ok,
                     ok ? "" : "capability phase failed");
        if (!ok) {
            allPass = false;
            state_.capabilitiesFailed.fetch_add(1, std::memory_order_relaxed);
        }
    }
    return allPass;
}

bool RuntimeKernel::discover() {
    return runPhase("discover", &RuntimeCapability::discover);
}

bool RuntimeKernel::admit() {
    bool ok = runPhase("admit", &RuntimeCapability::admit);
    if (ok) state_.capabilitiesAdmitted.store(registry_.size(),
                                               std::memory_order_release);
    return ok;
}

bool RuntimeKernel::initialize() {
    bool ok = runPhase("initialize", &RuntimeCapability::initialize);
    if (ok) {
        state_.mode.store(RuntimeMode::Running, std::memory_order_release);
        state_.healthy.store(true, std::memory_order_release);
    }
    return ok;
}

bool RuntimeKernel::execute() {
    state_.executionCount.fetch_add(1, std::memory_order_relaxed);
    return runPhase("execute", &RuntimeCapability::execute);
}

bool RuntimeKernel::observe() {
    return runPhase("observe", &RuntimeCapability::observe);
}

bool RuntimeKernel::verify() {
    state_.verificationCount.fetch_add(1, std::memory_order_relaxed);
    return runPhase("verify", &RuntimeCapability::verify);
}

bool RuntimeKernel::commit() {
    return runPhase("commit", &RuntimeCapability::commit);
}

bool RuntimeKernel::persist() {
    return runPhase("persist", &RuntimeCapability::persist);
}

bool RuntimeKernel::shutdown() {
    state_.mode.store(RuntimeMode::ShuttingDown, std::memory_order_release);
    runPhase("shutdown", &RuntimeCapability::shutdown);
    state_.mode.store(RuntimeMode::Shutdown, std::memory_order_release);
    state_.healthy.store(false, std::memory_order_release);
    return true;
}

} // namespace rawrxd::runtime