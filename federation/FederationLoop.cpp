#include "federation/FederationLoop.hpp"
#include "federation/FederationGraph.hpp"
#include "federation/CrossClusterCoordinator.hpp"
#include "federation/NegotiationProtocol.hpp"
#include "federation/FederatedIdentity.hpp"
#include "federation/GlobalResourceEconomy.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void FederationLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    FederationGraph::Init();
    CrossClusterCoordinator::Init();
    NegotiationProtocol::Init();
    FederatedIdentity::Init();
    GlobalResourceEconomy::Init();
    s_initialized = true;
}

void FederationLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all federation components
    FederationGraph::OnTick();
    CrossClusterCoordinator::OnTick();
    NegotiationProtocol::OnTick();
    FederatedIdentity::OnTick();
    GlobalResourceEconomy::OnTick();
}

bool FederationLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
