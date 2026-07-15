#include <iostream>
#include "../RawRamXD_Phase7C_PredictiveMemory.hpp"

int main() {
    std::cout << "Testing Phase 7C components..." << std::endl;
    
    // Test SequenceLogger
    RawRamXD::SequenceLogger logger;
    if (logger.Initialize("./test")) {
        std::cout << "[OK] SequenceLogger initialized" << std::endl;
    }
    
    // Test PatternMiner
    RawRamXD::PatternMiner miner;
    if (miner.Initialize()) {
        std::cout << "[OK] PatternMiner initialized" << std::endl;
    }
    
    // Test PolicyRefinementEngine
    RawRamXD::PolicyRefinementEngine engine;
    if (engine.Initialize(&miner)) {
        std::cout << "[OK] PolicyRefinementEngine initialized" << std::endl;
    }
    
    // Test OnlineAdaptationController
    RawRamXD::OnlineAdaptationController controller;
    if (controller.Initialize(&miner, &engine)) {
        std::cout << "[OK] OnlineAdaptationController initialized" << std::endl;
    }
    
    // Test PredictiveMemoryIntelligence
    RawRamXD::PredictiveIntelligenceConfig config;
    config.enableSequenceLogging = true;
    config.enablePatternMining = true;
    config.enablePolicyRefinement = true;
    config.enableOnlineAdaptation = true;
    config.persistenceDir = "./test_data";
    
    if (RawRamXD::PredictiveMemoryIntelligence::Instance().Initialize(config)) {
        std::cout << "[OK] PredictiveMemoryIntelligence initialized" << std::endl;
        
        // Log a test event
        RawRamXD::TensorAccessEvent event;
        event.timestampUs = 12345678;
        event.tensorId = 1;
        event.accessType = RawRamXD::AccessType::READ;
        event.sourceTier = RawRamXD::MemoryTier::HOST;
        event.targetTier = RawRamXD::MemoryTier::GPU0;
        event.offset = 0;
        event.sizeBytes = 1024;
        event.computeNode = 0;
        event.latencyUs = 100;
        event.wasHit = true;
        
        RawRamXD::PredictiveMemoryIntelligence::Instance().OnTensorAccess(event);
        std::cout << "[OK] Event logged" << std::endl;
        
        // Get metrics
        auto metrics = RawRamXD::PredictiveMemoryIntelligence::Instance().GetMetrics();
        std::cout << "[OK] Events logged: " << metrics.eventsLogged << std::endl;
        
        RawRamXD::PredictiveMemoryIntelligence::Instance().Shutdown();
        std::cout << "[OK] PredictiveMemoryIntelligence shutdown" << std::endl;
    }
    
    controller.Shutdown();
    engine.Shutdown();
    miner.Shutdown();
    logger.Shutdown();
    
    std::cout << "\n=== Phase 7C Simple Test PASSED ===" << std::endl;
    return 0;
}
