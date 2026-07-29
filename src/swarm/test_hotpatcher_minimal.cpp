// Minimal test for SwarmHotpatcher
#include "SwarmHotpatcher.hpp"
#include <iostream>

int main() {
    std::cout << "SwarmHotpatcher Test\n";
    
    Sovereign::SwarmHotpatcher& hotpatcher = Sovereign::SwarmHotpatcher::GetInstance();
    
    if (hotpatcher.Initialize()) {
        std::cout << "Initialized successfully\n";
        std::cout << "Total gates: " << hotpatcher.GetTotalGateCount() << "\n";
        hotpatcher.Shutdown();
        std::cout << "Shutdown complete\n";
        return 0;
    }
    
    return 1;
}
