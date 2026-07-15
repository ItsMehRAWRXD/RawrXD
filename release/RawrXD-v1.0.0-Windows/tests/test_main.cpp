#include <gtest/gtest.h>
#include "rawrxd/core/Logger.hpp"

int main(int argc, char** argv) {
    // Initialize logger for tests
    rawrxd::core::Logger::Initialize("test", rawrxd::core::LogLevel::WARN);
    
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    
    rawrxd::core::Logger::Shutdown();
    return result;
}
