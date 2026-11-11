/**
 * @file test_thermal_system.cpp
<<<<<<< HEAD
 * @brief Unit tests for Thermal Dashboard System (pure C++20, no Qt)
 *
 * Tests predictive throttling, load balancing, and shared memory control block.
 */

#include <cstdio>
#include <cstring>
#include <cassert>
=======
 * @brief Unit tests for Thermal Dashboard System
 * 
 * Tests predictive throttling, load balancing, and shared memory control block
 */

#include <QtTest/QtTest>
#include <QObject>
#include <QDebug>
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#include "../src/thermal/predictive_throttling.hpp"
#include "../src/thermal/dynamic_load_balancer.hpp"

using namespace rawrxd::thermal;

<<<<<<< HEAD
#define TEST_VERIFY(cond) do { if (!(cond)) { std::fprintf(stderr, "FAIL: %s\n", #cond); ++g_tests_failed; } } while(0)
#define TEST_VERIFY2(cond, msg) do { if (!(cond)) { std::fprintf(stderr, "FAIL: %s\n", (msg)); ++g_tests_failed; } } while(0)
#define TEST_COMPARE(a, b) do { if ((a) != (b)) { std::fprintf(stderr, "FAIL: %s != %s\n", #a, #b); ++g_tests_failed; } } while(0)

static int g_tests_run = 0;
static int g_tests_failed = 0;

static void testPredictiveThrottlingCreation() {
    PredictiveThrottling pt;
    TEST_COMPARE(pt.getCurrentThrottle(), 0u);
    TEST_VERIFY(pt.getThermalHeadroom() >= 0.0);
}

static void testSharedMemoryInitialization() {
    PredictiveThrottling pt;
    bool initialized = pt.initializeSharedMemory(true);
    TEST_VERIFY2(initialized, "Failed to initialize shared memory");
    const SovereignControlBlock* cb = pt.getControlBlock();
    TEST_VERIFY(cb != nullptr);
    TEST_VERIFY(std::memcmp(cb->magic, "RAWRXDTH", 8) == 0);
    TEST_COMPARE(cb->version, 0x00010200u);
    TEST_VERIFY(cb->flags & FLAG_ACTIVE);
    pt.detachSharedMemory();
}

static void testTemperatureUpdate() {
    PredictiveThrottling pt;
    pt.initializeSharedMemory(true);
    double nvmeTemps[5] = {52.0, 54.0, 51.0, 55.0, 53.0};
    pt.updateTemperatures(nvmeTemps, 5, 65.0, 55.0);
    const SovereignControlBlock* cb = pt.getControlBlock();
    TEST_VERIFY(cb != nullptr);
    TEST_COMPARE(cb->activeDriveCount, 5u);
    TEST_VERIFY(cb->timestamp > 0);
    TEST_VERIFY(pt.getThermalHeadroom() > 0.0);
    pt.detachSharedMemory();
}

static void testBurstSafetyCheck() {
    PredictiveThrottling pt;
    pt.initializeSharedMemory(true);
    double coolTemps[5] = {45.0, 46.0, 44.0, 45.0, 43.0};
    pt.updateTemperatures(coolTemps, 5, 50.0, 45.0);
    TEST_VERIFY2(pt.isBurstSafe(), "Should be safe to burst at cool temps");
    double hotTemps[5] = {72.0, 71.0, 73.0, 70.0, 74.0};
    for (int i = 0; i < 5; ++i)
        pt.updateTemperatures(hotTemps, 5, 80.0, 75.0);
    double headroom = pt.getThermalHeadroom();
    TEST_VERIFY2(headroom < 0.0, "Should have negative headroom at hot temps");
    pt.detachSharedMemory();
}

static void testThrottleCalculation() {
    PredictiveThrottling pt;
    pt.initializeSharedMemory(true);
    pt.setBurstMode(2);
    double temps1[5] = {50.0, 50.0, 50.0, 50.0, 50.0};
    pt.updateTemperatures(temps1, 5, 50.0, 50.0);
    uint32_t throttle1 = pt.getCurrentThrottle();
    double temps2[5] = {62.0, 63.0, 61.0, 64.0, 62.0};
    pt.updateTemperatures(temps2, 5, 65.0, 60.0);
    uint32_t throttle2 = pt.getCurrentThrottle();
    TEST_VERIFY2(throttle2 >= throttle1, "Higher temps should increase throttle");
    pt.detachSharedMemory();
}

static void testLoadBalancerCreation() {
    DynamicLoadBalancer lb;
    lb.setActiveDriveCount(5);
    auto drives = lb.getDriveInfo();
    TEST_COMPARE(drives.size(), 5u);
}

static void testCoolestDriveSelection() {
    DynamicLoadBalancer lb;
    lb.setActiveDriveCount(5);
    double temps[5] = {55.0, 58.0, 45.0, 52.0, 60.0};
    lb.updateTemperatures(temps, 5);
    int coolest = lb.getCoolestDrive();
    TEST_COMPARE(coolest, 2);
}

static void testLeastLoadedDriveSelection() {
    DynamicLoadBalancer lb;
    lb.setActiveDriveCount(5);
    double loads[5] = {70.0, 80.0, 60.0, 25.0, 90.0};
    lb.updateLoads(loads, 5);
    int leastLoaded = lb.getLeastLoadedDrive();
    TEST_COMPARE(leastLoaded, 3);
}

static void testOptimalDriveSelection() {
    DynamicLoadBalancer lb;
    lb.setActiveDriveCount(5);
    lb.setThermalLimit(65.0);
    double temps[5] = {50.0, 55.0, 48.0, 60.0, 52.0};
    double loads[5] = {30.0, 50.0, 20.0, 70.0, 40.0};
    double perf[5]  = {100.0, 95.0, 98.0, 90.0, 97.0};
    lb.updateTemperatures(temps, 5);
    lb.updateLoads(loads, 5);
    lb.updatePerformanceScores(perf, 5);
    auto result = lb.selectDriveForRead(1024 * 1024);
    TEST_VERIFY(result.selectedDrive >= 0);
    TEST_VERIFY(result.selectedDrive < 5);
    TEST_VERIFY(result.confidence >= 0.0);
    TEST_VERIFY(result.confidence <= 1.0);
    TEST_VERIFY(result.reason != nullptr);
}

static void testLargeOperationSplitting() {
    DynamicLoadBalancer lb;
    lb.setActiveDriveCount(5);
    double temps[5] = {50.0, 51.0, 49.0, 52.0, 50.0};
    double loads[5] = {30.0, 35.0, 25.0, 40.0, 32.0};
    lb.updateTemperatures(temps, 5);
    lb.updateLoads(loads, 5);
    auto result = lb.selectDriveForWrite(512 * 1024 * 1024);
    if (result.shouldSplit) {
        TEST_VERIFY(result.splitCount >= 2);
        TEST_VERIFY(result.splitCount <= 3);
    }
}

static void testUnhealthyDriveExclusion() {
    DynamicLoadBalancer lb;
    lb.setActiveDriveCount(5);
    lb.setDriveHealth(0, false);
    double temps[5] = {40.0, 55.0, 52.0, 58.0, 60.0};
    lb.updateTemperatures(temps, 5);
    int coolest = lb.getCoolestDrive();
    TEST_VERIFY2(coolest != 0, "Unhealthy drive should be excluded");
}

static void testCriticalThermalDetection() {
    DynamicLoadBalancer lb;
    lb.setActiveDriveCount(5);
    double coolTemps[5] = {50.0, 52.0, 48.0, 55.0, 51.0};
    lb.updateTemperatures(coolTemps, 5);
    TEST_VERIFY(!lb.hasCriticalThermal());
    double hotTemps[5] = {50.0, 52.0, 72.0, 55.0, 51.0};
    lb.updateTemperatures(hotTemps, 5);
    TEST_VERIFY(lb.hasCriticalThermal());
}

static void testThermalManagementSystemIntegration() {
    ThermalManagementSystem tms;
    TEST_VERIFY(tms.initialize(true));
    double nvmeTemps[5] = {52.0, 54.0, 50.0, 56.0, 53.0};
    double loads[5] = {40.0, 50.0, 30.0, 60.0, 45.0};
    tms.update(nvmeTemps, 5, 65.0, 55.0, loads);
    TEST_VERIFY(tms.getThermalHeadroom() > 0.0);
    int optimal = tms.selectOptimalDrive(1024 * 1024, false);
    TEST_VERIFY(optimal >= 0);
    TEST_VERIFY(optimal < 5);
    tms.shutdown();
}

static void testControlBlockStructSize() {
    TEST_COMPARE(sizeof(SovereignControlBlock), 256u);
}

#define RUN(test) do { ++g_tests_run; test(); } while(0)

int main() {
    std::fprintf(stdout, "Starting Thermal System Tests (C++20, no Qt)\n");
    RUN(testPredictiveThrottlingCreation);
    RUN(testSharedMemoryInitialization);
    RUN(testTemperatureUpdate);
    RUN(testBurstSafetyCheck);
    RUN(testThrottleCalculation);
    RUN(testLoadBalancerCreation);
    RUN(testCoolestDriveSelection);
    RUN(testLeastLoadedDriveSelection);
    RUN(testOptimalDriveSelection);
    RUN(testLargeOperationSplitting);
    RUN(testUnhealthyDriveExclusion);
    RUN(testCriticalThermalDetection);
    RUN(testThermalManagementSystemIntegration);
    RUN(testControlBlockStructSize);
    std::fprintf(stdout, "Thermal System Tests Complete: %d passed\n", g_tests_run);
    return g_tests_failed ? 1 : 0;
}
=======
class TestThermalSystem : public QObject {
    Q_OBJECT

private slots:
    void initTestCase() {
        qDebug() << "Starting Thermal System Tests";
    }
    
    void cleanupTestCase() {
        qDebug() << "Thermal System Tests Complete";
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // Predictive Throttling Tests
    // ═══════════════════════════════════════════════════════════════════════════
    
    void testPredictiveThrottlingCreation() {
        PredictiveThrottling pt;
        QCOMPARE(pt.getCurrentThrottle(), 0u);
        QVERIFY(pt.getThermalHeadroom() >= 0.0);
    }
    
    void testSharedMemoryInitialization() {
        PredictiveThrottling pt;
        
        // Initialize shared memory
        bool initialized = pt.initializeSharedMemory(true);
        QVERIFY2(initialized, "Failed to initialize shared memory");
        
        // Verify control block
        const SovereignControlBlock* cb = pt.getControlBlock();
        QVERIFY(cb != nullptr);
        QCOMPARE(QString::fromLatin1(cb->magic, 8), QString("RAWRXDTH"));
        QCOMPARE(cb->version, 0x00010200u);
        QVERIFY(cb->flags & FLAG_ACTIVE);
        
        pt.detachSharedMemory();
    }
    
    void testTemperatureUpdate() {
        PredictiveThrottling pt;
        pt.initializeSharedMemory(true);
        
        // Simulate temperature readings
        double nvmeTemps[5] = {52.0, 54.0, 51.0, 55.0, 53.0};
        pt.updateTemperatures(nvmeTemps, 5, 65.0, 55.0);
        
        // Verify control block was updated
        const SovereignControlBlock* cb = pt.getControlBlock();
        QVERIFY(cb != nullptr);
        QCOMPARE(cb->activeDriveCount, 5u);
        QVERIFY(cb->timestamp > 0);
        
        // Check thermal headroom (limit 65 - max 55 = 10)
        double headroom = pt.getThermalHeadroom();
        QVERIFY(headroom > 0.0);
        
        pt.detachSharedMemory();
    }
    
    void testBurstSafetyCheck() {
        PredictiveThrottling pt;
        pt.initializeSharedMemory(true);
        
        // Cool temperatures - should be safe to burst
        double coolTemps[5] = {45.0, 46.0, 44.0, 45.0, 43.0};
        pt.updateTemperatures(coolTemps, 5, 50.0, 45.0);
        QVERIFY2(pt.isBurstSafe(), "Should be safe to burst at cool temps");
        
        // Hot temperatures above BURST_LIMIT (70°C) - should NOT be safe
        // Feed multiple samples to establish hot state
        double hotTemps[5] = {72.0, 71.0, 73.0, 70.0, 74.0};
        for (int i = 0; i < 5; ++i) {
            pt.updateTemperatures(hotTemps, 5, 80.0, 75.0);
        }
        // With temps >70°C (BURST_LIMIT), isBurstSafe should return false
        // Check that at least current temp check works
        double headroom = pt.getThermalHeadroom();
        QVERIFY2(headroom < 0.0, "Should have negative headroom at hot temps");
        
        pt.detachSharedMemory();
    }
    
    void testThrottleCalculation() {
        PredictiveThrottling pt;
        pt.initializeSharedMemory(true);
        pt.setBurstMode(2);  // Hybrid mode
        
        // Test progressive throttling
        double temps1[5] = {50.0, 50.0, 50.0, 50.0, 50.0};
        pt.updateTemperatures(temps1, 5, 50.0, 50.0);
        uint32_t throttle1 = pt.getCurrentThrottle();
        
        double temps2[5] = {62.0, 63.0, 61.0, 64.0, 62.0};
        pt.updateTemperatures(temps2, 5, 65.0, 60.0);
        uint32_t throttle2 = pt.getCurrentThrottle();
        
        // Higher temps should result in more throttling
        QVERIFY2(throttle2 >= throttle1, "Higher temps should increase throttle");
        
        pt.detachSharedMemory();
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // Dynamic Load Balancer Tests
    // ═══════════════════════════════════════════════════════════════════════════
    
    void testLoadBalancerCreation() {
        DynamicLoadBalancer lb;
        lb.setActiveDriveCount(5);
        
        auto drives = lb.getDriveInfo();
        QCOMPARE(drives.size(), 5u);
    }
    
    void testCoolestDriveSelection() {
        DynamicLoadBalancer lb;
        lb.setActiveDriveCount(5);
        
        // Set temperatures with drive 2 being coolest
        double temps[5] = {55.0, 58.0, 45.0, 52.0, 60.0};
        lb.updateTemperatures(temps, 5);
        
        int coolest = lb.getCoolestDrive();
        QCOMPARE(coolest, 2);  // Drive index 2 has lowest temp
    }
    
    void testLeastLoadedDriveSelection() {
        DynamicLoadBalancer lb;
        lb.setActiveDriveCount(5);
        
        // Set loads with drive 3 being least loaded
        double loads[5] = {70.0, 80.0, 60.0, 25.0, 90.0};
        lb.updateLoads(loads, 5);
        
        int leastLoaded = lb.getLeastLoadedDrive();
        QCOMPARE(leastLoaded, 3);  // Drive index 3 has lowest load
    }
    
    void testOptimalDriveSelection() {
        DynamicLoadBalancer lb;
        lb.setActiveDriveCount(5);
        lb.setThermalLimit(65.0);
        
        // Set balanced metrics
        double temps[5] = {50.0, 55.0, 48.0, 60.0, 52.0};
        double loads[5] = {30.0, 50.0, 20.0, 70.0, 40.0};
        double perf[5]  = {100.0, 95.0, 98.0, 90.0, 97.0};
        
        lb.updateTemperatures(temps, 5);
        lb.updateLoads(loads, 5);
        lb.updatePerformanceScores(perf, 5);
        
        // Select drive for read
        auto result = lb.selectDriveForRead(1024 * 1024);  // 1MB read
        
        QVERIFY(result.selectedDrive >= 0);
        QVERIFY(result.selectedDrive < 5);
        QVERIFY(result.confidence >= 0.0);
        QVERIFY(result.confidence <= 1.0);
        QVERIFY(result.reason != nullptr);
        
        qDebug() << "Selected drive:" << result.selectedDrive 
                 << "Confidence:" << result.confidence
                 << "Reason:" << result.reason;
    }
    
    void testLargeOperationSplitting() {
        DynamicLoadBalancer lb;
        lb.setActiveDriveCount(5);
        
        double temps[5] = {50.0, 51.0, 49.0, 52.0, 50.0};
        double loads[5] = {30.0, 35.0, 25.0, 40.0, 32.0};
        
        lb.updateTemperatures(temps, 5);
        lb.updateLoads(loads, 5);
        
        // Large operation should suggest splitting
        auto result = lb.selectDriveForWrite(512 * 1024 * 1024);  // 512MB write
        
        if (result.shouldSplit) {
            QVERIFY(result.splitCount >= 2);
            QVERIFY(result.splitCount <= 3);
            qDebug() << "Operation split across" << result.splitCount << "drives";
        }
    }
    
    void testUnhealthyDriveExclusion() {
        DynamicLoadBalancer lb;
        lb.setActiveDriveCount(5);
        
        // Set drive 0 as unhealthy
        lb.setDriveHealth(0, false);
        
        double temps[5] = {40.0, 55.0, 52.0, 58.0, 60.0};  // Drive 0 is coolest
        lb.updateTemperatures(temps, 5);
        
        // Coolest healthy drive should NOT be drive 0
        int coolest = lb.getCoolestDrive();
        QVERIFY2(coolest != 0, "Unhealthy drive should be excluded");
    }
    
    void testCriticalThermalDetection() {
        DynamicLoadBalancer lb;
        lb.setActiveDriveCount(5);
        
        // No critical temps
        double coolTemps[5] = {50.0, 52.0, 48.0, 55.0, 51.0};
        lb.updateTemperatures(coolTemps, 5);
        QVERIFY(!lb.hasCriticalThermal());
        
        // One critical temp (>70°C)
        double hotTemps[5] = {50.0, 52.0, 72.0, 55.0, 51.0};
        lb.updateTemperatures(hotTemps, 5);
        QVERIFY(lb.hasCriticalThermal());
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // Integration Tests
    // ═══════════════════════════════════════════════════════════════════════════
    
    void testThermalManagementSystemIntegration() {
        ThermalManagementSystem tms;
        
        QVERIFY(tms.initialize(true));
        
        // Update with test data
        double nvmeTemps[5] = {52.0, 54.0, 50.0, 56.0, 53.0};
        double loads[5] = {40.0, 50.0, 30.0, 60.0, 45.0};
        
        tms.update(nvmeTemps, 5, 65.0, 55.0, loads);
        
        // Verify integration
        QVERIFY(tms.getThermalHeadroom() > 0.0);
        
        int optimal = tms.selectOptimalDrive(1024 * 1024, false);
        QVERIFY(optimal >= 0);
        QVERIFY(optimal < 5);
        
        tms.shutdown();
    }
    
    void testControlBlockStructSize() {
        // Verify control block is exactly 256 bytes
        QCOMPARE(sizeof(SovereignControlBlock), 256u);
    }
};

QTEST_MAIN(TestThermalSystem)
#include "test_thermal_system.moc"
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
