#!/usr/bin/env node

// RawrZ Stealth Engine Integration Test
const rawrzEngine = require('./src/engines/rawrz-engine');

class StealthIntegrationTester {
    constructor() {
        this.testResults = [];
    }

    async runIntegrationTest() {
        console.log('🔗 RawrZ Stealth Engine Integration Test');
        console.log('========================================\n');

        try {
            // Initialize the main RawrZ engine
            console.log('🚀 Initializing RawrZ Engine...');
            await rawrzEngine.initializeModules();
            console.log('✅ RawrZ Engine initialized successfully\n');

            // Test stealth integration through main engine
            await this.testStealthIntegration();
            
            // Test stealth with different modes
            await this.testStealthModes();
            
            // Test stealth status and monitoring
            await this.testStealthMonitoring();
            
            // Display results
            this.displayResults();
            
        } catch (error) {
            console.error('❌ Integration test failed:', error.message);
            process.exit(1);
        }
    }

    async testStealthIntegration() {
        console.log('🧪 Testing Stealth Engine Integration...');
        
        try {
            // Test stealth through main engine
            const result = await rawrzEngine.enableStealth('full');
            
            if (result && result.enabled) {
                this.recordTest('Stealth Integration', true, 
                    `Stealth enabled through main engine: ${result.mode} mode`);
                
                if (result.capabilities) {
                    const capabilityCount = Object.keys(result.capabilities).length;
                    this.recordTest('Capability Integration', true, 
                        `${capabilityCount} capabilities integrated successfully`);
                }
                
                if (result.status) {
                    this.recordTest('Status Integration', true, 
                        'Status tracking integrated successfully');
                }
            } else {
                this.recordTest('Stealth Integration', false, 
                    'Stealth not properly enabled through main engine');
            }
            
        } catch (error) {
            this.recordTest('Stealth Integration', false, 
                `Integration error: ${error.message}`);
        }
    }

    async testStealthModes() {
        console.log('\n🧪 Testing Stealth Modes Integration...');
        
        const modes = ['basic', 'standard', 'full', 'maximum'];
        
        for (const mode of modes) {
            try {
                const result = await rawrzEngine.enableStealth(mode);
                
                if (result && result.enabled && result.mode === mode) {
                    this.recordTest(`Mode: ${mode}`, true, 
                        `Mode enabled with ${Object.keys(result.capabilities || {}).length} capabilities`);
                } else {
                    this.recordTest(`Mode: ${mode}`, false, 
                        'Mode not properly enabled through integration');
                }
            } catch (error) {
                this.recordTest(`Mode: ${mode}`, false, 
                    `Mode error: ${error.message}`);
            }
        }
    }

    async testStealthMonitoring() {
        console.log('\n🧪 Testing Stealth Monitoring Integration...');
        
        try {
            // Test if we can access stealth status through the engine
            const stealthModule = rawrzEngine.modules.get('stealth');
            
            if (stealthModule) {
                const status = stealthModule.getStatus();
                
                if (status) {
                    this.recordTest('Status Monitoring', true, 
                        `Status accessible: ${status.enabled ? 'enabled' : 'disabled'}`);
                    
                    if (status.availableModes) {
                        this.recordTest('Mode Monitoring', true, 
                            `${status.availableModes.length} modes available`);
                    }
                    
                    if (status.detectionMethods) {
                        const methodCount = Object.keys(status.detectionMethods).length;
                        this.recordTest('Method Monitoring', true, 
                            `${methodCount} detection method categories available`);
                    }
                } else {
                    this.recordTest('Status Monitoring', false, 
                        'Status not accessible through integration');
                }
            } else {
                this.recordTest('Stealth Module Access', false, 
                    'Stealth module not accessible through main engine');
            }
            
        } catch (error) {
            this.recordTest('Stealth Monitoring', false, 
                `Monitoring error: ${error.message}`);
        }
    }

    recordTest(testName, passed, message) {
        this.testResults.push({ testName, passed, message });
        
        if (passed) {
            console.log(`✅ ${testName}: ${message}`);
        } else {
            console.log(`❌ ${testName}: ${message}`);
        }
    }

    displayResults() {
        console.log('\n📊 Integration Test Results');
        console.log('===========================');
        
        const passed = this.testResults.filter(r => r.passed).length;
        const total = this.testResults.length;
        const successRate = ((passed / total) * 100).toFixed(1);
        
        console.log(`Total Tests: ${total}`);
        console.log(`Passed: ${passed} ✅`);
        console.log(`Failed: ${total - passed} ❌`);
        console.log(`Success Rate: ${successRate}%`);
        
        if (total - passed > 0) {
            console.log('\n❌ Failed Tests:');
            this.testResults
                .filter(r => !r.passed)
                .forEach(r => console.log(`  - ${r.testName}: ${r.message}`));
        }
        
        console.log('\n🎯 Integration Test Complete!');
        
        if (passed === total) {
            console.log('🎉 All integration tests passed! Stealth engine is fully integrated.');
            process.exit(0);
        } else {
            console.log('⚠️  Some integration tests failed. Please review the results above.');
            process.exit(1);
        }
    }
}

// Run the integration test
async function main() {
    const tester = new StealthIntegrationTester();
    await tester.runIntegrationTest();
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('❌ Integration test failed:', error.message);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection:', reason);
    process.exit(1);
});

// Run tests if this file is executed directly
if (require.main === module) {
    main().catch(error => {
        console.error('❌ Integration test failed:', error.message);
        process.exit(1);
    });
}

module.exports = StealthIntegrationTester;
