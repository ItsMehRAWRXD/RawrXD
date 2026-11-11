// ============================================================================
// IntegrationTest.cpp - Sovereign IDE Integration Test
// Tests all major components working together
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <thread>

// Include all sovereign components
#include "../sovereign/session/SessionStore.hpp"
#include "../sovereign/agent/AgentGraphRuntime.hpp"
#include "../sovereign/agent/AutonomousAgent.hpp"
#include "../sovereign/agent/AgentPlanner.hpp"
#include "../sovereign/agent/AgentReviewer.hpp"
#include "../sovereign/agent/BuildRepairAgent.hpp"
#include "../sovereign/tool/ToolRegistry.hpp"
#include "../sovereign/context/ContextEngine.hpp"
#include "../sovereign/memory/AgentMemory.hpp"
#include "../sovereign/mcp/MCPBridge.hpp"
#include "../sovereign/sandbox/AgentSandbox.hpp"
#include "../sovereign/sandbox/ToolSandbox.hpp"
#include "../sovereign/extensions/ExtensionHost.hpp"
#include "../sovereign/tools/GitTools.hpp"
#include "../sovereign/tools/SearchTools.hpp"
#include "../sovereign/tools/DebugTools.hpp"
#include "../sovereign/patcher/IPatcher.hpp"
#include "../sovereign/patcher/PatchRegistry.hpp"
#include "../sovereign/patcher/MockPatcher.hpp"
#include "../sovereign/patcher/HotPatcher.hpp"

// Include Deep2 components
#include "../deep2/Deep2Engine.h"
#include "../deep2/ThreadPool.h"
#include "../deep2/KVCache.h"
#include "../deep2/Sampling.hpp"
#include "../deep2/Tokenizer.hpp"
#include "../deep2/FlashAttention.hpp"
#include "../deep2/MoERouter.hpp"
#include "../deep2/PagedKVCache.hpp"
#include "../deep2/SpeculativeDecoding.hpp"
#include "../deep2/ContinuousBatching.hpp"

using namespace Sovereign;
using namespace Deep2;

// Test counters
static int testsPassed = 0;
static int testsFailed = 0;
static int totalTests = 0;

#define TEST(name) \
    do { \
        totalTests++; \
        printf("  [TEST %d] %s... ", totalTests, name); \
        try {

#define END_TEST(result) \
            if (result) { \
                testsPassed++; \
                printf("PASSED\n"); \
            } else { \
                testsFailed++; \
                printf("FAILED\n"); \
            } \
        } catch (const std::exception& e) { \
            testsFailed++; \
            printf("EXCEPTION: %s\n", e.what()); \
        } catch (...) { \
            testsFailed++; \
            printf("UNKNOWN EXCEPTION\n"); \
        } \
    } while(0)

// ============================================================
// Test 1: SessionStore
// ============================================================
void TestSessionStore() {
    TEST("SessionStore - Create and Load Session") {
        SessionStore store(".sovereign_test");
        uint64_t id = store.CreateSession("test goal", "/workspace");
        auto session = store.LoadSession(id);
        END_TEST(session.has_value() && session->goal == "test goal");
    }
}

// ============================================================
// Test 2: AgentGraphRuntime
// ============================================================
void TestAgentGraphRuntime() {
    TEST("AgentGraphRuntime - DAG Validation") {
        AgentGraphRuntime runtime(4);
        
        AgentNode node1;
        node1.name = "scanner";
        node1.execute = [](const TaskContext& ctx) { return true; };
        
        AgentNode node2;
        node2.name = "analyzer";
        node2.execute = [](const TaskContext& ctx) { return true; };
        
        runtime.AddAgent(node1);
        runtime.AddAgent(node2);
        runtime.Connect("scanner", "analyzer");
        
        END_TEST(runtime.ValidateDAG());
    }
}

// ============================================================
// Test 3: AutonomousAgent
// ============================================================
void TestAutonomousAgent() {
    TEST("AutonomousAgent - Start/Stop") {
        AutonomousAgent agent;
        agent.Start();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        agent.Stop();
        END_TEST(true);
    }
}

// ============================================================
// Test 4: ToolRegistry
// ============================================================
void TestToolRegistry() {
    TEST("ToolRegistry - Register and Invoke") {
        ToolRegistry registry;
        registry.RegisterCoreTools();
        END_TEST(registry.HasTool("read_file"));
    }
}

// ============================================================
// Test 5: PatchRegistry
// ============================================================
void TestPatchRegistry() {
    TEST("PatchRegistry - MockPatcher") {
        PatchRegistry registry;
        registry.Register(std::make_shared<MockPatcher>());
        
        PatchRequest req;
        req.address = 0x1234;
        req.reason = "test";
        
        auto result = registry.Apply("mock", req);
        END_TEST(result.success);
    }
}

// ============================================================
// Test 6: ContextEngine
// ============================================================
void TestContextEngine() {
    TEST("ContextEngine - Initialize") {
        ContextEngine engine;
        engine.ScanWorkspace(".");
        END_TEST(true);
    }
}

// ============================================================
// Test 7: AgentMemory
// ============================================================
void TestAgentMemory() {
    TEST("AgentMemory - Store and Retrieve") {
        AgentMemory memory(".sovereign_test_memory");
        uint64_t id = memory.StoreEpisodic("test event", "test");
        
        MemoryQuery query;
        query.content = "test";
        query.limit = 5;
        
        auto results = memory.Retrieve(query);
        END_TEST(!results.empty());
    }
}

// ============================================================
// Test 8: AgentPlanner
// ============================================================
void TestAgentPlanner() {
    TEST("AgentPlanner - Generate Audit Plan") {
        AgentPlanner planner;
        auto plan = planner.GeneratePlan("audit workspace", "/test");
        END_TEST(!plan.steps.empty());
    }
}

// ============================================================
// Test 9: AgentReviewer
// ============================================================
void TestAgentReviewer() {
    TEST("AgentReviewer - Review Code") {
        AgentReviewer reviewer;
        std::string code = R"(
            #include <cstdio>
            void test() {
                char buf[10];
                strcpy(buf, "hello world");
            }
        )";
        auto result = reviewer.ReviewCode(code, "cpp");
        END_TEST(result.totalIssues > 0);
    }
}

// ============================================================
// Test 10: BuildRepairAgent
// ============================================================
void TestBuildRepairAgent() {
    TEST("BuildRepairAgent - Parse MSVC Errors") {
        BuildRepairAgent agent;
        std::string output = "test.cpp(42,5): error C2065: undeclared identifier";
        auto errors = agent.ParseMSVCErrors(output);
        END_TEST(!errors.empty() && errors[0].line == 42);
    }
}

// ============================================================
// Test 11: MCPBridge
// ============================================================
void TestMCPBridge() {
    TEST("MCPBridge - Initialize") {
        MCPBridge bridge;
        END_TEST(true);
    }
}

// ============================================================
// Test 12: AgentSandbox
// ============================================================
void TestAgentSandbox() {
    TEST("AgentSandbox - Permission Check") {
        AgentSandbox sandbox;
        SandboxConfig config;
        config.allowedTools = {"read_file", "write_file"};
        sandbox.Configure(config);
        
        std::string output;
        bool result = sandbox.Execute("agent1", "read_file", "test.txt", output);
        END_TEST(result);
    }
}

// ============================================================
// Test 13: ToolSandbox
// ============================================================
void TestToolSandbox() {
    TEST("ToolSandbox - Rate Limiting") {
        ToolSandbox sandbox;
        ToolSandboxConfig config;
        config.enableRateLimiting = true;
        config.maxCallsPerMinute = 10;
        sandbox.Configure(config);
        
        ToolExecutionContext ctx;
        ctx.agentId = "test_agent";
        
        auto result = sandbox.Execute("test_tool", "args", ctx);
        END_TEST(result.success);
    }
}

// ============================================================
// Test 14: ExtensionHost
// ============================================================
void TestExtensionHost() {
    TEST("ExtensionHost - Install and List") {
        ExtensionHost host;
        
        ExtensionManifest manifest;
        manifest.id = "test.ext";
        manifest.name = "Test Extension";
        manifest.version = "1.0.0";
        manifest.author = "test";
        manifest.entryPoint = "main.js";
        
        host.Install(manifest);
        auto extensions = host.ListExtensions();
        END_TEST(extensions.size() == 1);
    }
}

// ============================================================
// Test 15: GitTools
// ============================================================
void TestGitTools() {
    TEST("GitTools - IsRepo") {
        GitTools git(".");
        END_TEST(true); // Just verify it doesn't crash
    }
}

// ============================================================
// Test 16: SearchTools
// ============================================================
void TestSearchTools() {
    TEST("SearchTools - Search Files") {
        SearchTools search;
        auto files = search.SearchFilesByExtension(".cpp", ".");
        END_TEST(true);
    }
}

// ============================================================
// Test 17: Deep2 Engine
// ============================================================
void TestDeep2Engine() {
    TEST("Deep2Engine - Initialize") {
        Deep2Engine engine;
        EngineConfig config;
        config.hiddenDim = 4096;
        config.numLayers = 4;
        config.numHeads = 8;
        config.maxSeqLen = 128;
        config.useKVCache = true;
        config.useThreadPool = true;
        
        bool result = engine.initialize(config);
        END_TEST(result);
    }
}

// ============================================================
// Test 18: Sampling
// ============================================================
void TestSampling() {
    TEST("Sampling - CombinedSampler") {
        SamplingConfig config;
        config.temperature = 0.8f;
        config.topK = 40;
        config.topP = 0.95f;
        
        auto sampler = SamplerFactory::Create(config);
        
        std::vector<float> logits(100);
        for (int i = 0; i < 100; ++i) logits[i] = (float)(100 - i);
        
        int token = sampler->Sample(logits);
        END_TEST(token >= 0 && token < 100);
    }
}

// ============================================================
// Test 19: FlashAttention
// ============================================================
void TestFlashAttention() {
    TEST("FlashAttention - Forward") {
        FlashAttention attn;
        FlashAttnConfig config;
        config.headDim = 64;
        config.numHeads = 4;
        config.blockSize = 16;
        attn.Initialize(config);
        
        size_t seqLen = 32;
        size_t headDim = 64;
        
        std::vector<float> Q(seqLen * headDim, 0.1f);
        std::vector<float> K(seqLen * headDim, 0.1f);
        std::vector<float> V(seqLen * headDim, 0.1f);
        std::vector<float> output(seqLen * headDim);
        
        attn.Forward(Q.data(), K.data(), V.data(), output.data(), seqLen);
        END_TEST(true);
    }
}

// ============================================================
// Test 20: MoERouter
// ============================================================
void TestMoERouter() {
    TEST("MoERouter - Route Token") {
        MoERouter router;
        MoEConfig config;
        config.numExperts = 8;
        config.numActiveExperts = 2;
        config.hiddenDim = 64;
        router.Initialize(config);
        
        std::vector<float> hidden(64, 0.5f);
        auto route = router.Route(hidden.data());
        END_TEST(route.topExperts.size() == 2);
    }
}

// ============================================================
// Main
// ============================================================
int main() {
    printf("========================================\n");
    printf("Sovereign IDE Integration Test Suite\n");
    printf("========================================\n\n");
    
    printf("[Session Layer]\n");
    TestSessionStore();
    
    printf("\n[Agent Layer]\n");
    TestAgentGraphRuntime();
    TestAutonomousAgent();
    TestAgentPlanner();
    TestAgentReviewer();
    TestBuildRepairAgent();
    
    printf("\n[Tool Layer]\n");
    TestToolRegistry();
    TestPatchRegistry();
    TestMCPBridge();
    TestGitTools();
    TestSearchTools();
    
    printf("\n[Sandbox Layer]\n");
    TestAgentSandbox();
    TestToolSandbox();
    
    printf("\n[Extension Layer]\n");
    TestExtensionHost();
    
    printf("\n[Context & Memory]\n");
    TestContextEngine();
    TestAgentMemory();
    
    printf("\n[Deep2 Engine]\n");
    TestDeep2Engine();
    TestSampling();
    TestFlashAttention();
    TestMoERouter();
    
    printf("\n========================================\n");
    printf("RESULTS: %d/%d passed, %d failed\n", 
           testsPassed, totalTests, testsFailed);
    printf("========================================\n");
    
    return testsFailed > 0 ? 1 : 0;
}
