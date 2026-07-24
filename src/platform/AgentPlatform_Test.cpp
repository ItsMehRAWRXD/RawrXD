//============================================================================
// AgentPlatform_Test.cpp
// Validation harness for RawrXD Agent Platform Layer
//============================================================================

#include "RawrXD_AgentPlatform.hpp"
#include <iostream>
#include <cassert>

using namespace RawrXD::Platform;

//============================================================================
// Test Utilities
//============================================================================

#define TEST(name) std::cout << "[TEST] " << #name << "... "; \
    try {

#define END_TEST() std::cout << "PASSED\n"; \
    } catch (const std::exception& e) { \
        std::cout << "FAILED: " << e.what() << "\n"; \
        return false; \
    }

#define ASSERT(cond) if (!(cond)) { \
    throw std::runtime_error("Assertion failed: " #cond); \
}

//============================================================================
// Test Suite
//============================================================================

bool TestUnifiedToolRegistry() {
    TEST(UnifiedToolRegistry_Singleton)
        auto& registry1 = UnifiedToolRegistry::Instance();
        auto& registry2 = UnifiedToolRegistry::Instance();
        ASSERT(&registry1 == &registry2);
    END_TEST()

    TEST(UnifiedToolRegistry_RegisterAndGet)
        UnifiedTool tool;
        tool.name = "test_tool";
        tool.description = "A test tool";
        tool.category = "test";
        tool.min_permission = PermissionLevel::READ_ONLY;
        tool.danger_level = DangerLevel::Safe;
        tool.execute = [](const std::string& input, const ToolContext& ctx) {
            return R"({"result": "success"})";
        };
        
        UnifiedToolRegistry::Instance().RegisterNativeTool(tool);
        
        auto retrieved = UnifiedToolRegistry::Instance().GetTool("test_tool");
        ASSERT(retrieved != nullptr);
        ASSERT(retrieved->name == "test_tool");
    END_TEST()

    TEST(UnifiedToolRegistry_ListTools)
        auto tools = UnifiedToolRegistry::Instance().ListTools();
        ASSERT(tools.size() > 0);
    END_TEST()

    TEST(UnifiedToolRegistry_ExecuteTool)
        ToolContext ctx;
        ctx.session_id = 1;
        ctx.permission = PermissionLevel::READ_ONLY;
        ctx.require_approval = false;
        
        bool approved = true;
        auto result = UnifiedToolRegistry::Instance().ExecuteTool("test_tool", "{}", ctx, approved);
        ASSERT(result.find("success") != std::string::npos);
    END_TEST()

    return true;
}

bool TestSessionManager() {
    TEST(SessionManager_CreateSession)
        uint64_t id = SessionManager::Instance().CreateSession(AgentMode::ASK, "test-model");
        ASSERT(id > 0);
        
        auto session = SessionManager::Instance().GetSession(id);
        ASSERT(session != nullptr);
        ASSERT(session->GetId() == id);
        ASSERT(session->GetMode() == AgentMode::ASK);
        ASSERT(session->GetModel() == "test-model");
        ASSERT(session->IsActive());
        
        SessionManager::Instance().CloseSession(id);
    END_TEST()

    TEST(SessionManager_ListSessions)
        uint64_t id1 = SessionManager::Instance().CreateSession(AgentMode::ASK, "model1");
        uint64_t id2 = SessionManager::Instance().CreateSession(AgentMode::AGENT, "model2");
        
        auto sessions = SessionManager::Instance().ListSessions();
        ASSERT(sessions.size() >= 2);
        
        SessionManager::Instance().CloseSession(id1);
        SessionManager::Instance().CloseSession(id2);
    END_TEST()

    return true;
}

bool TestAgentSession() {
    TEST(AgentSession_Messages)
        uint64_t id = SessionManager::Instance().CreateSession(AgentMode::ASK, "test");
        auto session = SessionManager::Instance().GetSession(id);
        
        ChatMessage msg1;
        msg1.role = "user";
        msg1.content = "Hello";
        session->AddMessage(msg1);
        
        ChatMessage msg2;
        msg2.role = "assistant";
        msg2.content = "Hi there";
        session->AddMessage(msg2);
        
        auto messages = session->GetMessages();
        ASSERT(messages.size() == 2);
        ASSERT(messages[0].content == "Hello");
        ASSERT(messages[1].content == "Hi there");
        
        SessionManager::Instance().CloseSession(id);
    END_TEST()

    TEST(AgentSession_BuildPrompt)
        uint64_t id = SessionManager::Instance().CreateSession(AgentMode::ASK, "test");
        auto session = SessionManager::Instance().GetSession(id);
        
        ChatMessage msg;
        msg.role = "user";
        msg.content = "Test message";
        session->AddMessage(msg);
        
        std::string prompt = session->BuildPromptWithHistory();
        ASSERT(prompt.find("Test message") != std::string::npos);
        
        SessionManager::Instance().CloseSession(id);
    END_TEST()

    return true;
}

bool TestModeRouter() {
    TEST(ModeRouter_Route)
        ModeRouter router;
        
        bool ask_called = false;
        router.SetAskHandler([&ask_called](const std::string& query, AgentSession* session) {
            ask_called = true;
            return "Ask response";
        });
        
        uint64_t id = SessionManager::Instance().CreateSession(AgentMode::ASK, "test");
        auto session = SessionManager::Instance().GetSession(id);
        
        std::string response = router.Route(AgentMode::ASK, "test query", session);
        ASSERT(ask_called);
        ASSERT(response == "Ask response");
        
        SessionManager::Instance().CloseSession(id);
    END_TEST()

    return true;
}

bool TestModelRegistry() {
    TEST(ModelRegistry_RegisterAndGet)
        ModelProfile model;
        model.name = "test-model";
        model.provider = "local";
        model.context_length = 4096;
        model.capabilities = {"coding"};
        
        ModelRegistry::Instance().RegisterModel(model);
        
        auto retrieved = ModelRegistry::Instance().GetModel("test-model");
        ASSERT(retrieved != nullptr);
        ASSERT(retrieved->name == "test-model");
        ASSERT(retrieved->context_length == 4096);
    END_TEST()

    TEST(ModelRegistry_ListModels)
        auto models = ModelRegistry::Instance().ListModels();
        ASSERT(models.size() > 0);
    END_TEST()

    TEST(ModelRegistry_GetByCapability)
        auto coding_models = ModelRegistry::Instance().GetModelsForCapability("coding");
        ASSERT(coding_models.size() > 0);
    END_TEST()

    return true;
}

bool TestExtensionHost() {
    TEST(ExtensionHost_LoadAndList)
        ExtensionManifest ext;
        ext.id = "test.extension";
        ext.name = "Test Extension";
        ext.version = "1.0.0";
        ext.enabled = true;
        
        ExtensionHost::Instance().LoadExtension(ext);
        
        ASSERT(ExtensionHost::Instance().IsExtensionLoaded("test.extension"));
        
        auto extensions = ExtensionHost::Instance().ListExtensions();
        ASSERT(extensions.size() > 0);
        
        ExtensionHost::Instance().UnloadExtension("test.extension");
    END_TEST()

    return true;
}

bool TestSovereignIDE() {
    TEST(SovereignIDE_CreateSession)
        SovereignIDE ide;
        
        uint64_t session_id = ide.CreateSession(AgentMode::ASK);
        ASSERT(session_id > 0);
        
        std::string info = ide.GetSessionInfo(session_id);
        ASSERT(info.find("Session") != std::string::npos);
        
        SessionManager::Instance().CloseSession(session_id);
    END_TEST()

    TEST(SovereignIDE_Status)
        SovereignIDE ide;
        
        std::string status = ide.GetStatus();
        ASSERT(status.find("RawrXD Sovereign IDE") != std::string::npos);
        ASSERT(status.find("Active Sessions") != std::string::npos);
    END_TEST()

    return true;
}

//============================================================================
// Main Test Runner
//============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "RawrXD Agent Platform Test Suite\n";
    std::cout << "========================================\n\n";

    int passed = 0;
    int failed = 0;

    auto run_test = [&](const char* name, bool (*test_func)()) {
        std::cout << "\n--- " << name << " ---\n";
        if (test_func()) {
            passed++;
            std::cout << "[OK] " << name << "\n";
        } else {
            failed++;
            std::cout << "[FAIL] " << name << "\n";
        }
    };

    run_test("UnifiedToolRegistry", TestUnifiedToolRegistry);
    run_test("SessionManager", TestSessionManager);
    run_test("AgentSession", TestAgentSession);
    run_test("ModeRouter", TestModeRouter);
    run_test("ModelRegistry", TestModelRegistry);
    run_test("ExtensionHost", TestExtensionHost);
    run_test("SovereignIDE", TestSovereignIDE);

    std::cout << "\n========================================\n";
    std::cout << "Results: " << passed << " passed, " << failed << " failed\n";
    std::cout << "========================================\n";

    return failed > 0 ? 1 : 0;
}
