#include "../src/agentic/MotdAuthorization.h"
#include "../src/agentic/ToolCallBridge.h"

#include <chrono>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

namespace fs = std::filesystem;

static int fail(const char* message) {
    std::cerr << "FAIL: " << message << '\n';
    return 1;
}

int main() {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path root = fs::temp_directory_path() /
        ("rawrxd_motd_auth_test_" + std::to_string(nonce));
    const fs::path policy = root / ".cursor" / "rules" / "PassiveRoleNotRoleplay.md";
    std::error_code ec;
    fs::create_directories(policy.parent_path(), ec);
    if (ec) return fail("could not create isolated fixture");

    {
        std::ofstream out(policy, std::ios::binary);
        out << "abc";
        if (!out) return fail("could not write isolated MOTD fixture");
    }

    int result = 0;
    rawrxd::agentic::MotdAuthorization auth(root);
    std::string reason, contents, digest, error;
    if (!auth.BeginTurn("session-A", 1)) result = fail("valid turn did not begin");
    else if (auth.AuthorizeTool("read_file", "session-A", 1, reason))
        result = fail("non-MOTD tool was allowed before policy read");
    else if (!auth.AuthorizeTool("read_motd", "session-A", 1, reason))
        result = fail("reserved MOTD read was denied");
    else if (!auth.ReadMotd("session-A", 1, contents, digest, error))
        result = fail("existing MOTD could not be read");
    else if (contents != "abc") result = fail("MOTD bytes changed during read");
    else if (digest != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        result = fail("MOTD SHA-256 does not match the known vector");
    else if (!auth.IsAcknowledged("session-A", 1))
        result = fail("successful read did not acknowledge this turn");
    else if (!auth.AuthorizeTool("read_file", "session-A", 1, reason))
        result = fail("tool remained blocked after successful MOTD read");
    else {
        auth.NoteExecution("session-A", 1);
        {
            auto turnGuard = auth.GuardTurn("session-A", 1);
        }
        if (auth.IsAcknowledged("session-A", 1) ||
            auth.GetState() != rawrxd::agentic::MotdAuthorization::State::Revoked)
            result = fail("RAII turn guard did not revoke authorization on scope exit");
        {
            std::ofstream out(policy, std::ios::binary | std::ios::trunc);
            out << "tampered";
        }
        if (result == 0 && !auth.BeginTurn("session-A", 1))
            result = fail("tamper-check turn did not begin");
        if (result == 0 && !auth.ReadMotd("session-A", 1, contents, digest, error))
            result = fail("tamper-check turn could not read policy");
        if (result == 0) {
            std::ofstream out(policy, std::ios::binary | std::ios::trunc);
            out << "replacement";
        }
        if (result == 0 && auth.AuthorizeTool("read_file", "session-A", 1, reason))
            result = fail("policy replacement did not revoke existing authorization");
        {
            std::ofstream out(policy, std::ios::binary | std::ios::trunc);
            out << "abc";
        }
        if (result == 0 && !auth.BeginTurn("session-A", 2))
            result = fail("second turn did not begin");
        else if (result == 0 && auth.AuthorizeTool("read_file", "session-A", 3, reason))
            result = fail("prior turn authorization survived a new turn id");
        else if (result == 0 && auth.IsAcknowledged("session-A", 2))
            result = fail("stale ACK was reported for a new turn");
        else if (result == 0 && auth.AuthorizeTool("read_file", "session-B", 2, reason))
            result = fail("authorization crossed session identity");
        else if (result == 0) {
            fs::remove(policy, ec);
            if (ec) result = fail("could not remove policy for missing-file case");
            else if (auth.ReadMotd("session-A", 2, contents, digest, error))
                result = fail("missing policy was treated as read success");
            else if (auth.AuthorizeTool("run_build", "session-A", 2, reason))
                result = fail("tool was allowed after failed MOTD read");
        }
    }

    if (result == 0) {
        {
            std::ofstream out(policy, std::ios::binary);
            out << "bridge policy";
            if (!out) result = fail("could not restore policy for bridge integration test");
        }

        if (result == 0) {
            std::atomic<int> concurrentPasses{0};
            auto exerciseIndependentSession = [&](const std::string& session) {
                rawrxd::agentic::MotdAuthorization concurrentAuth(root);
                std::string localReason, localContents, localDigest, localError;
                if (concurrentAuth.BeginTurn(session, 1) &&
                    concurrentAuth.AuthorizeTool("read_motd", session, 1, localReason) &&
                    concurrentAuth.ReadMotd(session, 1, localContents, localDigest, localError) &&
                    concurrentAuth.AuthorizeTool("read_file", session, 1, localReason)) {
                    ++concurrentPasses;
                    concurrentAuth.EndTurn(session, 1);
                }
            };
            std::thread first(exerciseIndependentSession, "parallel-A");
            std::thread second(exerciseIndependentSession, "parallel-B");
            first.join();
            second.join();
            if (concurrentPasses.load() != 2)
                result = fail("concurrent independent sessions leaked or lost authorization state");
        }

        if (result == 0) {
            rawrxd::tools::Registry registry;
            int executions = 0;
            rawrxd::tools::Tool probe;
            probe.name = "probe";
            probe.description = "test-only read-only tool";
            probe.risk = rawrxd::tools::Risk::ReadOnly;
            probe.invoke = [&executions](const rawrxd::tools::Request&) {
                ++executions;
                return rawrxd::tools::Result{true, "probe executed", ""};
            };
            registry.add(probe);

            RawrXD::Agent::ToolCallBridge bridge;
            bridge.SetWorkspaceRoot(root);
            bridge.SetRegistry(&registry);
            if (!bridge.BeginUserTurn("bridge-session", 1)) {
                result = fail("tool bridge could not begin its turn");
            } else {
                [[maybe_unused]] auto bridgeTurnGuard = bridge.GuardUserTurn();
                RawrXD::Agent::ToolCall call;
                call.id = "before-ack";
                call.name = "probe";
                call.arguments = nlohmann::json::object();
                auto beforeAck = bridge.ExecuteToolCall(call);
                if (bridge.BeginUserTurn("overlap", 1) || beforeAck.success || executions != 0) {
                    result = fail("tool bridge executed a tool before MOTD ACK");
                } else {
                    call.id = "policy-read";
                    call.name = "read_motd";
                    auto read = bridge.ExecuteToolCall(call);
                    if (!read.success || read.content.find("MOTD_ACK=1") == std::string::npos ||
                        read.content.find("MOTD_SHA256=") == std::string::npos) {
                        result = fail("tool bridge did not return a verifiable MOTD receipt");
                    } else {
                        call.id = "after-ack";
                        call.name = "probe";
                        auto afterAck = bridge.ExecuteToolCall(call);
                        if (!afterAck.success || executions != 1) {
                            result = fail("tool bridge did not release tools after successful MOTD read");
                        } else {
                            bridge.EndUserTurn();
                            if (!bridge.BeginUserTurn("bridge-session", 2)) {
                                result = fail("tool bridge did not start a fresh user turn after revocation");
                            } else {
                                call.id = "stale-turn";
                                auto stale = bridge.ExecuteToolCall(call);
                                if (stale.success || executions != 1) {
                                    result = fail("tool bridge reused an ACK from the previous turn");
                                }
                                bridge.EndUserTurn();
                            }
                        }
                    }
                }
            }
        }
    }

    fs::remove_all(root, ec);
    if (result == 0) std::cout << "MOTD_AUTHORIZATION_TEST PASS\n";
    return result;
}
