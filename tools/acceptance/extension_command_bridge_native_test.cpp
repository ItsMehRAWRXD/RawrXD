// Native integration test: compiles the actual extension command bridge, no mocks.
#include "../../~dev/rawrxd/src/core/extension_host_production.cpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <stdexcept>
#include <string>
#include <vector>

struct ThrowOnCopy {
    ThrowOnCopy() = default;
    ThrowOnCopy(ThrowOnCopy&&) noexcept = default;
    ThrowOnCopy(const ThrowOnCopy&) { throw std::runtime_error("copy failed"); }
    bool operator()(const std::string&) const { return true; }
};

int main() {
    auto& host = RawrXD::Extensions::ExtensionHost::GetInstance();
    host.Shutdown();
    assert(!host.IsInitialized());
    assert(!host.RegisterCommand("before-init", [](const std::string&) { return true; }));
    assert(!host.ExecuteCommand("missing", ""));
    assert(host.Initialize());
    assert(host.IsInitialized());
    assert(host.Initialize());
    assert(!host.RegisterCommand("", [](const std::string&) { return true; }));
    assert(!host.RegisterCommand("null-handler", {}));
    assert(!host.RegisterCommand("bad command", [](const std::string&) { return true; }));
    assert(!host.RegisterExtensionCommand("extension.one", "bad command", [](const std::string&) { return true; }));
    int calls = 0;
    assert(host.RegisterCommand("host-command", [&](const std::string& arg) {
        ++calls;
        return arg == "expected";
    }));
    assert(!host.RegisterCommand("host-command", [](const std::string&) { return true; }));
    assert(host.ExecuteCommand("host-command", "expected"));
    assert(calls == 1);
    assert(!host.ExecuteCommand("host-command", "other"));
    assert(calls == 2);
    assert(!host.RegisterExtensionCommand("", "bad", [](const std::string&) { return true; }));
    assert(!host.RegisterExtensionCommand("bad id", "bad", [](const std::string&) { return true; }));
    assert(!host.RegisterExtensionCommand("bad\tid", "bad-tab", [](const std::string&) { return true; }));
    assert(!host.RegisterExtensionCommand("bad\nid", "bad-newline", [](const std::string&) { return true; }));
    assert(!host.RegisterExtensionCommand("extension.one", "host-command", [](const std::string&) { return true; }));
    assert(host.RegisterExtensionCommand("extension.one", "extension-command", [&](const std::string&) {
        // Re-entrant unregister must not deadlock.
        host.UnregisterExtensionCommands("extension.one");
        return true;
    }));
    assert(host.ExecuteCommand("extension-command", ""));
    assert(!host.ExecuteCommand("extension-command", ""));
    // Ownership must be isolated: unloading one extension cannot remove
    // another extension's commands or unowned host commands.
    assert(host.RegisterExtensionCommand("extension.alpha", "alpha", [](const std::string&) { return true; }));
    assert(host.RegisterExtensionCommand("extension.beta", "beta", [](const std::string&) { return true; }));
    host.UnregisterExtensionCommands("extension.alpha");
    assert(!host.ExecuteCommand("alpha", ""));
    assert(host.ExecuteCommand("beta", ""));
    assert(host.ExecuteCommand("host-command", "expected"));
    host.UnregisterExtensionCommands("extension.beta");
    assert(!host.ExecuteCommand("beta", ""));
    assert(host.RegisterCommand("throwing", [](const std::string&) -> bool {
        throw std::runtime_error("expected");
    }));
    assert(!host.ExecuteCommand("throwing", ""));
    // std::function callback copy may throw even when invoking it would not.
    // Construct with move, then exercise the copy performed by dispatch.
    assert(host.RegisterCommand("copy-throws", ThrowOnCopy{}));
    assert(!host.ExecuteCommand("copy-throws", ""));
    assert(host.UnregisterCommand("copy-throws"));
    // Nested command dispatch must not deadlock the registry mutex.
    assert(host.RegisterCommand("inner", [](const std::string& arg) {
        return arg == "nested";
    }));
    assert(host.RegisterCommand("outer", [&](const std::string&) {
        return host.ExecuteCommand("inner", "nested");
    }));
    assert(host.ExecuteCommand("outer", ""));
    assert(host.UnregisterCommand("outer"));
    assert(host.UnregisterCommand("inner"));
    // Once shut down, neither dispatch nor new registrations may succeed.
    const auto available = host.GetAvailableCommands();
    assert(available.size() == 2);
    assert(host.UnregisterCommand("throwing"));
    assert(!host.UnregisterCommand("throwing"));
    host.Shutdown();
    assert(!host.IsInitialized());
    assert(host.GetAvailableCommands().empty());
    assert(!host.ExecuteCommand("host-command", ""));
    assert(host.Initialize());
    assert(host.GetAvailableCommands().empty());
    host.Shutdown();
}
