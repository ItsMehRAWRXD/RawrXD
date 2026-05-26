#pragma once
namespace RawrXD::UI {
    template <typename... Args> inline void drainPendingVcsIndexSnapshots(Args&&...) {}
    struct SidebarStagingPanel {
        template <typename... Args> inline int SomeFunc(Args&&...) { return 0; }
    };
}
struct NeuralBridge {
    static bool IsInitialized() { return true; }
    static void Shutdown() {}
};
