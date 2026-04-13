// Stub implementations for GUI components not available in headless builds.
#include <memory>

// Forward declare the classes to satisfy the compiler for the unique_ptr types.
class OutlinePanel {};
class DockingPaneManager {};

namespace Win32IDE {
    std::unique_ptr<OutlinePanel> createOutlinePanel() { return nullptr; }
    std::unique_ptr<DockingPaneManager> createDockingPaneManager() { return nullptr; }
    void goToLine(int line, int col) {}
}
