// unlinked_symbols_batch_014.cpp
// Headless / link-gap factories for OutlinePanel + DockingPaneManager.
// Real types: src/win32app/OutlinePanel.h, DockingPaneManager.h
// Win32IDE product UI path uses Win32IDE::initOutlinePanel / DockingPaneManager.cpp —
// do not dual-link stub OutlinePanel classes. PROMOTE=0.

#include <memory>

#include "../win32app/OutlinePanel.h"
#include "../win32app/DockingPaneManager.h"

namespace Win32IDE {

std::unique_ptr<OutlinePanel> createOutlinePanel() {
    return std::make_unique<OutlinePanel>();
}

std::unique_ptr<DockingPaneManager> createDockingPaneManager() {
    return std::make_unique<DockingPaneManager>();
}

void goToLine(int line, int col) {
    // Headless: no editor HWND. Product path: Win32IDE::gotoLine.
    (void)line;
    (void)col;
}

} // namespace Win32IDE
