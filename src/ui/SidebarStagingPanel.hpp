#pragma once
#include <windows.h>

class SidebarStagingPanel {
public:
    SidebarStagingPanel() = default;
    ~SidebarStagingPanel() = default;
    void Initialize(HWND parent) { (void)parent; }
    void Show() {}
    void Hide() {}
};
