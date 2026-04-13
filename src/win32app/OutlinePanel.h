#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <functional>

class OutlinePanel
{
public:
    OutlinePanel() = default;
    ~OutlinePanel() = default;

    void Create(HWND hParent) {}
    void UpdateSymbols(const std::vector<std::string>& symbols) {}
    void SetSelectionCallback(std::function<void(int)> cb) {}
};
