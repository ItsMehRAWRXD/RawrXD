// ============================================================================
// win32_feature_adapter.h — Win32 GUI ↔ SharedFeatureRegistry Adapter
// ============================================================================
// Architecture: C++20, Win32, no Qt, no exceptions
// Bridges Win32IDE's WM_COMMAND dispatch into the unified feature registry.
// Provides routeCommandUnified() that Win32IDE_Core.cpp calls from onCommand().
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED.
// ============================================================================

#pragma once

#ifndef RAWRXD_WIN32_FEATURE_ADAPTER_H
#define RAWRXD_WIN32_FEATURE_ADAPTER_H

#include <windows.h>
#include "../core/shared_feature_dispatch.h"
#include "../core/unified_command_dispatch.hpp"
#include "../core/feature_handlers.h"
#include <cstring>
#include <string>

// Forward declare Win32IDE — we operate on void* internally
class Win32IDE;

// ============================================================================
// GUI OUTPUT CALLBACK — Routes to Win32 IDE status bar / output panel
// ============================================================================

// Optional IDE append-output callback (set by Win32IDE init so handler output goes to output panel)
typedef void (*IdeAppendOutputFn)(void* ide, const char* text);
static IdeAppendOutputFn s_ideAppendOutput = nullptr;
static void setIdeAppendOutput(IdeAppendOutputFn fn) { s_ideAppendOutput = fn; }

// Output callback for GUI context — routes handler output to IDE output panel when registered
static void gui_status_output(const char* text, void* userData) {
    if (!text || !userData) return;
    if (s_ideAppendOutput) {
        s_ideAppendOutput(userData, text);
    } else {
        OutputDebugStringA(text);
    }
}

// ============================================================================
// UNIFIED GUI DISPATCH — Attempt to route a WM_COMMAND ID through the
//                        shared feature registry before legacy handlers
// ============================================================================
// Returns true if the command was handled by the unified dispatch.
// Returns false if it should fall through to Win32IDE's legacy routeCommand().
// ============================================================================

static bool routeCommandUnified(int commandId, void* idePtr, HWND hwndMain = nullptr) {
    // PRIMARY PATH: Direct dispatch from g_commandRegistry[] (SSOT)
    CommandContext ctx{};
    ctx.rawInput = "";
    ctx.args = "";
    ctx.idePtr = idePtr;
    ctx.hwnd = hwndMain;
    ctx.cliStatePtr = nullptr;
    ctx.commandId = static_cast<uint32_t>(commandId);
    ctx.isGui = true;
    ctx.isHeadless = false;
    ctx.outputFn = gui_status_output;
    ctx.outputUserData = idePtr;

    auto result = RawrXD::Dispatch::dispatchByGuiId(
        static_cast<uint32_t>(commandId), ctx);

    if (result.status == RawrXD::Dispatch::DispatchStatus::OK ||
        result.status == RawrXD::Dispatch::DispatchStatus::HANDLER_ERROR) {
        return true;
    }

    auto& registry = SharedFeatureRegistry::instance();
    auto registryResult = registry.dispatchByCommandId(
        static_cast<uint32_t>(commandId), ctx);
    if (registryResult.success) {
        return true;
    }

    return false;
}

static bool isFeatureAvailableGui(int commandId) {
    auto& registry = SharedFeatureRegistry::instance();
    const FeatureDescriptor* desc = registry.findByCommandId(static_cast<uint32_t>(commandId));
    if (!desc) return false;
    return desc->guiSupported && (desc->handler != nullptr);
}

static const char* getFeatureNameGui(int commandId) {
    auto& registry = SharedFeatureRegistry::instance();
    const FeatureDescriptor* desc = registry.findByCommandId(static_cast<uint32_t>(commandId));
    return desc ? desc->name : nullptr;
}

static const char* getFeatureDescGui(int commandId) {
    auto& registry = SharedFeatureRegistry::instance();
    const FeatureDescriptor* desc = registry.findByCommandId(static_cast<uint32_t>(commandId));
    return desc ? desc->description : nullptr;
}

static const char* getFeatureShortcutGui(int commandId) {
    auto& registry = SharedFeatureRegistry::instance();
    const FeatureDescriptor* desc = registry.findByCommandId(static_cast<uint32_t>(commandId));
    return desc ? desc->shortcut : nullptr;
}

static size_t getGuiRegisteredCount() {
    return SharedFeatureRegistry::instance().getGuiFeatures().size();
}

static uint64_t getGuiDispatchCount() {
    return SharedFeatureRegistry::instance().totalDispatched();
}

static int populateMenuFromRegistry(HMENU hMenu, FeatureGroup group) {
    auto& registry = SharedFeatureRegistry::instance();
    auto features = registry.getByGroup(group);
    int count = 0;

    for (const auto* feat : features) {
        if (!feat->guiSupported || feat->commandId == 0) continue;

        std::string label(feat->name);
        if (feat->shortcut && feat->shortcut[0]) {
            label += "\t";
            label += feat->shortcut;
        }

        AppendMenuA(hMenu, MF_STRING, feat->commandId, label.c_str());
        ++count;
    }

    return count;
}

static void updateStatusBarWithRegistryStats(HWND hwndStatusBar, int partIndex) {
    if (!hwndStatusBar || !IsWindow(hwndStatusBar)) return;

    auto& registry = SharedFeatureRegistry::instance();
    size_t total = registry.totalRegistered();
    uint64_t dispatched = registry.totalDispatched();

    char buf[128];
    snprintf(buf, sizeof(buf), "Features: %zu | Dispatched: %llu", total,
             (unsigned long long)dispatched);
    SendMessageA(hwndStatusBar, SB_SETTEXTA, partIndex, (LPARAM)buf);
}

#endif // RAWRXD_WIN32_FEATURE_ADAPTER_H
