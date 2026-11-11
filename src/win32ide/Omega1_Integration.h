// ============================================================================
// Omega1 Integration Master Header
// Single include for all OMEGA-1 IDE integration components
// ============================================================================

#pragma once

// Protocol definitions
#include "Omega1_IPC_Protocol.h"

// IPC Client
#include "Omega1_IPC_Client.h"

// IDE Bridge
#include "Omega1_IDE_Bridge.h"

// Keyboard Hook
#include "Omega1_Keyboard_Hook.h"

// Version info
#define OMEGA1_IDE_INTEGRATION_VERSION "2.0.0"
#define OMEGA1_IDE_INTEGRATION_DATE "2026-07-28"

// Quick start macros for IDE integration
#define OMEGA1_INIT(hwndMain, hwndStatus) \
    RawrXD::Omega1::IDEIntegrationBridge::GetInstance().Initialize((hwndMain), (hwndStatus))

#define OMEGA1_SHUTDOWN() \
    RawrXD::Omega1::IDEIntegrationBridge::GetInstance().Shutdown()

#define OMEGA1_CONNECT() \
    RawrXD::Omega1::IDEIntegrationBridge::GetInstance().ConnectToServer()

#define OMEGA1_TRIGGER_COMPLETION(hwndEditor) \
    RawrXD::Omega1::IDEIntegrationBridge::GetInstance().TriggerGhostCompletion((hwndEditor))

#define OMEGA1_CANCEL() \
    RawrXD::Omega1::IDEIntegrationBridge::GetInstance().CancelGhostCompletion()

#define OMEGA1_IS_GENERATING() \
    RawrXD::Omega1::IDEIntegrationBridge::GetInstance().IsGenerating()

#define OMEGA1_GET_GHOST_TEXT() \
    RawrXD::Omega1::IDEIntegrationBridge::GetInstance().GetCurrentGhostText()

#define OMEGA1_ACCEPT() \
    RawrXD::Omega1::IDEIntegrationBridge::GetInstance().AcceptGhostText()

#define OMEGA1_REJECT() \
    RawrXD::Omega1::IDEIntegrationBridge::GetInstance().RejectGhostText()

#define OMEGA1_UPDATE_STATUS() \
    RawrXD::Omega1::IDEIntegrationBridge::GetInstance().UpdateStatusBar()

#define OMEGA1_ON_IDLE() \
    RawrXD::Omega1::IDEIntegrationBridge::GetInstance().OnIdle()

#define OMEGA1_HANDLE_MESSAGE(hwnd, msg, wp, lp) \
    RawrXD::Omega1::IDEIntegrationBridge::GetInstance().HandleMessage((hwnd), (msg), (wp), (lp))

// Keyboard hook macros
#define OMEGA1_INSTALL_HOOK(hwnd) \
    RawrXD::Omega1::KeyboardHook::GetInstance().Install((hwnd))

#define OMEGA1_REMOVE_HOOK() \
    RawrXD::Omega1::KeyboardHook::GetInstance().Remove()
