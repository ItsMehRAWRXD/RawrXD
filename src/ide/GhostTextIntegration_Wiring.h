/*===========================================================================
 * GhostTextIntegration_Wiring.h
 * RawrXD IDE - GhostTextEngine Integration Wiring Header
 *===========================================================================*/

#ifndef GHOSTTEXT_INTEGRATION_WIRING_H
#define GHOSTTEXT_INTEGRATION_WIRING_H

#include <windows.h>
#include <string>

// Forward declarations
struct RawrXD_IDE;

#ifdef __cplusplus
namespace RawrXD {
namespace IDE {

/**
 * Initialize GhostTextEngine integration
 * Called during IDE startup
 */
bool GhostTextIntegration_Initialize(RawrXD_IDE* ide);

/**
 * Shutdown GhostTextEngine integration
 * Called during IDE shutdown
 */
void GhostTextIntegration_Shutdown(RawrXD_IDE* ide);

/**
 * Check if GhostText integration is available
 */
bool GhostTextIntegration_IsAvailable();

/**
 * Route WM_TIMER messages for GhostText debounce
 */
void GhostTextIntegration_OnTimer(RawrXD_IDE* ide, WPARAM timerId);

/**
 * Route custom window messages for GhostText
 */
LRESULT GhostTextIntegration_OnCustomMessage(RawrXD_IDE* ide, UINT msg, WPARAM wParam, LPARAM lParam);

/**
 * Route editor text change events (EN_CHANGE)
 */
void GhostTextIntegration_OnTextChanged(RawrXD_IDE* ide);

/**
 * Route keyboard input for GhostText navigation
 * Returns true if key was handled
 */
bool GhostTextIntegration_OnKeyDown(RawrXD_IDE* ide, WPARAM key);

/**
 * Route paint messages for ghost text rendering
 */
void GhostTextIntegration_OnPaint(RawrXD_IDE* ide, HDC hdc, const RECT* editorRect);

/**
 * Initialize SovereignInferenceBridge for GhostText
 */
bool GhostTextIntegration_InitSovereignBridge();

/**
 * Force dismiss any active ghost text
 */
void GhostTextIntegration_ForceDismiss(RawrXD_IDE* ide);

/**
 * Check if ghost text is currently active
 */
bool GhostTextIntegration_IsActive();

/**
 * Get current suggestion info
 */
bool GhostTextIntegration_GetCurrentSuggestion(std::string& outText, float& outConfidence);

/**
 * Enable/disable GhostText integration
 */
void GhostTextIntegration_SetEnabled(bool enabled);

} // namespace IDE
} // namespace RawrXD
#endif // __cplusplus

/*===========================================================================
 * C API
 *===========================================================================*/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * C API wrapper for initialization
 */
BOOL RawrXD_GhostText_Init(RawrXD_IDE* ide);

/**
 * C API wrapper for shutdown
 */
void RawrXD_GhostText_Shutdown(RawrXD_IDE* ide);

/**
 * C API wrapper for text change notification
 */
void RawrXD_GhostText_OnTextChanged(RawrXD_IDE* ide);

/**
 * C API wrapper for key handling
 * Returns TRUE if key was handled
 */
BOOL RawrXD_GhostText_OnKeyDown(RawrXD_IDE* ide, WPARAM key);

/**
 * C API wrapper for paint
 */
void RawrXD_GhostText_OnPaint(RawrXD_IDE* ide, HDC hdc, const RECT* editorRect);

/**
 * C API wrapper for timer
 */
void RawrXD_GhostText_OnTimer(RawrXD_IDE* ide, WPARAM timerId);

/**
 * C API wrapper for custom messages
 */
LRESULT RawrXD_GhostText_OnCustomMessage(RawrXD_IDE* ide, UINT msg, WPARAM wParam, LPARAM lParam);

/**
 * C API wrapper for force dismiss
 */
void RawrXD_GhostText_ForceDismiss(RawrXD_IDE* ide);

/**
 * C API wrapper for availability check
 */
BOOL RawrXD_GhostText_IsAvailable();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GHOSTTEXT_INTEGRATION_WIRING_H
