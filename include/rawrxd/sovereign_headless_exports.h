/* ============================================================================
 * sovereign_headless_exports.h
 * Headless Sovereign MASM runtime exports for RawrEngine integration.
 * ============================================================================ */

#ifndef RAWRXD_SOVEREIGN_HEADLESS_EXPORTS_H
#define RAWRXD_SOVEREIGN_HEADLESS_EXPORTS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------- Input Hub ------------------------- */

/*
 * Registers raw input devices for the provided HWND target.
 * Returns 1 on success, 0 on failure.
 */
uint64_t XR_Input_Register_Devices(void *target_hwnd);

/*
 * Parses a WM_INPUT lParam/HRAWINPUT packet.
 * Returns 1 when supported input packet is consumed, 0 otherwise.
 */
uint64_t XR_Input_Parse_Message(void *raw_input_handle);

extern uint64_t g_Raw_Input_Device_Base;
extern uint32_t g_Input_Buffer_Bytes;
extern int32_t g_Mouse_Delta_X;
extern int32_t g_Mouse_Delta_Y;
extern uint64_t g_Keyboard_State_Bitmask[4];

/* ------------------------- Time Sync ------------------------- */

/*
 * Initializes high-resolution timer state.
 * Returns 1 on success, 0 on failure.
 */
uint64_t XR_Time_Initialize(void);

/*
 * Queries elapsed microseconds since the previous baseline tick.
 * Returns microseconds as integer. Returns 0 if unavailable.
 */
uint64_t XR_Time_Query_Interval(void);

extern uint64_t g_Clock_Frequency;
extern uint64_t g_Time_Baseline_Tick;
extern uint64_t g_Time_Current_Tick;
extern uint64_t g_Microseconds_Delta;

/* ---------------------- Diagnostic Trap ---------------------- */

/*
 * Raises an assert trap when condition_value == 0.
 * location_tag is persisted in global diagnostic memory.
 */
void XR_Diagnostic_Raise_Assert(uint64_t condition_value, uint32_t location_tag);

/*
 * Captures GPR and SIMD register state into caller-provided telemetry block.
 * destination must reference at least 512 writable bytes.
 */
void XR_Diagnostic_Capture_Register_Dump(void *destination);

extern uint64_t g_Crash_Dump_Address;
extern uint32_t g_Assert_Failed_Flag;

#ifdef __cplusplus
}
#endif

#endif /* RAWRXD_SOVEREIGN_HEADLESS_EXPORTS_H */