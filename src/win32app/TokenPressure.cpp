// TokenPressure.cpp — host adapter over TOKEN_PRESSURE_VALVE_001 drop (no local MASM).
#include "TokenPressure.hpp"
#include "RawrXD_TokenPressureValve.hpp"
#include "RawrXD_TokenPressureValveBridge.hpp"

#include <cstring>

static TPV_State g_tpv = {};
static bool g_ready = false;

namespace token_pressure {

void ProcessStartup() noexcept
{
    std::memset(&g_tpv, 0, sizeof(g_tpv));
    TPV_InitState(&g_tpv, TPV_MODE_NEEDLE, 0);
    g_ready = true;
}

void SetSpray(SprayMode mode) noexcept
{
    if (!g_ready)
        ProcessStartup();
    TPV_SetMode(&g_tpv, static_cast<uint32_t>(mode));
}

ValveAction OnUtf8Chunk(const char* utf8, std::size_t bytes) noexcept
{
    if (!utf8 || bytes == 0)
        return ValveAction::Pass;
    if (!g_ready)
        ProcessStartup();

    TPV_Result result = {};
    const uint32_t token_id =
        static_cast<uint32_t>(bytes) ^
        (utf8[0] << 8) ^
        (bytes > 1 ? static_cast<uint32_t>(utf8[bytes - 1]) << 16 : 0u);
    TPV_UpdateUtf8Token(&g_tpv, token_id, utf8, static_cast<uint32_t>(bytes), &result);

    if (result.action & TPV_ACT_STOP_HINT)
        return ValveAction::StopRequest;
    if (result.action & TPV_ACT_REPEAT_PENALTY)
        return ValveAction::PenalizeRepeat;
    if (result.action & (TPV_ACT_NARROW | TPV_ACT_COMPRESS))
        return ValveAction::PreferStop;
    return ValveAction::Pass;
}

void ObserveTerminalError() noexcept
{
    SetSpray(SprayMode::RepairJet);
    if (!g_ready)
        return;
    TPV_Result result = {};
    TPV_UpdateToken(&g_tpv, 0x45525221u /* ERR! */, TPV_TOK_ERROR, &result);
    (void)result;
}

}  // namespace token_pressure
