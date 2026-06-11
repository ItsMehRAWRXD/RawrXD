// Compiled when RAWRXD_ENABLE_IDE_PROBE_GATES=OFF — satisfies main_win32 probe symbols without harness TUs.

#include "Win32IDE_KVApertureProbe.h"
#include "Win32IDE_TextEngineProbe.h"
#include "Win32IDE_TokenTickProbe.h"
#include "Win32IDE_ParityEngine.h"
#include "Win32IDE_ExecutionTruth.h"
#include "Win32IDE_ActionGraph.h"
#include "Win32IDE_ContextGovernor.h"
#include "Win32IDE_GGUFManifold.h"
#include "Win32IDE_TBA_LinkGraph.h"
#include "Win32IDE_Phase19_2_Soak.h"
#include "sovereign/sovereign_smoketests.h"

bool HasKVApertureProbeFlag(const char*)
{
    return false;
}

int RunKVApertureProbe(const char*, std::uint64_t, int, std::uint64_t)
{
    return 2;
}

bool HasTextEngineProbeFlag(const char*)
{
    return false;
}

int RunTextEngineProbe(const char*, int)
{
    return 2;
}

bool HasTokenTickFlag(const char*)
{
    return false;
}

int RunTokenTickProbe(const char*, std::uint64_t, int, std::uint32_t, std::uint32_t, std::uint32_t)
{
    return 2;
}

bool HasParityEngineFlag(const char*)
{
    return false;
}

int RunParityEngineProbe(const char*, std::uint64_t, int, std::uint32_t)
{
    return 2;
}

bool HasExecutionTruthFlag(const char*)
{
    return false;
}

int RunExecutionTruth(const char*, std::uint64_t, int)
{
    return 2;
}

bool HasSovereignActionGraphFlag(const char*)
{
    return false;
}

int RunSovereignActionGraph(const char*, std::uint64_t, int)
{
    return 2;
}

bool HasSovereignContextGovernorFlag(const char*)
{
    return false;
}

int RunSovereignContextGovernor(const char*, std::uint64_t, int)
{
    return 2;
}

bool HasGGUFManifoldFlag(const char*)
{
    return false;
}

int RunGGUFManifoldProbe(const char*, std::uint64_t, int)
{
    return 2;
}

bool HasTBALinkGraphFlag(const char*)
{
    return false;
}

int RunTBALinkGraph(const char*, std::uint64_t, int)
{
    return 2;
}

bool HasPhase19_2SoakFlag(const char*)
{
    return false;
}

int RunPhase19_2Soak(const char*, std::uint64_t, int)
{
    return 2;
}

namespace RawrXD::Tests
{

int RunSmoketests(const wchar_t*)
{
    return 2;
}

}  // namespace RawrXD::Tests
