// GpuPreflightReset.cpp — PnP Code 31 (CM_PROB_FAILED_ADD) recognize + reset
#include "GpuPreflight.hpp"

#include <setupapi.h>
#include <cfgmgr32.h>
#include <cstdio>

#ifndef CM_PROB_NONE
#define CM_PROB_NONE 0
#endif
#ifndef DN_STARTED
#define DN_STARTED 0x00000008
#endif
#ifndef CM_PROB_FAILED_ADD
#define CM_PROB_FAILED_ADD 0x0000001F // Device Manager "Code 31"
#endif
#ifndef CM_PROB_FAILED_START
#define CM_PROB_FAILED_START 0x0000000A
#endif
#ifndef CM_PROB_NEED_RESTART
#define CM_PROB_NEED_RESTART 0x0000000E
#endif
#ifndef CM_PROB_FAILED_POST_START
#define CM_PROB_FAILED_POST_START 0x0000002B
#endif
#ifndef CR_ACCESS_DENIED
#define CR_ACCESS_DENIED 0x00000033
#endif
#ifndef CM_SETUP_DEVNODE_READY
#define CM_SETUP_DEVNODE_READY 0x00000000
#endif
#ifndef ERROR_GEN_FAILURE
#define ERROR_GEN_FAILURE 31 // Win32; same numeric as CM_PROB_FAILED_ADD
#endif
#ifndef DXGI_ERROR_DEVICE_REMOVED
#define DXGI_ERROR_DEVICE_REMOVED ((long)0x887A0005L)
#endif
#ifndef DXGI_ERROR_DEVICE_HUNG
#define DXGI_ERROR_DEVICE_HUNG ((long)0x887A0006L)
#endif
#ifndef DXGI_ERROR_DEVICE_RESET
#define DXGI_ERROR_DEVICE_RESET ((long)0x887A0007L)
#endif

bool GpuIsCode31(DWORD problem) {
    return problem == CM_PROB_FAILED_ADD || problem == (DWORD)ERROR_GEN_FAILURE;
}

bool GpuProblemCodeRecoverable(DWORD problem) {
    return GpuIsCode31(problem) || problem == CM_PROB_FAILED_START ||
           problem == CM_PROB_NEED_RESTART || problem == CM_PROB_FAILED_POST_START;
}

bool GpuIsDxgiDeviceRemovedHr(long hr) {
    return hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_HUNG ||
           hr == DXGI_ERROR_DEVICE_RESET;
}

static bool SetupDiToggleDevNode(DEVINST target, DWORD stateChange, DWORD scope) {
    static const GUID kDisplay = {0x4d36e968, 0xe325, 0x11ce,
                                  {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};
    HDEVINFO h = SetupDiGetClassDevsW(&kDisplay, nullptr, nullptr, DIGCF_PRESENT);
    if (h == INVALID_HANDLE_VALUE) return false;
    SP_DEVINFO_DATA d{};
    d.cbSize = sizeof(d);
    bool ok = false;
    for (DWORD i = 0; SetupDiEnumDeviceInfo(h, i, &d); ++i) {
        if (d.DevInst != target) continue;
        SP_PROPCHANGE_PARAMS pcp{};
        pcp.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        pcp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
        pcp.StateChange = stateChange;
        pcp.Scope = scope;
        pcp.HwProfile = 0;
        if (!SetupDiSetClassInstallParamsW(h, &d, &pcp.ClassInstallHeader, sizeof(pcp))) {
            std::fprintf(stderr, "GPU_RESET_SETUPDI_SETPARAMS gle=%lu\n", GetLastError());
            break;
        }
        ok = SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, h, &d) == TRUE;
        if (!ok) {
            std::fprintf(stderr, "GPU_RESET_SETUPDI_CALL gle=%lu state=%lu scope=%lu\n",
                         GetLastError(), stateChange, scope);
        }
        break;
    }
    SetupDiDestroyDeviceInfoList(h);
    return ok;
}

static bool SetupDiToggleBothScopes(DEVINST target, DWORD stateChange) {
    bool a = SetupDiToggleDevNode(target, stateChange, DICS_FLAG_GLOBAL);
    bool b = SetupDiToggleDevNode(target, stateChange, DICS_FLAG_CONFIGSPECIFIC);
    return a || b;
}

static bool DevNodeHealthy(DEVINST devInst, DWORD* outStatus, DWORD* outProblem) {
    DWORD status = 0, problem = 0;
    CONFIGRET cr = CM_Get_DevNode_Status(&status, &problem, devInst, 0);
    if (outStatus) *outStatus = status;
    if (outProblem) *outProblem = problem;
    return (cr == CR_SUCCESS) && ((status & DN_STARTED) != 0) &&
           (problem == CM_PROB_NONE);
}

bool AttemptGpuDevNodeReset(DEVINST devInst, DWORD problemBefore) {
    if (!devInst) return false;
    std::fprintf(stderr,
                 "GPU_RESET_BEGIN problem=%lu CODE31=%d recoverable=%d\n",
                 problemBefore, GpuIsCode31(problemBefore) ? 1 : 0,
                 GpuProblemCodeRecoverable(problemBefore) ? 1 : 0);
    std::fflush(stderr);
    if (!GpuProblemCodeRecoverable(problemBefore)) {
        std::fprintf(stderr, "GPU_RESET=SKIP reason=UNRECOVERABLE_CODE\n");
        std::fflush(stderr);
        return false;
    }

    // 1) Soft restart first (Device Manager "Restart") — often enough for Code 31.
    std::fprintf(stderr, "GPU_RESET_STEP=PROPCHANGE\n");
    std::fflush(stderr);
    (void)SetupDiToggleBothScopes(devInst, DICS_PROPCHANGE);
    Sleep(1000);
    DWORD status = 0, problem = 0;
    if (DevNodeHealthy(devInst, &status, &problem)) {
        std::fprintf(stderr,
                     "GPU_RESET_AFTER status=0x%lX problem=%lu started=1 ok=1 "
                     "need_elevation=0\nGPU_RESET=PASS\n",
                     status, problem);
        std::fflush(stderr);
        return true;
    }

    // 2) CM disable → enable (needs SeLoadDriverPrivilege / Admin).
    CONFIGRET crDis = CM_Disable_DevNode(devInst, 0);
    std::fprintf(stderr, "GPU_RESET_DISABLE cr=0x%lX\n", (unsigned long)crDis);
    std::fflush(stderr);
    if (crDis == CR_ACCESS_DENIED) {
        std::fprintf(stderr, "GPU_RESET_DISABLE_FALLBACK=SetupDi DICS_DISABLE\n");
        std::fflush(stderr);
        (void)SetupDiToggleBothScopes(devInst, DICS_DISABLE);
    }
    Sleep(750);

    CONFIGRET crEn = CM_Enable_DevNode(devInst, 0);
    std::fprintf(stderr, "GPU_RESET_ENABLE cr=0x%lX\n", (unsigned long)crEn);
    std::fflush(stderr);
    if (crEn == CR_ACCESS_DENIED || crDis == CR_ACCESS_DENIED) {
        std::fprintf(stderr, "GPU_RESET_ENABLE_FALLBACK=SetupDi DICS_ENABLE+PROPCHANGE\n");
        std::fflush(stderr);
        (void)SetupDiToggleBothScopes(devInst, DICS_ENABLE);
        (void)SetupDiToggleBothScopes(devInst, DICS_PROPCHANGE);
    }

    // 3) Force ready + parent re-enumerate (helps FAILED_ADD / Code 31).
    CONFIGRET crSetup = CM_Setup_DevNode(devInst, CM_SETUP_DEVNODE_READY);
    std::fprintf(stderr, "GPU_RESET_SETUP_DEVNODE cr=0x%lX\n", (unsigned long)crSetup);
    std::fflush(stderr);
    DEVINST parent = 0;
    if (CM_Get_Parent(&parent, devInst, 0) == CR_SUCCESS && parent) {
        CONFIGRET crRe = CM_Reenumerate_DevNode(parent, 0);
        std::fprintf(stderr, "GPU_RESET_REENUM_PARENT cr=0x%lX\n", (unsigned long)crRe);
        std::fflush(stderr);
    }
    Sleep(1500);

    bool ok = DevNodeHealthy(devInst, &status, &problem);
    bool needElev = (crDis == CR_ACCESS_DENIED) || (crEn == CR_ACCESS_DENIED) ||
                    (crSetup == CR_ACCESS_DENIED);
    // Soft reset left recoverable Code 10/31 (or CM denied) → UAC PnP helper.
    if (!ok && (needElev || GpuProblemCodeRecoverable(problem))) {
        std::fprintf(stderr, "GPU_RESET_AUTO_ELEV_PNP=1 need_elev=%d problem=%lu\n",
                     needElev ? 1 : 0, problem);
        std::fflush(stderr);
        bool elevLaunched = false;
        const bool elevCleared = AttemptElevatedGpuPnpCycleEx(&elevLaunched);
        if (elevLaunched) needElev = false; // elevation obtained; remaining fail ≠ access
        if (elevCleared || elevLaunched)
            ok = DevNodeHealthy(devInst, &status, &problem);
    }
    std::fprintf(stderr,
                 "GPU_RESET_AFTER status=0x%lX problem=%lu started=%d ok=%d "
                 "need_elevation=%d\nGPU_RESET=%s\n",
                 status, problem, ((status & DN_STARTED) != 0) ? 1 : 0, ok ? 1 : 0,
                 needElev ? 1 : 0, ok ? "PASS" : (needElev ? "FAIL_NEED_ELEVATION" : "FAIL"));
    std::fflush(stderr);
    return ok;
}
