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

static bool SetupDiToggleDevNode(DEVINST target, DWORD stateChange) {
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
        pcp.Scope = DICS_FLAG_CONFIGSPECIFIC;
        pcp.HwProfile = 0;
        if (!SetupDiSetClassInstallParamsW(h, &d, &pcp.ClassInstallHeader, sizeof(pcp)))
            break;
        ok = SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, h, &d) == TRUE;
        break;
    }
    SetupDiDestroyDeviceInfoList(h);
    return ok;
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

    CONFIGRET crDis = CM_Disable_DevNode(devInst, 0);
    std::fprintf(stderr, "GPU_RESET_DISABLE cr=0x%lX\n", (unsigned long)crDis);
    std::fflush(stderr);
    if (crDis == CR_ACCESS_DENIED) {
        std::fprintf(stderr, "GPU_RESET_DISABLE_FALLBACK=SetupDi DICS_DISABLE\n");
        std::fflush(stderr);
        (void)SetupDiToggleDevNode(devInst, DICS_DISABLE);
    }
    Sleep(750);

    CONFIGRET crEn = CM_Enable_DevNode(devInst, 0);
    std::fprintf(stderr, "GPU_RESET_ENABLE cr=0x%lX\n", (unsigned long)crEn);
    std::fflush(stderr);
    if (crEn == CR_ACCESS_DENIED || crDis == CR_ACCESS_DENIED) {
        std::fprintf(stderr, "GPU_RESET_ENABLE_FALLBACK=SetupDi DICS_ENABLE+PROPCHANGE\n");
        std::fflush(stderr);
        (void)SetupDiToggleDevNode(devInst, DICS_ENABLE);
        (void)SetupDiToggleDevNode(devInst, DICS_PROPCHANGE);
    }
    Sleep(1500);

    DWORD status = 0, problem = 0;
    CONFIGRET crSt = CM_Get_DevNode_Status(&status, &problem, devInst, 0);
    const bool ok = (crSt == CR_SUCCESS) && ((status & DN_STARTED) != 0) &&
                    (problem == CM_PROB_NONE);
    const bool needElev = (crDis == CR_ACCESS_DENIED) || (crEn == CR_ACCESS_DENIED);
    std::fprintf(stderr,
                 "GPU_RESET_AFTER status=0x%lX problem=%lu started=%d ok=%d "
                 "need_elevation=%d\nGPU_RESET=%s\n",
                 status, problem, ((status & DN_STARTED) != 0) ? 1 : 0, ok ? 1 : 0,
                 needElev ? 1 : 0, ok ? "PASS" : (needElev ? "FAIL_NEED_ELEVATION" : "FAIL"));
    std::fflush(stderr);
    return ok;
}
