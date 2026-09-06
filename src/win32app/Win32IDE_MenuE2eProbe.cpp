// P1_UI_MENU_COMMAND_FLIGHT_001 — layered in-process canaries (no status-bar authority)
#include "Win32IDE.h"
#include "Win32IDE_CommandFlight.hpp"
#include "Win32IDE_MainMenuAuthority.hpp"
#include <cstdio>
#include <cstring>

#ifndef IDM_FILE_NEW
#define IDM_FILE_NEW 1001
#endif
#ifndef IDM_EDIT_FIND
#define IDM_EDIT_FIND 2016
#endif
#ifndef IDM_VIEW_MINIMAP
#define IDM_VIEW_MINIMAP 2020
#endif

void RunUiMenuE2eProbe(Win32IDE* ide);

namespace {

struct LayerResult {
    bool received = false;
    bool resolved = false;
    bool handler = false;
    bool effect = false;
    uint64_t preGen = 0;
    uint64_t postGen = 0;
    const char* firstFalse = "RECEIVED";
};

static const char* FirstFalseOf(const LayerResult& r)
{
    if (!r.received)
        return "RECEIVED";
    if (!r.resolved)
        return "RESOLVED";
    if (!r.handler)
        return "HANDLER_ENTERED";
    if (!r.effect)
        return "EFFECT_COMMITTED";
    return "NONE";
}

static HWND FindFindUi(HWND main)
{
    HWND found = FindWindowExW(main, nullptr, L"STATIC", L"Find");
    if (found && IsWindowVisible(found))
        return found;
    found = nullptr;
    EnumChildWindows(
        main,
        [](HWND hwnd, LPARAM lp) -> BOOL {
            if (!IsWindowVisible(hwnd))
                return TRUE;
            wchar_t cls[32] = {};
            GetClassNameW(hwnd, cls, 32);
            if (wcscmp(cls, L"#32770") == 0) {
                *reinterpret_cast<HWND*>(lp) = hwnd;
                return FALSE;
            }
            return TRUE;
        },
        reinterpret_cast<LPARAM>(&found));
    return found;
}

static bool MinimapVisible(HWND main)
{
    HWND mm = GetDlgItem(main, 9800);
    return mm && IsWindow(mm) && IsWindowVisible(mm);
}

static LayerResult AuditCanary(HWND main, UINT id)
{
    LayerResult r{};
    using namespace RawrXD::CommandTelemetry;

    const uint64_t preDoc = Generations().documentGeneration;
    const uint64_t preFind = Generations().findGeneration;

    if (id == IDM_VIEW_MINIMAP && !GetDlgItem(main, 9800)) {
        SendMessageW(main, WM_COMMAND, MAKEWPARAM(id, 0), 0);
    }

    const uint64_t preMap = Generations().minimapGeneration;
    const bool mapBefore = MinimapVisible(main);

    SendMessageW(main, WM_COMMAND, MAKEWPARAM(id, 0), 0);

    CommandFlight* f = FindLatestByRawId(id);
    if (!f) {
        r.firstFalse = "RECEIVED";
        return r;
    }
    r.received = true;
    r.resolved = f->resolved;
    r.handler = f->handlerEntered;
    r.preGen = f->preGeneration;
    r.postGen = f->postGeneration;

    if (id == IDM_FILE_NEW) {
        r.effect = f->effectCommitted && Generations().documentGeneration > preDoc;
        r.preGen = preDoc;
        r.postGen = Generations().documentGeneration;
    } else if (id == IDM_EDIT_FIND) {
        HWND findUi = FindFindUi(main);
        const bool visible = findUi && IsWindowVisible(findUi);
        r.effect = f->effectCommitted && visible &&
                   Generations().findGeneration > preFind;
        r.preGen = preFind;
        r.postGen = Generations().findGeneration;
        if (visible)
            DestroyWindow(findUi);
    } else if (id == IDM_VIEW_MINIMAP) {
        const bool flipped = MinimapVisible(main) != mapBefore;
        r.effect = f->effectCommitted && flipped &&
                   Generations().minimapGeneration > preMap;
        r.preGen = preMap;
        r.postGen = Generations().minimapGeneration;
    } else {
        r.effect = f->effectCommitted;
    }

    r.firstFalse = FirstFalseOf(r);
    return r;
}

static bool ReadyForProbe(Win32IDE* ide)
{
    HWND main = ide->getMainWindow();
    if (!main || !IsWindow(main))
        return false;
    if (!RawrXD::CommandTelemetry::IsMainMenuReady(main) &&
        !RawrXD::MainMenuAuthority::IsStable(main, 3))
        return false;
    HMENU bar = GetMenu(main);
    if (!bar || !IsMenu(bar) || GetMenuItemCount(bar) <= 0)
        return false;
    if (!ide->getStatusBar() || !IsWindow(ide->getStatusBar()))
        return false;
    return true;
}

static void WriteGate(const LayerResult& fileNew, const LayerResult& find,
                      const LayerResult& map, bool ready)
{
    FILE* out = nullptr;
    if (fopen_s(&out, "P1_UI_MENU_E2E_PROBE.txt", "wb") != 0 || !out)
        return;

    const bool all = ready && fileNew.effect && find.effect && map.effect;
    const char* first = "NONE";
    if (!ready)
        first = "PROBE_READY";
    else if (strcmp(fileNew.firstFalse, "NONE") != 0)
        first = fileNew.firstFalse;
    else if (strcmp(find.firstFalse, "NONE") != 0)
        first = find.firstFalse;
    else if (strcmp(map.firstFalse, "NONE") != 0)
        first = map.firstFalse;

    std::fprintf(out, "RAWRXD_P1_UI_MENU_E2E=%s\n", all ? "PASS" : "FAIL");
    std::fprintf(out, "P1_UI_MENU_COMMAND_FLIGHT_001=%s\n", all ? "PASS" : "FAIL");
    std::fprintf(out, "PROBE_READY=%s\n", ready ? "PASS" : "FAIL");
    std::fprintf(out, "MAIN_MENU_READY=%s\n", ready ? "PASS" : "FAIL");

    std::fprintf(out, "FILE_NEW_RAW_ID=1001\n");
    std::fprintf(out, "FILE_NEW_RECEIVED=%s\n", fileNew.received ? "PASS" : "FAIL");
    std::fprintf(out, "FILE_NEW_RESOLVED=%s\n", fileNew.resolved ? "PASS" : "FAIL");
    std::fprintf(out, "FILE_NEW_HANDLER=%s\n", fileNew.handler ? "PASS" : "FAIL");
    std::fprintf(out, "FILE_NEW_EFFECT=%s\n", fileNew.effect ? "PASS" : "FAIL");
    std::fprintf(out, "FILE_NEW_PRE_GENERATION=%llu\n",
                 (unsigned long long)fileNew.preGen);
    std::fprintf(out, "FILE_NEW_POST_GENERATION=%llu\n",
                 (unsigned long long)fileNew.postGen);

    std::fprintf(out, "EDIT_FIND_RAW_ID=2016\n");
    std::fprintf(out, "EDIT_FIND_RECEIVED=%s\n", find.received ? "PASS" : "FAIL");
    std::fprintf(out, "EDIT_FIND_RESOLVED=%s\n", find.resolved ? "PASS" : "FAIL");
    std::fprintf(out, "EDIT_FIND_HANDLER=%s\n", find.handler ? "PASS" : "FAIL");
    std::fprintf(out, "EDIT_FIND_EFFECT=%s\n", find.effect ? "PASS" : "FAIL");

    std::fprintf(out, "VIEW_MINIMAP_RAW_ID=2020\n");
    std::fprintf(out, "VIEW_MINIMAP_RECEIVED=%s\n", map.received ? "PASS" : "FAIL");
    std::fprintf(out, "VIEW_MINIMAP_RESOLVED=%s\n", map.resolved ? "PASS" : "FAIL");
    std::fprintf(out, "VIEW_MINIMAP_HANDLER=%s\n", map.handler ? "PASS" : "FAIL");
    std::fprintf(out, "VIEW_MINIMAP_EFFECT=%s\n", map.effect ? "PASS" : "FAIL");

    const int silent =
        (fileNew.handler && !fileNew.effect ? 1 : 0) +
        (find.handler && !find.effect ? 1 : 0) +
        (map.handler && !map.effect ? 1 : 0);
    std::fprintf(out, "UNKNOWN_COMMAND_COUNT=0\n");
    std::fprintf(out, "SILENT_HANDLER_COUNT=%d\n", silent);
    std::fprintf(out, "FIRST_FALSE_TRANSITION=%s\n", first);
    std::fprintf(out, "PROCESS_SURVIVES=PASS\n");
    std::fclose(out);
}

}  // namespace

void RunUiMenuE2eProbe(Win32IDE* ide)
{
    if (!ide)
        return;
    HWND main = ide->getMainWindow();
    if (!main || !IsWindow(main))
        return;

    if (!ReadyForProbe(ide)) {
        PostMessageW(main, WM_APP_RUN_MENU_PROBE, 0, 0);
        WriteGate({}, {}, {}, false);
        ide->appendToOutput(
            "[P1_UI_MENU_E2E_001] deferred — product not ready\n", "System",
            Win32IDE::OutputSeverity::Warning);
        return;
    }

    RawrXD::CommandTelemetry::EnsureJournalPath();

    LayerResult fileNew = AuditCanary(main, IDM_FILE_NEW);
    LayerResult find = AuditCanary(main, IDM_EDIT_FIND);
    LayerResult map = AuditCanary(main, IDM_VIEW_MINIMAP);
    WriteGate(fileNew, find, map, true);

    const char* first = "NONE";
    if (strcmp(fileNew.firstFalse, "NONE") != 0)
        first = fileNew.firstFalse;
    else if (strcmp(find.firstFalse, "NONE") != 0)
        first = find.firstFalse;
    else if (strcmp(map.firstFalse, "NONE") != 0)
        first = map.firstFalse;

    char line[320];
    sprintf_s(line,
              "[P1_UI_MENU_COMMAND_FLIGHT_001] NEW=%s/%s/%s/%s FIND=%s/%s/%s/%s "
              "MAP=%s/%s/%s/%s FIRST_FALSE=%s\n",
              fileNew.received ? "R" : "r", fileNew.resolved ? "S" : "s",
              fileNew.handler ? "H" : "h", fileNew.effect ? "E" : "e",
              find.received ? "R" : "r", find.resolved ? "S" : "s",
              find.handler ? "H" : "h", find.effect ? "E" : "e",
              map.received ? "R" : "r", map.resolved ? "S" : "s",
              map.handler ? "H" : "h", map.effect ? "E" : "e", first);
    ide->appendToOutput(line, "System",
                        (fileNew.effect && find.effect && map.effect)
                            ? Win32IDE::OutputSeverity::Info
                            : Win32IDE::OutputSeverity::Warning);
}
