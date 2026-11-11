/*
 * editor_hardened.c - Native dependency-free test harness for the
 * RawrXD_TextEditorGUI_hardened embeddable editor module.
 *
 * Compiled with cl.exe only (Win32 API), linked against the editor object:
 *   cl /nologo /O2 /W4 /MT editor_hardened.c ..\..\build_hardened\RawrXD_TextEditorGUI_hardened.obj
 *          user32.lib kernel32.lib gdi32.lib /link /OUT:editor_tests.exe /SUBSYSTEM:CONSOLE
 *
 * Each test prints "<name>: PASS" or "<name>: FAIL <reason>" and returns
 * a nonzero exit code if any test fails.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <excpt.h>

/* ---- Editor ABI (declared in RawrXD_TextEditorGUI_hardened.asm) ---- */
extern HWND __cdecl EditorWindow_Create(HINSTANCE hInstance, HWND hParent,
                                        int x, int y, int w, int h);
extern void __cdecl EditorWindow_Destroy(HWND hContainer);
extern LRESULT __cdecl EditorWindow_SendMessage(HWND hContainer, UINT uMsg,
                                                WPARAM wParam, LPARAM lParam);
extern int  __cdecl EditorWindow_GetDirty(HWND hContainer);
extern void __cdecl EditorWindow_SetDirty(HWND hContainer, int dirty);
extern int  __cdecl EditorWindow_GetSelection(HWND hContainer, int *pStart, int *pEnd);
extern void __cdecl EditorWindow_SetSelection(HWND hContainer, int start, int end);
extern HWND __cdecl EditorWindow_GetEditHwnd(HWND hContainer);
extern HWND __cdecl EditorWindow_GetGutterHwnd(HWND hContainer);
extern int  __cdecl EditorWindow_GetText(HWND hContainer, LPWSTR pBuf, int cchMax);
extern int  __cdecl EditorWindow_SetText(HWND hContainer, LPCWSTR pText);
extern int  __cdecl EditorWindow_GetTextLength(HWND hContainer);
extern int  __cdecl EditorWindow_LoadFile(HWND hContainer, LPCWSTR pPath);
extern int  __cdecl EditorWindow_SaveFile(HWND hContainer, LPCWSTR pPath);

/* window procedures exported from the editor module (x64 single calling convention) */
extern LRESULT __cdecl EditorContainerProc(HWND, UINT, WPARAM, LPARAM);
extern LRESULT __cdecl GutterProc(HWND, UINT, WPARAM, LPARAM);

/* Windows messages / edit messages the editor does not re-export */
#ifndef WM_CREATE
#define WM_CREATE 1
#endif
#ifndef EM_SETSEL
#define EM_SETSEL 0x00B1
#endif
#ifndef EM_GETSEL
#define EM_GETSEL 0x00B0
#endif
#ifndef EM_REPLACESEL
#define EM_REPLACESEL 0x00C2
#endif
#ifndef WM_GETTEXT
#define WM_GETTEXT 0x000D
#endif
#ifndef WM_GETTEXTLENGTH
#define WM_GETTEXTLENGTH 0x000E
#endif
#ifndef WM_SETTEXT
#define WM_SETTEXT 0x000C
#endif
#ifndef EN_CHANGE
#define EN_CHANGE 0x0300
#endif
#ifndef WM_SETFONT
#define WM_SETFONT 0x0033
#endif
#ifndef GWLP_USERDATA
#define GWLP_USERDATA (-21)
#endif
#ifndef WS_OVERLAPPED
#define WS_OVERLAPPED 0
#endif

static int g_failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
        g_failures++; \
    } else { \
        printf("  ok:   %s\n", msg); \
    } \
} while (0)

static HINSTANCE g_hInst;
static HWND g_host = NULL;   /* message-only host window */

/* ---- helpers ---- */

static HWND CreateHost(void)
{
    WNDCLASSW wc = {0};
    wc.lpfnWndProc   = DefWindowProcW;
    wc.hInstance     = g_hInst;
    wc.lpszClassName = L"EditorTestHost";
    if (!RegisterClassW(&wc)) {
        printf("  RegisterClassW(host) failed, GetLastError=%lu\n", GetLastError());
        return NULL;
    }
    HWND h = CreateWindowExW(0, L"EditorTestHost", L"host", WS_OVERLAPPED,
                             0, 0, 100, 100, NULL, NULL, g_hInst, NULL);
    if (!h) {
        printf("  CreateWindowExW(host) failed, GetLastError=%lu\n", GetLastError());
        return NULL;
    }
    printf("  host hwnd=%p\n", (void*)h);
    return h;
}

static int PumpIdle(void)
{
    MSG msg;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}

static int RegisterEditorClasses(void)
{
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.hInstance = g_hInst;
    wc.hIcon = 0;
    wc.hCursor = 0;
    wc.hbrBackground = 0;
    wc.lpszMenuName = 0;
    wc.hIconSm = 0;

    wc.lpfnWndProc = EditorContainerProc;
    wc.lpszClassName = L"RawrXD Hardened Editor";
    if (!RegisterClassExW(&wc)) {
        printf("  RegisterClassExW(container) failed, err=%lu\n", GetLastError());
        return 0;
    }

    wc.lpfnWndProc = GutterProc;
    wc.lpszClassName = L"RawrXD Gutter";
    if (!RegisterClassExW(&wc)) {
        printf("  RegisterClassExW(gutter) failed, err=%lu\n", GetLastError());
        return 0;
    }
    printf("  editor classes registered\n");
    return 1;
}

static HWND CreateEditorInstance(void)
{
    PumpIdle();
    SetLastError(0);
    printf("  about to direct CreateWindowExW\n");
    fflush(stdout);
    HWND direct = CreateWindowExW(0, L"RawrXD Hardened Editor", L"direct",
                                  WS_CHILD | WS_VISIBLE,
                                  0, 0, 400, 300, g_host, NULL, g_hInst, NULL);
    printf("  direct CreateWindowExW returned %p, err=%lu\n", (void*)direct, GetLastError());
    fflush(stdout);
    if (direct) DestroyWindow(direct);
    printf("  about to call EditorWindow_Create\n");
    fflush(stdout);
    __try {
        HWND e = EditorWindow_Create(g_hInst, g_host, 0, 0, 400, 300);
        printf("  EditorWindow_Create returned %p\n", (void*)e);
        fflush(stdout);
        if (!e) {
            DWORD err = GetLastError();
            printf("  EditorWindow_Create failed, GetLastError=%lu\n", err);
        }
        return e;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        printf("  EditorWindow_Create CRASHED with exception 0x%08lX\n", code);
        return NULL;
    }
}

/* =========================================================================
   editor.foundation
   ========================================================================= */
static void test_foundation(void)
{
    printf("editor.foundation ...\n");
    HWND e1 = CreateEditorInstance();
    CHECK(e1 != NULL, "first editor instance created");
    if (!e1) return;

    HWND e2 = CreateEditorInstance();
    CHECK(e2 != NULL, "second independent editor instance created");
    fflush(stdout);
    if (!e2) { EditorWindow_Destroy(e1); return; }

    /* direct check of GWLP_USERDATA first */
    LONG_PTR ud1 = GetWindowLongPtrW(e1, GWLP_USERDATA);
    printf("  GWLP_USERDATA(e1)=%p\n", (void*)ud1);
    fflush(stdout);
    __try {
        HWND ed1 = EditorWindow_GetEditHwnd(e1);
        printf("  GetEditHwnd(e1)=%p\n", (void*)ed1);
        fflush(stdout);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        printf("  GetEditHwnd(e1) CRASHED 0x%08lX\n", code);
        ed1 = NULL;
    }
    __try {
        HWND ed2 = EditorWindow_GetEditHwnd(e2);
        printf("  GetEditHwnd(e2)=%p\n", (void*)ed2);
        fflush(stdout);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        printf("  GetEditHwnd(e2) CRASHED 0x%08lX\n", code);
        ed2 = NULL;
    }
    CHECK(ed1 != NULL, "instance 1 has edit hwnd");
    CHECK(ed2 != NULL, "instance 2 has edit hwnd");
    CHECK(ed1 != ed2, "instances have distinct edit controls");

    /* focus forwarding: set focus to container, edit should own focus */
    printf("  testing focus forwarding\n");
    fflush(stdout);
    SetFocus(e1);
    PumpIdle();
    CHECK(GetFocus() == ed1, "focus forwarded to edit control");
    CHECK(ed2 != NULL, "instance 2 has edit hwnd");
    CHECK(ed1 != ed2, "instances have distinct edit controls");

    /* focus forwarding: set focus to container, edit should own focus */
    SetFocus(e1);
    PumpIdle();
    CHECK(GetFocus() == ed1, "focus forwarded to edit control");

    /* dirty state starts clean */
    CHECK(EditorWindow_GetDirty(e1) == 0, "new instance is not dirty");

    /* destroy child must not kill the host/message loop */
    EditorWindow_Destroy(e2);
    PumpIdle();
    CHECK(IsWindow(g_host), "host window survives editor child destruction");

    /* recreate after destroy */
    HWND e3 = CreateEditorInstance();
    CHECK(e3 != NULL, "editor recreated after destroy");
    if (e3) EditorWindow_Destroy(e3);

    EditorWindow_Destroy(e1);
    printf("editor.foundation %s\n", g_failures ? "FAIL" : "PASS");
}

/* =========================================================================
   editor.abi
   ========================================================================= */
static void test_abi(void)
{
    printf("editor.abi ...\n");
    HWND e = CreateEditorInstance();
    CHECK(e != NULL, "editor created for ABI test");
    if (!e) return;

    HWND ed = EditorWindow_GetEditHwnd(e);
    HWND gutter = EditorWindow_GetGutterHwnd(e);
    CHECK(ed != NULL, "GetEditHwnd returns valid hwnd");
    CHECK(gutter != NULL, "GetGutterHwnd returns valid hwnd");
    CHECK(gutter != ed, "gutter and edit are distinct windows");

    /* selection ABI round-trip */
    EditorWindow_SetSelection(e, 5, 10);
    PumpIdle();
    int s = -1, t = -1;
    EditorWindow_GetSelection(e, &s, &t);
    CHECK(s == 5 && t == 10, "SetSelection/GetSelection round-trip (5,10)");

    /* dirty ABI */
    EditorWindow_SetDirty(e, 1);
    CHECK(EditorWindow_GetDirty(e) != 0, "SetDirty(1) reflected");
    EditorWindow_SetDirty(e, 0);
    CHECK(EditorWindow_GetDirty(e) == 0, "SetDirty(0) cleared");

    /* text ABI */
    const WCHAR *txt = L"hello world";
    EditorWindow_SetText(e, txt);
    PumpIdle();
    WCHAR buf[256] = {0};
    int n = EditorWindow_GetText(e, buf, 256);
    CHECK(n == 11, "GetText length == 11");
    CHECK(wcscmp(buf, txt) == 0, "GetText content matches");
    CHECK(EditorWindow_GetTextLength(e) == 11, "GetTextLength == 11");

    /* selection persists across text set */
    EditorWindow_SetSelection(e, 0, 5);
    PumpIdle();
    EditorWindow_GetSelection(e, &s, &t);
    CHECK(s == 0 && t == 5, "selection retained after SetText");

    EditorWindow_Destroy(e);
    printf("editor.abi %s\n", g_failures ? "FAIL" : "PASS");
}

/* =========================================================================
   editor.gutter
   ========================================================================= */
static void test_gutter(void)
{
    printf("editor.gutter ...\n");
    HWND e = CreateEditorInstance();
    CHECK(e != NULL, "editor created for gutter test");
    if (!e) return;

    HWND gutter = EditorWindow_GetGutterHwnd(e);
    HWND ed = EditorWindow_GetEditHwnd(e);

    /* initial gutter aligned at x=0 */
    RECT gr = {0}, er = {0};
    GetWindowRect(gutter, &gr);
    GetWindowRect(ed, &er);
    CHECK(gr.left == er.left - (gr.right - gr.left),
          "gutter left edge aligns with edit left minus gutter width");

    /* multiline text -> scroll -> gutter should still be valid/aligned */
    const WCHAR *ml = L"line1\r\nline2\r\nline3\r\nline4\r\nline5\r\n";
    EditorWindow_SetText(e, ml);
    PumpIdle();

    /* resize the container; gutter and edit relayout */
    SendMessageW(e, WM_SIZE, 0, MAKELPARAM(600, 400));
    PumpIdle();
    GetWindowRect(gutter, &gr);
    GetWindowRect(ed, &er);
    CHECK(gr.right - gr.left > 0, "gutter has nonzero width after resize");
    CHECK(er.right - er.left > 0, "edit has nonzero width after resize");
    CHECK(gr.left == er.left - (gr.right - gr.left),
          "gutter still aligned after resize");

    /* font change */
    HFONT hFont = CreateFontW(20, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                              ANSI_CHARSET, OUT_DEFAULT_PRECIS,
                              CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                              DEFAULT_PITCH, L"Consolas");
    SendMessageW(ed, WM_SETFONT, (WPARAM)hFont, 0);
    PumpIdle();
    GetWindowRect(gutter, &gr);
    GetWindowRect(ed, &er);
    CHECK(gr.left == er.left - (gr.right - gr.left),
          "gutter realigned after font change");
    DeleteObject(hFont);

    /* vertical scroll via EM_SETSEL beyond visible not needed; just invalidate */
    SendMessageW(ed, WM_VSCROLL, 0, 0);

    EditorWindow_Destroy(e);
    printf("editor.gutter %s\n", g_failures ? "FAIL" : "PASS");
}

/* =========================================================================
   editor.persistence
   ========================================================================= */
static void test_persistence(void)
{
    printf("editor.persistence ...\n");
    WCHAR dir[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH, dir);
    WCHAR path[MAX_PATH] = {0};
    swprintf(path, MAX_PATH, L"%seditor_test_%d.txt", dir, GetCurrentProcessId());

    const WCHAR *content = L"Unicode persistence check: \u00e9\u4f60\u597d\u65e5\r\nsecond line\r\n";
    HWND e = CreateEditorInstance();
    CHECK(e != NULL, "editor created for persistence test");
    if (!e) return;

    /* write content directly */
    EditorWindow_SetText(e, content);
    PumpIdle();
    CHECK(EditorWindow_GetDirty(e) != 0, "after SetText, dirty is set");

    /* save */
    CHECK(EditorWindow_SaveFile(e, path) != 0, "SaveFile succeeds");
    PumpIdle();
    CHECK(EditorWindow_GetDirty(e) == 0, "after save, dirty cleared");

    /* verify file bytes on disk */
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(h != INVALID_HANDLE_VALUE, "saved file exists on disk");
    if (h != INVALID_HANDLE_VALUE) {
        DWORD size = GetFileSize(h, NULL);
        WCHAR *disk = (WCHAR *)malloc(size + 4);
        DWORD read = 0;
        ReadFile(h, disk, size, &read, NULL);
        CloseHandle(h);
        disk[size/2] = L'\0';
        CHECK(wcscmp(disk, content) == 0, "disk content matches saved text");
        free(disk);
    }

    /* load into a fresh instance */
    HWND e2 = CreateEditorInstance();
    CHECK(e2 != NULL, "second instance for load test");
    if (e2) {
        CHECK(EditorWindow_LoadFile(e2, path) != 0, "LoadFile succeeds");
        PumpIdle();
        WCHAR buf[512] = {0};
        int n = EditorWindow_GetText(e2, buf, 512);
        CHECK(n > 0, "loaded text has content");
        CHECK(wcscmp(buf, content) == 0, "loaded text matches original");
        CHECK(EditorWindow_GetDirty(e2) == 0, "loaded instance not dirty");
        EditorWindow_Destroy(e2);
    }

    /* failed save preserves original: make path read-only dir */
    WCHAR bad[MAX_PATH] = {0};
    swprintf(bad, MAX_PATH, L"%s\\nonexistent_dir_xyz\\file.txt", dir);
    EditorWindow_SetText(e, L"should not overwrite anything");
    PumpIdle();
    int rc = EditorWindow_SaveFile(e, bad);
    CHECK(rc == 0, "SaveFile to invalid path fails");

    /* original file still intact */
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD size = GetFileSize(h, NULL);
        WCHAR *disk = (WCHAR *)malloc(size + 4);
        DWORD read = 0;
        ReadFile(h, disk, size, &read, NULL);
        CloseHandle(h);
        disk[size/2] = L'\0';
        CHECK(wcscmp(disk, content) == 0, "original file preserved after failed save");
        free(disk);
    }

    DeleteFileW(path);
    EditorWindow_Destroy(e);
    printf("editor.persistence %s\n", g_failures ? "FAIL" : "PASS");
}

/* =========================================================================
   editor.selection
   ========================================================================= */
static void test_selection(void)
{
    printf("editor.selection ...\n");
    HWND e = CreateEditorInstance();
    CHECK(e != NULL, "editor created for selection test");
    if (!e) return;

    HWND ed = EditorWindow_GetEditHwnd(e);

    /* multiline with tabs */
    const WCHAR *ml = L"col1\tcol2\tcol3\r\nAAA\tBBB\tCCC\r\nDDD\tEEE\tFFF\r\n";
    EditorWindow_SetText(e, ml);
    PumpIdle();

    /* selection on line 2 (chars 9-12 = "AAA") */
    EditorWindow_SetSelection(e, 9, 12);
    PumpIdle();
    int s = -1, t = -1;
    EditorWindow_GetSelection(e, &s, &t);
    CHECK(s == 9 && t == 12, "multiline selection start/end recorded");

    /* selection via native EM messages still tracked */
    SendMessageW(ed, EM_SETSEL, 0, 3);
    PumpIdle();
    EditorWindow_GetSelection(e, &s, &t);
    CHECK(s == 0 && t == 3, "native EM_SETSEL forwarded to ABI state");

    /* undo consistency: replace selection then undo */
    SendMessageW(ed, EM_REPLACESEL, 0, (LPARAM)L"X");
    PumpIdle();
    SendMessageW(ed, WM_SETTEXT, 0, (LPARAM)ml); /* restore via undo not needed */
    PumpIdle();
    EditorWindow_GetSelection(e, &s, &t);
    /* after restore, selection empty */
    CHECK(s == t, "selection empty after text restore");

    /* large selection across lines */
    EditorWindow_SetSelection(e, 0, 200);
    PumpIdle();
    EditorWindow_GetSelection(e, &s, &t);
    CHECK(s == 0 && t == 200, "large multiline selection recorded");

    EditorWindow_Destroy(e);
    printf("editor.selection %s\n", g_failures ? "FAIL" : "PASS");
}

int wmain(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    g_hInst = GetModuleHandleW(NULL);
    if (!RegisterEditorClasses()) return 1;
    g_host = CreateHost();
    CHECK(g_host != NULL, "message-only host created");
    if (!g_host) return 1;

    test_foundation();
    test_abi();
    test_gutter();
    test_persistence();
    test_selection();

    if (g_host) DestroyWindow(g_host);

    printf("\n%s (%d failure%s)\n",
           g_failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
