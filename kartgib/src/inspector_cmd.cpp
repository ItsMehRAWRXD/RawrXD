#include "editor_api.hpp"
#include "terrain_studio.hpp"
#include <cstdio>
#include <string>
HWND inspectorEdit(int index);
HWND inspectorList();

static float readEdit(HWND edit) {
    wchar_t text[64]{};
    GetWindowTextW(edit, text, 64);
    float v = 0;
    swscanf_s(text, L"%f", &v);
    return v;
}
static void writeEdit(HWND edit, float v) {
    if (!edit || GetFocus() == edit) return;
    wchar_t text[64]{};
    swprintf_s(text, L"%.2f", v);
    wchar_t cur[64]{};
    GetWindowTextW(edit, cur, 64);
    if (wcscmp(cur, text) != 0) SetWindowTextW(edit, text);
}
static void saveBrushFile() {
    const StudioBrush& b = studioBrush();
    FILE* f = nullptr;
    fopen_s(&f, "F:/rawrxd/kartgib/evidence/studio_project/brush.txt", "w");
    if (f) { std::fprintf(f, "%d %.4f %.4f %.4f\n", b.mode, b.radius, b.strength, b.falloff); std::fclose(f); }
}
void inspectorOnCommand(int id) {
    if (id == 1001) {
        int sel = static_cast<int>(SendMessageW(inspectorList(), LB_GETCURSEL, 0, 0));
        if (sel >= 0) editorSelect(static_cast<int>(SendMessageW(inspectorList(), LB_GETITEMDATA, sel, 0)));
        return;
    }
    if (id == 1020) {
        int sel = editorSelected();
        if (sel < 0) return;
        editorCommand(sel, readEdit(inspectorEdit(0)), readEdit(inspectorEdit(1)), readEdit(inspectorEdit(2)),
            readEdit(inspectorEdit(3)), readEdit(inspectorEdit(4)));
    } else if (id >= 1040 && id <= 1043) {
        int mode = id - 1040;
        float radius = readEdit(inspectorEdit(5)), strength = readEdit(inspectorEdit(6)), fall = readEdit(inspectorEdit(7));
        if (radius < 1.0f) radius = 1.0f;
        if (strength < 0.1f) strength = 0.1f;
        if (fall < 0.5f) fall = 2.0f;
        studioSetBrush(mode, radius, strength, fall);
        saveBrushFile();
    } else if (id == 1050) editorUndo();
    else if (id == 1051) editorRedo();
    else if (id == 1060 || id == 1061) {
        int sel = editorSelected(), other = 0;
        for (int i = 0; i < editorCount(); ++i) if (editorAt(i)->id != sel) { other = editorAt(i)->id; break; }
        editorParent(sel, id == 1061 ? 0 : other);
    }
}
void inspectorRefresh() {
    HWND list = inspectorList();
    if (!list) return;
    int n = editorCount();
    static int seen = -2;
    if (seen != editorRevision() || static_cast<int>(SendMessageW(list, LB_GETCOUNT, 0, 0)) != n) {
        seen = editorRevision();
        SendMessageW(list, LB_RESETCONTENT, 0, 0);
        for (int i = 0; i < n; ++i) {
            wchar_t line[64]{};
            swprintf_s(line, L"%d %d %S", editorAt(i)->id, editorAt(i)->parent, editorAt(i)->name);
            int row = static_cast<int>(SendMessageW(list, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(line)));
            SendMessageW(list, LB_SETITEMDATA, row, editorAt(i)->id);
        }
    }
    const EditorEnt* e = nullptr;
    for (int i = 0; i < n; ++i) if (editorAt(i)->id == editorSelected()) e = editorAt(i);
    if (e) {
        writeEdit(inspectorEdit(0), e->x); writeEdit(inspectorEdit(1), e->y); writeEdit(inspectorEdit(2), e->z);
        writeEdit(inspectorEdit(3), e->yaw); writeEdit(inspectorEdit(4), e->scale);
    }
    const StudioBrush& b = studioBrush();
    writeEdit(inspectorEdit(5), b.radius); writeEdit(inspectorEdit(6), b.strength); writeEdit(inspectorEdit(7), b.falloff);
}
