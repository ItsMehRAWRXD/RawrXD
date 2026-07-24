// ============================================================================
// collab_stubs.cpp - Stub implementations for collaboration features
// ============================================================================

#include <string>
#include <windows.h>

struct CursorInfo {
    int x, y;
    int line, column;
};

class CRDTBuffer {
public:
    void applyRemoteOperation(const std::string& op) {
        (void)op;
        OutputDebugStringA("[CRDTBuffer] applyRemoteOperation stub called\n");
    }
};

class CursorWidget {
public:
    void updateCursor(const std::string& id, const CursorInfo& info) {
        (void)id;
        (void)info;
        OutputDebugStringA("[CursorWidget] updateCursor stub called\n");
    }

    void removeCursor(const std::string& id) {
        (void)id;
        OutputDebugStringA("[CursorWidget] removeCursor stub called\n");
    }
};
