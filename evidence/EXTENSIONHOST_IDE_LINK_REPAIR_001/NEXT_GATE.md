# Next gate

LINK_REPAIR=PASS
IDE_BUILD=FAIL
EXTENSIONHOST_BUILD=PASS_PREVIOUSLY_VERIFIED
DEPLOYMENT=NOT_VERIFIED
RUNTIME=NOT_RUN
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0

The five-file CMake repair eliminated all original 18 unresolved symbols. The first newly exposed blocker is seven unresolved `RawrXDChatWindow_*` symbols. Their implementations are in `src/win32app/Win32IDE_ChatWindow.cpp`, which is absent from the IDE target graph. No further repair was applied.
