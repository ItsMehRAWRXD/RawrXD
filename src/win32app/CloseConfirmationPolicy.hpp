#pragma once
// Portable policy shared by native close confirmation and regression tests.
// Win32 MessageBox IDNO is 7; all other responses must not discard edits.
namespace rawrxd::ide {
constexpr bool isExplicitDiscard(int dialogResult) noexcept {
    return dialogResult == 7;
}
constexpr bool mayCloseDirtyDocument(int dialogResult, bool saveSucceeded) noexcept {
    return isExplicitDiscard(dialogResult) || (dialogResult == 6 && saveSucceeded);
}
}
