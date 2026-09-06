#pragma once
class Win32IDE;

namespace RawrXD::CommandHome {

class Shell {
public:
    static void Create(Win32IDE* ide);
    static void Layout(Win32IDE* ide, int clientW, int clientH);
    static void ApplyMode(Win32IDE* ide);
    static void RefreshContextBar(Win32IDE* ide);
    static void RefreshActivityStrip(Win32IDE* ide);
    static void RefreshFooter(Win32IDE* ide);
};

} // namespace RawrXD::CommandHome
