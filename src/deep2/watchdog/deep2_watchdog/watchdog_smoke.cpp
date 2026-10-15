#include "deep2_progress_watchdog.hpp"
#include <cassert>
#include <cstdio>
#include <atomic>
int main(){
    using namespace rawrxd::watchdog;
    {
        Watchdog w({80,500,5});
        std::atomic<bool> timedOut{false};
        assert(w.Start([&](Status s){timedOut=(s.state==State::StartupTimedOut);}));
        Sleep(150);w.Stop();assert(timedOut && w.CancellationRequested());
    }
    {
        Watchdog w({80,500,5});
        std::atomic<bool> timedOut{false};
        assert(w.Start([&](Status){timedOut=true;}));
        w.Progress(Activity::ModelLayer);
        Sleep(130);assert(!timedOut && w.Inspect().state==State::Active);
        w.Finish();w.Stop();
    }
    {
        Watchdog w({80,140,5});
        std::atomic<bool> wallTimeout{false};
        assert(w.Start([&](Status s){wallTimeout=(s.state==State::WallTimedOut);}));
        w.Progress(Activity::PrefillToken);
        Sleep(200);w.Stop();assert(wallTimeout);
    }
    std::puts("WATCHDOG_SMOKE_PASS");
}
