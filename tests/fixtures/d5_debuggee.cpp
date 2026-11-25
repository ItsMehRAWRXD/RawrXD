// D5 debuggee: a global constructor writes the watched global's address to
// d5_watch_addr.txt BEFORE main (so the test can arm DR0 while the debuggee
// is paused at the main breakpoint), then main writes the global in a loop
// with a sleep between writes so the hardware breakpoint event is delivered.
// A marker file proves the loop actually executes under the debugger.
#include <windows.h>
#include <stdio.h>
static volatile int g_watched = 0;
struct WatchAddrInit {
    WatchAddrInit() {
        FILE* f = fopen("d5_watch_addr.txt", "w");
        if (f) {
            fprintf(f, "%p\n", (void*)&g_watched);
            fclose(f);
        }
    }
} s_watchAddrInit;
int main(void) {
    for (int i = 0; i < 200; ++i) {
        if (i == 0) {
            FILE* m = fopen("d5_loop_marker.txt", "w");
            if (m) {
                fprintf(m, "loop entered\n");
                fclose(m);
            }
        }
        g_watched = g_watched + 1;
        if (g_watched == 3) printf("three\n");
        Sleep(50);
    }
    printf("done %d\n", g_watched);
    return 0;
}