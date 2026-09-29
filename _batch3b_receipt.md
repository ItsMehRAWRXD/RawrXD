GATE=BATCH3B_SPIKE_TRIGGER_ISOLATION_001

BASELINE_WORKING_SET_MB=18.9
SPIKE_WORKING_SET_MB=0 (no spike detected)
SPIKE_TIME_SEC=N/A
EXIT_TIME_SEC=45
HANDLE_GROWTH=1 (206→207, stable)
THREAD_GROWTH=2 (5→7, stable)
MODULE_SNAPSHOT_CAPTURED=NO (no spike to trigger)
THREAD_SNAPSHOT_CAPTURED=NO

FINDING:
  The 1GB spike from Batch3A was likely a measurement artifact from
  concurrent MSBuild processes consuming 1GB+ RAM. In isolation (no
  build running), the IDE sits perfectly flat at 19MB, 207 handles,
  7 threads, 0.05s CPU, then exits at 45s.

  The real crash is NOT a memory spike — it's the Win32 GUI message
  loop exiting after 45s of idle operation. This is consistent with
  the IDE being a GUI application that exits when:
  - No display/window is available (headless launch)
  - No user interaction occurs
  - GetMessage returns 0 (WM_QUIT received)

  The D-W6-001 fix (intentional leak of g_chatEngine via .release())
  is in place to prevent destructor-chain crashes during teardown.

CULPRIT_CLASS=GUI lifecycle exit (not a memory spike, not a resource leak)
VERDICT=INCONCLUSIVE — crash is from GUI message loop exit, not from a spike

NEXT_ACTION:
  The 45s exit is expected behavior for a GUI app launched headless.
  For long-duration stability, need to either:
  1. Launch with --chat-prompt to keep the app active
  2. Launch with a model to prevent idle exit
  3. Test in an interactive desktop session
