# Dispatch breadcrumbs

No runtime breadcrumb file or console trace was captured for this reproduction. The existing source markers remain the expected evidence points: `WM_COMMAND_ENTER`, `onCommand_ENTER`, route entry/exit, and `WM_COMMAND_EXIT_OK` in `src/win32app/Win32IDE_Core.cpp:610-622`, `5250+`, and approximately `5838-5878`.

Because the top-level menu was opened but no leaf command selected, absence of a command breadcrumb is consistent with no command dispatch. It does not establish a menu-initialization defect.
