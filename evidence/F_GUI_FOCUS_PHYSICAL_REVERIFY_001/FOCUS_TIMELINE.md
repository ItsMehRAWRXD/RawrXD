# Focus Timeline

Physical observations:

| Stage | Foreground HWND | Foreground thread | Target GUI thread | `GetGUIThreadInfo.hwndActive` | `hwndFocus` | Caller `GetFocus` |
|---|---:|---:|---:|---:|---:|---:|
| Before | `656022` | `10416` | `24496` | `0` | `0` | `0` |
| After handoff | `656022` | `10416` | `24496` | `0` | `0` | `0` |

Target editor HWND was `1051364`. `editor_is_gui_focus=false`.
