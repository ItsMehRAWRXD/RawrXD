# Editor focus boundary

The candidate opened an untitled workspace and displayed a central editor region. The accessibility tree exposed a separate `PowerShell Console` edit with control ID 1001 and did not expose the central editor as a targetable edit. A click in the central editor region did not establish editor focus; the subsequent focus report identified the top-level IDE window rather than the editor. Test text was not entered and no editor request was triggered.

Classification: `EDITOR_FOCUS=FAIL_NOT_EDITOR`.
