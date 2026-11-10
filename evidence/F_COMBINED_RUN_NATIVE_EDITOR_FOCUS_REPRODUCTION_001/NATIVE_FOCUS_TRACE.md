# Native focus trace

Before the candidate was raised, the foreground was the Edge window. The candidate child inventory nevertheless found the intended editor:

`HWND=3607288 CLASS=RichEdit20A ID=1001 PARENT=724068 VISIBLE=True`.

After raising the candidate and issuing one normal click in the central editor region, `GetGUIThreadInfo` reported:

```text
FG=724068/RawrXD_IDE_Window pid=23584 tid=13868
active=724068/RawrXD_IDE_Window
focus=3607288/RichEdit20A/id=1001/parent=724068/vis=True
```

This is direct native evidence that the intended central editor owned keyboard focus in this diagnostic run.
