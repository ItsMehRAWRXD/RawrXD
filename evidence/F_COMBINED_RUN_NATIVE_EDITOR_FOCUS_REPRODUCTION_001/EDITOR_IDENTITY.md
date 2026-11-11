# Editor identity

The intended editor was confirmed by native Win32 identity, not accessibility text:

- Class: `RichEdit20A`
- Control ID: `1001`
- Parent: candidate main HWND `724068`
- Visibility: true
- Focus after normal click: true

The accessibility layer continued to label an ID-1001 edit as `PowerShell Console`; that label is therefore not authoritative for native focus ownership.
