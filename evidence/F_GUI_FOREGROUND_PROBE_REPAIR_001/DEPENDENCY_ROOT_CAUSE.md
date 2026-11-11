# Dependency Root Cause

The prior probe referenced `System.Drawing.Point` and `System.Drawing.Rectangle` without loading a drawing assembly. Compilation failed before any Win32 API call. These types were unnecessary; explicit sequential Win32 `POINT` and `RECT` structures are sufficient.
