# Leaf command map

The candidate's top-level `Commands` menu is populated as a broad command catalog; the prior runtime accessibility tree exposed child labels such as `AIContext`, `AIMode`, `Agent`, `Backend`, `Debug`, `Marketplace`, `Modules`, `Telemetry`, and `Voice`. The captured run did not select a leaf, so no numeric leaf ID was emitted.

The concrete extension-panel command IDs are defined in `src/win32app/Win32IDE_ExtensionsPanel.cpp:30-38`: install `11810`, enable `11811`, disable `11812`, uninstall `11813`, reload `11814`. The same file creates the corresponding controls at lines 164-172 and handles them at lines 371-445.

No source evidence maps the generic top-level `Commands` catalog to an ExtensionHost child launch. The direct extension handlers are panel operations; the ProductExtensionRuntime API is a separate route surface.
