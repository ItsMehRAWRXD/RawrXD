@echo off
set EXE=F:\~dev\rawrxd\build-win32ide-p1\bin\RawrXD-Win32IDE.exe
findstr /m /c:"IDE_LoadModel" "%EXE%" && echo HAS_IDE_LoadModel || echo NO_IDE_LoadModel
findstr /m /c:"LoadModel_skipped_abort" "%EXE%" && echo HAS_SKIPPED || echo NO_SKIPPED
findstr /m /c:"XFMR_KV_ALLOC" "%EXE%" && echo HAS_XFMR_CKPT || echo NO_XFMR_CKPT
findstr /m /c:"calling_LoadModel_UI_pump" "%EXE%" && echo HAS_UI_PUMP || echo NO_UI_PUMP
findstr /m /c:"p1_cpu_load_ckpt" "%EXE%" && echo HAS_CKPT_PATH || echo NO_CKPT_PATH
exit /b 0
