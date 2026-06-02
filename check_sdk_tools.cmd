@echo off
if exist "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\rc.exe" (echo RC_22621_OK) else (echo RC_22621_MISSING)
if exist "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\mt.exe" (echo MT_22621_OK) else (echo MT_22621_MISSING)
if exist "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\rc.exe" (echo RC_26100_OK) else (echo RC_26100_MISSING)
if exist "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\mt.exe" (echo MT_26100_OK) else (echo MT_26100_MISSING)
