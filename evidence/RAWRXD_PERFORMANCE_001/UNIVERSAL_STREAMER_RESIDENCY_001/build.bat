@echo off
setlocal
set CFLAGS=/nologo /TC /O2 /W3 /D_CRT_SECURE_NO_WARNINGS
set CORE=ur_provider_file.obj ur_index.obj ur_op_auth.obj ur_slot.obj ur_alias.obj ur_device.obj ur_hot_lease.obj ur_demote.obj ur_promote.obj ur_residency.obj ur_plan.obj ur_ns.obj
cl %CFLAGS% /c ur_provider_file.c || exit /b 1
cl %CFLAGS% /c ur_index.c || exit /b 1
cl %CFLAGS% /c ur_op_auth.c || exit /b 1
cl %CFLAGS% /c ur_slot.c || exit /b 1
cl %CFLAGS% /c ur_alias.c || exit /b 1
cl %CFLAGS% /c ur_device.c || exit /b 1
cl %CFLAGS% /c ur_hot_lease.c || exit /b 1
cl %CFLAGS% /c ur_demote.c || exit /b 1
cl %CFLAGS% /c ur_promote.c || exit /b 1
cl %CFLAGS% /c ur_residency.c || exit /b 1
cl %CFLAGS% /c ur_plan.c || exit /b 1
cl %CFLAGS% /c ur_ns.c || exit /b 1
cl /nologo /EHsc /O2 /W3 /c ur_gpu_d3d12_init.cpp || exit /b 1
cl /nologo /EHsc /O2 /W3 /c ur_gpu_d3d12_util.cpp || exit /b 1
cl /nologo /EHsc /O2 /W3 /c ur_gpu_d3d12_copy.cpp || exit /b 1
cl /nologo /EHsc /O2 /W3 /c ur_gpu_d3d12_readback.cpp || exit /b 1
cl /nologo /EHsc /O2 /W3 smoke_d3d12_create.cpp /link d3d12.lib dxgi.lib /OUT:smoke_d3d12_create.exe || exit /b 1
smoke_d3d12_create.exe || exit /b 1
cl %CFLAGS% /c smoke_acceptance15.c || exit /b 1
link /nologo %CORE% smoke_acceptance15.obj /OUT:smoke_acceptance15.exe || exit /b 1
smoke_acceptance15.exe || exit /b 1
cl %CFLAGS% /c smoke_lifecycle.c || exit /b 1
link /nologo %CORE% smoke_lifecycle.obj /OUT:smoke_lifecycle.exe || exit /b 1
smoke_lifecycle.exe || exit /b 1
cl %CFLAGS% /c smoke_join.c || exit /b 1
link /nologo %CORE% smoke_join.obj /OUT:smoke_join.exe || exit /b 1
smoke_join.exe || exit /b 1
cl %CFLAGS% /c smoke_alias.c || exit /b 1
link /nologo %CORE% smoke_alias.obj /OUT:smoke_alias.exe || exit /b 1
smoke_alias.exe || exit /b 1
cl %CFLAGS% /c smoke_hot.c || exit /b 1
link /nologo %CORE% smoke_hot.obj /OUT:smoke_hot.exe || exit /b 1
smoke_hot.exe || exit /b 1
cl %CFLAGS% /c smoke_gpu.c || exit /b 1
link /nologo %CORE% ur_gpu_d3d12_init.obj ur_gpu_d3d12_util.obj ur_gpu_d3d12_copy.obj ur_gpu_d3d12_readback.obj smoke_gpu.obj d3d12.lib dxgi.lib /OUT:smoke_gpu.exe || exit /b 1
smoke_gpu.exe || exit /b 1
cl %CFLAGS% /c smoke_namespace.c || exit /b 1
link /nologo %CORE% smoke_namespace.obj /OUT:smoke_namespace.exe || exit /b 1
smoke_namespace.exe || exit /b 1
cl %CFLAGS% /c smoke_plan.c || exit /b 1
link /nologo %CORE% smoke_plan.obj /OUT:smoke_plan.exe || exit /b 1
smoke_plan.exe || exit /b 1
echo UNIVERSAL_STREAMER_RESIDENCY_BUILD=PASS
echo REAL_REGION_LIFECYCLE_001=PASS
echo RESIDENCY_JOIN_WAIT_001=PASS
echo REGION_ALIAS_COHERENCE_001=PASS
echo REAL_DEVICE_HOT_UPLOAD_001=PASS
echo RAM_TO_GPU_PROMOTION_001=PASS
