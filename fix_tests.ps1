$tests = @('test_dll_load_unload', 'test_dll_multithread', 'test_cpp_api', 'test_inference_integration', 'test_win32ide_integration', 'test_config_roundtrip', 'test_memory_stress', 'test_symbol_exports', 'test_cross_config', 'test_debug_info')
$content = Get-Content F:\rawrxd\tests\CMakeLists.txt -Raw
foreach ($test in $tests) {
    $old = "if(MSVC)`n    set_target_properties($test PROPERTIES`n        MSVC_RUNTIME_LIBRARY `"MultiThreadedDLL`$<`$<CONFIG:Debug>:Debug>`"`n    )`nendif()"
    $new = "if(MSVC)`n    set_target_properties($test PROPERTIES`n        MSVC_RUNTIME_LIBRARY_DEBUG `"MultiThreadedDLLDebug`"`n        MSVC_RUNTIME_LIBRARY_RELEASE `"MultiThreadedDLL`"`n        MSVC_RUNTIME_LIBRARY_RELWITHDEBINFO `"MultiThreadedDLL`"`n        MSVC_RUNTIME_LIBRARY_MINSIZEREL `"MultiThreadedDLL`"`n    )`nendif()"
    $content = $content.Replace($old, $new)
}
Set-Content F:\rawrxd\tests\CMakeLists.txt $content
Write-Host 'Done'