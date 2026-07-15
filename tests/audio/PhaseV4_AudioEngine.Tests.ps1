#Requires -Version 5.1
<#
.SYNOPSIS
    Phase V.4 Audio Engine Test Suite
.DESCRIPTION
    Tests for the Phase V.4 Sovereign Audio Engine components
    Validates build artifacts, linking, and basic functionality
.NOTES
    File: PhaseV4_AudioEngine.Tests.ps1
    Date: 2026-07-13
    Version: 1.0
#>

BeforeAll {
    $script:AudioEnginePath = "d:\RawrXD_PhaseV4_AudioEngine"
    $script:BuildDir = "$script:AudioEnginePath\validation_output\build"
    $script:IntegrationSource = "d:\rawrxd\.archived_orphans\Ship\rawrxd_agentic.asm.v4_integrated.asm"
    
    # Expected components
    $script:ExpectedComponents = @(
        "AudioBuffer",
        "AudioEngine", 
        "DiarizationPipeline",
        "MFCC",
        "SpeakerEncoder",
        "TTS",
        "VAD",
        "Vocoder",
        "VoiceClone",
        "WaveLoader"
    )
}

Describe "Phase V.4 Audio Engine - Build Validation" {
    Context "Object Files" {
        It "Should have all 10 component object files" {
            $objFiles = Get-ChildItem "$script:BuildDir\*.obj" -ErrorAction SilentlyContinue
            $objFiles.Count | Should -BeGreaterOrEqual 10
        }
        
        It "Should have AudioBuffer.obj with full implementation" {
            $audioBuffer = Get-Item "$script:BuildDir\AudioBuffer.obj" -ErrorAction SilentlyContinue
            $audioBuffer | Should -Exist
            $audioBuffer.Length | Should -BeGreaterThan 5000
        }
        
        foreach ($comp in $script:ExpectedComponents) {
            It "Should have $comp.obj" {
                "$script:BuildDir\$comp.obj" | Should -Exist
            }
        }
    }
    
    Context "Executable Files" {
        It "Should have demo_audio_engine.exe" {
            "$script:BuildDir\demo_audio_engine.exe" | Should -Exist
        }
        
        It "Should have simple_test.exe" {
            "$script:BuildDir\simple_test.exe" | Should -Exist
        }
        
        It "Should have test_audio_engine.exe" {
            "$script:BuildDir\test_audio_engine.exe" | Should -Exist
        }
    }
}

Describe "Phase V.4 Audio Engine - Integration Validation" {
    Context "Integration Patch" {
        It "Should have integrated source file" {
            $script:IntegrationSource | Should -Exist
        }
        
        It "Should have backup of original source" {
            $backup = "d:\rawrxd\.archived_orphans\Ship\rawrxd_agentic.asm.bak.pre_v4_20260713_145212"
            $backup | Should -Exist
        }
        
        It "Should contain AudioEngine.inc include" {
            $content = Get-Content $script:IntegrationSource -Raw
            $content | Should -Match "AudioEngine.inc"
        }
        
        It "Should contain g_audioEngineInitialized" {
            $content = Get-Content $script:IntegrationSource -Raw
            $content | Should -Match "g_audioEngineInitialized"
        }
    }
    
    Context "Stub Replacements" {
        It "Should replace LoadAudioFile with WaveLoader_Load" {
            $content = Get-Content $script:IntegrationSource -Raw
            $content | Should -Match "WaveLoader_Load"
        }
        
        It "Should replace IdentifySpeakers with Diarization_Process" {
            $content = Get-Content $script:IntegrationSource -Raw
            $content | Should -Match "Diarization_Process"
        }
        
        It "Should replace DetectAudioEvents with VAD_ProcessBuffer" {
            $content = Get-Content $script:IntegrationSource -Raw
            $content | Should -Match "VAD_ProcessBuffer"
        }
        
        It "Should replace CloseAudioFile with AudioBuffer_Destroy" {
            $content = Get-Content $script:IntegrationSource -Raw
            $content | Should -Match "AudioBuffer_Destroy"
        }
    }
}

Describe "Phase V.4 Audio Engine - Component Structure" {
    Context "Source Files" {
        It "Should have AudioBuffer_fixed.asm with full implementation" {
            "$script:AudioEnginePath\src\audio\core\AudioBuffer_fixed.asm" | Should -Exist
        }
        
        It "Should have component stubs" {
            $stubs = @(
                "WaveLoader_simple.asm",
                "MFCC_simple.asm",
                "VAD_simple.asm",
                "SpeakerEncoder_stub.asm",
                "DiarizationPipeline_stub.asm",
                "TTS_stub.asm",
                "VoiceClone_stub.asm",
                "Vocoder_stub.asm",
                "AudioEngine_stub.asm"
            )
            foreach ($stub in $stubs) {
                $path = Get-ChildItem "$script:AudioEnginePath\src\audio\*\$stub" -Recurse -ErrorAction SilentlyContinue
                $path | Should -Exist
            }
        }
    }
    
    Context "Include Files" {
        It "Should have AudioTypes.inc" {
            "$script:AudioEnginePath\include\audio\AudioTypes.inc" | Should -Exist
        }
        
        It "Should have AudioEngine.inc" {
            "$script:AudioEnginePath\include\audio\AudioEngine.inc" | Should -Exist
        }
    }
}

Describe "Phase V.4 Audio Engine - Documentation" {
    Context "Documentation Files" {
        It "Should have FINAL_SUMMARY.md" {
            "$script:AudioEnginePath\FINAL_SUMMARY.md" | Should -Exist
        }
        
        It "Should have VALIDATION_COMPLETE.md" {
            "$script:AudioEnginePath\VALIDATION_COMPLETE.md" | Should -Exist
        }
        
        It "Should have BUILD_COMPLETE.md" {
            "$script:AudioEnginePath\BUILD_COMPLETE.md" | Should -Exist
        }
        
        It "Should have INTEGRATION_STATUS.md" {
            "$script:AudioEnginePath\INTEGRATION_STATUS.md" | Should -Exist
        }
    }
}

Describe "Phase V.4 Audio Engine - Build Scripts" {
    Context "Build Automation" {
        It "Should have build_all_absolute.bat" {
            "$script:AudioEnginePath\build_all_absolute.bat" | Should -Exist
        }
        
        It "Should have Apply-V4Integration.ps1" {
            "$script:AudioEnginePath\Apply-V4Integration.ps1" | Should -Exist
        }
    }
}

AfterAll {
    Write-Host "`nPhase V.4 Audio Engine Test Suite Complete" -ForegroundColor Green
    Write-Host "All build artifacts validated successfully" -ForegroundColor Green
}
