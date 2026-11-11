# Smoke Tests for Hotpatch System
# Quick validation that core functionality works
# Run before deployments

BeforeAll {
    $script:SecureHotpatchPath = "security/integration/secure_hotpatch.ps1"
    $script:HealthCheckPath = "monitoring/scripts/health_check.ps1"
}

Describe "Hotpatch Smoke Tests" -Tag "Smoke" {
    
    Context "System Availability" {
        
        It "Should respond to status check" {
            $result = & $script:SecureHotpatchPath -Operation status
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should complete health check" {
            $result = & $script:HealthCheckPath -JsonOutput
            $json = $result | ConvertFrom-Json
            $json.overall_status | Should -Not -BeNullOrEmpty
        }
        
        It "Should have healthy overall status" {
            $result = & $script:HealthCheckPath -JsonOutput
            $json = $result | ConvertFrom-Json
            $json.overall_status | Should -BeIn @("healthy", "degraded")
        }
    }
    
    Context "Core Components" {
        
        It "Should have RBAC system operational" {
            $result = & $script:HealthCheckPath -JsonOutput
            $json = $result | ConvertFrom-Json
            
            $rbacCheck = $json.checks | Where-Object { $_.component -eq "Security" -and $_.check -eq "RBAC System" }
            $rbacCheck.status | Should -Be "pass"
        }
        
        It "Should have audit logger operational" {
            $result = & $script:HealthCheckPath -JsonOutput
            $json = $result | ConvertFrom-Json
            
            $auditCheck = $json.checks | Where-Object { $_.component -eq "Security" -and $_.check -eq "Audit Logger" }
            $auditCheck.status | Should -Be "pass"
        }
        
        It "Should have patch registry operational" {
            $result = & $script:HealthCheckPath -JsonOutput
            $json = $result | ConvertFrom-Json
            
            $registryCheck = $json.checks | Where-Object { $_.component -eq "Hotpatch" -and $_.check -eq "Patch Registry" }
            $registryCheck.status | Should -Be "pass"
        }
    }
    
    Context "Security Integration" {
        
        It "Should have security wrapper loaded" {
            $result = & $script:SecureHotpatchPath -Operation status
            $result | Should -Match "Security wrapper loaded"
        }
        
        It "Should have compliance checker operational" {
            $result = & $script:HealthCheckPath -JsonOutput
            $json = $result | ConvertFrom-Json
            
            $complianceCheck = $json.checks | Where-Object { $_.component -eq "Security" -and $_.check -eq "Compliance" }
            $complianceCheck.status | Should -BeIn @("pass", "warning")
        }
    }
    
    Context "Basic Operations" {
        
        It "Should list patches without error" {
            { & $script:SecureHotpatchPath -SystemType swarm -Operation list } | 
                Should -Not -Throw
        }
        
        It "Should support dry-run operation" {
            # Create minimal test patch
            $testPatch = @{
                patch_id = "smoke-test-patch"
                version = "1.0.0"
                system_type = "swarm"
                components = @()
                files = @()
            } | ConvertTo-Json
            
            $testPatch | Out-File "tests/fixtures/smoke_test_patch.json"
            
            { 
                & $script:SecureHotpatchPath `
                    -SystemType swarm `
                    -Operation dryrun `
                    -PatchPath "tests/fixtures/smoke_test_patch.json"
            } | Should -Not -Throw
            
            Remove-Item "tests/fixtures/smoke_test_patch.json" -Force
        }
    }
    
    Context "Performance" {
        
        It "Should complete status check within 5 seconds" {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            & $script:SecureHotpatchPath -Operation status | Out-Null
            $sw.Stop()
            
            $sw.ElapsedMilliseconds | Should -BeLessThan 5000
        }
        
        It "Should complete health check within 30 seconds" {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            & $script:HealthCheckPath -JsonOutput | Out-Null
            $sw.Stop()
            
            $sw.ElapsedMilliseconds | Should -BeLessThan 30000
        }
    }
}

Describe "Smoke Test - Critical Path" -Tag "Smoke", "Critical" {
    
    Context "End-to-End Critical Path" {
        
        It "Should complete full critical path" {
            # 1. Check status
            $status = & $script:SecureHotpatchPath -Operation status
            $status | Should -Not -BeNullOrEmpty
            
            # 2. Run health check
            $health = & $script:HealthCheckPath -JsonOutput
            $healthJson = $health | ConvertFrom-Json
            $healthJson.overall_status | Should -Not -Be "critical"
            
            # 3. List patches
            $patches = & $script:SecureHotpatchPath -SystemType swarm -Operation list
            $patches | Should -Not -BeNullOrEmpty
            
            Write-Host "✅ Critical path completed successfully" -ForegroundColor Green
        }
    }
}
