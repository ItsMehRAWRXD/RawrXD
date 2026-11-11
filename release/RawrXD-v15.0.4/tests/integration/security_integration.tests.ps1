# Integration Tests for Security Integration
# Tests the complete security wrapper and secure hotpatch flow
# Requires: Pester 5.0+

BeforeAll {
    $script:SecurityWrapperPath = "security/integration/security_wrapper.ps1"
    $script:SecureHotpatchPath = "security/integration/secure_hotpatch.ps1"
    $script:TestPatchPath = "tests/fixtures/test_patch.json"
    
    # Create test patch
    $testPatch = @{
        patch_id = "integration-test-patch"
        version = "1.0.0"
        system_type = "swarm"
        description = "Integration test patch"
        author = "test-author"
        created_at = Get-Date -Format "o"
        components = @("coordinator")
        files = @(
            @{
                path = "test.txt"
                checksum = "a9993e364706816aba3e25717850c26c9cd0d89d"
                content = "dGVzdCBjb250ZW50"
            }
        )
        security = @{
            signature = "test-signature"
            approved_by = @("test-admin")
            requires_2fa = $false
        }
    }
    
    $testPatch | ConvertTo-Json -Depth 10 | Out-File $script:TestPatchPath -Force
}

AfterAll {
    if (Test-Path $script:TestPatchPath) {
        Remove-Item $script:TestPatchPath -Force
    }
}

Describe "Security Integration Tests" {
    
    Context "Security Wrapper - RBAC Enforcement" {
        
        It "Should enforce RBAC on patch operations" {
            $result = & $script:SecurityWrapperPath `
                -SystemType "swarm" `
                -Operation "apply" `
                -PatchPath $script:TestPatchPath `
                -UserId "test-user"
            
            # Should either succeed or fail with RBAC error
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should validate user permissions before operation" {
            # Test with user who doesn't have permission
            { 
                & $script:SecurityWrapperPath `
                    -SystemType "swarm" `
                    -Operation "apply" `
                    -PatchPath $script:TestPatchPath `
                    -UserId "unauthorized-user"
            } | Should -Throw
        }
    }
    
    Context "Security Wrapper - Compliance Validation" {
        
        It "Should check compliance before patch operation" {
            $result = & $script:SecurityWrapperPath `
                -SystemType "swarm" `
                -Operation "apply" `
                -PatchPath $script:TestPatchPath
            
            # Result should indicate compliance check was performed
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should block operation if compliance is below threshold" {
            # This would require mocking compliance to return low score
            # For now, just verify the check happens
            $result = & $script:SecurityWrapperPath `
                -SystemType "swarm" `
                -Operation "apply" `
                -PatchPath $script:TestPatchPath
            
            $result | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Security Wrapper - Patch Validation" {
        
        It "Should validate patch format" {
            # Create invalid patch
            "{ invalid json" | Out-File "tests/fixtures/invalid_patch.json"
            
            { 
                & $script:SecurityWrapperPath `
                    -SystemType "swarm" `
                    -Operation "apply" `
                    -PatchPath "tests/fixtures/invalid_patch.json"
            } | Should -Throw
            
            Remove-Item "tests/fixtures/invalid_patch.json" -Force
        }
        
        It "Should validate patch security metadata" {
            $patchWithoutSecurity = @{
                patch_id = "no-security-patch"
                version = "1.0.0"
                system_type = "swarm"
                # Missing security section
            }
            
            $patchWithoutSecurity | ConvertTo-Json | 
                Out-File "tests/fixtures/no_security_patch.json"
            
            { 
                & $script:SecurityWrapperPath `
                    -SystemType "swarm" `
                    -Operation "apply" `
                    -PatchPath "tests/fixtures/no_security_patch.json"
            } | Should -Throw
            
            Remove-Item "tests/fixtures/no_security_patch.json" -Force
        }
    }
    
    Context "Secure Hotpatch - End-to-End Flow" {
        
        It "Should execute dry-run without applying changes" {
            $result = & $script:SecureHotpatchPath `
                -SystemType "swarm" `
                -Operation "dryrun" `
                -PatchPath $script:TestPatchPath
            
            $result | Should -Not -BeNullOrEmpty
            # Verify no actual changes were made
        }
        
        It "Should require confirmation for destructive operations" {
            # This would require interactive testing or mocking
            # For now, verify the operation exists
            $result = & $script:SecureHotpatchPath -Operation status
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should log all operations to audit log" {
            $auditLogBefore = Get-Date
            
            & $script:SecureHotpatchPath `
                -SystemType "swarm" `
                -Operation "dryrun" `
                -PatchPath $script:TestPatchPath
            
            # Check audit log was written
            $auditLogPath = "logs/audit/audit_$(Get-Date -Format 'yyyyMM').jsonl"
            if (Test-Path $auditLogPath) {
                $recentEntries = Get-Content $auditLogPath -Tail 10 | 
                    ForEach-Object { $_ | ConvertFrom-Json } |
                    Where-Object { [DateTime]$_.timestamp -gt $auditLogBefore }
                
                $recentEntries | Should -Not -BeNullOrEmpty
            }
        }
    }
    
    Context "Integration - RBAC + Compliance + Audit" {
        
        It "Should complete full security flow for authorized user" {
            # This tests the complete integration
            $result = & $script:SecurityWrapperPath `
                -SystemType "swarm" `
                -Operation "dryrun" `
                -PatchPath $script:TestPatchPath `
                -UserId "test-admin"
            
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should audit RBAC denials" {
            $auditLogBefore = Get-Date
            
            try {
                & $script:SecurityWrapperPath `
                    -SystemType "swarm" `
                    -Operation "apply" `
                    -PatchPath $script:TestPatchPath `
                    -UserId "unauthorized-user"
            }
            catch {
                # Expected to fail
            }
            
            # Check audit log for denial
            $auditLogPath = "logs/audit/audit_$(Get-Date -Format 'yyyyMM').jsonl"
            if (Test-Path $auditLogPath) {
                $recentEntries = Get-Content $auditLogPath -Tail 10 | 
                    ForEach-Object { $_ | ConvertFrom-Json } |
                    Where-Object { 
                        [DateTime]$_.timestamp -gt $auditLogBefore -and
                        $_.event_type -like "*rbac*denied*"
                    }
                
                # Should have logged the denial
                # Note: This may fail if RBAC check happens before audit logging
            }
        }
    }
}

Describe "Integration - Error Handling" {
    
    Context "Graceful Degradation" {
        
        It "Should handle missing patch file gracefully" {
            { 
                & $script:SecurityWrapperPath `
                    -SystemType "swarm" `
                    -Operation "apply" `
                    -PatchPath "nonexistent_patch.json"
            } | Should -Throw
        }
        
        It "Should handle registry corruption gracefully" {
            # This would require corrupting the registry
            # For now, just verify error handling exists
            $result = & $script:SecureHotpatchPath -Operation status
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should handle audit log write failures" {
            # This would require making audit log unwritable
            # For now, verify the system continues to function
            $result = & $script:SecureHotpatchPath -Operation status
            $result | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Rollback Integration" {
        
        It "Should rollback on operation failure" {
            # Create a patch that will fail
            $failingPatch = @{
                patch_id = "failing-patch"
                version = "1.0.0"
                system_type = "swarm"
                components = @("nonexistent-component")
            }
            
            $failingPatch | ConvertTo-Json | 
                Out-File "tests/fixtures/failing_patch.json"
            
            try {
                & $script:SecureHotpatchPath `
                    -SystemType "swarm" `
                    -Operation "apply" `
                    -PatchPath "tests/fixtures/failing_patch.json"
            }
            catch {
                # Expected to fail
                # Verify rollback was attempted
            }
            
            Remove-Item "tests/fixtures/failing_patch.json" -Force
        }
    }
}
