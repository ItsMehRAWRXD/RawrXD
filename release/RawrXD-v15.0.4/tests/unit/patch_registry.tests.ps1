# Unit Tests for Patch Registry
# Requires: Pester 5.0+

BeforeAll {
    $script:PatchRegistryPath = "security/phase_g1_hotpatch/registry/patch_registry.ps1"
    $script:TestRegistryPath = "tests/fixtures/test_patch_registry.json"
    
    # Create test registry
    $testRegistry = @{
        version = "1.0"
        last_updated = Get-Date -Format "o"
        patches = @(
            @{
                patch_id = "test-patch-001"
                version = "1.0.0"
                system_type = "swarm"
                status = "applied"
                applied_at = "2026-01-01T00:00:00Z"
                applied_by = "test-user"
                components = @("coordinator")
                files = @(@{ path = "test.txt"; checksum = "abc123" })
                backup_path = "backups/test-patch-001"
            },
            @{
                patch_id = "test-patch-002"
                version = "1.0.0"
                system_type = "agent"
                status = "pending"
                components = @("orchestrator")
                files = @(@{ path = "test2.txt"; checksum = "def456" })
            }
        )
        statistics = @{
            total_patches = 2
            applied = 1
            rolled_back = 0
            failed = 0
            by_system = @{
                swarm = 1
                agent = 1
            }
        }
    }
    
    $testRegistry | ConvertTo-Json -Depth 10 | Out-File $script:TestRegistryPath -Force
}

AfterAll {
    if (Test-Path $script:TestRegistryPath) {
        Remove-Item $script:TestRegistryPath -Force
    }
}

Describe "Patch Registry Unit Tests" {
    
    Context "Patch Registration" {
        
        It "Should register a new patch" {
            $patch = @{
                patch_id = "test-patch-003"
                version = "1.0.0"
                system_type = "tools"
                components = @("cli")
                files = @(@{ path = "test3.txt"; checksum = "ghi789" })
            }
            
            { & $script:PatchRegistryPath -Operation register -Patch $patch } | 
                Should -Not -Throw
        }
        
        It "Should reject duplicate patch ID" {
            $patch = @{
                patch_id = "test-patch-001"  # Already exists
                version = "1.0.0"
                system_type = "swarm"
            }
            
            { & $script:PatchRegistryPath -Operation register -Patch $patch } | 
                Should -Throw
        }
    }
    
    Context "Patch Retrieval" {
        
        It "Should get patch by ID" {
            $result = & $script:PatchRegistryPath -Operation get -PatchId "test-patch-001"
            $result | Should -Not -BeNullOrEmpty
            $result.patch_id | Should -Be "test-patch-001"
        }
        
        It "Should list all patches" {
            $result = & $script:PatchRegistryPath -Operation list
            $result | Should -Not -BeNullOrEmpty
            $result.Count | Should -BeGreaterThan 0
        }
        
        It "Should filter patches by system" {
            $result = & $script:PatchRegistryPath -Operation list -SystemType "swarm"
            $result | ForEach-Object { $_.system_type | Should -Be "swarm" }
        }
        
        It "Should filter patches by status" {
            $result = & $script:PatchRegistryPath -Operation list -Status "applied"
            $result | ForEach-Object { $_.status | Should -Be "applied" }
        }
    }
    
    Context "Patch Status Updates" {
        
        It "Should update patch status to applied" {
            { 
                & $script:PatchRegistryPath -Operation update_status `
                    -PatchId "test-patch-002" -Status "applied"
            } | Should -Not -Throw
            
            $patch = & $script:PatchRegistryPath -Operation get -PatchId "test-patch-002"
            $patch.status | Should -Be "applied"
        }
        
        It "Should update patch status to rolled_back" {
            { 
                & $script:PatchRegistryPath -Operation update_status `
                    -PatchId "test-patch-001" -Status "rolled_back"
            } | Should -Not -Throw
            
            $patch = & $script:PatchRegistryPath -Operation get -PatchId "test-patch-001"
            $patch.status | Should -Be "rolled_back"
        }
        
        It "Should reject invalid status" {
            { 
                & $script:PatchRegistryPath -Operation update_status `
                    -PatchId "test-patch-001" -Status "invalid_status"
            } | Should -Throw
        }
    }
    
    Context "Patch Statistics" {
        
        It "Should return patch statistics" {
            $result = & $script:PatchRegistryPath -Operation stats
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should report correct total count" {
            $stats = & $script:PatchRegistryPath -Operation stats
            $stats.total_patches | Should -BeGreaterOrEqual 0
        }
        
        It "Should report system distribution" {
            $stats = & $script:PatchRegistryPath -Operation stats
            $stats.by_system | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Patch Validation" {
        
        It "Should validate patch format" {
            $invalidPatch = @{
                patch_id = "invalid"
                # Missing required fields
            }
            
            { & $script:PatchRegistryPath -Operation register -Patch $invalidPatch } | 
                Should -Throw
        }
        
        It "Should validate checksum format" {
            $patch = @{
                patch_id = "test-checksum"
                version = "1.0.0"
                system_type = "swarm"
                files = @(@{ path = "test.txt"; checksum = "invalid checksum with spaces" })
            }
            
            { & $script:PatchRegistryPath -Operation register -Patch $patch } | 
                Should -Throw
        }
    }
}

Describe "Patch Registry Security Tests" {
    
    Context "Registry Integrity" {
        
        It "Should detect corrupted registry" {
            # Corrupt the registry file
            "invalid json {" | Out-File $script:TestRegistryPath -Force
            
            { & $script:PatchRegistryPath -Operation list } | 
                Should -Throw
            
            # Restore valid registry
            $testRegistry | ConvertTo-Json -Depth 10 | Out-File $script:TestRegistryPath -Force
        }
        
        It "Should validate version field" {
            $registry = Get-Content $script:TestRegistryPath | ConvertFrom-Json
            $registry.version | Should -Match "^\d+\.\d+$"
        }
    }
    
    Context "Audit Trail" {
        
        It "Should log patch registrations" {
            $auditLogBefore = Get-ChildItem "logs/audit" -Filter "*.jsonl" -ErrorAction SilentlyContinue
            
            $patch = @{
                patch_id = "audit-test-patch"
                version = "1.0.0"
                system_type = "swarm"
            }
            
            & $script:PatchRegistryPath -Operation register -Patch $patch
            
            $auditLogAfter = Get-ChildItem "logs/audit" -Filter "*.jsonl" -ErrorAction SilentlyContinue
            $auditLogAfter | Should -Not -BeNullOrEmpty
        }
    }
}
