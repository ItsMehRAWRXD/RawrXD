# Unit Tests for RBAC Manager
# Requires: Pester 5.0+
# Run with: Invoke-Pester -Path tests/unit/rbac_manager.tests.ps1

BeforeAll {
    $script:TestRoot = Join-Path $PSScriptRoot ".."
    $script:ProjectRoot = Join-Path $PSScriptRoot "..\.."
    $script:TestRBACPath = Join-Path $script:TestRoot "fixtures/test_rbac_config.json"
    $script:RBACManagerPath = Join-Path $script:ProjectRoot "security/phase_h_enterprise_security/rbac/rbac_manager.ps1"
    
    # Create test RBAC config
    $testConfig = @{
        roles = @(
            @{
                name = "super-admin"
                level = 100
                permissions = @("*")
                inherits_from = $null
            },
            @{
                name = "test-role"
                level = 50
                permissions = @("patch:view", "patch:dryrun")
                inherits_from = $null
            }
        )
        users = @(
            @{
                user_id = "test-admin"
                role = "super-admin"
                assigned_at = "2026-01-01T00:00:00Z"
            },
            @{
                user_id = "test-user"
                role = "test-role"
                assigned_at = "2026-01-01T00:00:00Z"
            }
        )
    }
    
    $testConfig | ConvertTo-Json -Depth 10 | Out-File $script:TestRBACPath -Force
}

AfterAll {
    # Cleanup
    if (Test-Path $script:TestRBACPath) {
        Remove-Item $script:TestRBACPath -Force
    }
}

Describe "RBAC Manager Unit Tests" {
    
    Context "Role Management" {
        
        It "Should list all roles" {
            $result = & $script:RBACManagerPath -Operation list
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should get role details" {
            $result = & $script:RBACManagerPath -Operation get_role -RoleName "super-admin"
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should return error for non-existent role" {
            { & $script:RBACManagerPath -Operation get_role -RoleName "non-existent" } | 
                Should -Throw
        }
    }
    
    Context "Permission Checking" {
        
        It "Should allow super-admin all permissions" {
            $result = & $script:RBACManagerPath -Operation check_permission `
                -UserId "test-admin" -PermissionName "patch:apply"
            $result | Should -Be $true
        }
        
        It "Should deny unauthorized permission" {
            $result = & $script:RBACManagerPath -Operation check_permission `
                -UserId "test-user" -PermissionName "patch:apply"
            $result | Should -Be $false
        }
        
        It "Should allow explicit permissions" {
            $result = & $script:RBACManagerPath -Operation check_permission `
                -UserId "test-user" -PermissionName "patch:view"
            $result | Should -Be $true
        }
    }
    
    Context "User Role Assignment" {
        
        It "Should assign role to user" {
            { & $script:RBACManagerPath -Operation assign_role `
                -UserId "new-test-user" -RoleName "test-role" } | 
                Should -Not -Throw
        }
        
        It "Should get user role" {
            $result = & $script:RBACManagerPath -Operation get_user_role -UserId "test-admin"
            $result | Should -Be "super-admin"
        }
        
        It "Should revoke user role" {
            { & $script:RBACManagerPath -Operation revoke_role -UserId "new-test-user" } | 
                Should -Not -Throw
        }
    }
    
    Context "Permission Inheritance" {
        
        It "Should inherit permissions from parent role" {
            # Create parent and child roles
            $parentRole = @{
                name = "parent-role"
                level = 70
                permissions = @("patch:view")
                inherits_from = $null
            }
            
            $childRole = @{
                name = "child-role"
                level = 60
                permissions = @("patch:dryrun")
                inherits_from = "parent-role"
            }
            
            # Add roles to config
            $config = Get-Content $script:TestRBACPath | ConvertFrom-Json
            $config.roles += $parentRole
            $config.roles += $childRole
            $config | ConvertTo-Json -Depth 10 | Out-File $script:TestRBACPath
            
            # Assign child role to user
            & $script:RBACManagerPath -Operation assign_role `
                -UserId "inheritance-test-user" -RoleName "child-role"
            
            # Check inherited permission
            $result = & $script:RBACManagerPath -Operation check_permission `
                -UserId "inheritance-test-user" -PermissionName "patch:view"
            $result | Should -Be $true
        }
    }
}

Describe "RBAC Security Tests" {
    
    Context "Input Validation" {
        
        It "Should reject empty user ID" {
            { & $script:RBACManagerPath -Operation check_permission `
                -UserId "" -PermissionName "patch:view" } | 
                Should -Throw
        }
        
        It "Should reject empty permission name" {
            { & $script:RBACManagerPath -Operation check_permission `
                -UserId "test-user" -PermissionName "" } | 
                Should -Throw
        }
        
        It "Should reject invalid role name characters" {
            { & $script:RBACManagerPath -Operation assign_role `
                -UserId "test" -RoleName "role;drop table" } | 
                Should -Throw
        }
    }
    
    Context "Audit Logging" {
        
        It "Should log permission checks" {
            $auditLogBefore = Get-Content "logs/audit/audit_$(Get-Date -Format 'yyyyMM').jsonl" -ErrorAction SilentlyContinue
            
            & $script:RBACManagerPath -Operation check_permission `
                -UserId "test-user" -PermissionName "patch:view"
            
            $auditLogAfter = Get-Content "logs/audit/audit_$(Get-Date -Format 'yyyyMM').jsonl" -ErrorAction SilentlyContinue
            
            $auditLogAfter | Should -Not -BeNullOrEmpty
        }
    }
}
