# RBAC Integration Tests
# Tests RBAC functionality across components

BeforeAll {
    $script:ProjectRoot = Join-Path $PSScriptRoot "..\.."
    $script:RBACManager = Join-Path $script:ProjectRoot "security\rbac\rbac_manager.ps1"
    $script:TestConfigPath = Join-Path $env:TEMP "rawrxd_rbac_integration.json"
    
    # Initialize test environment
    if (Test-Path $script:TestConfigPath) {
        Remove-Item $script:TestConfigPath -Force
    }
    
    & $script:RBACManager -Operation init -ConfigPath $script:TestConfigPath
}

AfterAll {
    if (Test-Path $script:TestConfigPath) {
        Remove-Item $script:TestConfigPath -Force
    }
}

Describe "RBAC Integration Tests" {
    
    Context "User Management Integration" {
        
        It "Should assign and verify user roles" {
            $userId = "integration-user"
            $roleName = "patch-operator"
            
            { & $script:RBACManager -Operation assign_role `
                -UserId $userId -RoleName $roleName -ConfigPath $script:TestConfigPath } | Should -Not -Throw
            
            $userRole = & $script:RBACManager -Operation get_user_role `
                -UserId $userId -ConfigPath $script:TestConfigPath -JsonOutput | ConvertFrom-Json
            
            $userRole.role | Should -Be $roleName
        }
        
        It "Should enforce permission checks" {
            $userId = "perm-test-user"
            & $script:RBACManager -Operation assign_role `
                -UserId $userId -RoleName "patch-viewer" -ConfigPath $script:TestConfigPath
            
            $viewPerm = & $script:RBACManager -Operation check_permission `
                -UserId $userId -Permission "patch:view" -ConfigPath $script:TestConfigPath -JsonOutput | ConvertFrom-Json
            $viewPerm.granted | Should -Be $true
            
            $applyPerm = & $script:RBACManager -Operation check_permission `
                -UserId $userId -Permission "patch:apply" -ConfigPath $script:TestConfigPath -JsonOutput | ConvertFrom-Json
            $applyPerm.granted | Should -Be $false
        }
    }
    
    Context "Role Inheritance Integration" {
        
        It "Should handle permission inheritance" {
            $config = Get-Content $script:TestConfigPath | ConvertFrom-Json
            
            $childRole = @{
                name = "test-child"
                level = 50
                permissions = @("test:child")
                inherits_from = "patch-viewer"
                description = "Test child role"
            }
            
            $config.roles += $childRole
            $config | ConvertTo-Json -Depth 10 | Out-File $script:TestConfigPath
            
            & $script:RBACManager -Operation assign_role `
                -UserId "inherit-test" -RoleName "test-child" -ConfigPath $script:TestConfigPath
            
            $inherited = & $script:RBACManager -Operation check_permission `
                -UserId "inherit-test" -Permission "patch:view" -ConfigPath $script:TestConfigPath -JsonOutput | ConvertFrom-Json
            $inherited.granted | Should -Be $true
        }
    }
    
    Context "Error Handling" {
        
        It "Should handle invalid roles gracefully" {
            { & $script:RBACManager -Operation assign_role `
                -UserId "test" -RoleName "invalid-role" -ConfigPath $script:TestConfigPath } | Should -Throw
        }
        
        It "Should handle unassigned users" {
            $result = & $script:RBACManager -Operation check_permission `
                -UserId "unassigned" -Permission "patch:view" -ConfigPath $script:TestConfigPath -JsonOutput | ConvertFrom-Json
            $result.granted | Should -Be $false
        }
    }
    
    Context "Configuration Persistence" {
        
        It "Should persist user assignments" {
            $userId = "persist-test"
            & $script:RBACManager -Operation assign_role `
                -UserId $userId -RoleName "patch-admin" -ConfigPath $script:TestConfigPath
            
            $config = Get-Content $script:TestConfigPath | ConvertFrom-Json
            $persistedUser = $config.users | Where-Object { $_.user_id -eq $userId }
            $persistedUser | Should -Not -BeNullOrEmpty
            $persistedUser.role | Should -Be "patch-admin"
        }
    }
}
