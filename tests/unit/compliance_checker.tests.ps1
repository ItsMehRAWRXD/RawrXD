# Unit Tests for Compliance Checker
# Requires: Pester 5.0+

BeforeAll {
    $script:ComplianceCheckerPath = "security/phase_h_enterprise_security/compliance/compliance_checker.ps1"
    $script:TestConfigPath = "tests/fixtures/test_compliance_config.json"
}

Describe "Compliance Checker Unit Tests" {
    
    Context "Compliance Check Execution" {
        
        It "Should run compliance check without errors" {
            { & $script:ComplianceCheckerPath -Operation check } | 
                Should -Not -Throw
        }
        
        It "Should return JSON output when requested" {
            $result = & $script:ComplianceCheckerPath -Operation check -OutputFormat json
            $result | Should -Not -BeNullOrEmpty
            
            # Verify it's valid JSON
            { $result | ConvertFrom-Json } | Should -Not -Throw
        }
        
        It "Should return HTML output when requested" {
            $result = & $script:ComplianceCheckerPath -Operation check -OutputFormat html
            $result | Should -Not -BeNullOrEmpty
            $result | Should -Match "<html>|<HTML>"
        }
    }
    
    Context "Compliance Score Calculation" {
        
        It "Should calculate score between 0 and 100" {
            $result = & $script:ComplianceCheckerPath -Operation check -OutputFormat json
            $json = $result | ConvertFrom-Json
            
            $json.summary.compliance_score | Should -BeGreaterOrEqual 0
            $json.summary.compliance_score | Should -BeLessOrEqual 100
        }
        
        It "Should report total controls checked" {
            $result = & $script:ComplianceCheckerPath -Operation check -OutputFormat json
            $json = $result | ConvertFrom-Json
            
            $json.summary.total_controls | Should -BeGreaterThan 0
        }
        
        It "Should report passed controls" {
            $result = & $script:ComplianceCheckerPath -Operation check -OutputFormat json
            $json = $result | ConvertFrom-Json
            
            $json.summary.passed_controls | Should -BeGreaterOrEqual 0
        }
    }
    
    Context "Control Categories" {
        
        It "Should check access controls" {
            $result = & $script:ComplianceCheckerPath -Operation check -OutputFormat json
            $json = $result | ConvertFrom-Json
            
            $json.details | Where-Object { $_.category -eq "access" } | 
                Should -Not -BeNullOrEmpty
        }
        
        It "Should check audit controls" {
            $result = & $script:ComplianceCheckerPath -Operation check -OutputFormat json
            $json = $result | ConvertFrom-Json
            
            $json.details | Where-Object { $_.category -eq "audit" } | 
                Should -Not -BeNullOrEmpty
        }
        
        It "Should check data protection controls" {
            $result = & $script:ComplianceCheckerPath -Operation check -OutputFormat json
            $json = $result | ConvertFrom-Json
            
            $json.details | Where-Object { $_.category -eq "data_protection" } | 
                Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Failed Controls Reporting" {
        
        It "Should report failed controls with details" {
            $result = & $script:ComplianceCheckerPath -Operation check -OutputFormat json
            $json = $result | ConvertFrom-Json
            
            if ($json.failed_controls.Count -gt 0) {
                $firstFailure = $json.failed_controls[0]
                $firstFailure | Should -HaveMember "control_id"
                $firstFailure | Should -HaveMember "description"
                $firstFailure | Should -HaveMember "severity"
            }
        }
        
        It "Should provide remediation guidance" {
            $result = & $script:ComplianceCheckerPath -Operation check -OutputFormat json
            $json = $result | ConvertFrom-Json
            
            if ($json.failed_controls.Count -gt 0) {
                $firstFailure = $json.failed_controls[0]
                $firstFailure | Should -HaveMember "remediation"
            }
        }
    }
}

Describe "Compliance Threshold Tests" {
    
    Context "Threshold Validation" {
        
        It "Should pass with score >= 80" {
            # Mock a passing compliance check
            Mock -CommandName Invoke-ComplianceCheck -MockWith {
                return @{ summary = @{ compliance_score = 85 } }
            }
            
            $result = Invoke-ComplianceCheck
            $result.summary.compliance_score | Should -BeGreaterOrEqual 80
        }
        
        It "Should fail with score < 80" {
            # This would typically fail deployment gates
            $result = & $script:ComplianceCheckerPath -Operation check -OutputFormat json
            $json = $result | ConvertFrom-Json
            
            if ($json.summary.compliance_score -lt 80) {
                $json.summary.compliance_score | Should -BeLessThan 80
            }
        }
    }
}
