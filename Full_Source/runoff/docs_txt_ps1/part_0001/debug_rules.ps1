$Script:RootPath = 'd:\lazy init ide'
$Script:ModuleOverridePrecedence = 'BaseFirst'
$Script:overrideMode = 'merge'
$Script:RulesProfile = 'default'
$Script:RulesConfigPath = Join-Path $RootPath '.wiringdigestrules.json'
$Script:rules = Get-Content $RulesConfigPath -Raw | ConvertFrom-Json
$Script:resolvedRules = $rules
if ($rules.profiles -and $rules.profiles.$RulesProfile) {
$Script:resolvedRules = $rules.profiles.$RulesProfile
}
"resolvedRulesType=$($resolvedRules.GetType().FullName)"
"resolvedKeys=$($resolvedRules.PSObject.Properties.Name -join ',')"
"rulesProfilesType=$($rules.profiles.GetType().FullName)"
"rulesProfilesKeys=$($rules.profiles.PSObject.Properties.Name -join ',')"
