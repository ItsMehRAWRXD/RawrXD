param(
    [Parameter(Mandatory=$true)][string]$ClientApiKey,
    [string]$StackName = "rawrxd-serverless-ai",
    [string]$Region = "us-east-1",
    [string]$RawrxdBaseUrl = "https://smart-otters-follow.loca.lt",
    [string]$RawrxdUpstreamKey = "rawrxd"
)

$ErrorActionPreference = "Stop"

if ($ClientApiKey.Length -lt 12) {
    throw "ClientApiKey must be at least 12 characters."
}

Push-Location $PSScriptRoot
try {
    sam build

    sam deploy `
        --stack-name $StackName `
        --region $Region `
        --resolve-s3 `
        --capabilities CAPABILITY_IAM `
        --no-confirm-changeset `
        --parameter-overrides `
            "RawrxdBaseUrl=$RawrxdBaseUrl" `
            "RawrxdUpstreamKey=$RawrxdUpstreamKey" `
            "ClientApiKey=$ClientApiKey"

    aws cloudformation describe-stacks `
        --stack-name $StackName `
        --region $Region `
        --query "Stacks[0].Outputs" `
        --output table
}
finally {
    Pop-Location
}
