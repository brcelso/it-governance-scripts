Set-StrictMode -Version 2.0

$libraryRoot = $PSScriptRoot
. (Join-Path $libraryRoot 'GovernanceOutput.ps1')
. (Join-Path $libraryRoot 'SoftwareCompliance.ps1')
. (Join-Path $libraryRoot 'VersionCompliance.ps1')

Export-ModuleMember -Function @(
    'Format-GovernanceTimestamp',
    'Format-GovernanceUtc',
    'Format-GovernanceDecimal',
    'Format-GovernanceSingleLine',
    'Export-GovernanceCsv',
    'Write-GovernanceJsonFile',
    'Add-GovernanceJsonLine',
    'Read-GovernanceJsonFile',
    'Read-GovernanceJsonlFile',
    'ConvertTo-GovernanceHtml',
    'Test-LocalComputerName',
    'Resolve-SoftwarePolicy',
    'Compare-SoftwareCompliance',
    'Get-AdminApprovalStatus',
    'Resolve-VersionPolicy',
    'Get-VersionCompliance',
    'ConvertTo-RemediationQueue',
    'Get-ComplianceDelta',
    'Get-PreviousAuditRun',
    'Get-VersionComplianceSummary'
)
