#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the endpoint governance collectors and writes a consolidated report.
.DESCRIPTION
    Collects inventory, installed software, software compliance, local
    administrator review, and endpoint security status. Detailed CSVs, a
    summary CSV, and a self-contained HTML report are written to one folder.
    -WhatIf still collects data and skips every file write.
.PARAMETER ComputerName
    Computers to include. The default is the local computer.
.PARAMETER Credential
    Optional credential passed to the collectors.
.PARAMETER OutputDirectory
    Folder for the report files. The default is .\output\inventory-<timestamp>.
.PARAMETER PolicyPath
    Software policy JSON. Without it, software compliance is skipped.
.PARAMETER ApprovedListPath
    JSON file of approved local administrator accounts.
.PARAMETER ApprovedAccount
    Additional approved administrator accounts.
.PARAMETER MaxSignatureAgeDays
    Passed to the security collector. The default is 7.
.PARAMETER CimProtocol
    Wsman or Dcom for inventory. The default is Wsman.
.PARAMETER TimeoutSec
    Inventory CIM timeout in seconds. The default is 60.
.PARAMETER IncludeSystemComponents
    Passed to the software collector.
.PARAMETER ExcludePattern
    Regular expression passed to the software collector.
.EXAMPLE
    .\Invoke-InventoryReport.ps1 -PolicyPath .\samples\software-policy.json -ApprovedListPath .\samples\approved-admins.json -OutputDirectory .\output
.EXAMPLE
    .\Invoke-InventoryReport.ps1 -ComputerName PC-EXAMPLE-01 -PolicyPath .\samples\software-policy.json -OutputDirectory .\output -WhatIf
.NOTES
    Version compliance uses a different inventory shape and stays in
    Test-VersionCompliance.ps1. This report does not deploy or change settings.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [string[]]$ComputerName = $(if ([string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) { 'localhost' } else { $env:COMPUTERNAME }),
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputDirectory = $(Join-Path (Join-Path (Get-Location).Path 'output') ('inventory-' + (Get-Date).ToString('yyyyMMdd-HHmmss'))),
    [string]$PolicyPath,
    [string]$ApprovedListPath,
    [string[]]$ApprovedAccount,
    [ValidateRange(0, 3650)]
    [int]$MaxSignatureAgeDays = 7,
    [ValidateSet('Wsman', 'Dcom')]
    [string]$CimProtocol = 'Wsman',
    [ValidateRange(1, 3600)]
    [int]$TimeoutSec = 60,
    [switch]$IncludeSystemComponents,
    [string]$ExcludePattern
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\EndpointGovernance.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    throw "Required module not found: $modulePath"
}
Import-Module -Name $modulePath -Force -DisableNameChecking

$stageErrors = New-Object System.Collections.Generic.List[string]

function Invoke-ReportStage {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    try {
        $output = & $Action
        if ($null -eq $output) { return @() }
        return @($output)
    }
    catch {
        $message = Format-GovernanceSingleLine -Text $_.Exception.Message
        [void]$script:stageErrors.Add(('{0}: {1}' -f $Name, $message))
        Write-Warning ('{0}: {1}' -f $Name, $message)
        return @()
    }
}

if ($PSCmdlet.ShouldProcess($OutputDirectory, 'Create report directory')) {
    [void][System.IO.Directory]::CreateDirectory($OutputDirectory)
}

$inventoryParameters = @{
    ComputerName = $ComputerName
    CimProtocol  = $CimProtocol
    TimeoutSec   = $TimeoutSec
    OutputPath   = (Join-Path $OutputDirectory 'endpoint-inventory.csv')
}
if ($PSBoundParameters.ContainsKey('Credential')) { $inventoryParameters['Credential'] = $Credential }
if ($WhatIfPreference) { $inventoryParameters['WhatIf'] = $true }
$inventory = Invoke-ReportStage -Name 'Endpoint inventory' -Action {
    & (Join-Path $PSScriptRoot 'Get-EndpointInventory.ps1') @inventoryParameters
}

$softwareParameters = @{
    ComputerName = $ComputerName
    OutputPath   = (Join-Path $OutputDirectory 'installed-software.csv')
}
if ($PSBoundParameters.ContainsKey('Credential')) { $softwareParameters['Credential'] = $Credential }
if ($IncludeSystemComponents) { $softwareParameters['IncludeSystemComponents'] = $true }
if (-not [string]::IsNullOrWhiteSpace($ExcludePattern)) { $softwareParameters['ExcludePattern'] = $ExcludePattern }
if ($WhatIfPreference) { $softwareParameters['WhatIf'] = $true }
$software = Invoke-ReportStage -Name 'Installed software' -Action {
    & (Join-Path $PSScriptRoot 'Get-InstalledSoftware.ps1') @softwareParameters
}

$softwareFailed = $false
foreach ($stageError in @($stageErrors)) {
    if ([string]$stageError -like 'Installed software:*') { $softwareFailed = $true }
}
if ($softwareFailed) {
    $placeholders = New-Object System.Collections.Generic.List[object]
    foreach ($computer in $ComputerName) {
        if ([string]::IsNullOrWhiteSpace($computer)) { continue }
        [void]$placeholders.Add([pscustomobject]@{
                ComputerName    = $computer.Trim()
                DisplayName     = ''
                DisplayVersion  = ''
                Publisher       = ''
                CollectionError = 'Installed software collection failed.'
            })
    }
    $software = $placeholders.ToArray()
}
elseif ($null -eq $software) {
    $software = @()
}

$compliance = @()
if ([string]::IsNullOrWhiteSpace($PolicyPath)) {
    Write-Warning 'Software compliance was not evaluated because PolicyPath was not provided.'
}
else {
    $compliance = Invoke-ReportStage -Name 'Software compliance' -Action {
        $parameters = @{
            PolicyPath        = $PolicyPath
            InstalledSoftware = @($software)
            ComputerName      = $ComputerName
            OutputPath        = (Join-Path $OutputDirectory 'software-compliance.csv')
        }
        if ($WhatIfPreference) { $parameters['WhatIf'] = $true }
        & (Join-Path $PSScriptRoot 'Test-SoftwareCompliance.ps1') @parameters
    }
}

$adminParameters = @{
    ComputerName = $ComputerName
    OutputPath   = (Join-Path $OutputDirectory 'local-admin-audit.csv')
}
if ($PSBoundParameters.ContainsKey('Credential')) { $adminParameters['Credential'] = $Credential }
if ($PSBoundParameters.ContainsKey('ApprovedListPath')) { $adminParameters['ApprovedListPath'] = $ApprovedListPath }
if ($PSBoundParameters.ContainsKey('ApprovedAccount')) { $adminParameters['ApprovedAccount'] = $ApprovedAccount }
if ($WhatIfPreference) { $adminParameters['WhatIf'] = $true }
$administrators = Invoke-ReportStage -Name 'Local administrator audit' -Action {
    & (Join-Path $PSScriptRoot 'Get-LocalAdminAudit.ps1') @adminParameters
}

$securityParameters = @{
    ComputerName        = $ComputerName
    MaxSignatureAgeDays = $MaxSignatureAgeDays
    OutputPath          = (Join-Path $OutputDirectory 'endpoint-security.csv')
}
if ($PSBoundParameters.ContainsKey('Credential')) { $securityParameters['Credential'] = $Credential }
if ($WhatIfPreference) { $securityParameters['WhatIf'] = $true }
$security = Invoke-ReportStage -Name 'Endpoint security' -Action {
    & (Join-Path $PSScriptRoot 'Get-EndpointSecurityStatus.ps1') @securityParameters
}

$summary = New-Object System.Collections.Generic.List[object]
foreach ($computer in $ComputerName) {
    if ([string]::IsNullOrWhiteSpace($computer)) { continue }
    $target = $computer.Trim()
    $inventoryRow = $inventory | Where-Object { $_.ComputerName -eq $target } | Select-Object -First 1
    $securityRow = $security | Where-Object { $_.ComputerName -eq $target } | Select-Object -First 1
    $softwareRows = @($software | Where-Object { $_.ComputerName -eq $target -and [string]::IsNullOrWhiteSpace([string]$_.CollectionError) -and -not [string]::IsNullOrWhiteSpace([string]$_.DisplayName) })
    $complianceRows = @($compliance | Where-Object { $_.ComputerName -eq $target })
    $adminRows = @($administrators | Where-Object { $_.ComputerName -eq $target -and $_.ApprovalStatus -eq 'Unapproved' })
    $errors = New-Object System.Collections.Generic.List[string]
    foreach ($source in @($inventoryRow, $securityRow)) {
        if ($null -eq $source) { continue }
        $errorText = [string]$source.CollectionError
        if (-not [string]::IsNullOrWhiteSpace($errorText)) { [void]$errors.Add($errorText) }
    }
    foreach ($failed in @($software | Where-Object { $_.ComputerName -eq $target -and -not [string]::IsNullOrWhiteSpace([string]$_.CollectionError) })) {
        [void]$errors.Add([string]$failed.CollectionError)
    }
    foreach ($failed in @($administrators | Where-Object { $_.ComputerName -eq $target -and -not [string]::IsNullOrWhiteSpace([string]$_.CollectionError) })) {
        [void]$errors.Add([string]$failed.CollectionError)
    }

    [void]$summary.Add([pscustomobject][ordered]@{
            ComputerName           = $target
            OperatingSystem        = $(if ($null -ne $inventoryRow) { [string]$inventoryRow.OperatingSystem } else { '' })
            TotalMemoryGB          = $(if ($null -ne $inventoryRow) { [string]$inventoryRow.TotalMemoryGB } else { '' })
            SerialNumber           = $(if ($null -ne $inventoryRow) { [string]$inventoryRow.SerialNumber } else { '' })
            LastBoot               = $(if ($null -ne $inventoryRow) { [string]$inventoryRow.LastBoot } else { '' })
            LoggedOnUser           = $(if ($null -ne $inventoryRow) { [string]$inventoryRow.LoggedOnUser } else { '' })
            InstalledSoftwareCount = [string]$softwareRows.Count
            CompliantSoftware      = [string]@($complianceRows | Where-Object { $_.Status -eq 'Compliant' }).Count
            NonCompliantSoftware   = [string]@($complianceRows | Where-Object { $_.Status -eq 'NonCompliant' }).Count
            UnknownSoftware        = [string]@($complianceRows | Where-Object { $_.Status -eq 'Unknown' }).Count
            UnapprovedAdmins       = [string]$adminRows.Count
            RealTimeProtection     = $(if ($null -ne $securityRow) { [string]$securityRow.RealTimeProtectionEnabled } else { '' })
            SignatureAgeDays       = $(if ($null -ne $securityRow) { [string]$securityRow.SignatureAgeDays } else { '' })
            BitLockerSummary       = $(if ($null -ne $securityRow) { [string]$securityRow.BitLockerSummary } else { '' })
            FirewallPublic         = $(if ($null -ne $securityRow) { [string]$securityRow.FirewallPublic } else { '' })
            PendingReboot          = $(if ($null -ne $securityRow) { [string]$securityRow.PendingReboot } else { '' })
            LastUpdateInstalledOn  = $(if ($null -ne $securityRow) { [string]$securityRow.LastUpdateInstalledOn } else { '' })
            CollectionErrors       = ($errors.ToArray() -join ' | ')
        })
}

$summaryRows = $summary.ToArray()
$summaryPath = Join-Path $OutputDirectory 'inventory-summary.csv'
$htmlPath = Join-Path $OutputDirectory 'inventory-summary.html'
if ($PSCmdlet.ShouldProcess($summaryPath, 'Export inventory summary CSV')) {
    Export-GovernanceCsv -Data $summaryRows -LiteralPath $summaryPath
}

$nonCompliant = @($compliance | Where-Object { $_.Status -eq 'NonCompliant' }).Count
$unapproved = @($administrators | Where-Object { $_.ApprovalStatus -eq 'Unapproved' }).Count
$pendingReboot = @($security | Where-Object { $_.PendingReboot -eq 'True' }).Count
$stale = @($security | Where-Object { $_.SignatureStatus -eq 'Stale' }).Count
$generatedAt = Format-GovernanceTimestamp -Value (Get-Date)
$html = ConvertTo-GovernanceHtml -Title 'Endpoint governance report' -Subtitle 'Read-only inventory, software compliance, privileged access review, and endpoint protection evidence.' -GeneratedAt $generatedAt -Highlights @(
    [pscustomobject]@{ Label = 'Computers'; Value = [string]@($summaryRows).Count }
    [pscustomobject]@{ Label = 'Installed titles'; Value = [string]@($software | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.DisplayName) }).Count }
    [pscustomobject]@{ Label = 'Noncompliant software'; Value = [string]$nonCompliant }
    [pscustomobject]@{ Label = 'Unapproved admins'; Value = [string]$unapproved }
    [pscustomobject]@{ Label = 'Pending reboot'; Value = [string]$pendingReboot }
    [pscustomobject]@{ Label = 'Stale signatures'; Value = [string]$stale }
) -Sections @(
    [pscustomobject]@{
        Title   = 'Summary'
        Note    = 'One row per requested computer. Detailed files are the CSV exports in this folder.'
        Columns = @('ComputerName', 'OperatingSystem', 'LoggedOnUser', 'InstalledSoftwareCount', 'NonCompliantSoftware', 'UnapprovedAdmins', 'RealTimeProtection', 'SignatureAgeDays', 'PendingReboot', 'CollectionErrors')
        Rows    = $summaryRows
    }
    [pscustomobject]@{
        Title   = 'Software compliance'
        Note    = 'Unknown means the title was not on the allow list or the block list.'
        Columns = @('ComputerName', 'DisplayName', 'DisplayVersion', 'Publisher', 'Status', 'Reason', 'Detail')
        Rows    = @($compliance | Where-Object { $_.Status -ne 'Compliant' })
    }
    [pscustomobject]@{
        Title   = 'Local administrators'
        Note    = 'Unapproved means the account was not on the supplied approved list.'
        Columns = @('ComputerName', 'MemberName', 'ObjectClass', 'ApprovalStatus', 'CollectionError')
        Rows    = $administrators
    }
)
if (-not [string]::IsNullOrWhiteSpace(($stageErrors.ToArray() -join ''))) {
    Write-Warning ('Report completed with stage errors: {0}' -f ($stageErrors.ToArray() -join ' | '))
}
if ($PSCmdlet.ShouldProcess($htmlPath, 'Write inventory HTML report')) {
    $encoding = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($htmlPath, $html, $encoding)
}

foreach ($row in $summaryRows) {
    Write-Output $row
}
