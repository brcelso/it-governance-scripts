#Requires -Version 5.1
<#
.SYNOPSIS
    Compares installed software with an allow, block, and required policy.
.DESCRIPTION
    Reads a policy JSON file and either an inventory CSV, objects already
    collected by Get-InstalledSoftware.ps1, or a live collection. Evaluation
    order is block, then allow, then required. Missing required software is
    reported for each computer in scope. A collection failure does not count
    as a missing install. Status is Compliant, NonCompliant, or Unknown.
.PARAMETER PolicyPath
    Path to the policy JSON file.
.PARAMETER InputPath
    CSV exported by Get-InstalledSoftware.ps1.
.PARAMETER InstalledSoftware
    Software objects already in memory. Do not combine with InputPath.
.PARAMETER ComputerName
    Computers to collect when no inventory is supplied. Also names computers
    that must be checked for required software even when they have no rows.
.PARAMETER Credential
    Optional remoting credential used only when this script collects software.
.PARAMETER OutputPath
    Optional compliance CSV path.
.PARAMETER IncludeSystemComponents
    Passed through when this script collects software itself.
.PARAMETER ExcludePattern
    Passed through when this script collects software itself.
.EXAMPLE
    .\Test-SoftwareCompliance.ps1 -PolicyPath .\samples\software-policy.json -InputPath .\output\installed-software.csv -OutputPath .\output\software-compliance.csv
.EXAMPLE
    .\Test-SoftwareCompliance.ps1 -PolicyPath .\samples\software-policy.json -ComputerName PC-EXAMPLE-01 -WhatIf
.OUTPUTS
    One compliance object per installed product, plus rows for missing required software.
.NOTES
    Unknown means the product is not on the allow list or the block list.
    It does not mean the product is approved.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter(Mandatory = $true)]
    [string]$PolicyPath,
    [string]$InputPath,
    [object[]]$InstalledSoftware,
    [string[]]$ComputerName,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputPath,
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

if ($PSBoundParameters.ContainsKey('InputPath') -and $PSBoundParameters.ContainsKey('InstalledSoftware')) {
    throw 'Pass either InputPath or InstalledSoftware, not both.'
}
if (-not (Test-Path -LiteralPath $PolicyPath)) {
    throw "Software policy not found: $PolicyPath"
}

$software = @()
if ($PSBoundParameters.ContainsKey('InstalledSoftware')) {
    $software = @($InstalledSoftware)
}
elseif ($PSBoundParameters.ContainsKey('InputPath')) {
    if (-not (Test-Path -LiteralPath $InputPath)) {
        throw "Installed software CSV not found: $InputPath"
    }
    $software = @(Import-Csv -LiteralPath $InputPath)
}
else {
    if (-not $PSBoundParameters.ContainsKey('ComputerName') -or $null -eq $ComputerName -or $ComputerName.Count -eq 0) {
        if ([string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) {
            $ComputerName = @('localhost')
        }
        else {
            $ComputerName = @($env:COMPUTERNAME)
        }
    }
    $collector = Join-Path $PSScriptRoot 'Get-InstalledSoftware.ps1'
    $parameters = @{
        ComputerName = $ComputerName
    }
    if ($PSBoundParameters.ContainsKey('Credential')) { $parameters['Credential'] = $Credential }
    if ($IncludeSystemComponents) { $parameters['IncludeSystemComponents'] = $true }
    if (-not [string]::IsNullOrWhiteSpace($ExcludePattern)) { $parameters['ExcludePattern'] = $ExcludePattern }
    if ($WhatIfPreference) { $parameters['WhatIf'] = $true }
    $software = @( & $collector @parameters )
}

$rawPolicy = Get-Content -LiteralPath $PolicyPath -Raw -Encoding UTF8 | ConvertFrom-Json
$compared = Compare-SoftwareCompliance -InstalledSoftware $software -Policy $rawPolicy -ComputerName $ComputerName
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    if ($PSCmdlet.ShouldProcess($OutputPath, 'Export software compliance CSV')) {
        Export-GovernanceCsv -Data $compared -LiteralPath $OutputPath
    }
}
foreach ($row in $compared) {
    Write-Output $row
}
