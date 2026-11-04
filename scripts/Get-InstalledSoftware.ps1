#Requires -Version 5.1
<#
.SYNOPSIS
    Lists installed software from the Windows uninstall registry keys.
.DESCRIPTION
    Reads the 64-bit, 32-bit, and current-user uninstall keys. Rows without a
    display name are ignored. System components are skipped unless
    -IncludeSystemComponents is set. Duplicate name, version, and publisher
    rows keep the 64-bit key, then the 32-bit key, then the current-user key.
    Remote computers are queried with PowerShell remoting. The script does
    not change installed software.
.PARAMETER ComputerName
    Computers to query. The default is the local computer.
.PARAMETER Credential
    Optional remoting credential.
.PARAMETER OutputPath
    Optional CSV path.
.PARAMETER IncludeSystemComponents
    Include registry rows marked as system components.
.PARAMETER ExcludePattern
    Regular expression. Matching display names are omitted.
.EXAMPLE
    .\Get-InstalledSoftware.ps1 -OutputPath .\output\installed-software.csv
.EXAMPLE
    .\Get-InstalledSoftware.ps1 -ComputerName PC-EXAMPLE-01 -ExcludePattern 'KB\d+'
.OUTPUTS
    One object per installed product.
.NOTES
    The current-user key on a remote computer is the profile of the remoting
    credential, which may differ from the interactive user.
    Requires Windows PowerShell 5.1 or PowerShell 7 on Windows. No external modules.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [string[]]$ComputerName = $(if ([string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) { 'localhost' } else { $env:COMPUTERNAME }),
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

if (-not [string]::IsNullOrWhiteSpace($ExcludePattern)) {
    try {
        [void][regex]::new($ExcludePattern)
    }
    catch {
        throw "ExcludePattern is not a valid regular expression: $ExcludePattern"
    }
}

$collector = {
    param($Options)

    Set-StrictMode -Version 2.0
    $ErrorActionPreference = 'Stop'

    function Get-RegistryValue {
        param($Item, [string]$Name)
        if ($null -eq $Item) { return $null }
        $property = $Item.PSObject.Properties[$Name]
        if ($null -eq $property) { return $null }
        return $property.Value
    }

    $views = @(
        @{ Scope = 'HKLM64'; Base = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' },
        @{ Scope = 'HKLM32'; Base = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' },
        @{ Scope = 'HKCU'; Base = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' }
    )
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($view in $views) {
        $base = [string]$view.Base
        if (-not (Test-Path -LiteralPath $base)) { continue }
        $entries = @()
        try {
            $entries = @(Get-ItemProperty -Path (Join-Path $base '*') -ErrorAction SilentlyContinue)
        }
        catch {
            $entries = @()
        }
        foreach ($entry in $entries) {
            if ($null -eq $entry) { continue }
            $displayName = [string](Get-RegistryValue -Item $entry -Name 'DisplayName')
            $displayName = $displayName.Trim()
            if ([string]::IsNullOrWhiteSpace($displayName)) { continue }
            $systemComponent = Get-RegistryValue -Item $entry -Name 'SystemComponent'
            if (-not $Options.IncludeSystemComponents -and ($systemComponent -eq 1 -or [string]$systemComponent -eq '1')) {
                continue
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$Options.ExcludePattern)) {
                if ($displayName -match [string]$Options.ExcludePattern) { continue }
            }
            $rawDate = [string](Get-RegistryValue -Item $entry -Name 'InstallDate')
            $installDate = $rawDate.Trim()
            if ($rawDate -match '^\d{8}$') {
                try {
                    $parsedDate = [datetime]::ParseExact($rawDate, 'yyyyMMdd', [System.Globalization.CultureInfo]::InvariantCulture)
                    $installDate = $parsedDate.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
                }
                catch {
                    $installDate = $rawDate.Trim()
                }
            }
            $keyName = ''
            $child = $entry.PSObject.Properties['PSChildName']
            if ($null -ne $child) { $keyName = [string]$child.Value }
            [void]$rows.Add([pscustomobject]@{
                    DisplayName    = $displayName
                    DisplayVersion = ([string](Get-RegistryValue -Item $entry -Name 'DisplayVersion')).Trim()
                    Publisher      = ([string](Get-RegistryValue -Item $entry -Name 'Publisher')).Trim()
                    InstallDate    = $installDate
                    Scope          = [string]$view.Scope
                    UninstallKey   = $keyName
                })
        }
    }
    return $rows.ToArray()
}

function Select-UniqueInstalledSoftware {
    param([object[]]$Software)

    $rank = @{
        HKLM64 = 0
        HKLM32 = 1
        HKCU   = 2
    }
    $groups = @{}
    foreach ($item in $Software) {
        if ($null -eq $item) { continue }
        $key = '{0}|{1}|{2}' -f ([string]$item.DisplayName).ToLowerInvariant(), ([string]$item.DisplayVersion).ToLowerInvariant(), ([string]$item.Publisher).ToLowerInvariant()
        if (-not $groups.ContainsKey($key)) {
            $groups[$key] = New-Object System.Collections.Generic.List[object]
        }
        [void]$groups[$key].Add($item)
    }
    $selected = New-Object System.Collections.Generic.List[object]
    foreach ($key in @($groups.Keys)) {
        $best = $null
        $bestRank = 99
        foreach ($item in $groups[$key].ToArray()) {
            $itemRank = 9
            if ($rank.ContainsKey([string]$item.Scope)) { $itemRank = [int]$rank[[string]$item.Scope] }
            if ($null -eq $best -or $itemRank -lt $bestRank) {
                $best = $item
                $bestRank = $itemRank
            }
        }
        if ($null -ne $best) { [void]$selected.Add($best) }
    }
    return $selected.ToArray()
}

$options = @{
    IncludeSystemComponents = [bool]$IncludeSystemComponents
    ExcludePattern          = [string]$ExcludePattern
}
$records = New-Object System.Collections.Generic.List[object]
foreach ($computer in $ComputerName) {
    if ([string]::IsNullOrWhiteSpace($computer)) { continue }
    $target = $computer.Trim()
    Write-Verbose ("Collecting installed software from {0}" -f $target)
    try {
        $collected = $null
        if (Test-LocalComputerName -ComputerName $target) {
            $collected = & $collector -Options $options
        }
        else {
            $invokeParameters = @{
                ComputerName = $target
                ScriptBlock  = $collector
                ArgumentList = (,$options)
                ErrorAction  = 'Stop'
            }
            if ($PSBoundParameters.ContainsKey('Credential')) {
                $invokeParameters['Credential'] = $Credential
            }
            $collected = Invoke-Command @invokeParameters
        }
        $unique = @(Select-UniqueInstalledSoftware -Software @($collected))
        foreach ($item in $unique) {
            if ($null -eq $item) { continue }
            [void]$records.Add([pscustomobject][ordered]@{
                    ComputerName   = $target
                    DisplayName    = [string]$item.DisplayName
                    DisplayVersion = [string]$item.DisplayVersion
                    Publisher      = [string]$item.Publisher
                    InstallDate    = [string]$item.InstallDate
                    Scope          = [string]$item.Scope
                    UninstallKey   = [string]$item.UninstallKey
                    CollectionError = ''
                })
        }
    }
    catch {
        [void]$records.Add([pscustomobject][ordered]@{
                ComputerName    = $target
                DisplayName     = ''
                DisplayVersion  = ''
                Publisher       = ''
                InstallDate     = ''
                Scope           = ''
                UninstallKey    = ''
                CollectionError = (Format-GovernanceSingleLine -Text $_.Exception.Message)
            })
    }
}

$rows = @($records.ToArray() | Sort-Object -Property ComputerName, DisplayName)
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    if ($PSCmdlet.ShouldProcess($OutputPath, 'Export installed software CSV')) {
        Export-GovernanceCsv -Data $rows -LiteralPath $OutputPath
    }
}
foreach ($row in $rows) {
    Write-Output $row
}
