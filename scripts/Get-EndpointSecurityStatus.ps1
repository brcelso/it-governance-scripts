#Requires -Version 5.1
<#
.SYNOPSIS
    Collects endpoint protection evidence from the local Windows security features.
.DESCRIPTION
    Reports Microsoft Defender service, real-time protection, and signature age,
    BitLocker volume status, firewall profile state, pending reboot signals, and
    the last successful Windows Update installation. Each signal is collected on
    its own so one failure does not hide the others. The script does not change
    protection settings.
.PARAMETER ComputerName
    Computers to query. The default is the local computer.
.PARAMETER Credential
    Optional remoting credential.
.PARAMETER MaxSignatureAgeDays
    Signatures older than this many whole days are Stale. The default is 7.
.PARAMETER OutputPath
    Optional CSV path.
.EXAMPLE
    .\Get-EndpointSecurityStatus.ps1 -MaxSignatureAgeDays 7 -OutputPath .\output\endpoint-security.csv
.EXAMPLE
    .\Get-EndpointSecurityStatus.ps1 -ComputerName PC-EXAMPLE-01, PC-EXAMPLE-02
.OUTPUTS
    One security status object per computer.
.NOTES
    Signature age uses whole days. An age equal to MaxSignatureAgeDays is Current.
    Requires Windows PowerShell 5.1 or PowerShell 7 on Windows. No external modules.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [string[]]$ComputerName = $(if ([string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) { 'localhost' } else { $env:COMPUTERNAME }),
    [System.Management.Automation.PSCredential]$Credential,
    [ValidateRange(0, 3650)]
    [int]$MaxSignatureAgeDays = 7,
    [string]$OutputPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\EndpointGovernance.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    throw "Required module not found: $modulePath"
}
Import-Module -Name $modulePath -Force -DisableNameChecking

$probe = {
    param($Options)

    Set-StrictMode -Version 2.0
    $ErrorActionPreference = 'Stop'
    $problems = New-Object System.Collections.Generic.List[string]

    function Format-ProbeTime {
        param($Value)
        if ($null -eq $Value -or $Value -isnot [datetime]) { return '' }
        $culture = [System.Globalization.CultureInfo]::InvariantCulture
        if ($Value.Kind -eq [System.DateTimeKind]::Utc) {
            return $Value.ToString('yyyy-MM-ddTHH:mm:ssZ', $culture)
        }
        return $Value.ToString('yyyy-MM-ddTHH:mm:ssK', $culture)
    }

    function Convert-EnabledFlag {
        param($Value)
        if ($null -eq $Value) { return 'Unavailable' }
        $text = [string]$Value
        if ($text -eq 'True' -or $text -eq '1') { return 'True' }
        if ($text -eq 'False' -or $text -eq '0') { return 'False' }
        return 'Unavailable'
    }

    function Convert-FirewallState {
        param($Value)
        if ($null -eq $Value) { return 'Unknown' }
        $text = [string]$Value
        if ($text -eq 'True' -or $text -eq '1') { return 'Enabled' }
        if ($text -eq 'False' -or $text -eq '0') { return 'Disabled' }
        return 'Unknown'
    }

    $defenderService = 'Unavailable'
    $antivirus = 'Unavailable'
    $realTime = 'Unavailable'
    $signatureUpdated = ''
    $signatureAge = ''
    $signatureStatus = 'Unknown'
    try {
        if (-not (Get-Command -Name 'Get-MpComputerStatus' -ErrorAction SilentlyContinue)) {
            throw 'Get-MpComputerStatus is not available.'
        }
        $status = Get-MpComputerStatus -ErrorAction Stop
        $defenderService = Convert-EnabledFlag -Value $status.AMServiceEnabled
        $antivirus = Convert-EnabledFlag -Value $status.AntivirusEnabled
        $realTime = Convert-EnabledFlag -Value $status.RealTimeProtectionEnabled
        $updated = $status.AntivirusSignatureLastUpdated
        if ($updated -is [datetime] -and $updated -gt [datetime]'2000-01-01') {
            $signatureUpdated = Format-ProbeTime -Value $updated
            $signatureAge = [string][math]::Floor(((Get-Date) - $updated).TotalDays)
            if ([int]$signatureAge -gt [int]$Options.MaxSignatureAgeDays) {
                $signatureStatus = 'Stale'
            }
            else {
                $signatureStatus = 'Current'
            }
        }
    }
    catch {
        [void]$problems.Add(('Defender: {0}' -f ([regex]::Replace($_.Exception.Message, '\s+', ' ').Trim())))
    }

    $bitlocker = 'Unavailable'
    try {
        $parts = New-Object System.Collections.Generic.List[string]
        if (Get-Command -Name 'Get-BitLockerVolume' -ErrorAction SilentlyContinue) {
            $volumes = @(Get-BitLockerVolume -ErrorAction Stop)
            foreach ($volume in $volumes) {
                if ($null -eq $volume) { continue }
                $mount = [string]$volume.MountPoint
                if ($mount.EndsWith('\')) { $mount = $mount.TrimEnd('\') }
                [void]$parts.Add(('{0} {1}/{2}' -f $mount, $volume.VolumeStatus, $volume.ProtectionStatus))
            }
        }
        else {
            $volumes = @(Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' -ClassName 'Win32_EncryptableVolume' -ErrorAction Stop)
            $protectionNames = @{ '0' = 'Off'; '1' = 'On'; '2' = 'Unknown' }
            $conversionNames = @{
                '0' = 'FullyDecrypted'
                '1' = 'FullyEncrypted'
                '2' = 'EncryptionInProgress'
                '3' = 'DecryptionInProgress'
                '4' = 'EncryptionPaused'
                '5' = 'DecryptionPaused'
            }
            foreach ($volume in $volumes) {
                if ($null -eq $volume) { continue }
                $letter = [string]$volume.DriveLetter
                if ([string]::IsNullOrWhiteSpace($letter)) { $letter = [string]$volume.DeviceID }
                $protection = [string]$volume.ProtectionStatus
                $conversion = [string]$volume.ConversionStatus
                if ($protectionNames.ContainsKey($protection)) { $protection = $protectionNames[$protection] }
                if ($conversionNames.ContainsKey($conversion)) { $conversion = $conversionNames[$conversion] }
                [void]$parts.Add(('{0} {1}/{2}' -f $letter, $conversion, $protection))
            }
        }
        if ($parts.Count -eq 0) { $bitlocker = 'No volumes reported' }
        else { $bitlocker = ($parts.ToArray() -join '; ') }
    }
    catch {
        [void]$problems.Add(('BitLocker: {0}' -f ([regex]::Replace($_.Exception.Message, '\s+', ' ').Trim())))
    }

    $firewall = @{
        Domain  = 'Unknown'
        Private = 'Unknown'
        Public  = 'Unknown'
    }
    try {
        if (-not (Get-Command -Name 'Get-NetFirewallProfile' -ErrorAction SilentlyContinue)) {
            throw 'Get-NetFirewallProfile is not available.'
        }
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        foreach ($firewallProfile in $profiles) {
            if ($null -eq $firewallProfile) { continue }
            $name = [string]$firewallProfile.Name
            $state = Convert-FirewallState -Value $firewallProfile.Enabled
            if ($name -match '^(Domain|Dom.nio)$') { $firewall.Domain = $state }
            elseif ($name -match '^(Private|Particular)$') { $firewall.Private = $state }
            elseif ($name -match '^(Public|P.blico)$') { $firewall.Public = $state }
        }
    }
    catch {
        [void]$problems.Add(('Firewall: {0}' -f ([regex]::Replace($_.Exception.Message, '\s+', ' ').Trim())))
    }

    $rebootReasons = New-Object System.Collections.Generic.List[string]
    $rebootPaths = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'; Reason = 'Windows Update reboot required' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'; Reason = 'Component Based Servicing reboot pending' }
    )
    foreach ($item in $rebootPaths) {
        try {
            if (Test-Path -LiteralPath ([string]$item.Path)) {
                [void]$rebootReasons.Add([string]$item.Reason)
            }
        }
        catch {
            [void]$problems.Add(('Pending reboot: {0}' -f ([regex]::Replace($_.Exception.Message, '\s+', ' ').Trim())))
        }
    }
    try {
        $sessionManager = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
        $pendingNames = $null
        if ($null -ne $sessionManager) {
            $property = $sessionManager.PSObject.Properties['PendingFileRenameOperations']
            if ($null -ne $property) { $pendingNames = $property.Value }
        }
        $hasRename = $false
        if ($pendingNames -is [string]) {
            $hasRename = -not [string]::IsNullOrWhiteSpace($pendingNames)
        }
        elseif ($null -ne $pendingNames) {
            foreach ($entry in @($pendingNames)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$entry)) { $hasRename = $true }
            }
        }
        if ($hasRename) { [void]$rebootReasons.Add('Pending file rename operations') }
    }
    catch {
        [void]$problems.Add(('Pending file rename: {0}' -f ([regex]::Replace($_.Exception.Message, '\s+', ' ').Trim())))
    }
    try {
        $active = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name 'ComputerName' -ErrorAction Stop).ComputerName
        $pending = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name 'ComputerName' -ErrorAction Stop).ComputerName
        if (-not [string]::Equals([string]$active, [string]$pending, [System.StringComparison]::OrdinalIgnoreCase)) {
            [void]$rebootReasons.Add('Computer rename pending')
        }
    }
    catch {
        [void]$problems.Add(('Computer rename: {0}' -f ([regex]::Replace($_.Exception.Message, '\s+', ' ').Trim())))
    }

    $lastUpdateOn = ''
    $lastUpdateTitle = ''
    $updateSession = $null
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $searcher = $updateSession.CreateUpdateSearcher()
        $count = [int]$searcher.GetTotalHistoryCount()
        if ($count -gt 0) {
            $take = $count
            if ($take -gt 100) { $take = 100 }
            $history = @($searcher.QueryHistory(0, $take))
            $best = $null
            foreach ($entry in $history) {
                if ($null -eq $entry) { continue }
                $operation = 0
                $resultCode = 0
                if ($null -ne $entry.PSObject.Properties['Operation']) { $operation = [int]$entry.Operation }
                if ($null -ne $entry.PSObject.Properties['ResultCode']) { $resultCode = [int]$entry.ResultCode }
                if ($operation -ne 1 -or $resultCode -ne 2) { continue }
                if ($entry.Date -isnot [datetime]) { continue }
                if ($null -eq $best -or $entry.Date -gt $best.Date) { $best = $entry }
            }
            if ($null -ne $best) {
                $lastUpdateOn = Format-ProbeTime -Value $best.Date
                $lastUpdateTitle = [regex]::Replace([string]$best.Title, '\s+', ' ').Trim()
            }
        }
    }
    catch {
        try {
            $hotfix = Get-HotFix -ErrorAction Stop |
                Where-Object { $_.InstalledOn -is [datetime] } |
                Sort-Object -Property InstalledOn -Descending |
                Select-Object -First 1
            if ($null -ne $hotfix) {
                $lastUpdateOn = Format-ProbeTime -Value $hotfix.InstalledOn
                $lastUpdateTitle = ('{0} {1}' -f $hotfix.Description, $hotfix.HotFixID).Trim()
            }
        }
        catch {
            [void]$problems.Add(('Windows Update: {0}' -f ([regex]::Replace($_.Exception.Message, '\s+', ' ').Trim())))
        }
    }
    finally {
        if ($null -ne $updateSession) {
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($updateSession)
        }
    }
    if ($lastUpdateTitle.Length -gt 180) {
        $lastUpdateTitle = $lastUpdateTitle.Substring(0, 180)
    }

    return [pscustomobject]@{
        DefenderServiceEnabled        = $defenderService
        AntivirusEnabled              = $antivirus
        RealTimeProtectionEnabled     = $realTime
        AntivirusSignatureLastUpdated = $signatureUpdated
        SignatureAgeDays              = $signatureAge
        SignatureStatus               = $signatureStatus
        BitLockerSummary              = $bitlocker
        FirewallDomain                = [string]$firewall.Domain
        FirewallPrivate               = [string]$firewall.Private
        FirewallPublic                = [string]$firewall.Public
        PendingReboot                 = $(if ($rebootReasons.Count -gt 0) { 'True' } else { 'False' })
        PendingRebootReasons          = ($rebootReasons.ToArray() -join '; ')
        LastUpdateInstalledOn         = $lastUpdateOn
        LastUpdateTitle               = $lastUpdateTitle
        CollectionError               = ($problems.ToArray() -join ' | ')
    }
}

$records = New-Object System.Collections.Generic.List[object]
$options = @{ MaxSignatureAgeDays = $MaxSignatureAgeDays }
foreach ($computer in $ComputerName) {
    if ([string]::IsNullOrWhiteSpace($computer)) { continue }
    $target = $computer.Trim()
    Write-Verbose ("Collecting endpoint security status from {0}" -f $target)
    $collectedAt = Format-GovernanceTimestamp -Value (Get-Date)
    try {
        $status = $null
        if (Test-LocalComputerName -ComputerName $target) {
            $status = & $probe -Options $options
        }
        else {
            $invokeParameters = @{
                ComputerName = $target
                ScriptBlock  = $probe
                ArgumentList = (,$options)
                ErrorAction  = 'Stop'
            }
            if ($PSBoundParameters.ContainsKey('Credential')) {
                $invokeParameters['Credential'] = $Credential
            }
            $status = Invoke-Command @invokeParameters
        }
        if ($status -is [System.Array]) { $status = $status | Select-Object -First 1 }
        [void]$records.Add([pscustomobject][ordered]@{
                ComputerName                  = $target
                DefenderServiceEnabled        = [string]$status.DefenderServiceEnabled
                AntivirusEnabled              = [string]$status.AntivirusEnabled
                RealTimeProtectionEnabled     = [string]$status.RealTimeProtectionEnabled
                AntivirusSignatureLastUpdated = [string]$status.AntivirusSignatureLastUpdated
                SignatureAgeDays              = [string]$status.SignatureAgeDays
                SignatureStatus               = [string]$status.SignatureStatus
                BitLockerSummary              = [string]$status.BitLockerSummary
                FirewallDomain                = [string]$status.FirewallDomain
                FirewallPrivate               = [string]$status.FirewallPrivate
                FirewallPublic                = [string]$status.FirewallPublic
                PendingReboot                 = [string]$status.PendingReboot
                PendingRebootReasons          = [string]$status.PendingRebootReasons
                LastUpdateInstalledOn         = [string]$status.LastUpdateInstalledOn
                LastUpdateTitle               = [string]$status.LastUpdateTitle
                CollectionError               = [string]$status.CollectionError
                CollectedAt                   = $collectedAt
            })
    }
    catch {
        [void]$records.Add([pscustomobject][ordered]@{
                ComputerName                  = $target
                DefenderServiceEnabled        = ''
                AntivirusEnabled              = ''
                RealTimeProtectionEnabled     = ''
                AntivirusSignatureLastUpdated = ''
                SignatureAgeDays              = ''
                SignatureStatus               = ''
                BitLockerSummary              = ''
                FirewallDomain                = ''
                FirewallPrivate               = ''
                FirewallPublic                = ''
                PendingReboot                 = ''
                PendingRebootReasons          = ''
                LastUpdateInstalledOn         = ''
                LastUpdateTitle               = ''
                CollectionError               = (Format-GovernanceSingleLine -Text $_.Exception.Message)
                CollectedAt                   = $collectedAt
            })
    }
}

$rows = $records.ToArray()
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    if ($PSCmdlet.ShouldProcess($OutputPath, 'Export endpoint security CSV')) {
        Export-GovernanceCsv -Data $rows -LiteralPath $OutputPath
    }
}
foreach ($row in $rows) {
    Write-Output $row
}
