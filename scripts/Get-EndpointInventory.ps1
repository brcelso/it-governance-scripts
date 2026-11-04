#Requires -Version 5.1
<#
.SYNOPSIS
    Collects a point-in-time hardware and operating system inventory.
.DESCRIPTION
    Reads hostname, operating system and build, CPU, memory, fixed disks,
    serial number, last boot, domain, and the logged-on user through CIM.
    One failing computer does not stop the rest of the list. The script is
    read-only. -WhatIf skips the CSV file and still returns the rows.
.PARAMETER ComputerName
    Computers to query. The default is the local computer.
.PARAMETER Credential
    Optional credential for a remote CIM session.
.PARAMETER CimProtocol
    Wsman or Dcom. The default is Wsman. Local queries do not open a session.
.PARAMETER TimeoutSec
    CIM operation timeout in seconds. The default is 60.
.PARAMETER OutputPath
    Optional CSV path. Parent folders are created when the file is written.
.EXAMPLE
    .\Get-EndpointInventory.ps1 -ComputerName PC-EXAMPLE-01, PC-EXAMPLE-02 -OutputPath .\output\endpoint-inventory.csv
.EXAMPLE
    .\Get-EndpointInventory.ps1 -OutputPath .\output\endpoint-inventory.csv -WhatIf
.OUTPUTS
    One inventory object per computer.
.NOTES
    Requires Windows PowerShell 5.1 or PowerShell 7 on Windows. No external modules.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [string[]]$ComputerName = $(if ([string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) { 'localhost' } else { $env:COMPUTERNAME }),
    [System.Management.Automation.PSCredential]$Credential,
    [ValidateSet('Wsman', 'Dcom')]
    [string]$CimProtocol = 'Wsman',
    [ValidateRange(1, 3600)]
    [int]$TimeoutSec = 60,
    [string]$OutputPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\EndpointGovernance.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    throw "Required module not found: $modulePath"
}
Import-Module -Name $modulePath -Force -DisableNameChecking

function Get-InventoryCimInstance {
    param(
        [string]$ClassName,
        [string]$Filter,
        $Session
    )

    $parameters = @{
        ClassName   = $ClassName
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($Filter)) {
        $parameters['Filter'] = $Filter
    }
    if ($null -ne $Session) {
        $parameters['CimSession'] = $Session
    }
    return @(Get-CimInstance @parameters)
}

function Test-UsefulSerial {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }
    $generic = @(
        '0',
        'none',
        'default string',
        'to be filled by o.e.m.',
        'system serial number',
        'not specified',
        'not applicable'
    )
    return -not ($generic -contains $Value.Trim().ToLowerInvariant())
}

function Select-InventorySerial {
    param(
        [AllowNull()][string]$BiosSerial,
        [AllowNull()][string]$ProductSerial
    )

    if (Test-UsefulSerial -Value $BiosSerial) { return $BiosSerial.Trim() }
    if (Test-UsefulSerial -Value $ProductSerial) { return $ProductSerial.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($BiosSerial)) { return $BiosSerial.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($ProductSerial)) { return $ProductSerial.Trim() }
    return ''
}

function ConvertTo-InventoryRecord {
    param(
        [string]$Computer,
        $System,
        $Product,
        $OperatingSystem,
        $Processors,
        $Disks,
        $Bios,
        [string]$CollectionError
    )

    $hostName = ''
    $domain = ''
    $partOfDomain = ''
    $loggedOnUser = ''
    $manufacturer = ''
    $model = ''
    $memory = ''
    if ($null -ne $System) {
        $hostName = Format-GovernanceSingleLine -Text ([string]$System.DNSHostName)
        if ([string]::IsNullOrWhiteSpace($hostName)) {
            $hostName = Format-GovernanceSingleLine -Text ([string]$System.Name)
        }
        $domain = Format-GovernanceSingleLine -Text ([string]$System.Domain)
        if ($null -ne $System.PartOfDomain) {
            if ($System.PartOfDomain) { $partOfDomain = 'Yes' } else { $partOfDomain = 'No' }
        }
        $loggedOnUser = Format-GovernanceSingleLine -Text ([string]$System.UserName)
        $manufacturer = Format-GovernanceSingleLine -Text ([string]$System.Manufacturer)
        $model = Format-GovernanceSingleLine -Text ([string]$System.Model)
        if ($null -ne $System.TotalPhysicalMemory) {
            $memory = Format-GovernanceDecimal -Value ([double]$System.TotalPhysicalMemory / 1GB) -Digits 1
        }
    }

    $caption = ''
    $version = ''
    $build = ''
    $architecture = ''
    $lastBoot = ''
    if ($null -ne $OperatingSystem) {
        $caption = Format-GovernanceSingleLine -Text ([string]$OperatingSystem.Caption)
        $version = Format-GovernanceSingleLine -Text ([string]$OperatingSystem.Version)
        $build = Format-GovernanceSingleLine -Text ([string]$OperatingSystem.BuildNumber)
        $architecture = Format-GovernanceSingleLine -Text ([string]$OperatingSystem.OSArchitecture)
        if ($null -ne $OperatingSystem.LastBootUpTime) {
            $lastBoot = Format-GovernanceTimestamp -Value $OperatingSystem.LastBootUpTime
        }
    }

    $cpuNames = New-Object System.Collections.Generic.List[string]
    $cores = 0
    $logical = 0
    foreach ($processor in @($Processors)) {
        if ($null -eq $processor) { continue }
        $cpuName = Format-GovernanceSingleLine -Text ([string]$processor.Name)
        if (-not [string]::IsNullOrWhiteSpace($cpuName) -and -not ($cpuNames -contains $cpuName)) {
            [void]$cpuNames.Add($cpuName)
        }
        if ($null -ne $processor.NumberOfCores) { $cores += [int]$processor.NumberOfCores }
        if ($null -ne $processor.NumberOfLogicalProcessors) { $logical += [int]$processor.NumberOfLogicalProcessors }
    }

    $diskParts = New-Object System.Collections.Generic.List[string]
    foreach ($disk in @($Disks | Sort-Object -Property DeviceID)) {
        if ($null -eq $disk) { continue }
        $sizeGb = 0.0
        $freeGb = 0.0
        if ($null -ne $disk.Size) { $sizeGb = [double]$disk.Size / 1GB }
        if ($null -ne $disk.FreeSpace) { $freeGb = [double]$disk.FreeSpace / 1GB }
        $deviceId = Format-GovernanceSingleLine -Text ([string]$disk.DeviceID)
        $summary = '{0} {1} GB total / {2} GB free' -f $deviceId, (Format-GovernanceDecimal -Value $sizeGb -Digits 1), (Format-GovernanceDecimal -Value $freeGb -Digits 1)
        [void]$diskParts.Add($summary)
    }

    $biosSerial = ''
    if ($null -ne $Bios) { $biosSerial = [string]$Bios.SerialNumber }
    $productSerial = ''
    if ($null -ne $Product) { $productSerial = [string]$Product.IdentifyingNumber }

    return [pscustomobject][ordered]@{
        ComputerName      = $Computer
        HostName          = $hostName
        Domain            = $domain
        PartOfDomain      = $partOfDomain
        LoggedOnUser      = $loggedOnUser
        OperatingSystem   = $caption
        OSVersion         = $version
        OSBuild           = $build
        OSArchitecture    = $architecture
        Manufacturer      = $manufacturer
        Model             = $model
        SerialNumber      = (Select-InventorySerial -BiosSerial $biosSerial -ProductSerial $productSerial)
        Cpu               = ($cpuNames.ToArray() -join '; ')
        CpuCores          = $(if ($cores -gt 0) { [string]$cores } else { '' })
        LogicalProcessors = $(if ($logical -gt 0) { [string]$logical } else { '' })
        TotalMemoryGB     = $memory
        DiskSummary       = ($diskParts.ToArray() -join '; ')
        LastBoot          = $lastBoot
        CollectionError   = (Format-GovernanceSingleLine -Text $CollectionError)
        CollectedAt       = (Format-GovernanceTimestamp -Value (Get-Date))
    }
}

$records = New-Object System.Collections.Generic.List[object]
foreach ($computer in $ComputerName) {
    if ([string]::IsNullOrWhiteSpace($computer)) { continue }
    $target = $computer.Trim()
    Write-Verbose ("Collecting endpoint inventory from {0}" -f $target)
    $session = $null
    $problems = New-Object System.Collections.Generic.List[string]
    $system = $null
    $product = $null
    $operatingSystem = $null
    $processors = @()
    $disks = @()
    $bios = $null
    try {
        if (-not (Test-LocalComputerName -ComputerName $target)) {
            $option = New-CimSessionOption -Protocol $CimProtocol -OperationTimeoutSec ([uint32]$TimeoutSec)
            $sessionParameters = @{
                ComputerName        = $target
                SessionOption       = $option
                OperationTimeoutSec = [uint32]$TimeoutSec
                ErrorAction         = 'Stop'
            }
            if ($PSBoundParameters.ContainsKey('Credential')) {
                $sessionParameters['Credential'] = $Credential
            }
            $session = New-CimSession @sessionParameters
        }

        try { $system = (Get-InventoryCimInstance -ClassName 'Win32_ComputerSystem' -Session $session | Select-Object -First 1) }
        catch { [void]$problems.Add(('ComputerSystem: {0}' -f (Format-GovernanceSingleLine -Text $_.Exception.Message))) }
        try { $product = (Get-InventoryCimInstance -ClassName 'Win32_ComputerSystemProduct' -Session $session | Select-Object -First 1) }
        catch { [void]$problems.Add(('ComputerSystemProduct: {0}' -f (Format-GovernanceSingleLine -Text $_.Exception.Message))) }
        try { $operatingSystem = (Get-InventoryCimInstance -ClassName 'Win32_OperatingSystem' -Session $session | Select-Object -First 1) }
        catch { [void]$problems.Add(('OperatingSystem: {0}' -f (Format-GovernanceSingleLine -Text $_.Exception.Message))) }
        try { $processors = @(Get-InventoryCimInstance -ClassName 'Win32_Processor' -Session $session) }
        catch { [void]$problems.Add(('Processor: {0}' -f (Format-GovernanceSingleLine -Text $_.Exception.Message))) }
        try { $disks = @(Get-InventoryCimInstance -ClassName 'Win32_LogicalDisk' -Filter 'DriveType = 3' -Session $session) }
        catch { [void]$problems.Add(('Disk: {0}' -f (Format-GovernanceSingleLine -Text $_.Exception.Message))) }
        try { $bios = (Get-InventoryCimInstance -ClassName 'Win32_BIOS' -Session $session | Select-Object -First 1) }
        catch { [void]$problems.Add(('BIOS: {0}' -f (Format-GovernanceSingleLine -Text $_.Exception.Message))) }
    }
    catch {
        [void]$problems.Add((Format-GovernanceSingleLine -Text $_.Exception.Message))
    }
    finally {
        if ($null -ne $session) {
            Remove-CimSession -CimSession $session
        }
    }

    [void]$records.Add((ConvertTo-InventoryRecord -Computer $target -System $system -Product $product -OperatingSystem $operatingSystem -Processors $processors -Disks $disks -Bios $bios -CollectionError ($problems.ToArray() -join ' | ')))
}

$rows = $records.ToArray()
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    if ($PSCmdlet.ShouldProcess($OutputPath, 'Export endpoint inventory CSV')) {
        Export-GovernanceCsv -Data $rows -LiteralPath $OutputPath
    }
}
foreach ($row in $rows) {
    Write-Output $row
}
