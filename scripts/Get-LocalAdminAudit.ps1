#Requires -Version 5.1
<#
.SYNOPSIS
    Lists members of the local Administrators group and flags unapproved accounts.
.DESCRIPTION
    Resolves the local Administrators group by the well-known SID S-1-5-32-544
    so the check still works when the group display name is localized. When
    Get-LocalGroupMember is unavailable, the script falls back to the local
    account directory. Approval is case-insensitive. Patterns that contain
    * or ? are wildcards. With no approved list, every member is Unknown.
    An empty approved list marks every member Unapproved.
.PARAMETER ComputerName
    Computers to query. The default is the local computer.
.PARAMETER Credential
    Optional remoting credential.
.PARAMETER ApprovedAccount
    Account names or SIDs that are approved. Wildcards are allowed.
.PARAMETER ApprovedListPath
    JSON file with an approvedAccounts array. Combined with ApprovedAccount.
.PARAMETER OutputPath
    Optional CSV path.
.EXAMPLE
    .\Get-LocalAdminAudit.ps1 -ApprovedListPath .\samples\approved-admins.json -OutputPath .\output\local-admin-audit.csv
.EXAMPLE
    .\Get-LocalAdminAudit.ps1 -ComputerName PC-EXAMPLE-01 -ApprovedAccount 'EXAMPLE\Endpoint-Admins'
.OUTPUTS
    One object per local administrator.
.NOTES
    This script only reads membership. It does not add or remove administrators.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [string[]]$ComputerName = $(if ([string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) { 'localhost' } else { $env:COMPUTERNAME }),
    [System.Management.Automation.PSCredential]$Credential,
    [string[]]$ApprovedAccount,
    [string]$ApprovedListPath,
    [string]$OutputPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\EndpointGovernance.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    throw "Required module not found: $modulePath"
}
Import-Module -Name $modulePath -Force -DisableNameChecking

$approved = $null
if ($PSBoundParameters.ContainsKey('ApprovedAccount') -or $PSBoundParameters.ContainsKey('ApprovedListPath')) {
    $approved = New-Object System.Collections.Generic.List[string]
    foreach ($account in @($ApprovedAccount)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$account)) {
            [void]$approved.Add(([string]$account).Trim())
        }
    }
    if ($PSBoundParameters.ContainsKey('ApprovedListPath')) {
        if (-not (Test-Path -LiteralPath $ApprovedListPath)) {
            throw "Approved account list not found: $ApprovedListPath"
        }
        $document = Get-Content -LiteralPath $ApprovedListPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $entries = $null
        if ($document -is [System.Array]) {
            $entries = $document
        }
        else {
            $entries = $document.PSObject.Properties['approvedAccounts']
            if ($null -eq $entries) {
                throw 'Approved list file must contain an approvedAccounts array.'
            }
            $entries = $entries.Value
        }
        foreach ($entry in @($entries)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$entry)) {
                [void]$approved.Add(([string]$entry).Trim())
            }
        }
    }
}

$collector = {
    Set-StrictMode -Version 2.0
    $ErrorActionPreference = 'Stop'
    $adminSid = 'S-1-5-32-544'
    $rows = New-Object System.Collections.Generic.List[object]

    if (Get-Command -Name 'Get-LocalGroup' -ErrorAction SilentlyContinue) {
        try {
            $group = Get-LocalGroup | Where-Object { [string]$_.SID -eq $adminSid } | Select-Object -First 1
            if ($null -eq $group) {
                throw 'Local Administrators group (S-1-5-32-544) was not found.'
            }
            $members = @(Get-LocalGroupMember -Group $group.Name -ErrorAction Stop)
            foreach ($member in $members) {
                if ($null -eq $member) { continue }
                [void]$rows.Add([pscustomobject]@{
                        MemberName      = [string]$member.Name
                        ObjectClass     = [string]$member.ObjectClass
                        PrincipalSource = [string]$member.PrincipalSource
                        Sid             = [string]$member.SID
                    })
            }
            return $rows.ToArray()
        }
        catch {
            if ($rows.Count -gt 0) { throw }
        }
    }

    $directory = [ADSI]'WinNT://./Administrators,group'
    $members = @($directory.Invoke('Members'))
    foreach ($member in $members) {
        if ($null -eq $member) { continue }
        $name = [string]$member.GetType().InvokeMember('Name', 'GetProperty', $null, $member, $null)
        $class = [string]$member.GetType().InvokeMember('Class', 'GetProperty', $null, $member, $null)
        $path = ''
        try {
            $path = [string]$member.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $member, $null)
        }
        catch {
            $path = ''
        }
        $memberName = $name
        if ($path -match '^WinNT://([^/]+)/([^/,]+)') {
            $memberName = '{0}\{1}' -f $Matches[1], $Matches[2]
        }
        $sid = ''
        try {
            $sidBytes = $member.GetType().InvokeMember('ObjectSID', 'GetProperty', $null, $member, $null)
            $sid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
        }
        catch {
            $sid = ''
        }
        [void]$rows.Add([pscustomobject]@{
                MemberName      = $memberName
                ObjectClass     = $class
                PrincipalSource = ''
                Sid             = $sid
            })
    }
    return $rows.ToArray()
}

$records = New-Object System.Collections.Generic.List[object]
foreach ($computer in $ComputerName) {
    if ([string]::IsNullOrWhiteSpace($computer)) { continue }
    $target = $computer.Trim()
    Write-Verbose ("Auditing local administrators on {0}" -f $target)
    $collectedAt = Format-GovernanceTimestamp -Value (Get-Date)
    try {
        $members = $null
        if (Test-LocalComputerName -ComputerName $target) {
            $members = & $collector
        }
        else {
            $invokeParameters = @{
                ComputerName = $target
                ScriptBlock  = $collector
                ErrorAction  = 'Stop'
            }
            if ($PSBoundParameters.ContainsKey('Credential')) {
                $invokeParameters['Credential'] = $Credential
            }
            $members = Invoke-Command @invokeParameters
        }
        foreach ($member in @($members)) {
            if ($null -eq $member) { continue }
            $status = Get-AdminApprovalStatus -MemberName ([string]$member.MemberName) -Sid ([string]$member.Sid) -ApprovedAccounts $approved
            [void]$records.Add([pscustomobject][ordered]@{
                    ComputerName    = $target
                    MemberName      = [string]$member.MemberName
                    ObjectClass     = [string]$member.ObjectClass
                    PrincipalSource = [string]$member.PrincipalSource
                    Sid             = [string]$member.Sid
                    ApprovalStatus  = $status
                    CollectionError = ''
                    CollectedAt     = $collectedAt
                })
        }
    }
    catch {
        [void]$records.Add([pscustomobject][ordered]@{
                ComputerName    = $target
                MemberName      = ''
                ObjectClass     = ''
                PrincipalSource = ''
                Sid             = ''
                ApprovalStatus  = ''
                CollectionError = (Format-GovernanceSingleLine -Text $_.Exception.Message)
                CollectedAt     = $collectedAt
            })
    }
}

$rows = @($records.ToArray() | Sort-Object -Property ComputerName, MemberName)
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    if ($PSCmdlet.ShouldProcess($OutputPath, 'Export local administrator audit CSV')) {
        Export-GovernanceCsv -Data $rows -LiteralPath $OutputPath
    }
}
foreach ($row in $rows) {
    Write-Output $row
}
