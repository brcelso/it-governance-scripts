#Requires -Version 5.1
<#
.SYNOPSIS
    Compares installed versions with a pinned or fleet-derived gold standard.
.DESCRIPTION
    Reads an inventory CSV (hostname, software, version, os, online) and a
    rules JSON file. For each software title the gold version is either pinned
    or derived from the fleet. Auto "most-common" uses the most frequent
    version and breaks ties toward the latest. Auto "latest" uses the highest
    version. Online machines vote first; if none are online, every observed
    version votes.

    Each in-scope machine is Compliant, Outdated, Missing, or Unknown.
    Outdated and Missing findings are stored in a persistent remediation queue
    (pending, sent, confirmed, or abandoned). The sent transition is a
    bookkeeping hook: this script never deploys software. Each run appends an
    audit JSONL snapshot and labels the delta against the previous run.
.PARAMETER InputPath
    Inventory CSV. Canonical columns are hostname, software, version, os, and online.
.PARAMETER RulesPath
    Rules JSON. Each software entry has name, gold ("auto" or a version),
    optional auto (most-common or latest), optional tolerance, and optional os filters.
.PARAMETER OutputPath
    Optional classification CSV.
.PARAMETER QueuePath
    Remediation queue JSON. The default is .\output\remediation-queue.json.
    Pass an empty string to skip the file.
.PARAMETER AuditPath
    Append-only audit JSONL. The default is .\output\version-audit.jsonl.
    Pass an empty string to skip the file.
.PARAMETER GoldPath
    Optional JSON file for the computed gold standard.
.PARAMETER SummaryPath
    Optional JSON file of status and delta counts.
.PARAMETER SubmitRemediation
    Moves current pending queue items to sent. No package is deployed.
    -WhatIf reports the transition and does not change the queue.
.PARAMETER AbandonId
    Queue ids to mark abandoned. Ids look like hostname|software, lower case.
.EXAMPLE
    .\Test-VersionCompliance.ps1 -InputPath .\samples\version-inventory.csv -RulesPath .\samples\version-rules.json -OutputPath .\output\version-compliance.csv
.EXAMPLE
    .\Test-VersionCompliance.ps1 -InputPath .\samples\version-inventory.csv -RulesPath .\samples\version-rules.json -SubmitRemediation -WhatIf
.OUTPUTS
    One classification object per machine and in-scope software title.
.NOTES
    Tolerance is added per component with no carry. A single integer applies
    to the last component of the gold version. 122.0.0 with tolerance 0.0.5
    is compared with the gold version as 122.0.5. Versions equal to or newer
    than gold are Compliant.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,
    [Parameter(Mandatory = $true)]
    [string]$RulesPath,
    [string]$OutputPath,
    [string]$QueuePath,
    [string]$AuditPath,
    [string]$GoldPath,
    [string]$SummaryPath,
    [switch]$SubmitRemediation,
    [string[]]$AbandonId
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\EndpointGovernance.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    throw "Required module not found: $modulePath"
}
Import-Module -Name $modulePath -Force -DisableNameChecking

function Invoke-VersionRemediationHook {
    <#
    .SYNOPSIS
        Records a remediation hand-off. Does not install or remove software.
    #>
    param($Item)

    $id = [string]$Item.id
    if ([string]::IsNullOrWhiteSpace($id)) {
        throw 'Remediation hook received a queue item without an id.'
    }
    return [pscustomobject]@{
        id       = $id
        hostname = [string]$Item.hostname
        software = [string]$Item.software
        action   = 'MarkSent'
        deployed = $false
        detail   = 'Remediation hook recorded the item as sent. No package was deployed.'
    }
}

if (-not (Test-Path -LiteralPath $InputPath)) {
    throw "Inventory CSV not found: $InputPath"
}
if (-not (Test-Path -LiteralPath $RulesPath)) {
    throw "Version rules not found: $RulesPath"
}
if (-not $PSBoundParameters.ContainsKey('QueuePath')) {
    $QueuePath = Join-Path (Join-Path (Get-Location).Path 'output') 'remediation-queue.json'
}
if (-not $PSBoundParameters.ContainsKey('AuditPath')) {
    $AuditPath = Join-Path (Join-Path (Get-Location).Path 'output') 'version-audit.jsonl'
}

$inventory = @(Import-Csv -LiteralPath $InputPath)
$rawPolicy = Get-Content -LiteralPath $RulesPath -Raw -Encoding UTF8 | ConvertFrom-Json
$evaluated = Get-VersionCompliance -Inventory $inventory -Policy $rawPolicy

$previous = @()
if (-not [string]::IsNullOrWhiteSpace($AuditPath) -and (Test-Path -LiteralPath $AuditPath)) {
    $existingLines = Read-GovernanceJsonlFile -LiteralPath $AuditPath
    $previous = Get-PreviousAuditRun -AuditRows $existingLines
}
$withDelta = Get-ComplianceDelta -Current $evaluated.Findings -Previous $previous

$now = [datetime]::UtcNow
$stamp = Format-GovernanceUtc -Value $now
$runId = $now.ToString('yyyyMMddTHHmmssZ', [System.Globalization.CultureInfo]::InvariantCulture)

$outputRows = New-Object System.Collections.Generic.List[object]
foreach ($row in $withDelta) {
    if ($null -eq $row) { continue }
    [void]$outputRows.Add([pscustomobject][ordered]@{
            runId           = $runId
            hostname        = [string]$row.hostname
            software        = [string]$row.software
            observedName    = [string]$row.observedName
            os              = [string]$row.os
            online          = [string]$row.online
            observedVersion = [string]$row.observedVersion
            goldVersion     = [string]$row.goldVersion
            goldSource      = [string]$row.goldSource
            tolerance       = [string]$row.tolerance
            status          = [string]$row.status
            reason          = [string]$row.reason
            previousStatus  = [string]$row.previousStatus
            delta           = [string]$row.delta
        })
}
$rows = $outputRows.ToArray()

$existingQueue = $null
if (-not [string]::IsNullOrWhiteSpace($QueuePath) -and (Test-Path -LiteralPath $QueuePath)) {
    $existingQueue = Read-GovernanceJsonFile -LiteralPath $QueuePath
}

$abandonApproved = New-Object System.Collections.Generic.List[string]
foreach ($id in @($AbandonId)) {
    if ([string]::IsNullOrWhiteSpace([string]$id)) { continue }
    $label = ([string]$id).Trim()
    if ($PSCmdlet.ShouldProcess($label, 'Abandon remediation queue item')) {
        [void]$abandonApproved.Add($label)
    }
}

$preview = ConvertTo-RemediationQueue -Queue $existingQueue -Findings $rows -Now $now -AbandonId $abandonApproved.ToArray()
foreach ($warning in @($preview.Warnings)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$warning)) {
        Write-Warning ([string]$warning)
    }
}

$submitIds = New-Object System.Collections.Generic.List[string]
if ($SubmitRemediation) {
    $eligible = $preview.EligibleSubmit
    foreach ($item in $eligible) {
        if ($null -eq $item) { continue }
        $label = '{0} | {1}' -f $item.hostname, $item.software
        if ($PSCmdlet.ShouldProcess($label, 'Record remediation as sent without deploying software')) {
            $hook = Invoke-VersionRemediationHook -Item $item
            if ($hook.deployed) {
                throw 'Remediation hook must not deploy software.'
            }
            [void]$submitIds.Add([string]$hook.id)
        }
    }
}

$updated = $preview
if ($submitIds.Count -gt 0) {
    $updated = ConvertTo-RemediationQueue -Queue $existingQueue -Findings $rows -Now $now -AbandonId $abandonApproved.ToArray() -SubmitId $submitIds.ToArray()
    foreach ($warning in @($updated.Warnings)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$warning)) {
            Write-Warning ([string]$warning)
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($QueuePath)) {
    if ($PSCmdlet.ShouldProcess($QueuePath, 'Update remediation queue')) {
        Write-GovernanceJsonFile -Value $updated.Queue -LiteralPath $QueuePath
    }
}
if (-not [string]::IsNullOrWhiteSpace($AuditPath)) {
    if ($PSCmdlet.ShouldProcess($AuditPath, 'Append version compliance audit snapshot')) {
        foreach ($row in $rows) {
            Add-GovernanceJsonLine -Value ([pscustomobject][ordered]@{
                    runId           = [string]$row.runId
                    at              = $stamp
                    hostname        = [string]$row.hostname
                    software        = [string]$row.software
                    observedName    = [string]$row.observedName
                    os              = [string]$row.os
                    online          = [string]$row.online
                    observedVersion = [string]$row.observedVersion
                    goldVersion     = [string]$row.goldVersion
                    goldSource      = [string]$row.goldSource
                    tolerance       = [string]$row.tolerance
                    status          = [string]$row.status
                    reason          = [string]$row.reason
                    previousStatus  = [string]$row.previousStatus
                    delta           = [string]$row.delta
                }) -LiteralPath $AuditPath
        }
    }
}
if (-not [string]::IsNullOrWhiteSpace($GoldPath)) {
    if ($PSCmdlet.ShouldProcess($GoldPath, 'Export computed gold standard JSON')) {
        Write-GovernanceJsonFile -Value $evaluated.Gold -LiteralPath $GoldPath
    }
}
$summary = Get-VersionComplianceSummary -Findings $rows -Gold $evaluated.Gold -RunId $runId -At $stamp
if (-not [string]::IsNullOrWhiteSpace($SummaryPath)) {
    if ($PSCmdlet.ShouldProcess($SummaryPath, 'Export version compliance summary JSON')) {
        Write-GovernanceJsonFile -Value $summary -LiteralPath $SummaryPath
    }
}
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    if ($PSCmdlet.ShouldProcess($OutputPath, 'Export version compliance CSV')) {
        Export-GovernanceCsv -Data $rows -LiteralPath $OutputPath
    }
}

Write-Verbose ("Run {0}: compliant={1} outdated={2} missing={3} unknown={4}" -f $runId, $summary.compliant, $summary.outdated, $summary.missing, $summary.unknown)
foreach ($row in $rows) {
    Write-Output $row
}
