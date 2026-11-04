# Fleet version gold standards, classification, remediation queue, and deltas.
# No remote calls and no software deployment.

function Get-DottedVersion {
    param([AllowNull()][string]$VersionText)

    if ([string]::IsNullOrWhiteSpace($VersionText)) {
        return $null
    }
    $text = $VersionText.Trim()
    if ($text.StartsWith('v') -or $text.StartsWith('V')) {
        $text = $text.Substring(1).Trim()
    }
    $match = [regex]::Match($text, '^\d+(\.\d+)*')
    if (-not $match.Success) {
        return $null
    }

    $parts = New-Object System.Collections.Generic.List[int]
    foreach ($piece in $match.Value.Split('.')) {
        $number = 0
        $style = [System.Globalization.NumberStyles]::None
        $culture = [System.Globalization.CultureInfo]::InvariantCulture
        if (-not [int]::TryParse($piece, $style, $culture, [ref]$number)) {
            return $null
        }
        [void]$parts.Add($number)
    }
    if ($parts.Count -eq 0) {
        return $null
    }

    return [pscustomobject]@{
        Text  = ($parts.ToArray() -join '.')
        Parts = [int[]]$parts.ToArray()
    }
}

function Compare-DottedVersion {
    param(
        $Left,
        $Right
    )

    $leftParts = (ConvertTo-ObjectArray -Value $Left)
    $rightParts = (ConvertTo-ObjectArray -Value $Right)
    $width = $leftParts.Count
    if ($rightParts.Count -gt $width) { $width = $rightParts.Count }
    for ($index = 0; $index -lt $width; $index++) {
        $leftValue = 0
        $rightValue = 0
        if ($index -lt $leftParts.Count -and $null -ne $leftParts[$index]) {
            $leftValue = [int]$leftParts[$index]
        }
        if ($index -lt $rightParts.Count -and $null -ne $rightParts[$index]) {
            $rightValue = [int]$rightParts[$index]
        }
        if ($leftValue -lt $rightValue) { return -1 }
        if ($leftValue -gt $rightValue) { return 1 }
    }
    return 0
}

function Get-AlignedTolerance {
    param(
        $GoldParts,
        [string]$ToleranceText,
        $ToleranceParts
    )

    $gold = (ConvertTo-ObjectArray -Value $GoldParts)
    $tolerance = (ConvertTo-ObjectArray -Value $ToleranceParts)
    $singleNumber = $tolerance.Count -eq 1 -and $gold.Count -gt 1 -and $ToleranceText.IndexOf('.') -lt 0
    if (-not $singleNumber) {
        return ,([int[]]@($tolerance))
    }

    $aligned = New-Object System.Collections.Generic.List[int]
    for ($index = 0; $index -lt ($gold.Count - 1); $index++) {
        [void]$aligned.Add(0)
    }
    [void]$aligned.Add([int]$tolerance[0])
    return ,([int[]]$aligned.ToArray())
}

function Add-DottedVersion {
    param(
        $VersionParts,
        $ToleranceParts,
        [int]$Width
    )

    $version = (ConvertTo-ObjectArray -Value $VersionParts)
    $tolerance = (ConvertTo-ObjectArray -Value $ToleranceParts)
    $sum = New-Object System.Collections.Generic.List[int]
    for ($index = 0; $index -lt $Width; $index++) {
        $versionValue = 0
        $toleranceValue = 0
        if ($index -lt $version.Count -and $null -ne $version[$index]) { $versionValue = [int]$version[$index] }
        if ($index -lt $tolerance.Count -and $null -ne $tolerance[$index]) { $toleranceValue = [int]$tolerance[$index] }
        [void]$sum.Add(($versionValue + $toleranceValue))
    }
    return ,([int[]]$sum.ToArray())
}

function Get-VersionDisposition {
    param(
        $InstalledParts,
        $GoldParts,
        $ToleranceParts
    )

    $compare = Compare-DottedVersion -Left $InstalledParts -Right $GoldParts
    if ($compare -ge 0) {
        return [pscustomobject]@{ Status = 'Compliant'; Reason = 'MeetsGold' }
    }

    $installed = (ConvertTo-ObjectArray -Value $InstalledParts)
    $gold = (ConvertTo-ObjectArray -Value $GoldParts)
    $tolerance = (ConvertTo-ObjectArray -Value $ToleranceParts)
    $width = $installed.Count
    if ($gold.Count -gt $width) { $width = $gold.Count }
    if ($tolerance.Count -gt $width) { $width = $tolerance.Count }
    $raised = Add-DottedVersion -VersionParts $installed -ToleranceParts $tolerance -Width $width
    $raisedCompare = Compare-DottedVersion -Left $raised -Right $gold
    if ($raisedCompare -ge 0) {
        return [pscustomobject]@{ Status = 'Compliant'; Reason = 'WithinTolerance' }
    }
    return [pscustomobject]@{ Status = 'Outdated'; Reason = 'OlderThanTolerance' }
}

function ConvertTo-OnlineFlag {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }
    switch ($Value.Trim().ToLowerInvariant()) {
        'true' { return 'true' }
        'yes' { return 'true' }
        'online' { return 'true' }
        '1' { return 'true' }
        'false' { return 'false' }
        'no' { return 'false' }
        'offline' { return 'false' }
        '0' { return 'false' }
        default { return '' }
    }
}

function Get-InventoryField {
    param(
        $Row,
        [string[]]$Names
    )

    foreach ($name in $Names) {
        if ($Row -is [System.Collections.IDictionary]) {
            $found = $false
            foreach ($key in @($Row.Keys)) {
                if ([string]::Equals([string]$key, $name, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $found = $true
                    break
                }
            }
            if (-not $found) { continue }
        }
        elseif ($null -eq $Row.PSObject.Properties[$name]) {
            continue
        }

        $value = Get-ObjectProperty -Object $Row -Name $name
        if ($null -eq $value) {
            return ''
        }
        return [string]$value
    }
    return ''
}

function ConvertTo-VersionInventoryRow {
    param($Row)

    $hostname = (Get-InventoryField -Row $Row -Names @('hostname', 'ComputerName', 'HostName')).Trim()
    $software = (Get-InventoryField -Row $Row -Names @('software', 'DisplayName', 'Name')).Trim()
    $version = (Get-InventoryField -Row $Row -Names @('version', 'DisplayVersion', 'Version')).Trim()
    $os = (Get-InventoryField -Row $Row -Names @('os', 'OperatingSystem', 'OS')).Trim()
    $online = ConvertTo-OnlineFlag -Value (Get-InventoryField -Row $Row -Names @('online', 'Online', 'IsOnline'))
    return [pscustomobject]@{
        hostname = $hostname
        software = $software
        version  = $version
        os       = $os
        online   = $online
    }
}

function ConvertTo-VersionRule {
    param(
        $Rule,
        [int]$Index
    )

    if ($null -eq $Rule) {
        throw "Version rule $Index is empty."
    }
    $name = [string](Get-ObjectProperty -Object $Rule -Name 'name')
    if ([string]::IsNullOrWhiteSpace($name)) {
        throw "Version rule $Index is missing a name."
    }
    $gold = [string](Get-ObjectProperty -Object $Rule -Name 'gold')
    if ([string]::IsNullOrWhiteSpace($gold)) {
        throw "Version rule $Index is missing gold."
    }
    $gold = $gold.Trim()
    $auto = [string](Get-ObjectProperty -Object $Rule -Name 'auto')
    if ([string]::IsNullOrWhiteSpace($auto)) {
        $auto = 'most-common'
    }
    $auto = $auto.Trim().ToLowerInvariant()
    if ($auto -ne 'most-common' -and $auto -ne 'latest') {
        throw "Version rule $Index has an unsupported auto method '$auto'. Use most-common or latest."
    }

    if ($gold.ToLowerInvariant() -eq 'auto') {
        $gold = 'auto'
    }
    else {
        $parsedGold = Get-DottedVersion -VersionText $gold
        if ($null -eq $parsedGold) {
            throw "Version rule $Index has a gold version that cannot be parsed: $gold"
        }
        $gold = $parsedGold.Text
    }

    $tolerance = [string](Get-ObjectProperty -Object $Rule -Name 'tolerance')
    if ([string]::IsNullOrWhiteSpace($tolerance)) {
        $tolerance = '0'
    }
    $tolerance = $tolerance.Trim()
    if ($null -eq (Get-DottedVersion -VersionText $tolerance)) {
        throw "Version rule $Index has a tolerance that cannot be parsed: $tolerance"
    }

    $os = New-Object System.Collections.Generic.List[string]
    foreach ($entry in (ConvertTo-ObjectArray -Value (Get-ObjectProperty -Object $Rule -Name 'os'))) {
        if ($null -eq $entry) { continue }
        $text = ([string]$entry).Trim()
        if (-not [string]::IsNullOrWhiteSpace($text)) {
            [void]$os.Add($text)
        }
    }

    return [pscustomobject][ordered]@{
        name      = $name.Trim()
        gold      = $gold
        auto      = $auto
        tolerance = $tolerance
        os        = $os.ToArray()
    }
}

function Resolve-VersionPolicy {
    <#
    .SYNOPSIS
        Validates a per-software version policy.
    .DESCRIPTION
        Each rule needs a name and gold. Gold is a pinned dotted version or
        auto. Auto uses most-common (tie breaks to the latest) or latest.
        Tolerance is a dotted version; a single integer applies to the last
        component of the gold version. OS filters are optional wildcards.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Policy
    )

    if ($null -eq $Policy) {
        throw 'Version policy is empty.'
    }

    $policyName = ''
    $policyVersion = ''
    $description = ''
    $rawRules = $null
    if ($Policy -is [System.Array]) {
        $rawRules = $Policy
    }
    else {
        $policyName = [string](Get-ObjectProperty -Object $Policy -Name 'name')
        $policyVersion = [string](Get-ObjectProperty -Object $Policy -Name 'version')
        $description = [string](Get-ObjectProperty -Object $Policy -Name 'description')
        $rawRules = Get-ObjectProperty -Object $Policy -Name 'software'
        if ($null -eq $rawRules) {
            $rawRules = Get-ObjectProperty -Object $Policy -Name 'rules'
        }
    }

    $rules = New-Object System.Collections.Generic.List[object]
    $index = 1
    foreach ($rule in (ConvertTo-ObjectArray -Value $rawRules)) {
        [void]$rules.Add((ConvertTo-VersionRule -Rule $rule -Index $index))
        $index += 1
    }
    if ($rules.Count -eq 0) {
        throw 'Version policy does not contain any software rules.'
    }

    return [pscustomobject][ordered]@{
        name        = $policyName
        version     = $policyVersion
        description = $description
        software    = $rules.ToArray()
    }
}

function Get-MachineOnline {
    param($Machine)

    $sawTrue = $false
    $sawFalse = $false
    foreach ($flag in @($Machine.onlineFlags)) {
        if ($flag -eq 'true') { $sawTrue = $true }
        elseif ($flag -eq 'false') { $sawFalse = $true }
    }
    if ($sawTrue) { return 'true' }
    if ($sawFalse) { return 'false' }
    return ''
}

function Get-MachineOsInfo {
    param($Machine)

    $values = @($Machine.osValues)
    if ($values.Count -gt 1) {
        return [pscustomobject]@{ Conflict = $true; Os = '' }
    }
    if ($values.Count -eq 1) {
        return [pscustomobject]@{ Conflict = $false; Os = [string]$values[0] }
    }
    return [pscustomobject]@{ Conflict = $false; Os = '' }
}

function Test-VersionOsScope {
    param(
        [string]$Os,
        [AllowNull()][string[]]$Filters,
        [bool]$Conflict
    )

    if ($Conflict) { return 'Unknown' }
    $filterList = (ConvertTo-ObjectArray -Value $Filters)
    if ($filterList.Count -eq 0) { return 'InScope' }
    if ([string]::IsNullOrWhiteSpace($Os)) { return 'Unknown' }
    foreach ($filter in $filterList) {
        if ([string]::IsNullOrWhiteSpace([string]$filter)) { continue }
        $options = [System.Management.Automation.WildcardOptions]::IgnoreCase
        $wildcard = New-Object System.Management.Automation.WildcardPattern([string]$filter, $options)
        if ($wildcard.IsMatch($Os)) { return 'InScope' }
    }
    return 'OutOfScope'
}

function Select-PreferredInstallation {
    param(
        $Current,
        $Candidate
    )

    if ($null -eq $Current) { return $Candidate }
    if ($null -eq $Candidate) { return $Current }
    $currentParsed = $null -ne $Current.parsed
    $candidateParsed = $null -ne $Candidate.parsed
    if ($candidateParsed -and -not $currentParsed) { return $Candidate }
    if ($currentParsed -and -not $candidateParsed) { return $Current }
    if ($currentParsed -and $candidateParsed) {
        $compare = Compare-DottedVersion -Left $Candidate.parsed.Parts -Right $Current.parsed.Parts
        if ($compare -gt 0) { return $Candidate }
    }
    return $Current
}

function Find-RuleInstallation {
    param(
        $MachineInstalls,
        [string]$RuleName
    )

    $best = $null
    foreach ($install in (ConvertTo-ObjectArray -Value $MachineInstalls)) {
        if ($null -eq $install) { continue }
        if (Test-RuleNameMatch -Value ([string]$install.software) -Pattern $RuleName) {
            $best = Select-PreferredInstallation -Current $best -Candidate $install
        }
    }
    return $best
}

function Select-GoldVersion {
    param(
        [object[]]$Votes,
        [string]$Method
    )

    $online = New-Object System.Collections.Generic.List[object]
    foreach ($vote in @($Votes)) {
        if ($null -ne $vote -and $vote.online -eq 'true') {
            [void]$online.Add($vote)
        }
    }
    $electorate = @($online.ToArray())
    $sourceNote = 'online'
    if ($electorate.Count -eq 0) {
        $electorate = @($Votes)
        $sourceNote = 'all-observed'
    }
    if ($electorate.Count -eq 0) {
        return [pscustomobject]@{
            Parsed     = $null
            SampleSize = 0
            Voters     = 'none'
        }
    }

    $best = $null
    if ($Method -eq 'latest') {
        foreach ($vote in $electorate) {
            if ($null -eq $best) {
                $best = $vote.parsed
            }
            elseif ((Compare-DottedVersion -Left $vote.parsed.Parts -Right $best.Parts) -gt 0) {
                $best = $vote.parsed
            }
        }
    }
    else {
        $counts = @{}
        foreach ($vote in $electorate) {
            $text = [string]$vote.parsed.Text
            if (-not $counts.ContainsKey($text)) {
                $counts[$text] = [pscustomobject]@{ Count = 0; Parsed = $vote.parsed }
            }
            $counts[$text].Count = [int]$counts[$text].Count + 1
        }
        foreach ($key in @($counts.Keys)) {
            $entry = $counts[$key]
            if ($null -eq $best) {
                $best = $entry
            }
            elseif ([int]$entry.Count -gt [int]$best.Count) {
                $best = $entry
            }
            elseif ([int]$entry.Count -eq [int]$best.Count) {
                if ((Compare-DottedVersion -Left $entry.Parsed.Parts -Right $best.Parsed.Parts) -gt 0) {
                    $best = $entry
                }
            }
        }
        if ($null -ne $best) { $best = $best.Parsed }
    }

    return [pscustomobject]@{
        Parsed     = $best
        SampleSize = $electorate.Count
        Voters     = $sourceNote
    }
}

function Get-VersionCompliance {
    <#
    .SYNOPSIS
        Computes a gold version per software title and classifies each machine.
    .DESCRIPTION
        Status values are Compliant, Outdated, Missing, and Unknown.
        Online machines cast the auto gold vote. If none are online, every
        observed version is used. A single integer tolerance is right-aligned
        to the gold version. Component addition has no carry: 122.0.0 plus
        tolerance 0.0.5 is compared with the gold version as 122.0.5.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Inventory = @(),
        [Parameter(Mandatory = $true)]
        $Policy
    )

    $resolved = Resolve-VersionPolicy -Policy $Policy
    $machines = @{}
    $machineOrder = New-Object System.Collections.Generic.List[string]
    $installations = @{}

    foreach ($row in (ConvertTo-ObjectArray -Value $Inventory)) {
        if ($null -eq $row) { continue }
        $mapped = ConvertTo-VersionInventoryRow -Row $row
        if ([string]::IsNullOrWhiteSpace($mapped.hostname)) { continue }
        $machineKey = $mapped.hostname.ToLowerInvariant()
        if (-not $machines.ContainsKey($machineKey)) {
            $machines[$machineKey] = [pscustomobject]@{
                hostname    = $mapped.hostname
                osValues    = New-Object System.Collections.Generic.List[string]
                onlineFlags = New-Object System.Collections.Generic.List[string]
            }
            $installations[$machineKey] = @{}
            [void]$machineOrder.Add($machineKey)
        }

        $machine = $machines[$machineKey]
        if (-not [string]::IsNullOrWhiteSpace($mapped.os)) {
            $knownOs = $false
            foreach ($existing in @($machine.osValues)) {
                if ([string]::Equals([string]$existing, $mapped.os, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $knownOs = $true
                    break
                }
            }
            if (-not $knownOs) { [void]$machine.osValues.Add($mapped.os) }
        }
        [void]$machine.onlineFlags.Add($mapped.online)

        if ([string]::IsNullOrWhiteSpace($mapped.software)) { continue }
        $softwareKey = $mapped.software.ToLowerInvariant()
        $candidate = [pscustomobject]@{
            software = $mapped.software
            version  = $mapped.version
            parsed   = (Get-DottedVersion -VersionText $mapped.version)
        }
        $current = $null
        if ($installations[$machineKey].ContainsKey($softwareKey)) {
            $current = $installations[$machineKey][$softwareKey]
        }
        $installations[$machineKey][$softwareKey] = Select-PreferredInstallation -Current $current -Candidate $candidate
    }

    $goldRows = New-Object System.Collections.Generic.List[object]
    $goldBySoftware = @{}

    foreach ($rule in (ConvertTo-ObjectArray -Value $resolved.software)) {
        $votes = New-Object System.Collections.Generic.List[object]
        foreach ($machineKey in @($machineOrder)) {
            $machine = $machines[$machineKey]
            $osInfo = Get-MachineOsInfo -Machine $machine
            $scope = Test-VersionOsScope -Os $osInfo.Os -Filters $rule.os -Conflict $osInfo.Conflict
            if ($scope -ne 'InScope') { continue }
            $installList = New-Object System.Collections.Generic.List[object]
            foreach ($key in @($installations[$machineKey].Keys)) {
                [void]$installList.Add($installations[$machineKey][$key])
            }
            $install = Find-RuleInstallation -MachineInstalls $installList.ToArray() -RuleName ([string]$rule.name)
            if ($null -eq $install -or $null -eq $install.parsed) { continue }
            [void]$votes.Add([pscustomobject]@{
                    parsed = $install.parsed
                    online = (Get-MachineOnline -Machine $machine)
                })
        }

        $goldText = ''
        $goldParsed = $null
        $source = [string]$rule.auto
        $sampleSize = 0
        $voters = 'none'
        if ([string]$rule.gold -eq 'auto') {
            $selected = Select-GoldVersion -Votes $votes.ToArray() -Method ([string]$rule.auto)
            $sampleSize = [int]$selected.SampleSize
            $voters = [string]$selected.Voters
            if ($null -ne $selected.Parsed) {
                $goldParsed = $selected.Parsed
                $goldText = [string]$selected.Parsed.Text
            }
        }
        else {
            $source = 'pinned'
            $goldParsed = Get-DottedVersion -VersionText ([string]$rule.gold)
            $goldText = [string]$goldParsed.Text
            $selected = Select-GoldVersion -Votes $votes.ToArray() -Method 'latest'
            $sampleSize = [int]$selected.SampleSize
            $voters = [string]$selected.Voters
        }

        $goldRow = [pscustomobject][ordered]@{
            software    = [string]$rule.name
            goldVersion = $goldText
            source      = $source
            tolerance   = [string]$rule.tolerance
            sampleSize  = $sampleSize
            voters      = $voters
            os          = ((ConvertTo-ObjectArray -Value $rule.os) -join ';')
        }
        [void]$goldRows.Add($goldRow)
        $goldBySoftware[[string]$rule.name] = [pscustomobject]@{
            Row     = $goldRow
            Parsed  = $goldParsed
            Rule    = $rule
        }
    }

    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($machineKey in @($machineOrder)) {
        $machine = $machines[$machineKey]
        $osInfo = Get-MachineOsInfo -Machine $machine
        $online = Get-MachineOnline -Machine $machine
        $installList = New-Object System.Collections.Generic.List[object]
        foreach ($key in @($installations[$machineKey].Keys)) {
            [void]$installList.Add($installations[$machineKey][$key])
        }

        foreach ($rule in (ConvertTo-ObjectArray -Value $resolved.software)) {
            $scope = Test-VersionOsScope -Os $osInfo.Os -Filters $rule.os -Conflict $osInfo.Conflict
            if ($scope -eq 'OutOfScope') { continue }
            $goldInfo = $goldBySoftware[[string]$rule.name]
            $install = Find-RuleInstallation -MachineInstalls $installList.ToArray() -RuleName ([string]$rule.name)
            $observedVersion = ''
            $observedName = ''
            if ($null -ne $install) {
                $observedVersion = [string]$install.version
                $observedName = [string]$install.software
            }

            $status = 'Unknown'
            $reason = 'GoldStandardUnavailable'
            if ($osInfo.Conflict) {
                $reason = 'OsConflict'
            }
            elseif ($scope -eq 'Unknown') {
                $reason = 'OsNotReported'
            }
            elseif ($null -eq $install) {
                if ($online -eq 'false') { $reason = 'OfflineUnverified' }
                elseif ($online -eq 'true') {
                    $status = 'Missing'
                    $reason = 'NotInstalled'
                }
                else { $reason = 'OnlineNotReported' }
            }
            elseif ($null -eq $install.parsed) {
                $reason = 'VersionUnreadable'
            }
            elseif ($null -eq $goldInfo.Parsed) {
                $reason = 'GoldStandardUnavailable'
            }
            else {
                $toleranceParsed = Get-DottedVersion -VersionText ([string]$rule.tolerance)
                $aligned = Get-AlignedTolerance -GoldParts $goldInfo.Parsed.Parts -ToleranceText ([string]$rule.tolerance) -ToleranceParts $toleranceParsed.Parts
                $disposition = Get-VersionDisposition -InstalledParts $install.parsed.Parts -GoldParts $goldInfo.Parsed.Parts -ToleranceParts $aligned
                $status = [string]$disposition.Status
                $reason = [string]$disposition.Reason
            }

            [void]$findings.Add([pscustomobject][ordered]@{
                    hostname        = [string]$machine.hostname
                    software        = [string]$rule.name
                    observedName    = $observedName
                    os              = [string]$osInfo.Os
                    online          = $online
                    observedVersion = $observedVersion
                    goldVersion     = [string]$goldInfo.Row.goldVersion
                    goldSource      = [string]$goldInfo.Row.source
                    tolerance       = [string]$rule.tolerance
                    status          = $status
                    reason          = $reason
                })
        }
    }

    $sortedFindings = @($findings.ToArray() | Sort-Object -Property hostname, software)
    $sortedGold = @($goldRows.ToArray() | Sort-Object -Property software)
    return [pscustomobject]@{
        Findings = $sortedFindings
        Gold     = $sortedGold
    }
}

function Get-RemediationId {
    param(
        [AllowNull()][string]$Hostname,
        [AllowNull()][string]$Software
    )

    return ('{0}|{1}' -f ([string]$Hostname).Trim().ToLowerInvariant(), ([string]$Software).Trim().ToLowerInvariant())
}

function Add-QueueHistory {
    param(
        $Item,
        $FromState,
        [string]$ToState,
        [string]$Note,
        [string]$Stamp
    )

    $fromValue = $null
    if ($null -ne $FromState -and -not [string]::IsNullOrWhiteSpace([string]$FromState)) {
        $fromValue = [string]$FromState
    }
    [void]$Item.history.Add([pscustomobject][ordered]@{
            at   = $Stamp
            from = $fromValue
            to   = $ToState
            note = $Note
        })
}

function Copy-QueueHistory {
    param($History)

    $list = New-Object System.Collections.Generic.List[object]
    foreach ($entry in (ConvertTo-ObjectArray -Value $History)) {
        if ($null -eq $entry) { continue }
        $fromValue = Get-ObjectProperty -Object $entry -Name 'from'
        $fromText = $null
        if ($null -ne $fromValue -and -not [string]::IsNullOrWhiteSpace([string]$fromValue)) {
            $fromText = [string]$fromValue
        }
        [void]$list.Add([pscustomobject][ordered]@{
                at   = [string](Get-ObjectProperty -Object $entry -Name 'at')
                from = $fromText
                to   = [string](Get-ObjectProperty -Object $entry -Name 'to')
                note = [string](Get-ObjectProperty -Object $entry -Name 'note')
            })
    }
    return ,$list
}

function Copy-MutableQueueItem {
    param($Existing)

    $history = Copy-QueueHistory -History (Get-ObjectProperty -Object $Existing -Name 'history')
    $sentAt = Get-ObjectProperty -Object $Existing -Name 'sentAt'
    $closedAt = Get-ObjectProperty -Object $Existing -Name 'closedAt'
    return @{
        id              = [string](Get-ObjectProperty -Object $Existing -Name 'id')
        hostname        = [string](Get-ObjectProperty -Object $Existing -Name 'hostname')
        software        = [string](Get-ObjectProperty -Object $Existing -Name 'software')
        state           = [string](Get-ObjectProperty -Object $Existing -Name 'state')
        status          = [string](Get-ObjectProperty -Object $Existing -Name 'status')
        reason          = [string](Get-ObjectProperty -Object $Existing -Name 'reason')
        observedVersion = [string](Get-ObjectProperty -Object $Existing -Name 'observedVersion')
        goldVersion     = [string](Get-ObjectProperty -Object $Existing -Name 'goldVersion')
        os              = [string](Get-ObjectProperty -Object $Existing -Name 'os')
        online          = [string](Get-ObjectProperty -Object $Existing -Name 'online')
        deployed        = $false
        createdAt       = [string](Get-ObjectProperty -Object $Existing -Name 'createdAt')
        updatedAt       = [string](Get-ObjectProperty -Object $Existing -Name 'updatedAt')
        sentAt          = $(if ([string]::IsNullOrWhiteSpace([string]$sentAt)) { $null } else { [string]$sentAt })
        closedAt        = $(if ([string]::IsNullOrWhiteSpace([string]$closedAt)) { $null } else { [string]$closedAt })
        history         = $history
    }
}

function Add-QueueObservation {
    param(
        $Item,
        $Finding,
        [string]$Stamp,
        [bool]$RecordHistory
    )

    $observed = [string](Get-ObjectProperty -Object $Finding -Name 'observedVersion')
    $gold = [string](Get-ObjectProperty -Object $Finding -Name 'goldVersion')
    $status = [string](Get-ObjectProperty -Object $Finding -Name 'status')
    $reason = [string](Get-ObjectProperty -Object $Finding -Name 'reason')
    $os = [string](Get-ObjectProperty -Object $Finding -Name 'os')
    $online = [string](Get-ObjectProperty -Object $Finding -Name 'online')
    $changed = (
        [string]$Item.status -ne $status -or
        [string]$Item.observedVersion -ne $observed -or
        [string]$Item.goldVersion -ne $gold -or
        [string]$Item.reason -ne $reason
    )
    $Item.hostname = [string](Get-ObjectProperty -Object $Finding -Name 'hostname')
    $Item.software = [string](Get-ObjectProperty -Object $Finding -Name 'software')
    $Item.status = $status
    $Item.reason = $reason
    $Item.observedVersion = $observed
    $Item.goldVersion = $gold
    $Item.os = $os
    $Item.online = $online
    $Item.deployed = $false
    if ($changed -and $RecordHistory) {
        $Item.updatedAt = $Stamp
        Add-QueueHistory -Item $Item -FromState ([string]$Item.state) -ToState ([string]$Item.state) -Note 'Observation updated.' -Stamp $Stamp
    }
}

function ConvertTo-MutableQueueItem {
    param(
        [string]$Id,
        $Finding,
        [string]$Stamp,
        [string]$Note
    )

    $item = @{
        id              = $Id
        hostname        = [string](Get-ObjectProperty -Object $Finding -Name 'hostname')
        software        = [string](Get-ObjectProperty -Object $Finding -Name 'software')
        state           = 'pending'
        status          = [string](Get-ObjectProperty -Object $Finding -Name 'status')
        reason          = [string](Get-ObjectProperty -Object $Finding -Name 'reason')
        observedVersion = [string](Get-ObjectProperty -Object $Finding -Name 'observedVersion')
        goldVersion     = [string](Get-ObjectProperty -Object $Finding -Name 'goldVersion')
        os              = [string](Get-ObjectProperty -Object $Finding -Name 'os')
        online          = [string](Get-ObjectProperty -Object $Finding -Name 'online')
        deployed        = $false
        createdAt       = $Stamp
        updatedAt       = $Stamp
        sentAt          = $null
        closedAt        = $null
        history         = (New-Object System.Collections.Generic.List[object])
    }
    Add-QueueHistory -Item $item -FromState $null -ToState 'pending' -Note $Note -Stamp $Stamp
    return $item
}

function ConvertTo-QueueOutputItem {
    param($Item)

    $history = New-Object System.Collections.Generic.List[object]
    foreach ($entry in $Item.history.ToArray()) {
        [void]$history.Add($entry)
    }
    return [pscustomobject][ordered]@{
        id              = [string]$Item.id
        hostname        = [string]$Item.hostname
        software        = [string]$Item.software
        state           = [string]$Item.state
        status          = [string]$Item.status
        reason          = [string]$Item.reason
        observedVersion = [string]$Item.observedVersion
        goldVersion     = [string]$Item.goldVersion
        os              = [string]$Item.os
        online          = [string]$Item.online
        deployed        = $false
        createdAt       = [string]$Item.createdAt
        updatedAt       = [string]$Item.updatedAt
        sentAt          = $Item.sentAt
        closedAt        = $Item.closedAt
        history         = $history.ToArray()
    }
}

function ConvertTo-RemediationQueue {
    <#
    .SYNOPSIS
        Merges version findings into a persistent remediation queue.
    .DESCRIPTION
        Outdated and Missing findings enter as pending. A later Compliant
        observation moves pending or sent items to confirmed. Confirmed items
        reopen to pending if the machine falls out of compliance again.
        Abandoned items stay closed. SubmitId moves pending items to sent and
        records that no software was deployed. The sent state is bookkeeping
        only. This function returns the new queue. It does not write a file
        and it does not deploy software.
    #>
    [CmdletBinding()]
    param(
        $Queue,
        [AllowEmptyCollection()]
        [object[]]$Findings = @(),
        [AllowNull()]
        [string[]]$SubmitId,
        [AllowNull()]
        [string[]]$AbandonId,
        [datetime]$Now = ([datetime]::UtcNow)
    )

    $stamp = Format-GovernanceUtc -Value $Now
    $itemsById = @{}
    $warnings = New-Object System.Collections.Generic.List[string]

    foreach ($existing in (ConvertTo-ObjectArray -Value (Get-ObjectProperty -Object $Queue -Name 'items'))) {
        if ($null -eq $existing) { continue }
        $id = [string](Get-ObjectProperty -Object $existing -Name 'id')
        if ([string]::IsNullOrWhiteSpace($id)) {
            [void]$warnings.Add('Skipped a queue item that has no id.')
            continue
        }
        $itemsById[$id.Trim().ToLowerInvariant()] = Copy-MutableQueueItem -Existing $existing
    }

    foreach ($finding in (ConvertTo-ObjectArray -Value $Findings)) {
        if ($null -eq $finding) { continue }
        $hostname = [string](Get-ObjectProperty -Object $finding -Name 'hostname')
        $software = [string](Get-ObjectProperty -Object $finding -Name 'software')
        $status = [string](Get-ObjectProperty -Object $finding -Name 'status')
        if ([string]::IsNullOrWhiteSpace($hostname) -or [string]::IsNullOrWhiteSpace($software)) { continue }
        $id = Get-RemediationId -Hostname $hostname -Software $software
        $current = $null
        if ($itemsById.ContainsKey($id)) { $current = $itemsById[$id] }

        if ($status -eq 'Outdated' -or $status -eq 'Missing') {
            $note = 'Queued because the installation is out of date.'
            if ($status -eq 'Missing') { $note = 'Queued because the software is missing.' }
            if ($null -eq $current) {
                $itemsById[$id] = ConvertTo-MutableQueueItem -Id $id -Finding $finding -Stamp $stamp -Note $note
            }
            elseif ([string]$current.state -eq 'abandoned') {
                Add-QueueObservation -Item $current -Finding $finding -Stamp $stamp -RecordHistory $true
            }
            elseif ([string]$current.state -eq 'confirmed') {
                Add-QueueObservation -Item $current -Finding $finding -Stamp $stamp -RecordHistory $false
                $fromState = [string]$current.state
                $current.state = 'pending'
                $current.sentAt = $null
                $current.closedAt = $null
                $current.updatedAt = $stamp
                $current.deployed = $false
                Add-QueueHistory -Item $current -FromState $fromState -ToState 'pending' -Note 'Reopened because the machine is no longer compliant.' -Stamp $stamp
            }
            else {
                Add-QueueObservation -Item $current -Finding $finding -Stamp $stamp -RecordHistory $true
            }
        }
        elseif ($status -eq 'Compliant' -and $null -ne $current -and ([string]$current.state -eq 'pending' -or [string]$current.state -eq 'sent')) {
            Add-QueueObservation -Item $current -Finding $finding -Stamp $stamp -RecordHistory $false
            $fromState = [string]$current.state
            $current.state = 'confirmed'
            $current.closedAt = $stamp
            $current.updatedAt = $stamp
            $current.deployed = $false
            Add-QueueHistory -Item $current -FromState $fromState -ToState 'confirmed' -Note 'Observed version now meets the gold standard.' -Stamp $stamp
        }
    }

    foreach ($rawAbandon in (ConvertTo-ObjectArray -Value $AbandonId)) {
        if ([string]::IsNullOrWhiteSpace([string]$rawAbandon)) { continue }
        $abandonKey = ([string]$rawAbandon).Trim().ToLowerInvariant()
        if (-not $itemsById.ContainsKey($abandonKey)) {
            [void]$warnings.Add("Abandon id was not found: $rawAbandon")
            continue
        }
        $item = $itemsById[$abandonKey]
        if ([string]$item.state -eq 'abandoned') { continue }
        if ([string]$item.state -eq 'confirmed') {
            [void]$warnings.Add("Confirmed item was not abandoned: $abandonKey")
            continue
        }
        $fromState = [string]$item.state
        $item.state = 'abandoned'
        $item.closedAt = $stamp
        $item.updatedAt = $stamp
        $item.deployed = $false
        Add-QueueHistory -Item $item -FromState $fromState -ToState 'abandoned' -Note 'Abandoned by the operator.' -Stamp $stamp
    }

    $submitLookup = @{}
    foreach ($rawSubmit in (ConvertTo-ObjectArray -Value $SubmitId)) {
        if ([string]::IsNullOrWhiteSpace([string]$rawSubmit)) { continue }
        $submitLookup[([string]$rawSubmit).Trim().ToLowerInvariant()] = $true
    }

    $eligible = New-Object System.Collections.Generic.List[object]
    foreach ($id in @($itemsById.Keys)) {
        $item = $itemsById[$id]
        $actionable = ([string]$item.status -eq 'Outdated' -or [string]$item.status -eq 'Missing')
        if ([string]$item.state -ne 'pending' -or -not $actionable) { continue }
        if ($submitLookup.ContainsKey([string]$id)) {
            $item.state = 'sent'
            $item.sentAt = $stamp
            $item.updatedAt = $stamp
            $item.deployed = $false
            Add-QueueHistory -Item $item -FromState 'pending' -ToState 'sent' -Note 'Marked sent by the remediation hook. No software was deployed.' -Stamp $stamp
        }
        else {
            [void]$eligible.Add((ConvertTo-QueueOutputItem -Item $item))
        }
    }

    $ordered = New-Object System.Collections.Generic.List[object]
    foreach ($id in (@($itemsById.Keys) | Sort-Object)) {
        [void]$ordered.Add((ConvertTo-QueueOutputItem -Item $itemsById[$id]))
    }
    $queueObject = [pscustomobject][ordered]@{
        version     = 1
        description = 'Persistent remediation queue. Items move from pending to sent, then to confirmed or abandoned. The sent state is bookkeeping only and does not deploy software.'
        updatedAt   = $stamp
        items       = $ordered.ToArray()
    }
    $eligibleSorted = @($eligible.ToArray() | Sort-Object -Property id)
    return [pscustomobject]@{
        Queue          = $queueObject
        EligibleSubmit = $eligibleSorted
        Warnings       = $warnings.ToArray()
    }
}

function Get-DeltaLabel {
    param(
        [AllowNull()][string]$Previous,
        [AllowNull()][string]$Current
    )

    if ([string]::IsNullOrWhiteSpace($Previous)) { return 'New' }
    if ($Previous -eq $Current) { return 'Unchanged' }
    if ($Current -eq 'Compliant' -and $Previous -ne 'Compliant') { return 'Improved' }
    if ($Previous -eq 'Compliant' -and $Current -ne 'Compliant') { return 'Regressed' }
    if ($Previous -eq 'Unknown') { return 'Observed' }
    if ($Current -eq 'Unknown') { return 'Inconclusive' }
    return 'Changed'
}

function Get-ComplianceDelta {
    <#
    .SYNOPSIS
        Labels each current finding against the previous run.
    .DESCRIPTION
        Delta is New, Unchanged, Improved, Regressed, Observed, Inconclusive,
        or Changed. Unknown to a known status is Observed. A known status that
        becomes Unknown is Inconclusive.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Current = @(),
        [AllowEmptyCollection()]
        [object[]]$Previous = @()
    )

    $previousById = @{}
    foreach ($row in (ConvertTo-ObjectArray -Value $Previous)) {
        if ($null -eq $row) { continue }
        $hostname = [string](Get-ObjectProperty -Object $row -Name 'hostname')
        $software = [string](Get-ObjectProperty -Object $row -Name 'software')
        if ([string]::IsNullOrWhiteSpace($hostname) -or [string]::IsNullOrWhiteSpace($software)) { continue }
        $id = Get-RemediationId -Hostname $hostname -Software $software
        $previousById[$id] = [string](Get-ObjectProperty -Object $row -Name 'status')
    }

    $output = New-Object System.Collections.Generic.List[object]
    foreach ($row in (ConvertTo-ObjectArray -Value $Current)) {
        if ($null -eq $row) { continue }
        $map = [ordered]@{}
        foreach ($property in @($row.PSObject.Properties)) {
            if ($property.MemberType -ne [System.Management.Automation.PSMemberTypes]::NoteProperty) { continue }
            $map[$property.Name] = $property.Value
        }
        $hostname = [string](Get-ObjectProperty -Object $row -Name 'hostname')
        $software = [string](Get-ObjectProperty -Object $row -Name 'software')
        $status = [string](Get-ObjectProperty -Object $row -Name 'status')
        $id = Get-RemediationId -Hostname $hostname -Software $software
        $previousStatus = ''
        if ($previousById.ContainsKey($id)) { $previousStatus = [string]$previousById[$id] }
        $map['previousStatus'] = $previousStatus
        $map['delta'] = (Get-DeltaLabel -Previous $previousStatus -Current $status)
        [void]$output.Add((ConvertTo-GovernanceObject -Properties $map))
    }
    return ,$output.ToArray()
}

function Get-PreviousAuditRun {
    <#
    .SYNOPSIS
        Returns the audit rows that belong to the latest stored run.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$AuditRows = @()
    )

    $groups = @{}
    $bestRun = $null
    $bestAt = [datetime]::MinValue
    $bestIndex = -1
    $index = 0
    foreach ($row in (ConvertTo-ObjectArray -Value $AuditRows)) {
        if ($null -eq $row) {
            $index += 1
            continue
        }
        $runId = [string](Get-ObjectProperty -Object $row -Name 'runId')
        if ([string]::IsNullOrWhiteSpace($runId)) {
            $index += 1
            continue
        }
        if (-not $groups.ContainsKey($runId)) {
            $groups[$runId] = New-Object System.Collections.Generic.List[object]
        }
        [void]$groups[$runId].Add($row)
        $atText = [string](Get-ObjectProperty -Object $row -Name 'at')
        $parsedAt = [datetime]::MinValue
        $styles = [System.Globalization.DateTimeStyles]::RoundtripKind
        $culture = [System.Globalization.CultureInfo]::InvariantCulture
        $parsed = [datetime]::TryParse($atText, $culture, $styles, [ref]$parsedAt)
        if (-not $parsed) { $parsedAt = [datetime]::MinValue }
        if ($null -eq $bestRun -or $parsedAt -gt $bestAt -or ($parsedAt -eq $bestAt -and $index -gt $bestIndex)) {
            $bestRun = $runId
            $bestAt = $parsedAt
            $bestIndex = $index
        }
        $index += 1
    }
    if ($null -eq $bestRun) {
        return ,([object[]]@())
    }
    return ,$groups[$bestRun].ToArray()
}

function Get-VersionComplianceSummary {
    <#
    .SYNOPSIS
        Counts findings by status and delta for one version-compliance run.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Findings = @(),
        [AllowEmptyCollection()]
        [object[]]$Gold = @(),
        [string]$RunId = '',
        [string]$At = ''
    )

    $statusNames = @('Compliant', 'Outdated', 'Missing', 'Unknown')
    $statusCounts = @{
        Compliant = 0
        Outdated  = 0
        Missing   = 0
        Unknown   = 0
    }
    $deltaCounts = @{}
    $findingCount = 0
    foreach ($row in (ConvertTo-ObjectArray -Value $Findings)) {
        if ($null -eq $row) { continue }
        $findingCount += 1
        $status = [string](Get-ObjectProperty -Object $row -Name 'status')
        if ($statusCounts.ContainsKey($status)) {
            $statusCounts[$status] = [int]$statusCounts[$status] + 1
        }
        $delta = [string](Get-ObjectProperty -Object $row -Name 'delta')
        if ([string]::IsNullOrWhiteSpace($delta)) { $delta = 'Unreported' }
        if (-not $deltaCounts.ContainsKey($delta)) { $deltaCounts[$delta] = 0 }
        $deltaCounts[$delta] = [int]$deltaCounts[$delta] + 1
    }

    return [pscustomobject][ordered]@{
        runId      = $RunId
        at         = $At
        findings   = $findingCount
        compliant  = [int]$statusCounts.Compliant
        outdated   = [int]$statusCounts.Outdated
        missing    = [int]$statusCounts.Missing
        unknown    = [int]$statusCounts.Unknown
        deltas     = [pscustomobject]$deltaCounts
        gold       = (ConvertTo-ObjectArray -Value $Gold)
        statuses   = @($statusNames)
    }
}
