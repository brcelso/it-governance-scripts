# Allow list, block list, and required-software comparison. No remote calls.

function Test-WildcardMatch {
    param(
        [AllowNull()][string]$Value,
        [AllowNull()][string]$Pattern
    )

    if ([string]::IsNullOrWhiteSpace($Pattern) -or $Pattern -eq '*') {
        return $true
    }
    $options = [System.Management.Automation.WildcardOptions]::IgnoreCase
    $wildcard = New-Object System.Management.Automation.WildcardPattern($Pattern, $options)
    return $wildcard.IsMatch([string]$Value)
}

function Test-RuleNameMatch {
    param(
        [AllowNull()][string]$Value,
        [AllowNull()][string]$Pattern
    )

    if ([string]::IsNullOrWhiteSpace($Pattern)) {
        return $false
    }
    if ($Pattern.Contains('*') -or $Pattern.Contains('?')) {
        $options = [System.Management.Automation.WildcardOptions]::IgnoreCase
        $wildcard = New-Object System.Management.Automation.WildcardPattern($Pattern, $options)
        return $wildcard.IsMatch([string]$Value)
    }
    return [string]::Equals([string]$Value, $Pattern, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-SoftwareVersion {
    param([AllowNull()][string]$VersionText)

    if ([string]::IsNullOrWhiteSpace($VersionText)) {
        return $null
    }
    $text = $VersionText.Trim()
    if ($text.StartsWith('v') -or $text.StartsWith('V')) {
        $text = $text.Substring(1)
    }
    $match = [regex]::Match($text, '^\d+(\.\d+){0,3}')
    if (-not $match.Success) {
        return $null
    }
    $parts = @($match.Value.Split('.'))
    if ($parts.Count -lt 2) {
        $parts = @($parts[0], '0')
    }
    try {
        return [version]($parts -join '.')
    }
    catch {
        return $null
    }
}

function ConvertTo-SoftwareRule {
    param(
        $Rule,
        [string]$Kind,
        [int]$Index
    )

    if ($null -eq $Rule) {
        throw "$Kind rule $Index is empty."
    }
    $name = [string](Get-ObjectProperty -Object $Rule -Name 'name')
    if ([string]::IsNullOrWhiteSpace($name)) {
        throw "$Kind rule $Index is missing a name."
    }
    $publisher = [string](Get-ObjectProperty -Object $Rule -Name 'publisher')
    $minVersion = [string](Get-ObjectProperty -Object $Rule -Name 'minVersion')
    $reason = [string](Get-ObjectProperty -Object $Rule -Name 'reason')
    if (-not [string]::IsNullOrWhiteSpace($minVersion) -and $null -eq (Get-SoftwareVersion -VersionText $minVersion)) {
        throw "$Kind rule $Index has a minimum version that cannot be parsed: $minVersion"
    }
    return [pscustomobject][ordered]@{
        name       = $name.Trim()
        publisher  = $publisher.Trim()
        minVersion = $minVersion.Trim()
        reason     = $reason.Trim()
    }
}

function ConvertTo-SoftwareRuleSet {
    param(
        $RawRules,
        [string]$Kind
    )

    $rules = New-Object System.Collections.Generic.List[object]
    $index = 1
    foreach ($rule in (ConvertTo-ObjectArray -Value $RawRules)) {
        [void]$rules.Add((ConvertTo-SoftwareRule -Rule $rule -Kind $Kind -Index $index))
        $index += 1
    }
    return ,$rules.ToArray()
}

function Resolve-SoftwarePolicy {
    <#
    .SYNOPSIS
        Validates and normalizes a software allow/block policy.
    .DESCRIPTION
        Accepts an object produced by ConvertFrom-Json. Rules use name,
        an optional publisher, an optional minVersion, and an optional reason.
        Name and publisher support wildcards only when they contain * or ?.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Policy
    )

    if ($null -eq $Policy) {
        throw 'Software policy is empty.'
    }
    if ($Policy -is [System.Array]) {
        throw 'Software policy must be a JSON object with allow, block, and required arrays.'
    }

    return [pscustomobject][ordered]@{
        name        = [string](Get-ObjectProperty -Object $Policy -Name 'name')
        version     = [string](Get-ObjectProperty -Object $Policy -Name 'version')
        description = [string](Get-ObjectProperty -Object $Policy -Name 'description')
        allow       = (ConvertTo-SoftwareRuleSet -RawRules (Get-ObjectProperty -Object $Policy -Name 'allow') -Kind 'Allow')
        block       = (ConvertTo-SoftwareRuleSet -RawRules (Get-ObjectProperty -Object $Policy -Name 'block') -Kind 'Block')
        required    = (ConvertTo-SoftwareRuleSet -RawRules (Get-ObjectProperty -Object $Policy -Name 'required') -Kind 'Required')
    }
}

function Test-SoftwareRuleMatch {
    param(
        [AllowNull()][string]$Name,
        [AllowNull()][string]$Publisher,
        $Rule
    )

    if (-not (Test-RuleNameMatch -Value $Name -Pattern ([string]$Rule.name))) {
        return $false
    }
    if ([string]::IsNullOrWhiteSpace([string]$Rule.publisher) -or [string]$Rule.publisher -eq '*') {
        return $true
    }
    return (Test-RuleNameMatch -Value $Publisher -Pattern ([string]$Rule.publisher))
}

function Get-MinimumVersionResult {
    param(
        [AllowNull()][string]$Actual,
        [AllowNull()][string]$Minimum
    )

    if ([string]::IsNullOrWhiteSpace($Minimum)) {
        return [pscustomobject]@{ Meets = $true; Detail = '' }
    }
    $actualVersion = Get-SoftwareVersion -VersionText $Actual
    $minimumVersion = Get-SoftwareVersion -VersionText $Minimum
    if ($null -eq $minimumVersion) {
        return [pscustomobject]@{
            Meets  = $false
            Detail = "Minimum version '$Minimum' cannot be parsed."
        }
    }
    if ($null -eq $actualVersion) {
        return [pscustomobject]@{
            Meets  = $false
            Detail = "Installed version '$Actual' cannot be compared with minimum $Minimum."
        }
    }
    if ($actualVersion -lt $minimumVersion) {
        return [pscustomobject]@{
            Meets  = $false
            Detail = "Installed version $Actual is below minimum $Minimum."
        }
    }
    return [pscustomobject]@{ Meets = $true; Detail = '' }
}

function ConvertTo-SoftwareComplianceRow {
    param(
        [string]$ComputerName,
        [string]$DisplayName,
        [string]$DisplayVersion,
        [string]$Publisher,
        [string]$Status,
        [string]$Reason,
        [string]$PolicyRule,
        [string]$Detail
    )

    return [pscustomobject][ordered]@{
        ComputerName   = $ComputerName
        DisplayName    = $DisplayName
        DisplayVersion = $DisplayVersion
        Publisher      = $Publisher
        Status         = $Status
        Reason         = $Reason
        PolicyRule     = $PolicyRule
        Detail         = $Detail
    }
}

function Add-UniqueComputerName {
    param(
        $List,
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return
    }
    foreach ($existing in @($List)) {
        if ([string]::Equals([string]$existing, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
            return
        }
    }
    [void]$List.Add($Name)
}

function Find-FirstSoftwareRule {
    param(
        [string]$Name,
        [string]$Publisher,
        [object[]]$Rules
    )

    foreach ($rule in @($Rules)) {
        if ($null -eq $rule) { continue }
        if (Test-SoftwareRuleMatch -Name $Name -Publisher $Publisher -Rule $rule) {
            return $rule
        }
    }
    return $null
}

function Compare-SoftwareCompliance {
    <#
    .SYNOPSIS
        Compares installed software with an allow, block, and required policy.
    .DESCRIPTION
        Block rules win. Allow and required rules then contribute minimum
        versions. Anything else is Unknown. A required title that is absent
        becomes a NonCompliant RequiredMissing row. A collection error does
        not invent a missing-software finding for that computer.

        Status is Compliant, NonCompliant, or Unknown.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$InstalledSoftware = @(),
        [Parameter(Mandatory = $true)]
        $Policy,
        [AllowNull()]
        [string[]]$ComputerName
    )

    $normalized = Resolve-SoftwarePolicy -Policy $Policy
    $results = New-Object System.Collections.Generic.List[object]
    $installedByComputer = @{}
    $failed = @{}
    $seen = New-Object System.Collections.Generic.List[string]

    foreach ($item in (ConvertTo-ObjectArray -Value $InstalledSoftware)) {
        if ($null -eq $item) { continue }
        $computer = [string](Get-ObjectProperty -Object $item -Name 'ComputerName')
        if ([string]::IsNullOrWhiteSpace($computer)) { continue }
        Add-UniqueComputerName -List $seen -Name $computer

        $collectionError = Format-GovernanceSingleLine -Text ([string](Get-ObjectProperty -Object $item -Name 'CollectionError'))
        $displayName = ([string](Get-ObjectProperty -Object $item -Name 'DisplayName')).Trim()
        $displayVersion = ([string](Get-ObjectProperty -Object $item -Name 'DisplayVersion')).Trim()
        $publisher = ([string](Get-ObjectProperty -Object $item -Name 'Publisher')).Trim()

        if (-not [string]::IsNullOrWhiteSpace($collectionError)) {
            $failed[$computer] = $true
            [void]$results.Add((ConvertTo-SoftwareComplianceRow -ComputerName $computer -DisplayName $displayName -DisplayVersion $displayVersion -Publisher $publisher -Status 'Unknown' -Reason 'CollectionFailed' -PolicyRule '' -Detail $collectionError))
            continue
        }
        if ([string]::IsNullOrWhiteSpace($displayName)) { continue }

        if (-not $installedByComputer.ContainsKey($computer)) {
            $installedByComputer[$computer] = New-Object System.Collections.Generic.List[object]
        }
        [void]$installedByComputer[$computer].Add([pscustomobject]@{
                DisplayName = $displayName
                Publisher   = $publisher
            })

        $blockMatch = Find-FirstSoftwareRule -Name $displayName -Publisher $publisher -Rules $normalized.block
        if ($null -ne $blockMatch) {
            $detail = [string]$blockMatch.reason
            if ([string]::IsNullOrWhiteSpace($detail)) { $detail = 'Matches a block rule.' }
            [void]$results.Add((ConvertTo-SoftwareComplianceRow -ComputerName $computer -DisplayName $displayName -DisplayVersion $displayVersion -Publisher $publisher -Status 'NonCompliant' -Reason 'Blocked' -PolicyRule ([string]$blockMatch.name) -Detail $detail))
            continue
        }

        $allowMatch = Find-FirstSoftwareRule -Name $displayName -Publisher $publisher -Rules $normalized.allow
        $requiredMatch = Find-FirstSoftwareRule -Name $displayName -Publisher $publisher -Rules $normalized.required
        if ($null -eq $allowMatch -and $null -eq $requiredMatch) {
            [void]$results.Add((ConvertTo-SoftwareComplianceRow -ComputerName $computer -DisplayName $displayName -DisplayVersion $displayVersion -Publisher $publisher -Status 'Unknown' -Reason 'NotListed' -PolicyRule '' -Detail 'Not on the allow list or the block list.'))
            continue
        }

        $minimumFailed = $false
        $detail = ''
        $policyRule = ''
        if ($null -ne $allowMatch) {
            $policyRule = [string]$allowMatch.name
            $check = Get-MinimumVersionResult -Actual $displayVersion -Minimum ([string]$allowMatch.minVersion)
            if (-not $check.Meets) {
                $minimumFailed = $true
                $detail = [string]$check.Detail
            }
        }
        if (-not $minimumFailed -and $null -ne $requiredMatch) {
            if ([string]::IsNullOrWhiteSpace($policyRule)) { $policyRule = [string]$requiredMatch.name }
            $check = Get-MinimumVersionResult -Actual $displayVersion -Minimum ([string]$requiredMatch.minVersion)
            if (-not $check.Meets) {
                $minimumFailed = $true
                $detail = [string]$check.Detail
                $policyRule = [string]$requiredMatch.name
            }
        }

        if ($minimumFailed) {
            [void]$results.Add((ConvertTo-SoftwareComplianceRow -ComputerName $computer -DisplayName $displayName -DisplayVersion $displayVersion -Publisher $publisher -Status 'NonCompliant' -Reason 'BelowMinimumVersion' -PolicyRule $policyRule -Detail $detail))
        }
        elseif ($null -ne $allowMatch) {
            [void]$results.Add((ConvertTo-SoftwareComplianceRow -ComputerName $computer -DisplayName $displayName -DisplayVersion $displayVersion -Publisher $publisher -Status 'Compliant' -Reason 'Allowed' -PolicyRule ([string]$allowMatch.name) -Detail 'Matches an allow rule.'))
        }
        else {
            [void]$results.Add((ConvertTo-SoftwareComplianceRow -ComputerName $computer -DisplayName $displayName -DisplayVersion $displayVersion -Publisher $publisher -Status 'Compliant' -Reason 'RequiredPresent' -PolicyRule ([string]$requiredMatch.name) -Detail 'Matches required software.'))
        }
    }

    $scope = New-Object System.Collections.Generic.List[string]
    foreach ($name in @($seen)) { Add-UniqueComputerName -List $scope -Name ([string]$name) }
    foreach ($name in (ConvertTo-ObjectArray -Value $ComputerName)) {
        Add-UniqueComputerName -List $scope -Name ([string]$name)
    }

    foreach ($computer in @($scope)) {
        if ($failed.ContainsKey([string]$computer)) { continue }
        $present = @()
        if ($installedByComputer.ContainsKey([string]$computer)) {
            $present = $installedByComputer[[string]$computer].ToArray()
        }
        foreach ($required in @($normalized.required)) {
            if ($null -eq $required) { continue }
            $found = $false
            foreach ($product in $present) {
                if (Test-SoftwareRuleMatch -Name ([string]$product.DisplayName) -Publisher ([string]$product.Publisher) -Rule $required) {
                    $found = $true
                    break
                }
            }
            if (-not $found) {
                $detail = 'Required software is not installed.'
                if (-not [string]::IsNullOrWhiteSpace([string]$required.minVersion)) {
                    $detail = "Required software is not installed. Minimum version is $($required.minVersion)."
                }
                [void]$results.Add((ConvertTo-SoftwareComplianceRow -ComputerName ([string]$computer) -DisplayName ([string]$required.name) -DisplayVersion '' -Publisher ([string]$required.publisher) -Status 'NonCompliant' -Reason 'RequiredMissing' -PolicyRule ([string]$required.name) -Detail $detail))
            }
        }
    }

    $rank = @{
        NonCompliant = 0
        Unknown      = 1
        Compliant    = 2
    }
    $sorted = @($results.ToArray() | Sort-Object -Property ComputerName, @{ Expression = { $rank[$_.Status] } }, DisplayName)
    return ,$sorted
}

function Get-AdminApprovalStatus {
    <#
    .SYNOPSIS
        Classifies a local administrator against an approved account list.
    .DESCRIPTION
        Returns Unknown when no list was supplied, Approved on a case-insensitive
        name or SID match, and Unapproved otherwise. Patterns that contain
        * or ? are wildcards. An empty list approves nobody.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][string]$MemberName,
        [AllowNull()][string]$Sid,
        [AllowNull()][string[]]$ApprovedAccounts
    )

    if ($null -eq $ApprovedAccounts) {
        return 'Unknown'
    }
    foreach ($pattern in (ConvertTo-ObjectArray -Value $ApprovedAccounts)) {
        if ([string]::IsNullOrWhiteSpace([string]$pattern)) { continue }
        $trimmed = ([string]$pattern).Trim()
        if (Test-RuleNameMatch -Value $MemberName -Pattern $trimmed) { return 'Approved' }
        if (-not [string]::IsNullOrWhiteSpace($Sid) -and (Test-RuleNameMatch -Value $Sid -Pattern $trimmed)) {
            return 'Approved'
        }
    }
    return 'Unapproved'
}
