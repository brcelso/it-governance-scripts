BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\EndpointGovernance.psm1') -Force

    function script:New-VersionRule {
    param(
        [string]$Name,
        [string]$Gold,
        [string]$Auto = 'most-common',
        [string]$Tolerance = '0',
        [string[]]$Os
    )
    $rule = [ordered]@{
        name      = $Name
        gold      = $Gold
        auto      = $Auto
        tolerance = $Tolerance
    }
    if ($null -ne $Os) { $rule['os'] = $Os }
    return [pscustomobject]$rule
}

    function script:New-InventoryRow {
    param(
        [string]$Hostname,
        [string]$Software,
        [string]$Version,
        [string]$Os = 'Windows 11',
        [string]$Online = 'true'
    )
    return [pscustomobject]@{
        hostname = $Hostname
        software = $Software
        version  = $Version
        os       = $Os
        online   = $Online
    }
}

    function script:Get-Finding {
    param($Findings, [string]$Hostname, [string]$Software)
    $matched = @($Findings | Where-Object { $_.hostname -eq $Hostname -and $_.software -eq $Software })
    return ,$matched
}

}

Describe 'Resolve-VersionPolicy' {
    It 'rejects an unparsable gold version' {
        $policy = [pscustomobject]@{ software = @(New-VersionRule -Name 'Example App' -Gold 'not-a-version') }
        { Resolve-VersionPolicy -Policy $policy } | Should -Throw -ExpectedMessage '*cannot be parsed*'
    }

    It 'rejects an unknown auto method' {
        $policy = [pscustomobject]@{ software = @(New-VersionRule -Name 'Example App' -Gold 'auto' -Auto 'popular') }
        { Resolve-VersionPolicy -Policy $policy } | Should -Throw -ExpectedMessage '*unsupported auto method*'
    }
}

Describe 'Get-VersionCompliance gold standard' {
    It 'uses the latest version when the most common versions tie' {
        $policy = [pscustomobject]@{ software = @(New-VersionRule -Name 'Example App' -Gold 'auto' -Auto 'most-common') }
        $inventory = @(
            (New-InventoryRow -Hostname 'PC-EXAMPLE-01' -Software 'Example App' -Version '1.0.0'),
            (New-InventoryRow -Hostname 'PC-EXAMPLE-02' -Software 'Example App' -Version '1.0.0'),
            (New-InventoryRow -Hostname 'PC-EXAMPLE-03' -Software 'Example App' -Version '2.0.0'),
            (New-InventoryRow -Hostname 'PC-EXAMPLE-04' -Software 'Example App' -Version '2.0.0')
        )
        $result = Get-VersionCompliance -Inventory $inventory -Policy $policy
        $result.Gold[0].goldVersion | Should -Be '2.0.0'
        $result.Gold[0].source | Should -Be 'most-common'
    }

    It 'keeps the majority version when it is older' {
        $policy = [pscustomobject]@{ software = @(New-VersionRule -Name 'Example App' -Gold 'auto' -Auto 'most-common') }
        $inventory = @(
            (New-InventoryRow -Hostname 'PC-EXAMPLE-01' -Software 'Example App' -Version '1.0.0'),
            (New-InventoryRow -Hostname 'PC-EXAMPLE-02' -Software 'Example App' -Version '1.0.0'),
            (New-InventoryRow -Hostname 'PC-EXAMPLE-03' -Software 'Example App' -Version '1.0.0'),
            (New-InventoryRow -Hostname 'PC-EXAMPLE-04' -Software 'Example App' -Version '2.0.0')
        )
        $result = Get-VersionCompliance -Inventory $inventory -Policy $policy
        $result.Gold[0].goldVersion | Should -Be '1.0.0'
    }

    It 'selects the highest version for the latest method' {
        $policy = [pscustomobject]@{ software = @(New-VersionRule -Name 'Example App' -Gold 'auto' -Auto 'latest') }
        $inventory = @(
            (New-InventoryRow -Hostname 'PC-EXAMPLE-01' -Software 'Example App' -Version '1.0.0'),
            (New-InventoryRow -Hostname 'PC-EXAMPLE-02' -Software 'Example App' -Version '1.0.0'),
            (New-InventoryRow -Hostname 'PC-EXAMPLE-03' -Software 'Example App' -Version '2.0.0')
        )
        $result = Get-VersionCompliance -Inventory $inventory -Policy $policy
        $result.Gold[0].goldVersion | Should -Be '2.0.0'
        $result.Gold[0].source | Should -Be 'latest'
    }

    It 'ignores offline versions while any online machine can vote' {
        $policy = [pscustomobject]@{ software = @(New-VersionRule -Name 'Example App' -Gold 'auto' -Auto 'latest') }
        $inventory = @(
            (New-InventoryRow -Hostname 'PC-EXAMPLE-01' -Software 'Example App' -Version '1.0.0' -Online 'true'),
            (New-InventoryRow -Hostname 'PC-EXAMPLE-02' -Software 'Example App' -Version '9.0.0' -Online 'false')
        )
        $result = Get-VersionCompliance -Inventory $inventory -Policy $policy
        $result.Gold[0].goldVersion | Should -Be '1.0.0'
        $result.Gold[0].voters | Should -Be 'online'
    }

    It 'falls back to offline versions when nobody is online' {
        $policy = [pscustomobject]@{ software = @(New-VersionRule -Name 'Example App' -Gold 'auto' -Auto 'latest') }
        $inventory = @(
            (New-InventoryRow -Hostname 'PC-EXAMPLE-02' -Software 'Example App' -Version '9.0.0' -Online 'false')
        )
        $result = Get-VersionCompliance -Inventory $inventory -Policy $policy
        $result.Gold[0].goldVersion | Should -Be '9.0.0'
        $result.Gold[0].voters | Should -Be 'all-observed'
    }
}

Describe 'Get-VersionCompliance classification' {
    It 'treats a newer build as compliant and a small gap as within tolerance' {
        $policy = [pscustomobject]@{
            software = @(New-VersionRule -Name 'Example Browser' -Gold '122.0.1' -Tolerance '0.0.5' -Os @('Windows 11*'))
        }
        $inventory = @(
            (New-InventoryRow -Hostname 'PC-EXAMPLE-01' -Software 'Example Browser' -Version '122.0.3'),
            (New-InventoryRow -Hostname 'PC-EXAMPLE-02' -Software 'Example Browser' -Version '122.0.0'),
            (New-InventoryRow -Hostname 'PC-EXAMPLE-03' -Software 'Example Browser' -Version '121.0.0')
        )
        $result = Get-VersionCompliance -Inventory $inventory -Policy $policy
        (Get-Finding -Findings $result.Findings -Hostname 'PC-EXAMPLE-01' -Software 'Example Browser').reason | Should -Be 'MeetsGold'
        (Get-Finding -Findings $result.Findings -Hostname 'PC-EXAMPLE-02' -Software 'Example Browser').reason | Should -Be 'WithinTolerance'
        (Get-Finding -Findings $result.Findings -Hostname 'PC-EXAMPLE-03' -Software 'Example Browser').status | Should -Be 'Outdated'
    }

    It 'right-aligns a single-number tolerance' {
        $policy = [pscustomobject]@{ software = @(New-VersionRule -Name 'Example Agent' -Gold '6.2.0' -Tolerance '1') }
        $inventory = @(
            (New-InventoryRow -Hostname 'PC-EXAMPLE-01' -Software 'Example Agent' -Version '6.2.0'),
            (New-InventoryRow -Hostname 'PC-EXAMPLE-03' -Software 'Example Agent' -Version '6.1.9')
        )
        $result = Get-VersionCompliance -Inventory $inventory -Policy $policy
        (Get-Finding -Findings $result.Findings -Hostname 'PC-EXAMPLE-01' -Software 'Example Agent').status | Should -Be 'Compliant'
        (Get-Finding -Findings $result.Findings -Hostname 'PC-EXAMPLE-03' -Software 'Example Agent').status | Should -Be 'Outdated'
    }

    It 'accepts a one-part version that matches the pinned gold version' {
        $policy = [pscustomobject]@{ software = @(New-VersionRule -Name 'Example App' -Gold '5') }
        $inventory = @(New-InventoryRow -Hostname 'PC-EXAMPLE-01' -Software 'Example App' -Version '5')
        $result = Get-VersionCompliance -Inventory $inventory -Policy $policy
        $result.Findings[0].status | Should -Be 'Compliant'
        $result.Gold[0].goldVersion | Should -Be '5'
    }

    It 'classifies the fictitious sample fleet' {
        $rulesPath = Join-Path $PSScriptRoot '..\samples\version-rules.json'
        $inventoryPath = Join-Path $PSScriptRoot '..\samples\version-inventory.csv'
        $policy = Get-Content -LiteralPath $rulesPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $inventory = @(Import-Csv -LiteralPath $inventoryPath)
        $result = Get-VersionCompliance -Inventory $inventory -Policy $policy
        $findings = $result.Findings
        @($findings).Count | Should -Be 17
        (Get-Finding -Findings $findings -Hostname 'PC-EXAMPLE-01' -Software 'Example Browser').status | Should -Be 'Compliant'
        (Get-Finding -Findings $findings -Hostname 'PC-EXAMPLE-03' -Software 'Example Browser').status | Should -Be 'Outdated'
        (Get-Finding -Findings $findings -Hostname 'PC-EXAMPLE-04' -Software 'Example Browser').status | Should -Be 'Outdated'
        (Get-Finding -Findings $findings -Hostname 'PC-EXAMPLE-04' -Software 'Example Endpoint Agent').reason | Should -Be 'OfflineUnverified'
        (Get-Finding -Findings $findings -Hostname 'LAPTOP-EXAMPLE-05' -Software 'Example Browser').reason | Should -Be 'VersionUnreadable'
        (Get-Finding -Findings $findings -Hostname 'PC-EXAMPLE-06' -Software 'Example Endpoint Agent').status | Should -Be 'Missing'
        (Get-Finding -Findings $findings -Hostname 'PC-EXAMPLE-02' -Software 'Example Pdf Reader').status | Should -Be 'Missing'
        (Get-Finding -Findings $findings -Hostname 'PC-EXAMPLE-03' -Software 'Example Pdf Reader').status | Should -Be 'Compliant'
        (Get-Finding -Findings $findings -Hostname 'PC-EXAMPLE-06' -Software 'Example Browser').Count | Should -Be 0
        ($result.Gold | Where-Object { $_.software -eq 'Example Endpoint Agent' }).goldVersion | Should -Be '6.2.0'
        ($result.Gold | Where-Object { $_.software -eq 'Example Pdf Reader' }).goldVersion | Should -Be '12.1.0'
    }
}

Describe 'ConvertTo-RemediationQueue' {
    BeforeAll {
        $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-01T12:00:00', 'Utc')
        $script:Finding = [pscustomobject]@{
            hostname        = 'PC-EXAMPLE-01'
            software        = 'Example Browser'
            status          = 'Outdated'
            reason          = 'OlderThanTolerance'
            observedVersion = '1.0.0'
            goldVersion     = '2.0.0'
            os              = 'Windows 11'
            online          = 'true'
        }
    }

    It 'queues a new outdated finding as pending and does not deploy' {
        $queue = ConvertTo-RemediationQueue -Findings @($script:Finding) -Now $script:Now
        $item = $queue.Queue.items[0]
        $item.state | Should -Be 'pending'
        $item.deployed | Should -BeFalse
        $queue.EligibleSubmit[0].id | Should -Be 'pc-example-01|example browser'
    }

    It 'does not duplicate an unchanged pending item' {
        $first = ConvertTo-RemediationQueue -Findings @($script:Finding) -Now $script:Now
        $second = ConvertTo-RemediationQueue -Queue $first.Queue -Findings @($script:Finding) -Now $script:Now.AddHours(1)
        @($second.Queue.items).Count | Should -Be 1
        @($second.Queue.items[0].history).Count | Should -Be 1
    }

    It 'marks a submitted item sent without deploying software' {
        $first = ConvertTo-RemediationQueue -Findings @($script:Finding) -Now $script:Now
        $sent = ConvertTo-RemediationQueue -Queue $first.Queue -Findings @($script:Finding) -Now $script:Now.AddHours(1) -SubmitId @($first.Queue.items[0].id)
        $sent.Queue.items[0].state | Should -Be 'sent'
        $sent.Queue.items[0].deployed | Should -BeFalse
        $sent.Queue.items[0].history[-1].note | Should -Be 'Marked sent by the remediation hook. No software was deployed.'
    }

    It 'confirms a pending item when the machine becomes compliant and reopens a regression' {
        $first = ConvertTo-RemediationQueue -Findings @($script:Finding) -Now $script:Now
        $fixed = [pscustomobject]@{
            hostname = 'PC-EXAMPLE-01'; software = 'Example Browser'; status = 'Compliant'; reason = 'MeetsGold'
            observedVersion = '2.0.0'; goldVersion = '2.0.0'; os = 'Windows 11'; online = 'true'
        }
        $confirmed = ConvertTo-RemediationQueue -Queue $first.Queue -Findings @($fixed) -Now $script:Now.AddHours(2)
        $confirmed.Queue.items[0].state | Should -Be 'confirmed'
        $reopened = ConvertTo-RemediationQueue -Queue $confirmed.Queue -Findings @($script:Finding) -Now $script:Now.AddHours(3)
        $reopened.Queue.items[0].state | Should -Be 'pending'
        $reopened.Queue.items[0].history[-1].note | Should -Be 'Reopened because the machine is no longer compliant.'
    }

    It 'keeps an abandoned item closed' {
        $first = ConvertTo-RemediationQueue -Findings @($script:Finding) -Now $script:Now
        $abandoned = ConvertTo-RemediationQueue -Queue $first.Queue -Findings @($script:Finding) -AbandonId @($first.Queue.items[0].id) -Now $script:Now.AddHours(1)
        $abandoned.Queue.items[0].state | Should -Be 'abandoned'
        $kept = ConvertTo-RemediationQueue -Queue $abandoned.Queue -Findings @($script:Finding) -Now $script:Now.AddHours(2)
        $kept.Queue.items[0].state | Should -Be 'abandoned'
        @($kept.EligibleSubmit).Count | Should -Be 0
    }

    It 'round-trips a one-item queue through JSON' {
        $first = ConvertTo-RemediationQueue -Findings @($script:Finding) -Now $script:Now
        $path = Join-Path $TestDrive 'queue.json'
        Write-GovernanceJsonFile -Value $first.Queue -LiteralPath $path
        $read = Read-GovernanceJsonFile -LiteralPath $path
        $again = ConvertTo-RemediationQueue -Queue $read -Findings @($script:Finding) -Now $script:Now.AddHours(1)
        @($again.Queue.items).Count | Should -Be 1
        $again.Queue.items[0].state | Should -Be 'pending'
    }
}

Describe 'Get-ComplianceDelta' {
    It 'labels the transition from the previous run' {
        $previous = @(
            [pscustomobject]@{ hostname = 'PC-EXAMPLE-01'; software = 'Example Browser'; status = 'Outdated' }
            [pscustomobject]@{ hostname = 'PC-EXAMPLE-02'; software = 'Example Browser'; status = 'Compliant' }
            [pscustomobject]@{ hostname = 'PC-EXAMPLE-03'; software = 'Example Browser'; status = 'Unknown' }
            [pscustomobject]@{ hostname = 'PC-EXAMPLE-04'; software = 'Example Browser'; status = 'Missing' }
        )
        $current = @(
            [pscustomobject]@{ hostname = 'PC-EXAMPLE-01'; software = 'Example Browser'; status = 'Compliant' }
            [pscustomobject]@{ hostname = 'PC-EXAMPLE-02'; software = 'Example Browser'; status = 'Outdated' }
            [pscustomobject]@{ hostname = 'PC-EXAMPLE-03'; software = 'Example Browser'; status = 'Outdated' }
            [pscustomobject]@{ hostname = 'PC-EXAMPLE-04'; software = 'Example Browser'; status = 'Unknown' }
            [pscustomobject]@{ hostname = 'PC-EXAMPLE-05'; software = 'Example Browser'; status = 'Missing' }
        )
        $delta = Get-ComplianceDelta -Current $current -Previous $previous
        ($delta | Where-Object { $_.hostname -eq 'PC-EXAMPLE-01' }).delta | Should -Be 'Improved'
        ($delta | Where-Object { $_.hostname -eq 'PC-EXAMPLE-02' }).delta | Should -Be 'Regressed'
        ($delta | Where-Object { $_.hostname -eq 'PC-EXAMPLE-03' }).delta | Should -Be 'Observed'
        ($delta | Where-Object { $_.hostname -eq 'PC-EXAMPLE-04' }).delta | Should -Be 'Inconclusive'
        ($delta | Where-Object { $_.hostname -eq 'PC-EXAMPLE-05' }).delta | Should -Be 'New'
    }
}

Describe 'Test-VersionCompliance.ps1' {
    BeforeAll {
        $script:VersionScript = Join-Path $PSScriptRoot '..\scripts\Test-VersionCompliance.ps1'
        $script:Rules = Join-Path $TestDrive 'rules.json'
        $script:Inventory = Join-Path $TestDrive 'inventory.csv'
        @{
            software = @(
                @{ name = 'Example Browser'; gold = '2.0.0'; tolerance = '0' }
            )
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $script:Rules -Encoding UTF8
        @(
            'hostname,software,version,os,online'
            'PC-EXAMPLE-01,Example Browser,1.0.0,Windows 11,true'
        ) | Set-Content -LiteralPath $script:Inventory -Encoding UTF8
    }

    It 'returns findings and does not write files when WhatIf is set' {
        $queue = Join-Path $TestDrive 'whatif-queue.json'
        $audit = Join-Path $TestDrive 'whatif-audit.jsonl'
        $rows = @(
            & $script:VersionScript -InputPath $script:Inventory -RulesPath $script:Rules -QueuePath $queue -AuditPath $audit -SubmitRemediation -WhatIf
        )
        $rows.Count | Should -Be 1
        $rows[0].status | Should -Be 'Outdated'
        $rows[0].delta | Should -Be 'New'
        Test-Path -LiteralPath $queue | Should -BeFalse
        Test-Path -LiteralPath $audit | Should -BeFalse
    }

    It 'persists the queue and reports an unchanged delta on the next run' {
        $queue = Join-Path $TestDrive 'persist-queue.json'
        $audit = Join-Path $TestDrive 'persist-audit.jsonl'
        $first = @(
            & $script:VersionScript -InputPath $script:Inventory -RulesPath $script:Rules -QueuePath $queue -AuditPath $audit
        )
        $first[0].delta | Should -Be 'New'
        $saved = Get-Content -LiteralPath $queue -Raw | ConvertFrom-Json
        @($saved.items)[0].state | Should -Be 'pending'
        @($saved.items)[0].deployed | Should -BeFalse

        $second = @(
            & $script:VersionScript -InputPath $script:Inventory -RulesPath $script:Rules -QueuePath $queue -AuditPath $audit -SubmitRemediation -WhatIf
        )
        $second[0].delta | Should -Be 'Unchanged'
        $stillPending = Get-Content -LiteralPath $queue -Raw | ConvertFrom-Json
        @($stillPending.items)[0].state | Should -Be 'pending'

        [void]@(
            & $script:VersionScript -InputPath $script:Inventory -RulesPath $script:Rules -QueuePath $queue -AuditPath $audit -SubmitRemediation
        )
        $sent = Get-Content -LiteralPath $queue -Raw | ConvertFrom-Json
        @($sent.items)[0].state | Should -Be 'sent'
        @($sent.items)[0].deployed | Should -BeFalse
        @(Get-Content -LiteralPath $audit | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count | Should -Be 2
    }
}
