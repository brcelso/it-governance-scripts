BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\EndpointGovernance.psm1') -Force
}

Describe 'Resolve-SoftwarePolicy' {
    It 'rejects a policy that is not an object' {
        { Resolve-SoftwarePolicy -Policy @('7-Zip') } | Should -Throw -ExpectedMessage '*JSON object*'
    }

    It 'rejects a rule without a name' {
        $policy = [pscustomobject]@{ allow = @([pscustomobject]@{ publisher = 'Example' }) }
        { Resolve-SoftwarePolicy -Policy $policy } | Should -Throw -ExpectedMessage '*missing a name*'
    }

    It 'loads the fictitious sample policy' {
        $path = Join-Path $PSScriptRoot '..\samples\software-policy.json'
        $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        $policy = Resolve-SoftwarePolicy -Policy $raw
        @($policy.allow).Count | Should -Be 4
        @($policy.block).Count | Should -Be 2
        @($policy.required).Count | Should -Be 1
    }
}

Describe 'Compare-SoftwareCompliance' {
    BeforeAll {
        $script:Policy = [pscustomobject]@{
            allow    = @(
                [pscustomobject]@{ name = '7-Zip'; publisher = 'Igor Pavlov'; minVersion = '23.0.0' }
                [pscustomobject]@{ name = 'Example Endpoint Agent'; publisher = 'Example Security'; minVersion = '5.0.0' }
            )
            block    = @(
                [pscustomobject]@{ name = '*Torrent*'; reason = 'Peer-to-peer file sharing is not approved.' }
                [pscustomobject]@{ name = 'Example Remote Tool'; reason = 'Remote access requires approval.' }
            )
            required = @(
                [pscustomobject]@{ name = 'Example Endpoint Agent'; publisher = 'Example Security'; minVersion = '5.0.0' }
            )
        }
    }

    It 'marks an allowed product as Compliant' {
        $installed = @(
            [pscustomobject]@{ ComputerName = 'PC-EXAMPLE-01'; DisplayName = '7-Zip'; DisplayVersion = '24.8'; Publisher = 'Igor Pavlov' }
        )
        $result = Compare-SoftwareCompliance -InstalledSoftware $installed -Policy $script:Policy
        $product = $result | Where-Object { $_.DisplayName -eq '7-Zip' }
        $product.Status | Should -Be 'Compliant'
        $product.Reason | Should -Be 'Allowed'
    }

    It 'marks a blocked wildcard as NonCompliant even when another rule would allow it' {
        $policy = [pscustomobject]@{
            allow = @([pscustomobject]@{ name = '*Torrent*'; publisher = '*' })
            block = @([pscustomobject]@{ name = '*Torrent*'; reason = 'Blocked tool.' })
        }
        $installed = @(
            [pscustomobject]@{ ComputerName = 'PC-EXAMPLE-01'; DisplayName = 'Nice Torrent Client'; DisplayVersion = '1.0'; Publisher = 'Fictional Apps' }
        )
        $result = Compare-SoftwareCompliance -InstalledSoftware $installed -Policy $policy
        $result[0].Status | Should -Be 'NonCompliant'
        $result[0].Reason | Should -Be 'Blocked'
    }

    It 'marks an older allowed version as NonCompliant' {
        $installed = @(
            [pscustomobject]@{ ComputerName = 'PC-EXAMPLE-02'; DisplayName = '7-Zip'; DisplayVersion = '19.0'; Publisher = 'Igor Pavlov' }
        )
        $result = Compare-SoftwareCompliance -InstalledSoftware $installed -Policy $script:Policy
        ($result | Where-Object { $_.DisplayName -eq '7-Zip' }).Reason | Should -Be 'BelowMinimumVersion'
    }

    It 'marks a product from another publisher as Unknown' {
        $installed = @(
            [pscustomobject]@{ ComputerName = 'PC-EXAMPLE-01'; DisplayName = '7-Zip'; DisplayVersion = '24.8'; Publisher = 'Someone Else' }
        )
        $result = Compare-SoftwareCompliance -InstalledSoftware $installed -Policy $script:Policy
        ($result | Where-Object { $_.DisplayName -eq '7-Zip' }).Status | Should -Be 'Unknown'
        ($result | Where-Object { $_.DisplayName -eq '7-Zip' }).Reason | Should -Be 'NotListed'
    }

    It 'reports required software that is not installed' {
        $installed = @(
            [pscustomobject]@{ ComputerName = 'PC-EXAMPLE-02'; DisplayName = '7-Zip'; DisplayVersion = '24.8'; Publisher = 'Igor Pavlov' }
        )
        $result = Compare-SoftwareCompliance -InstalledSoftware $installed -Policy $script:Policy
        $missing = $result | Where-Object { $_.Reason -eq 'RequiredMissing' }
        $missing.Status | Should -Be 'NonCompliant'
        $missing.DisplayName | Should -Be 'Example Endpoint Agent'
    }

    It 'treats required software that is absent from the allow list as Compliant when present' {
        $policy = [pscustomobject]@{
            required = @([pscustomobject]@{ name = 'Example Endpoint Agent'; publisher = 'Example Security'; minVersion = '5.0.0' })
        }
        $installed = @(
            [pscustomobject]@{ ComputerName = 'PC-EXAMPLE-01'; DisplayName = 'Example Endpoint Agent'; DisplayVersion = '5.4.1'; Publisher = 'Example Security' }
        )
        $result = Compare-SoftwareCompliance -InstalledSoftware $installed -Policy $policy
        $result[0].Status | Should -Be 'Compliant'
        $result[0].Reason | Should -Be 'RequiredPresent'
    }

    It 'does not invent a missing product when collection failed' {
        $installed = @(
            [pscustomobject]@{ ComputerName = 'PC-EXAMPLE-03'; DisplayName = ''; DisplayVersion = ''; Publisher = ''; CollectionError = 'access denied' }
        )
        $result = Compare-SoftwareCompliance -InstalledSoftware $installed -Policy $script:Policy
        @($result | Where-Object { $_.Reason -eq 'RequiredMissing' }).Count | Should -Be 0
        $result[0].Reason | Should -Be 'CollectionFailed'
    }

    It 'classifies the fictitious installed-software sample' {
        $policyPath = Join-Path $PSScriptRoot '..\samples\software-policy.json'
        $inventoryPath = Join-Path $PSScriptRoot '..\samples\example-output\installed-software.csv'
        $policy = Get-Content -LiteralPath $policyPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $installed = @(Import-Csv -LiteralPath $inventoryPath)
        $result = Compare-SoftwareCompliance -InstalledSoftware $installed -Policy $policy -ComputerName @('PC-EXAMPLE-01', 'PC-EXAMPLE-02')
        ($result | Where-Object { $_.ComputerName -eq 'PC-EXAMPLE-01' -and $_.DisplayName -eq 'Microsoft Edge' }).Status | Should -Be 'Compliant'
        ($result | Where-Object { $_.ComputerName -eq 'PC-EXAMPLE-01' -and $_.DisplayName -eq 'Nice Torrent Client' }).Reason | Should -Be 'Blocked'
        ($result | Where-Object { $_.ComputerName -eq 'PC-EXAMPLE-01' -and $_.DisplayName -eq 'Python 3.12.6' }).Status | Should -Be 'Unknown'
        ($result | Where-Object { $_.ComputerName -eq 'PC-EXAMPLE-02' -and $_.DisplayName -eq '7-Zip' }).Reason | Should -Be 'BelowMinimumVersion'
        ($result | Where-Object { $_.ComputerName -eq 'PC-EXAMPLE-02' -and $_.Reason -eq 'RequiredMissing' }).DisplayName | Should -Be 'Example Endpoint Agent'
        @($result | Where-Object { $_.ComputerName -eq 'PC-EXAMPLE-01' -and $_.Reason -eq 'RequiredMissing' }).Count | Should -Be 0
    }
}

Describe 'Get-AdminApprovalStatus' {
    It 'returns Unknown when no list was supplied' {
        Get-AdminApprovalStatus -MemberName 'EXAMPLE\user01' -ApprovedAccounts $null | Should -Be 'Unknown'
    }

    It 'returns Unapproved for an empty list' {
        Get-AdminApprovalStatus -MemberName 'EXAMPLE\user01' -ApprovedAccounts @() | Should -Be 'Unapproved'
    }

    It 'matches a wildcard and a SID without case sensitivity' {
        $approved = @('EXAMPLE\Endpoint-Admins', 'S-1-5-21-2000000000-2000000000-2000000000-1001')
        Get-AdminApprovalStatus -MemberName 'example\endpoint-admins' -ApprovedAccounts $approved | Should -Be 'Approved'
        Get-AdminApprovalStatus -MemberName 'PC-EXAMPLE-01\LocalAdmin' -Sid 'S-1-5-21-2000000000-2000000000-2000000000-1001' -ApprovedAccounts @('S-1-5-21-2000000000-2000000000-2000000000-1001') | Should -Be 'Approved'
        Get-AdminApprovalStatus -MemberName 'PC-EXAMPLE-01\user01' -ApprovedAccounts $approved | Should -Be 'Unapproved'
    }
}

Describe 'ConvertTo-GovernanceHtml' {
    It 'encodes untrusted cell text' {
        $html = ConvertTo-GovernanceHtml -Title 'Report' -Sections @(
            [pscustomobject]@{
                Title   = 'Rows'
                Columns = @('Status', 'Detail')
                Rows    = @([pscustomobject]@{ Status = 'NonCompliant'; Detail = '<script>alert(1)</script>' })
            }
        )
        $html | Should -Match '&lt;script&gt;'
        $html | Should -Not -Match '<script>alert'
        $html | Should -Match 'status-bad'
    }
}
