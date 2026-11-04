# Shared formatting and file helpers. No remote calls.

function Get-ObjectProperty {
    param(
        $Object,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in @($Object.Keys)) {
            if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $Object[$key]
            }
        }
        return $null
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function ConvertTo-ObjectArray {
    param($Value)

    $list = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Value) {
        return ,$list.ToArray()
    }

    if ($Value -is [string] -or -not ($Value -is [System.Collections.IEnumerable])) {
        [void]$list.Add($Value)
        return ,$list.ToArray()
    }

    foreach ($item in $Value) {
        [void]$list.Add($item)
    }
    return ,$list.ToArray()
}

function ConvertTo-GovernanceObject {
    param(
        [Parameter(Mandatory = $true)]
        $Properties
    )

    $object = New-Object psobject
    foreach ($key in @($Properties.Keys)) {
        $object | Add-Member -NotePropertyName ([string]$key) -NotePropertyValue $Properties[$key] -Force
    }
    return $object
}

function Format-GovernanceSingleLine {
    [CmdletBinding()]
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }
    return ([regex]::Replace($Text, '\s+', ' ')).Trim()
}

function Format-GovernanceUtc {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$Value
    )

    $utc = $Value
    if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) {
        $utc = [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
    }
    else {
        $utc = $Value.ToUniversalTime()
    }
    return $utc.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Format-GovernanceTimestamp {
    [CmdletBinding()]
    param($Value)

    if ($null -eq $Value) {
        return ''
    }

    $date = $null
    if ($Value -is [datetime]) {
        $date = [datetime]$Value
    }
    else {
        $text = Format-GovernanceSingleLine -Text ([string]$Value)
        if ([string]::IsNullOrWhiteSpace($text)) {
            return ''
        }
        $parsed = [datetime]::MinValue
        $styles = [System.Globalization.DateTimeStyles]::RoundtripKind
        $culture = [System.Globalization.CultureInfo]::InvariantCulture
        if ([datetime]::TryParse($text, $culture, $styles, [ref]$parsed)) {
            $date = $parsed
        }
        else {
            return $text
        }
    }

    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    if ($date.Kind -eq [System.DateTimeKind]::Utc) {
        return $date.ToString('yyyy-MM-ddTHH:mm:ssZ', $culture)
    }
    return $date.ToString('yyyy-MM-ddTHH:mm:ssK', $culture)
}

function Format-GovernanceDecimal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [double]$Value,
        [int]$Digits = 1
    )

    $format = '0'
    if ($Digits -gt 0) {
        $format = '0.' + ('0' * $Digits)
    }
    return $Value.ToString($format, [System.Globalization.CultureInfo]::InvariantCulture)
}

function Test-LocalComputerName {
    [CmdletBinding()]
    param([AllowNull()][string]$ComputerName)

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        return $true
    }

    $names = New-Object System.Collections.Generic.List[string]
    foreach ($name in @('.', 'localhost', '127.0.0.1', '::1')) {
        [void]$names.Add($name)
    }
    if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) {
        [void]$names.Add($env:COMPUTERNAME)
    }
    try {
        $hostName = [System.Net.Dns]::GetHostName()
        if (-not [string]::IsNullOrWhiteSpace($hostName)) {
            [void]$names.Add($hostName)
        }
    }
    catch {
        Write-Verbose 'Local host name was not available for computer name comparison.'
    }

    $target = $ComputerName.Trim()
    foreach ($name in $names) {
        if ([string]::Equals($name, $target, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function ConvertTo-JsonLiteral {
    param([AllowNull()][string]$Text)

    if ($null -eq $Text) {
        return 'null'
    }

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    foreach ($char in $Text.ToCharArray()) {
        $code = [int]$char
        if ($code -eq 34) {
            [void]$builder.Append('\"')
        }
        elseif ($code -eq 92) {
            [void]$builder.Append('\\')
        }
        elseif ($code -eq 8) {
            [void]$builder.Append('\b')
        }
        elseif ($code -eq 9) {
            [void]$builder.Append('\t')
        }
        elseif ($code -eq 10) {
            [void]$builder.Append('\n')
        }
        elseif ($code -eq 12) {
            [void]$builder.Append('\f')
        }
        elseif ($code -eq 13) {
            [void]$builder.Append('\r')
        }
        elseif ($code -lt 32) {
            [void]$builder.Append(('\u{0:x4}' -f $code))
        }
        else {
            [void]$builder.Append($char)
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Test-JsonNumber {
    param($Value)

    return (
        $Value -is [byte] -or
        $Value -is [int16] -or
        $Value -is [int32] -or
        $Value -is [int64] -or
        $Value -is [uint16] -or
        $Value -is [uint32] -or
        $Value -is [uint64] -or
        $Value -is [decimal] -or
        $Value -is [double] -or
        $Value -is [single]
    )
}

function ConvertTo-GovernanceJsonValue {
    param(
        $Value,
        [int]$Depth,
        [int]$Level,
        [bool]$Compress
    )

    if ($Depth -lt 0) {
        return 'null'
    }
    if ($null -eq $Value) {
        return 'null'
    }
    if ($Value -is [string]) {
        return (ConvertTo-JsonLiteral -Text $Value)
    }
    if ($Value -is [bool]) {
        if ($Value) { return 'true' }
        return 'false'
    }
    if ($Value -is [datetime]) {
        return (ConvertTo-JsonLiteral -Text (Format-GovernanceUtc -Value $Value))
    }
    if (Test-JsonNumber -Value $Value) {
        return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [enum]) {
        return (ConvertTo-JsonLiteral -Text ([string]$Value))
    }

    $indent = ''
    $nextIndent = ''
    $newline = ''
    $separator = ','
    $nameSeparator = ':'
    if (-not $Compress) {
        $indent = '  ' * $Level
        $nextIndent = '  ' * ($Level + 1)
        $newline = "`n"
        $separator = ",`n"
        $nameSeparator = ': '
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($key in @($Value.Keys)) {
            $rendered = ConvertTo-GovernanceJsonValue -Value $Value[$key] -Depth ($Depth - 1) -Level ($Level + 1) -Compress $Compress
            [void]$parts.Add(('{0}{1}{2}{3}' -f $nextIndent, (ConvertTo-JsonLiteral -Text ([string]$key)), $nameSeparator, $rendered))
        }
        if ($parts.Count -eq 0) { return '{}' }
        if ($Compress) { return '{' + (($parts -join $separator).Trim()) + '}' }
        return '{' + $newline + ($parts -join $separator) + $newline + $indent + '}'
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($item in $Value) {
            $rendered = ConvertTo-GovernanceJsonValue -Value $item -Depth ($Depth - 1) -Level ($Level + 1) -Compress $Compress
            [void]$parts.Add($nextIndent + $rendered)
        }
        if ($parts.Count -eq 0) { return '[]' }
        if ($Compress) { return '[' + (($parts -join $separator).Trim()) + ']' }
        return '[' + $newline + ($parts -join $separator) + $newline + $indent + ']'
    }

    $parts = New-Object System.Collections.Generic.List[string]
    $wroteProperty = $false
    foreach ($property in @($Value.PSObject.Properties)) {
        if ($property.MemberType -ne [System.Management.Automation.PSMemberTypes]::NoteProperty) {
            continue
        }
        $wroteProperty = $true
        $rendered = ConvertTo-GovernanceJsonValue -Value $property.Value -Depth ($Depth - 1) -Level ($Level + 1) -Compress $Compress
        [void]$parts.Add(('{0}{1}{2}{3}' -f $nextIndent, (ConvertTo-JsonLiteral -Text $property.Name), $nameSeparator, $rendered))
    }
    if (-not $wroteProperty) {
        return (ConvertTo-JsonLiteral -Text ([string]$Value))
    }
    if ($parts.Count -eq 0) { return '{}' }
    if ($Compress) { return '{' + (($parts -join $separator).Trim()) + '}' }
    return '{' + $newline + ($parts -join $separator) + $newline + $indent + '}'
}

function ConvertTo-GovernanceJson {
    [CmdletBinding()]
    param(
        $Value,
        [int]$Depth = 8,
        [switch]$Compress
    )

    return ConvertTo-GovernanceJsonValue -Value $Value -Depth $Depth -Level 0 -Compress ([bool]$Compress)
}

function Initialize-GovernanceDirectory {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $parent = Split-Path -Parent $LiteralPath
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [void][System.IO.Directory]::CreateDirectory($parent)
    }
}

function Write-GovernanceJsonFile {
    [CmdletBinding()]
    param(
        $Value,
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,
        [switch]$Compress
    )

    $json = ConvertTo-GovernanceJson -Value $Value -Compress:$Compress
    if (-not $json.EndsWith("`n")) {
        $json += "`n"
    }
    Initialize-GovernanceDirectory -LiteralPath $LiteralPath
    $encoding = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($LiteralPath, $json, $encoding)
}

function Add-GovernanceJsonLine {
    [CmdletBinding()]
    param(
        $Value,
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    $line = (ConvertTo-GovernanceJson -Value $Value -Compress) + "`n"
    Initialize-GovernanceDirectory -LiteralPath $LiteralPath
    $encoding = New-Object System.Text.UTF8Encoding $false
    if (Test-Path -LiteralPath $LiteralPath) {
        [System.IO.File]::AppendAllText($LiteralPath, $line, $encoding)
    }
    else {
        [System.IO.File]::WriteAllText($LiteralPath, $line, $encoding)
    }
}

function Read-GovernanceJsonFile {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        return $null
    }
    $raw = [System.IO.File]::ReadAllText($LiteralPath)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }
    return ($raw | ConvertFrom-Json)
}

function Read-GovernanceJsonlFile {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $rows = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        return ,$rows.ToArray()
    }
    foreach ($line in [System.IO.File]::ReadAllLines($LiteralPath)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        [void]$rows.Add(($line | ConvertFrom-Json))
    }
    return ,$rows.ToArray()
}

function Export-GovernanceCsv {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object[]]$Data,
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    if ($null -eq $Data) {
        $Data = @()
    }
    Initialize-GovernanceDirectory -LiteralPath $LiteralPath
    $lines = @($Data | ConvertTo-Csv -NoTypeInformation)
    $encoding = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllLines($LiteralPath, $lines, $encoding)
}

function ConvertTo-HtmlText {
    param([AllowNull()][string]$Text)

    if ($null -eq $Text) {
        return ''
    }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-StatusCssClass {
    param(
        [AllowNull()][string]$Column,
        [AllowNull()][string]$Value
    )

    if ($Column -ne 'Status' -and $Column -ne 'ApprovalStatus' -and $Column -ne 'status') {
        return ''
    }
    switch ($Value) {
        'Compliant' { return 'status-ok' }
        'Approved' { return 'status-ok' }
        'NonCompliant' { return 'status-bad' }
        'Unapproved' { return 'status-bad' }
        'Outdated' { return 'status-bad' }
        'Missing' { return 'status-bad' }
        'Unknown' { return 'status-review' }
        default { return '' }
    }
}

function ConvertTo-GovernanceHtml {
    <#
    .SYNOPSIS
        Builds a self-contained HTML report.
    .DESCRIPTION
        Renders summary highlights and tables. Values are HTML-encoded.
        The document does not reference external sites. The function returns
        a string and does not write a file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        [string]$Subtitle = '',
        [AllowEmptyCollection()]
        [object[]]$Highlights = @(),
        [AllowEmptyCollection()]
        [object[]]$Sections = @(),
        [string]$GeneratedAt = '',
        [int]$MaxRows = 1000
    )

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.AppendLine('<!DOCTYPE html>')
    [void]$builder.AppendLine('<html lang="en">')
    [void]$builder.AppendLine('<head>')
    [void]$builder.AppendLine('<meta charset="utf-8">')
    [void]$builder.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$builder.Append('<title>')
    [void]$builder.Append((ConvertTo-HtmlText -Text $Title))
    [void]$builder.AppendLine('</title>')
    [void]$builder.AppendLine('<style>')
    [void]$builder.AppendLine('body{font-family:Segoe UI,Calibri,sans-serif;margin:24px;color:#1c1c1c;background:#fff;}')
    [void]$builder.AppendLine('h1{font-size:1.6rem;margin:0 0 .25rem;} h2{font-size:1.15rem;margin:1.4rem 0 .4rem;}')
    [void]$builder.AppendLine('.subtitle,.note,footer{color:#444;} .note{font-size:.9rem;margin:0 0 .6rem;}')
    [void]$builder.AppendLine('.highlights{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0 8px;}')
    [void]$builder.AppendLine('.highlight{border:1px solid #d5d5d5;border-radius:6px;padding:10px 14px;min-width:140px;}')
    [void]$builder.AppendLine('.highlight .label{display:block;font-size:.78rem;color:#555;} .highlight .value{font-size:1.25rem;font-weight:650;}')
    [void]$builder.AppendLine('table{border-collapse:collapse;width:100%;margin:0 0 1.2rem;font-size:.92rem;}')
    [void]$builder.AppendLine('th,td{border:1px solid #d8d8d8;padding:6px 8px;text-align:left;vertical-align:top;}')
    [void]$builder.AppendLine('th{background:#f3f5f7;} tr:nth-child(even){background:#fafafa;}')
    [void]$builder.AppendLine('.status-ok{color:#0d6b32;font-weight:650;} .status-bad{color:#a11;font-weight:650;} .status-review{color:#8a5a00;font-weight:650;}')
    [void]$builder.AppendLine('footer{margin-top:8px;font-size:.85rem;}')
    [void]$builder.AppendLine('</style>')
    [void]$builder.AppendLine('</head>')
    [void]$builder.AppendLine('<body>')
    [void]$builder.Append('<h1>')
    [void]$builder.Append((ConvertTo-HtmlText -Text $Title))
    [void]$builder.AppendLine('</h1>')
    if (-not [string]::IsNullOrWhiteSpace($Subtitle)) {
        [void]$builder.Append('<p class="subtitle">')
        [void]$builder.Append((ConvertTo-HtmlText -Text $Subtitle))
        [void]$builder.AppendLine('</p>')
    }
    if (-not [string]::IsNullOrWhiteSpace($GeneratedAt)) {
        [void]$builder.Append('<p class="note">Generated ')
        [void]$builder.Append((ConvertTo-HtmlText -Text $GeneratedAt))
        [void]$builder.AppendLine('</p>')
    }

    $highlightItems = (ConvertTo-ObjectArray -Value $Highlights)
    if ($highlightItems.Count -gt 0) {
        [void]$builder.AppendLine('<div class="highlights">')
        foreach ($item in $highlightItems) {
            if ($null -eq $item) { continue }
            $label = [string](Get-ObjectProperty -Object $item -Name 'Label')
            $value = [string](Get-ObjectProperty -Object $item -Name 'Value')
            [void]$builder.Append('<div class="highlight"><span class="label">')
            [void]$builder.Append((ConvertTo-HtmlText -Text $label))
            [void]$builder.Append('</span><span class="value">')
            [void]$builder.Append((ConvertTo-HtmlText -Text $value))
            [void]$builder.AppendLine('</span></div>')
        }
        [void]$builder.AppendLine('</div>')
    }

    foreach ($section in (ConvertTo-ObjectArray -Value $Sections)) {
        if ($null -eq $section) { continue }
        $sectionTitle = [string](Get-ObjectProperty -Object $section -Name 'Title')
        $note = [string](Get-ObjectProperty -Object $section -Name 'Note')
        $columns = (ConvertTo-ObjectArray -Value (Get-ObjectProperty -Object $section -Name 'Columns'))
        $rows = (ConvertTo-ObjectArray -Value (Get-ObjectProperty -Object $section -Name 'Rows'))
        [void]$builder.Append('<h2>')
        [void]$builder.Append((ConvertTo-HtmlText -Text $sectionTitle))
        [void]$builder.AppendLine('</h2>')
        if (-not [string]::IsNullOrWhiteSpace($note)) {
            [void]$builder.Append('<p class="note">')
            [void]$builder.Append((ConvertTo-HtmlText -Text $note))
            [void]$builder.AppendLine('</p>')
        }

        $shown = $rows
        $truncated = $false
        if ($MaxRows -gt 0 -and $rows.Count -gt $MaxRows) {
            $shown = @($rows | Select-Object -First $MaxRows)
            $truncated = $true
        }
        if ($truncated) {
            [void]$builder.Append('<p class="note">Showing the first ')
            [void]$builder.Append((ConvertTo-HtmlText -Text ([string]$MaxRows)))
            [void]$builder.Append(' of ')
            [void]$builder.Append((ConvertTo-HtmlText -Text ([string]$rows.Count)))
            [void]$builder.AppendLine(' rows. The CSV export keeps the full set.</p>')
        }

        [void]$builder.AppendLine('<table>')
        [void]$builder.Append('<thead><tr>')
        foreach ($column in $columns) {
            [void]$builder.Append('<th>')
            [void]$builder.Append((ConvertTo-HtmlText -Text ([string]$column)))
            [void]$builder.Append('</th>')
        }
        [void]$builder.AppendLine('</tr></thead>')
        [void]$builder.AppendLine('<tbody>')
        if ($shown.Count -eq 0) {
            [void]$builder.Append('<tr><td colspan="')
            $span = $columns.Count
            if ($span -lt 1) { $span = 1 }
            [void]$builder.Append([string]$span)
            [void]$builder.AppendLine('">No rows.</td></tr>')
        }
        foreach ($row in $shown) {
            if ($null -eq $row) { continue }
            [void]$builder.Append('<tr>')
            foreach ($column in $columns) {
                $columnName = [string]$column
                $cell = [string](Get-ObjectProperty -Object $row -Name $columnName)
                $class = Get-StatusCssClass -Column $columnName -Value $cell
                if ([string]::IsNullOrWhiteSpace($class)) {
                    [void]$builder.Append('<td>')
                }
                else {
                    [void]$builder.Append('<td class="')
                    [void]$builder.Append($class)
                    [void]$builder.Append('">')
                }
                [void]$builder.Append((ConvertTo-HtmlText -Text $cell))
                [void]$builder.Append('</td>')
            }
            [void]$builder.AppendLine('</tr>')
        }
        [void]$builder.AppendLine('</tbody></table>')
    }

    [void]$builder.AppendLine('<footer>Generated locally. Read-only endpoint governance evidence. Review the rows before sharing them.</footer>')
    [void]$builder.AppendLine('</body>')
    [void]$builder.AppendLine('</html>')
    return $builder.ToString()
}
