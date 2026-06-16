param(
    [string]$IngestUrl = "",
    [string]$BaseUrl = "https://192.168.1.35",
    [string]$StatePath = "C:\ProgramData\RdegonSIEM\collector-state.json",
    [string]$LogPath = "C:\ProgramData\RdegonSIEM\collector.log",
    [int]$BatchSize = 80,
    [int]$MaxSendBatch = 20,
    [ValidateSet("ports", "paths")]
    [string]$RoutingMode = "ports",
    [string]$SharedSecret = "",
    [switch]$InstallTask,
    [switch]$IncludeXml,
    [string]$TaskName = "RdegonSIEMCollector",
    [string[]]$Channels = @(
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-PowerShell/Operational",
        "Windows PowerShell",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-WMI-Activity/Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-WinRM/Operational"
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Initialize-Tls {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

function Ensure-StateDirectory {
    $dir = Split-Path -Parent $StatePath
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

function Write-DiagnosticLog([string]$Message, [string]$Level = "INFO") {
    try {
        Ensure-StateDirectory
        $timestamp = (Get-Date).ToUniversalTime().ToString("o")
        Add-Content -Path $LogPath -Encoding UTF8 -Value ("[{0}] [{1}] {2}" -f $timestamp, $Level, $Message)
    } catch {
    }
}

function Sanitize-Text([string]$Value) {
    if ($null -eq $Value) {
        return ""
    }
    $builder = [System.Text.StringBuilder]::new()
    for ($index = 0; $index -lt $Value.Length; $index++) {
        $char = $Value[$index]
        $code = [int][char]$char
        if ([char]::IsHighSurrogate($char)) {
            if ($index + 1 -lt $Value.Length -and [char]::IsLowSurrogate($Value[$index + 1])) {
                [void]$builder.Append($char)
                $index += 1
                [void]$builder.Append($Value[$index])
            }
            continue
        }
        if ([char]::IsLowSurrogate($char)) {
            continue
        }
        if ($code -lt 32 -and $code -notin @(9, 10, 13)) {
            continue
        }
        [void]$builder.Append($char)
    }
    return $builder.ToString()
}

function Sanitize-Value($Value) {
    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [string]) {
        return (Sanitize-Text $Value)
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $table = @{}
        foreach ($key in $Value.Keys) {
            $table[[string]$key] = Sanitize-Value $Value[$key]
        }
        return $table
    }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = @()
        foreach ($item in $Value) {
            $items += Sanitize-Value $item
        }
        return $items
    }
    return $Value
}

function Load-State {
    if (-not (Test-Path $StatePath)) {
        return @{}
    }
    try {
        $content = Get-Content -Raw -Path $StatePath
        if (-not $content) {
            return @{}
        }
        $payload = $content | ConvertFrom-Json
        $table = @{}
        if ($payload -and $payload.PSObject -and $payload.PSObject.Properties) {
            foreach ($property in $payload.PSObject.Properties) {
                $table[[string]$property.Name] = $property.Value
            }
        }
        return $table
    } catch {
        Write-DiagnosticLog -Level "WARN" -Message ("Failed to load state file {0}: {1}" -f $StatePath, $_.Exception.Message)
        return @{}
    }
}

function Save-State([hashtable]$State) {
    Ensure-StateDirectory
    ($State | ConvertTo-Json -Depth 6) | Set-Content -Encoding UTF8 -Path $StatePath
}

function Get-XmlPropertyValue($Node, [string]$PropertyName) {
    if (-not $Node) {
        return $null
    }
    $prop = $Node.PSObject.Properties[$PropertyName]
    if ($prop) {
        return $prop.Value
    }
    return $null
}

function Get-XmlNodeText($Node) {
    if (-not $Node) {
        return ""
    }
    $nodeText = Get-XmlPropertyValue $Node "#text"
    if ($nodeText) {
        return [string]$nodeText
    }
    if ($Node.PSObject.Properties["InnerText"] -and $Node.InnerText) {
        return [string]$Node.InnerText
    }
    return [string]$Node
}

function Get-XmlElementChildren($Node) {
    if (-not $Node) {
        return @()
    }
    $children = Get-XmlPropertyValue $Node "ChildNodes"
    if (-not $children) {
        return @()
    }
    $items = @()
    foreach ($child in @($children)) {
        if (-not $child) {
            continue
        }
        $nodeType = Get-XmlPropertyValue $child "NodeType"
        if ($nodeType -and $nodeType -ne [System.Xml.XmlNodeType]::Element) {
            continue
        }
        $items += $child
    }
    return $items
}

function Convert-EventData([xml]$XmlEvent) {
    $payload = @{}
    $eventNode = Get-XmlPropertyValue $XmlEvent "Event"
    $eventDataNode = Get-XmlPropertyValue $eventNode "EventData"
    $eventDataItems = @()
    if ($eventDataNode) {
        $eventDataItems = @(Get-XmlPropertyValue $eventDataNode "Data")
    }
    if ($eventDataItems.Count -gt 0) {
        $index = 0
        foreach ($node in $eventDataItems) {
            if (-not $node) {
                $index += 1
                continue
            }
            $nodeType = Get-XmlPropertyValue $node "NodeType"
            if ($nodeType -and $nodeType -ne [System.Xml.XmlNodeType]::Element) {
                $index += 1
                continue
            }
            $name = [string](Get-XmlPropertyValue $node "Name")
            if (-not $name) {
                $name = [string](Get-XmlPropertyValue $node "LocalName")
            }
            if (-not $name) {
                $name = "data_$index"
            }
            $payload[$name] = Get-XmlNodeText $node
            $index += 1
        }
    }

    $userDataNode = Get-XmlPropertyValue $eventNode "UserData"
    $userDataItems = @()
    if ($userDataNode) {
        $userDataItems = @(Get-XmlPropertyValue $userDataNode "ChildNodes")
    }
    if ($userDataItems.Count -gt 0) {
        foreach ($node in $userDataItems) {
            if (-not $node) {
                continue
            }
            foreach ($child in @(Get-XmlElementChildren $node)) {
                $localName = [string](Get-XmlPropertyValue $child "LocalName")
                if (-not $localName) {
                    continue
                }
                $payload[$localName] = [string](Get-XmlPropertyValue $child "InnerText")
            }
        }
    }
    return $payload
}

function Get-NewEvents([string]$Channel, [long]$LastRecordId) {
    try {
        $events = Get-WinEvent -LogName $Channel -MaxEvents $BatchSize -ErrorAction Stop
    } catch {
        Write-DiagnosticLog -Level "WARN" -Message ("Skipping unreadable or unavailable channel {0}: {1}" -f $Channel, $_.Exception.Message)
        Write-Warning ("Skipping unreadable or unavailable channel {0}: {1}" -f $Channel, $_.Exception.Message)
        return @()
    }
    if (-not $events) {
        return @()
    }
    $fresh = $events | Where-Object { $_.RecordId -gt $LastRecordId } | Sort-Object RecordId
    return @($fresh)
}

function Get-EventDisplayValue($EventRecord, [string]$PropertyName) {
    try {
        return (Sanitize-Text ([string]($EventRecord.$PropertyName)))
    } catch {
        Write-DiagnosticLog -Level "WARN" -Message ("Failed to read {0} for {1}/{2}/{3}: {4}" -f $PropertyName, $EventRecord.LogName, $EventRecord.ProviderName, $EventRecord.RecordId, $_.Exception.Message)
        return ""
    }
}

function Get-EventKeywords($EventRecord) {
    try {
        if ($EventRecord.KeywordsDisplayNames) {
            return @($EventRecord.KeywordsDisplayNames | Where-Object { $_ } | ForEach-Object { Sanitize-Text ([string]$_) })
        }
    } catch {
        Write-DiagnosticLog -Level "WARN" -Message ("Failed to read KeywordsDisplayNames for {0}/{1}/{2}: {3}" -f $EventRecord.LogName, $EventRecord.ProviderName, $EventRecord.RecordId, $_.Exception.Message)
    }
    return @()
}

function Convert-ToPayload($EventRecord) {
    $xmlString = $EventRecord.ToXml()
    $xml = [xml]$xmlString
    $eventNode = Get-XmlPropertyValue $xml "Event"
    $system = Get-XmlPropertyValue $eventNode "System"
    $eventData = Convert-EventData $xml
    $execution = Get-XmlPropertyValue $system "Execution"
    $keywords = @(Get-EventKeywords $EventRecord)
    $computer = [string](Get-XmlPropertyValue $system "Computer")
    $eventRecordId = [string](Get-XmlPropertyValue $system "EventRecordID")
    $processId = ""
    $threadId = ""
    if ($execution) {
        $processId = [string](Get-XmlPropertyValue $execution "ProcessID")
        $threadId = [string](Get-XmlPropertyValue $execution "ThreadID")
    }
    $payload = @{
        source_type = "windows_event_json"
        collector = "powershell"
        source = $env:COMPUTERNAME
        host = @{ name = $env:COMPUTERNAME }
        computer_name = $EventRecord.MachineName
        channel = [string]$EventRecord.LogName
        provider = [string]$EventRecord.ProviderName
        event_id = [int]$EventRecord.Id
        event_code = [string]$EventRecord.Id
        record_id = [int64]$EventRecord.RecordId
        level = Get-EventDisplayValue -EventRecord $EventRecord -PropertyName "LevelDisplayName"
        task = Get-EventDisplayValue -EventRecord $EventRecord -PropertyName "TaskDisplayName"
        opcode = Get-EventDisplayValue -EventRecord $EventRecord -PropertyName "OpcodeDisplayName"
        keywords = [string]::Join(",", @($keywords))
        time_created = $EventRecord.TimeCreated.ToUniversalTime().ToString("o")
        message = Get-EventDisplayValue -EventRecord $EventRecord -PropertyName "Message"
        event = @{
            provider = [string]$EventRecord.ProviderName
            id = [string]$EventRecord.Id
            code = [string]$EventRecord.Id
            type = "windows_event"
        }
        windows = @{
            system = @{
                computer = $computer
                event_record_id = $eventRecordId
                execution = @{
                    process_id = $processId
                    thread_id = $threadId
                }
            }
            event_data = $eventData
        }
    }
    if ($IncludeXml) {
        $payload.windows.xml = $xmlString
    }
    return (Sanitize-Value $payload)
}

function Normalize-BaseUrl([string]$Url) {
    return ([string]$Url).TrimEnd("/")
}

function Join-UrlPath([string]$Base, [string]$Path) {
    $normalizedBase = Normalize-BaseUrl $Base
    $normalizedPath = "/" + ([string]$Path).TrimStart("/")
    return "$normalizedBase$normalizedPath"
}

function Get-IngestUrlForChannel([string]$Channel) {
    if ($IngestUrl) {
        return (Normalize-IngestUrl $IngestUrl)
    }
    if ($RoutingMode -eq "paths") {
        switch ($Channel) {
            "Security" { return (Join-UrlPath $BaseUrl "/ingest/windows/security") }
            "Microsoft-Windows-Sysmon/Operational" { return (Join-UrlPath $BaseUrl "/ingest/windows/sysmon") }
            "Microsoft-Windows-PowerShell/Operational" { return (Join-UrlPath $BaseUrl "/ingest/windows/powershell") }
            "Windows PowerShell" { return (Join-UrlPath $BaseUrl "/ingest/windows/powershell") }
            default { return (Join-UrlPath $BaseUrl "/ingest/windows/base") }
        }
    }
    switch ($Channel) {
        "Security" { return "$BaseUrl`:9441/" }
        "Microsoft-Windows-Sysmon/Operational" { return "$BaseUrl`:9442/" }
        "Microsoft-Windows-PowerShell/Operational" { return "$BaseUrl`:9443/" }
        "Windows PowerShell" { return "$BaseUrl`:9443/" }
        default { return "$BaseUrl`:9440/" }
    }
}

function Normalize-IngestUrl([string]$Url) {
    if (-not $Url) {
        return $Url
    }
    try {
        $uri = [Uri]$Url
        if ($uri.Port -ge 9440 -and $uri.Port -le 9446) {
            return ("{0}://{1}:{2}/" -f $uri.Scheme, $uri.Host, $uri.Port)
        }
    } catch {
    }
    return $Url
}

function Send-Batch([array]$Batch, [string]$TargetUrl) {
    if (-not $Batch.Count) {
        return $null
    }
    $sliceSize = [Math]::Max(1, [Math]::Min($MaxSendBatch, $Batch.Count))
    $lastResponse = $null
    $headers = @{}
    if ($SharedSecret) {
        $headers["x-rdegon-ingest-secret"] = $SharedSecret
    }
    for ($offset = 0; $offset -lt $Batch.Count; $offset += $sliceSize) {
        $slice = @($Batch[$offset..([Math]::Min($offset + $sliceSize - 1, $Batch.Count - 1))])
        $json = $slice | ConvertTo-Json -Depth 10 -Compress
        try {
            $lastResponse = Invoke-RestMethod -Method Post -Uri $TargetUrl -ContentType "application/json" -Headers $headers -Body $json
        } catch {
            $responseText = $_.Exception.Message
            if (($responseText -match "413" -or $responseText -match "400") -and $slice.Count -gt 1) {
                $midpoint = [Math]::Floor($slice.Count / 2)
                $left = @($slice[0..([Math]::Max(0, $midpoint - 1))])
                $right = @($slice[$midpoint..($slice.Count - 1)])
                $lastResponse = Send-Batch -Batch $left -TargetUrl $TargetUrl
                $lastResponse = Send-Batch -Batch $right -TargetUrl $TargetUrl
                continue
            }
            if ($responseText -match "400" -and $slice.Count -eq 1) {
                $badEvent = $slice[0]
                $badChannel = [string]($badEvent.channel)
                $badProvider = [string]($badEvent.provider)
                $badRecordId = [string]($badEvent.record_id)
                $badEventId = [string]($badEvent.event_id)
                Write-DiagnosticLog -Level "WARN" -Message ("Skipping rejected event {0}/{1}/{2}/{3} to {4}: {5}" -f $badChannel, $badProvider, $badEventId, $badRecordId, $TargetUrl, $responseText)
                continue
            }
            throw
        }
    }
    return $lastResponse
}

function Install-CollectorTask {
    $quotedScript = '"' + $PSCommandPath + '"'
    $taskArgument = "-NoProfile -ExecutionPolicy Bypass -File $quotedScript -BaseUrl `"$BaseUrl`" -RoutingMode `"$RoutingMode`""
    if ($IngestUrl) {
        $taskArgument = "-NoProfile -ExecutionPolicy Bypass -File $quotedScript -IngestUrl `"$IngestUrl`" -RoutingMode `"$RoutingMode`""
    }
    if ($StatePath) {
        $taskArgument += " -StatePath `"$StatePath`""
    }
    if ($LogPath) {
        $taskArgument += " -LogPath `"$LogPath`""
    }
    if ($BatchSize -gt 0) {
        $taskArgument += " -BatchSize $BatchSize"
    }
    if ($MaxSendBatch -gt 0) {
        $taskArgument += " -MaxSendBatch $MaxSendBatch"
    }
    if ($SharedSecret) {
        $taskArgument += " -SharedSecret `"$SharedSecret`""
    }
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $taskArgument
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Write-Host "Scheduled task installed:" $TaskName
}

if ($InstallTask) {
    Install-CollectorTask
    exit 0
}

Initialize-Tls
$state = Load-State
$batch = @()
try {
    foreach ($channel in $Channels) {
        $lastRecordId = 0
        if ($state.ContainsKey($channel)) {
            $lastRecordId = [long]$state[$channel]
        }
        $events = Get-NewEvents -Channel $channel -LastRecordId $lastRecordId
        $channelBatch = @()
        $channelLastRecordId = $lastRecordId
        foreach ($event in $events) {
            try {
                $channelBatch += Convert-ToPayload $event
                if ([long]$event.RecordId -gt $channelLastRecordId) {
                    $channelLastRecordId = [long]$event.RecordId
                }
            } catch {
                Write-DiagnosticLog -Level "WARN" -Message ("Skipping unreadable event {0}/{1}/{2}: {3}" -f $channel, $event.ProviderName, $event.RecordId, $_.Exception.Message)
            }
        }
        if ($channelBatch.Count -gt 0) {
            $targetUrl = Get-IngestUrlForChannel $channel
            $response = Send-Batch -Batch $channelBatch -TargetUrl $targetUrl
            $batch += $channelBatch
            $state[$channel] = $channelLastRecordId
            Save-State -State $state
            Write-DiagnosticLog -Message ("Sent {0} events from {1} to {2}" -f $channelBatch.Count, $channel, $targetUrl)
            Write-Host ("Sent {0} events from {1} to {2}" -f $channelBatch.Count, $channel, $targetUrl)
            if ($response) {
                $response | ConvertTo-Json -Depth 4
            }
        } elseif (-not $state.ContainsKey($channel)) {
            $state[$channel] = $channelLastRecordId
        }
    }

    Save-State -State $state
    if ($batch.Count -gt 0) {
        Write-DiagnosticLog -Message ("Sent {0} total Windows events." -f $batch.Count)
        Write-Host ("Sent {0} total Windows events." -f $batch.Count)
    } else {
        Write-DiagnosticLog -Message "No new Windows events to send."
        Write-Host "No new Windows events to send."
    }
} catch {
    Write-DiagnosticLog -Level "ERROR" -Message ("Collector failed: {0}" -f $_.Exception.ToString())
    throw
}
