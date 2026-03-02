
<#
.SYNOPSIS
Queries the Microsoft 365 Unified Audit Log for a specific SharePoint/OneDrive file.

.PARAMETER FileUrl
Full URL of the file (e.g., https://contoso.sharepoint.com/sites/TeamA/Shared%20Documents/Specs/Design.docx)

.PARAMETER StartDate
Start of the time window (local date accepted). Default: (Get-Date).AddDays(-7)

.PARAMETER StartTime
Optional time-of-day to combine with StartDate (format HH:mm, local time). Default: 00:00

.PARAMETER EndDate
End of the time window (local date accepted). Default: (Get-Date)

.PARAMETER EndTime
Optional time-of-day to combine with EndDate (format HH:mm, local time). Default: 23:59:59

.PARAMETER Operations
Optional array of operations to filter server-side (default includes common file ops):
FileAccessed, FileDownloaded, FileDeleted, FileDeletedFirstStageRecycleBin,
FileDeletedSecondStageRecycleBin, FileRenamed, FileMoved, FileModified, FileUploaded,
SharingSet, SharingInvitationCreated, SecureLinkCreated, SecureLinkUpdated, SecureLinkUsed

.PARAMETER OutputCsvPath
Optional path to save results as CSV.

.PARAMETER MaxResults
Max records to fetch (paging handled in batches of 5000). Default: 50000

Examples:

# Whole days (as before)
.\AuditLogQuery.ps1 `
  -FileUrl "https://<tenant>.sharepoint.com/contentstorage/CSP_<contaienerURLFromSPAC/Document Library/<DocumentName>.docx" `
  -StartDate (Get-Date "2026-03-01") `
  -EndDate   (Get-Date "2026-03-03") `
  -OutputCsvPath "C:\Temp\Report_File_Audit.csv"

# Precise 3-minute window using StartTime/EndTime (LOCAL time; script converts to UTC)
#   1 edit at 7:39, 2 edits at 7:40, 1 edit at 7:41
.\AuditLogQuery.ps1 `
  -FileUrl "https://<tenant>.sharepoint.com/contentstorage/CSP_<contaienerURLFromSPAC/Document Library/<DocumentName>.docx" `
  -StartDate (Get-Date "2025-11-18") -StartTime "13:15" `
  -EndDate   (Get-Date "2025-11-18") -EndTime   "13:25" `
  -OutputCsvPath "C:\Temp\Report_File_Audit.csv"

#>

param(
    [Parameter(Mandatory=$true)]
    [string]$FileUrl,

    [datetime]$StartDate = (Get-Date),

    # New: optional time-of-day (local), format HH:mm
    [ValidatePattern('^\d{2}:\d{2}$')]
    [string]$StartTime,

    [datetime]$EndDate   = (Get-Date),

    # New: optional time-of-day (local), format HH:mm
    [ValidatePattern('^\d{2}:\d{2}$')]
    [string]$EndTime,

    [string[]]$Operations = @(
        'FileAccessed',
        'FileDownloaded',
        'FileDeleted',
        'FileDeletedFirstStageRecycleBin',
        'FileDeletedSecondStageRecycleBin',
        'FileRenamed',
        'FileMoved',
        'FileModified',
        'FileUploaded',
        'SharingSet',
        'SharingInvitationCreated',
        'SecureLinkCreated',
        'SecureLinkUpdated',
        'SecureLinkUsed',
        'SensitivityLabelApplied',
        'SensitivityLabelUpdated',
        'SensitivityLabelRemoved',
        'SensitivityLabeledFileOpened',
        'SensitivityLabeledFileRenamed',
        'SensitivityLabelPolicyMatched'
    ),

    [string]$OutputCsvPath,

    [int]$MaxResults = 50000
)

function Ensure-Module {
    param([string]$Name, [string]$MinVersion = '3.0.0')
    $mod = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $mod) {
        Write-Host "Installing module $Name..." -ForegroundColor Yellow
        Install-Module $Name -Scope CurrentUser -Force -AllowClobber
    } elseif ([version]$mod.Version -lt [version]$MinVersion) {
        Write-Host "Updating module $Name to at least $MinVersion..." -ForegroundColor Yellow
        Install-Module $Name -Scope CurrentUser -Force -AllowClobber
    }
}

function Connect-Audit {
    # Connect to Exchange Online for Search-UnifiedAuditLog
    if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
        Ensure-Module -Name ExchangeOnlineManagement -MinVersion '3.3.0'
    }
    if (-not (Get-Module ExchangeOnlineManagement)) {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
    }
    if (-not (Get-ConnectionInformation)) {
        Connect-ExchangeOnline -ShowBanner:$false
    }
}

function Resolve-WindowUtc {
    param(
        [datetime]$StartDate,
        [string]$StartTime,
        [datetime]$EndDate,
        [string]$EndTime
    )

    # Compose local start/end DateTime from date + optional HH:mm
    $startLocal = if ($StartTime) {
        $parts = $StartTime.Split(':')
        [datetime]::new($StartDate.Year, $StartDate.Month, $StartDate.Day, [int]$parts[0], [int]$parts[1], 0)
    } else {
        # default to 00:00 for start
        [datetime]::new($StartDate.Year, $StartDate.Month, $StartDate.Day, 0, 0, 0)
    }

    $endLocal = if ($EndTime) {
        $parts = $EndTime.Split(':')
        [datetime]::new($EndDate.Year, $EndDate.Month, $EndDate.Day, [int]$parts[0], [int]$parts[1], 0)
    } else {
        # default to end of day for end
        [datetime]::new($EndDate.Year, $EndDate.Month, $EndDate.Day, 23, 59, 59)
    }

    # Validate
    if ($endLocal -le $startLocal) {
        throw "End datetime ($endLocal) must be greater than start datetime ($startLocal)."
    }

    # Convert local → UTC (UAL expects UTC)
    $startUtc = [TimeZoneInfo]::ConvertTimeToUtc($startLocal, [TimeZoneInfo]::Local)
    $endUtc   = [TimeZoneInfo]::ConvertTimeToUtc($endLocal,   [TimeZoneInfo]::Local)

    [pscustomobject]@{
        StartLocal = $startLocal
        EndLocal   = $endLocal
        StartUtc   = $startUtc
        EndUtc     = $endUtc
    }
}

function Get-AuditLogForFile {
    param(
        [string]$FileUrl,
        [datetime]$StartUtc,
        [datetime]$EndUtc,
        [string[]]$Operations,
        [int]$MaxResults
    )

    # Normalize URL for comparisons (audit holds exact URL in AuditData.ObjectId for SP file events)
    $normalizedTarget = $FileUrl.Trim()
    $normalizedTargetLower = $normalizedTarget.ToLower()

    # Pre-compute multiple target forms for matching across record types.
    # MipLabel events may store ObjectId as URL-decoded, as a relative path, or in FullPath.
    $uri = [uri]$normalizedTarget
    $targetDecodedLower    = [uri]::UnescapeDataString($normalizedTarget).ToLower()
    $targetRelPathLower    = [uri]::UnescapeDataString($uri.AbsolutePath).ToLower()

    # Label operations that use MipLabel record type and may have different ObjectId formats
    $labelOps = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)
    @('SensitivityLabelApplied','SensitivityLabelUpdated','SensitivityLabelRemoved',
      'SensitivityLabeledFileOpened','SensitivityLabeledFileRenamed','SensitivityLabelPolicyMatched') |
        ForEach-Object { $null = $labelOps.Add($_) }

    $pageSize = 5000
    $totalFetched = 0
    $all = @()
    $unmatchedLabelDiag = @()   # diagnostic: label events that didn't match the file URL

    # We’ll loop by operation subsets to keep server-side filtering effective and avoid timeouts.
    $opBatches = @()
    if ($Operations.Count -le 15) {
        $opBatches = ,$Operations
    } else {
        # Chunk operations into reasonable batches
        $opBatches = $Operations | ForEach-Object -Begin { $temp=@() } -Process {
            $temp += $_
            if ($temp.Count -ge 12) { ,$temp; $temp=@() }
        } -End { if ($temp.Count) { ,$temp } }
    }

    foreach ($opBatch in $opBatches) {
        # Use a unique SessionId to enable paging across repeated calls
        $sessionId = [guid]::NewGuid().ToString()
        $more = $true
        $iteration = 0

        while ($more -and $totalFetched -lt $MaxResults) {
            $iteration++
            Write-Host "Querying UAL batch (ops: $($opBatch -join ',')) iteration $iteration..." -ForegroundColor Cyan

            $results = Search-UnifiedAuditLog `
                -StartDate $StartUtc `
                -EndDate $EndUtc `
                -Operations $opBatch `
                -ResultSize $pageSize `
                -SessionId $sessionId `
                -SessionCommand ReturnNextPreviewPage `
                -ErrorAction Stop

            if (-not $results) {
                $more = $false
                break
            }

            foreach ($r in $results) {
                # Expand JSON
                $data = $null
                try {
                    $data = $r.AuditData | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    continue
                }

                # Match the event to the target file using multiple strategies.
                # Different record types (SharePointFileOperation vs MipLabel) store the file
                # identifier differently: full URL, URL-decoded URL, or relative path.
                $objectId = ($data.ObjectId | ForEach-Object { $_ })
                $match = $false

                if ($objectId) {
                    $oidRaw     = "$objectId"
                    $oidLower   = $oidRaw.ToLower()
                    $oidDecoded = [uri]::UnescapeDataString($oidRaw).ToLower()

                    # Exact encoded URL  |  exact decoded URL  |  ObjectId is relative path only
                    if     ($oidLower   -eq $normalizedTargetLower)  { $match = $true }
                    elseif ($oidDecoded -eq $targetDecodedLower)     { $match = $true }
                    elseif ($oidLower   -eq $targetRelPathLower)     { $match = $true }
                    elseif ($oidDecoded -eq $targetRelPathLower)     { $match = $true }
                    elseif ($data.TargetFilePath) {
                        $tfpLower = "$($data.TargetFilePath)".ToLower()
                        if ($tfpLower -eq $normalizedTargetLower -or $tfpLower -eq $targetDecodedLower) { $match = $true }
                    }
                }

                # Purview/MIP: FullPath is a relative path, sometimes with backslashes
                if (-not $match -and $data.FullPath) {
                    $fp = "$($data.FullPath)".Replace('\', '/').ToLower()
                    if ($fp -eq $targetRelPathLower -or $fp.EndsWith($targetRelPathLower)) { $match = $true }
                }

                # Purview/MIP: SourceRelativeUrl is present in some MipLabel events
                if (-not $match -and $data.SourceRelativeUrl) {
                    $sruLower = "$($data.SourceRelativeUrl)".ToLower()
                    if ($sruLower -eq $targetRelPathLower -or $targetRelPathLower.EndsWith($sruLower)) { $match = $true }
                }

                # Diagnostic: collect unmatched label events so we can inspect their ObjectId format
                if (-not $match -and $labelOps.Contains($r.Operations)) {
                    $unmatchedLabelDiag += [pscustomobject]@{
                        Time             = $r.CreationDate
                        Operation        = $r.Operations
                        RecordType       = $r.RecordType
                        UserId           = $r.UserIds -join '; '
                        ObjectId         = $data.ObjectId
                        FullPath         = $data.FullPath
                        SourceRelativeUrl= $data.SourceRelativeUrl
                        ItemName         = $data.ItemName
                    }
                }

                if ($match) {
                    $totalFetched++
                    $all += [pscustomobject]@{
                        TimeGeneratedUtc   = [datetime]$r.CreationDate
                        Operation          = $r.Operations
                        Workload           = $r.Workload
                        UserId             = $r.UserIds -join '; '
                        RecordType         = $r.RecordType
                        OrganizationId     = $r.OrganizationId
                        ResultStatus       = $r.ResultStatus
                        ClientIP           = $data.ClientIP
                        UserAgent          = $data.UserAgent
                        SiteUrl            = $data.SiteUrl
                        SourceFileExtension= $data.SourceFileExtension
                        SourceRelativeUrl  = $data.SourceRelativeUrl
                        ListId             = $data.ListId
                        ListItemUniqueId   = $data.ListItemUniqueId
                        ObjectId           = $data.ObjectId
                        TargetFilePath     = $data.TargetFilePath
                        DestinationFileUrl = $data.DestinationFileUrl
                        DestinationRelativeUrl = $data.DestinationRelativeUrl
                        SharingType        = $data.SharingType
                        SharingUrl         = $data.SharingUrl
                        SharingInvitationId= $data.SharingInvitationId
                        SensitivityLabelId      = $data.SensitivityLabelId
                        OldSensitivityLabelId   = $data.OldSensitivityLabelId
                        SensitivityLabelEventType = $data.SensitivityLabelEventType
                        CorrelationId           = $data.CorrelationId
                        AuditDataRaw       = $r.AuditData
                    }
                    if ($totalFetched -ge $MaxResults) { break }
                }
            }

            if ($results.Count -lt $pageSize -or $totalFetched -ge $MaxResults) {
                $more = $false
            }
        }
    }

    # Surface any label events that were returned but didn't match the file URL.
    # This lets you see exactly what ObjectId / FullPath format Purview is using for your tenant.
    if ($unmatchedLabelDiag.Count -gt 0) {
        Write-Warning ("Found {0} sensitivity label event(s) in the time window that did NOT match the target file URL. " +
                       "Review the ObjectId/FullPath columns below to identify the format and adjust matching if needed.") `
            -f $unmatchedLabelDiag.Count
        $unmatchedLabelDiag | Format-Table Time, Operation, RecordType, ObjectId, FullPath, SourceRelativeUrl, ItemName -AutoSize
    }

    $all | Sort-Object TimeGeneratedUtc
}

#---------------- MAIN ----------------#

# Compose and display the effective window
$resolved = Resolve-WindowUtc -StartDate $StartDate -StartTime $StartTime -EndDate $EndDate -EndTime $EndTime

Write-Host "Connecting to Exchange Online..." -ForegroundColor Green
Connect-Audit

Write-Host ("Searching Unified Audit Log from (LOCAL) {0} to {1}" -f $resolved.StartLocal, $resolved.EndLocal) -ForegroundColor Green
Write-Host ("                       (UTC)   {0} to {1}" -f $resolved.StartUtc,   $resolved.EndUtc)   -ForegroundColor DarkGray
Write-Host "   $FileUrl" -ForegroundColor Yellow
Write-Host "Operations: $($Operations -join ', ')" -ForegroundColor Green

$results = Get-AuditLogForFile -FileUrl $FileUrl -StartUtc $resolved.StartUtc -EndUtc $resolved.EndUtc -Operations $Operations -MaxResults $MaxResults

if (-not $results -or $results.Count -eq 0) {
    Write-Host "No audit records found for the specified file and date/time range." -ForegroundColor Yellow
} else {
    Write-Host ("Found {0} matching audit events." -f $results.Count) -ForegroundColor Cyan

    $results |
        Select-Object TimeGeneratedUtc, Operation, UserId, ClientIP, UserAgent, ResultStatus, ObjectId |
        Format-Table -AutoSize

    if ($OutputCsvPath) {
        $dir = Split-Path -Parent $OutputCsvPath
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
        $results | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Saved CSV to $OutputCsvPath" -ForegroundColor Green
    }
}

# Optional cleanup
