<#
.SYNOPSIS
    AD April '26 Check0r - Kerberos RC4/AES Readiness Checker for On-Prem Active Directory

.DESCRIPTION
    READ-ONLY script that collects and correlates:
      - Domain Controller inventory
      - KDC registry override indicators (DefaultDomainSupportedEncTypes / SupportedEncryptionTypes)
      - New KDC readiness System events (Event IDs 201-209) from DCs
      - SPN-enabled account inventory + msDS-SupportedEncryptionTypes analysis
      - Legacy/at-risk endpoint inventory based on OperatingSystem strings

    Output:
      - Human-readable FindingsSummary.txt (+ optional .md)
      - CSV exports for each data set
      - Transcript log of runtime output

.CREATED BY
    Benjamin Iheukumere | SafLink IT

.NOTES
    - Requires RSAT ActiveDirectory module on the executing system.
    - Remote DC checks may require:
        - WinRM (for registry check via Invoke-Command)
        - Remote event log access / firewall rules (for Get-WinEvent -ComputerName)
    - Script makes NO CHANGES.

#>

# -------------------------------------------------------------------
# IMPORTANT POWERSHELL RULE:
# The param() block must be the first executable statement in the file.
# -------------------------------------------------------------------
[CmdletBinding()]
param(
    # How many days back to query KDC readiness events (201-209)
    [int]$DaysBack = 30,

    # Output root folder. If empty, script will use its own folder (robustly detected).
    [string]$OutputRoot = "",

    # Provide DCs manually (FQDN/hostname). If empty -> auto-discover.
    [string[]]$DomainControllers = @(),

    # Force prompting for DCs if auto-discovery fails.
    [switch]$PromptForDCs,

    # Limit number of events per DC (0 = unlimited)
    [int]$MaxEventsPerDC = 0,

    # Disable transcript
    [switch]$NoTranscript
)

# =========================
#   CONFIGURATION (EDIT ME)
# =========================
$Config = [ordered]@{
    DaysBack                  = $DaysBack
    KdcReadinessEventIds      = @(201,202,203,204,205,206,207,208,209)

    # OutputRoot will be finalized after we robustly detect script directory.
    OutputRoot                = $OutputRoot

    DomainControllersOverride = $DomainControllers
    PromptForDCsIfNeeded      = [bool]$PromptForDCs
    MaxEventsPerDC            = $MaxEventsPerDC

    RunDcInventory            = $true
    RunKdcRegistryCheck       = $true   # WinRM needed
    RunKdcEventCollection     = $true   # Remote event log access needed
    RunSpnInventory           = $true
    RunLegacyOsInventory      = $true

    IncludeComputerSpns       = $true
    IncludeUserSpns           = $true
    IncludeGmsaSpns           = $true

    # Triage regex: adjust as needed per environment.
    LegacyOsRegex             = 'Windows XP|Windows 2000|Windows Server 2003|Windows Vista|Windows Server 2008(?! R2)|Windows 7(?! )|Windows Server 2008 R2|Windows Server 2012(?! R2)'

    WriteMarkdownReport       = $true
    UseTranscript             = (-not [bool]$NoTranscript)
}

# =========================
#       ASCII BANNER
# =========================
$Banner = @"
  /$$$$$$                      /$$ /$$       /$$ /$$$$$$   /$$$$$$                              
 /$$__  $$                    |__/| $$      | $//$$__  $$ /$$__  $$                             
| $$  \ $$  /$$$$$$   /$$$$$$  /$$| $$      |_/|__/  \ $$| $$  \__/                             
| $$$$$$$$ /$$__  $$ /$$__  $$| $$| $$           /$$$$$$/| $$$$$$$                              
| $$__  $$| $$  \ $$| $$  \__/| $$| $$          /$$____/ | $$__  $$                             
| $$  | $$| $$  | $$| $$      | $$| $$         | $$      | $$  \ $$                             
| $$  | $$| $$$$$$$/| $$      | $$| $$         | $$$$$$$$|  $$$$$$/                             
|__/  |__/| $$____/ |__/      |__/|__/         |________/ \______/                              
          | $$                                                                                  
          | $$                                                                                  
          |__/                                                                                  
  /$$$$$$  /$$$$$$$         /$$$$$$  /$$                           /$$        /$$$$$$           
 /$$__  $$| $$__  $$       /$$__  $$| $$                          | $$       /$$$_  $$          
| $$  \ $$| $$  \ $$      | $$  \__/| $$$$$$$   /$$$$$$   /$$$$$$$| $$   /$$| $$$$\ $$  /$$$$$$ 
| $$$$$$$$| $$  | $$      | $$      | $$__  $$ /$$__  $$ /$$_____/| $$  /$$/| $$ $$ $$ /$$__  $$
| $$__  $$| $$  | $$      | $$      | $$  \ $$| $$$$$$$$| $$      | $$$$$$/ | $$\ $$$$| $$  \__/
| $$  | $$| $$  | $$      | $$    $$| $$  | $$| $$_____/| $$      | $$_  $$ | $$ \ $$$| $$      
| $$  | $$| $$$$$$$/      |  $$$$$$/| $$  | $$|  $$$$$$$|  $$$$$$$| $$ \  $$|  $$$$$$/| $$      
|__/  |__/|_______/        \______/ |__/  |__/ \_______/ \_______/|__/  \__/ \______/ |__/      
                                                                                                
                                                                                                
                                                                                                

          Created by: Benjamin Iheukumere | SafeLink IT
          Purpose   : Kerberos RC4/AES Readiness Checks for April 2026 changes
          Mode      : READ-ONLY (no changes are made)
"@
Write-Host $Banner

# =========================
#     UTILITIES / HELPERS
# =========================
function Get-ScriptDirectory {
    <#
        Robustly determines the directory the script is running from.
        Works across different PowerShell versions/hosts.
    #>
    try {
        if ($PSScriptRoot -and $PSScriptRoot.Trim().Length -gt 0) {
            return $PSScriptRoot
        }
    } catch {}

    try {
        if ($PSCommandPath -and $PSCommandPath.Trim().Length -gt 0) {
            return (Split-Path -Parent $PSCommandPath)
        }
    } catch {}

    try {
        if ($MyInvocation.MyCommand.Path -and $MyInvocation.MyCommand.Path.Trim().Length -gt 0) {
            return (Split-Path -Parent $MyInvocation.MyCommand.Path)
        }
    } catch {}

    return (Get-Location).Path
}

function Convert-EncTypeMask {
    param([Nullable[int]]$Mask)

    if ($null -eq $Mask) { return "DEFAULT(null)" }
    if ($Mask -eq 0)     { return "DEFAULT(0)" }

    $map = [ordered]@{
        "RC4_HMAC" = 0x4
        "AES128"   = 0x8
        "AES256"   = 0x10
    }

    $enabled = foreach ($k in $map.Keys) {
        if (($Mask -band $map[$k]) -ne 0) { $k }
    }

    if (-not $enabled) { return "UNKNOWN($Mask)" }
    return ($enabled -join ",")
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function New-OutputFolder {
    param([string]$Root, [string]$DomainName)

    if ([string]::IsNullOrWhiteSpace($Root)) {
        throw "OutputRoot is empty. Provide -OutputRoot or allow the script to detect its directory."
    }

    # Ensure root exists
    if (-not (Test-Path -Path $Root)) {
        New-Item -Path $Root -ItemType Directory -Force | Out-Null
    }

    # Normalize to full path
    $RootFull = [System.IO.Path]::GetFullPath($Root)

    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $safeDomain = ($DomainName -replace '[^a-zA-Z0-9\.\-_]','_')
    $folder = Join-Path $RootFull ("AD-April26-Check0r_{0}_{1}" -f $safeDomain, $stamp)

    New-Item -Path $folder -ItemType Directory -Force | Out-Null
    New-Item -Path (Join-Path $folder "csv")    -ItemType Directory -Force | Out-Null
    New-Item -Path (Join-Path $folder "logs")   -ItemType Directory -Force | Out-Null
    New-Item -Path (Join-Path $folder "report") -ItemType Directory -Force | Out-Null

    return $folder
}

$Global:ReportLines = New-Object System.Collections.Generic.List[string]
$Global:ReportFile  = $null

function Add-ReportLine {
    param([string]$Text, [switch]$NoConsole)

    $Global:ReportLines.Add($Text) | Out-Null
    if (-not $NoConsole) { Write-Host $Text }
    if ($Global:ReportFile) { Add-Content -Path $Global:ReportFile -Value $Text -Encoding UTF8 }
}

function Add-Section {
    param([string]$Title)
    Add-ReportLine ""
    Add-ReportLine ("=" * 80)
    Add-ReportLine $Title
    Add-ReportLine ("=" * 80)
}

# =========================
#     EVENT EXPLANATIONS
# =========================
$EventRemediation = @{
    201 = @{
        Title = "RC4-only client + blank msDS-SupportedEncryptionTypes (AUDIT)"
        What  = "Client only advertised RC4. Service account had no explicit msDS-SupportedEncryptionTypes. KDC likely issued RC4 ticket for compatibility."
        Fix   = @(
            "Preferred: Upgrade/fix the client/appliance/keytab so it supports and advertises AES.",
            "Scoped workaround: Explicitly add RC4 to the *service account* msDS-SupportedEncryptionTypes (e.g., 0x1C / 28) ONLY for that service that must accept RC4.",
            "Avoid domain-wide DefaultDomainSupportedEncTypes overrides unless you fully understand the blast radius."
        )
    }
    202 = @{
        Title = "Account lacks AES keys + blank msDS-SupportedEncryptionTypes (AUDIT)"
        What  = "Service account likely does not have AES keys (old password set, hash-only migration, or keytab without AES)."
        Fix   = @(
            "Reset/rotate the service account password to generate AES keys (best) or migrate to gMSA where possible.",
            "For non-Windows services using keytabs: regenerate keytabs including AES (and validate KVNO)."
        )
    }
    203 = @{
        Title = "RC4-only client + blank msDS-SupportedEncryptionTypes (DENIED in enforcement)"
        What  = "Same as 201, but in enforcement behavior this would be blocked/denied."
        Fix   = @(
            "Upgrade/fix client or keytab to support AES.",
            "If unavoidable: explicitly add RC4 to the service account msDS-SupportedEncryptionTypes for a scoped exception (document + timebox)."
        )
    }
    204 = @{
        Title = "Account lacks AES keys + blank msDS-SupportedEncryptionTypes (DENIED in enforcement)"
        What  = "Same as 202, but in enforcement behavior this would be blocked/denied."
        Fix   = @(
            "Reset/rotate the service account password (or migrate to gMSA).",
            "Regenerate keytabs with AES where applicable."
        )
    }
    205 = @{
        Title = "DefaultDomainSupportedEncTypes override in use"
        What  = "DC is using an explicit KDC default enc type override (DDSET), which can hide readiness issues."
        Fix   = @(
            "Remove the override if feasible.",
            "If you must keep it: scope exceptions per account instead and monitor events; treat override as temporary technical debt."
        )
    }
    206 = @{
        Title = "RC4-only client + AES-only msDS-SupportedEncryptionTypes (AUDIT)"
        What  = "Service is configured AES-only but client is RC4-only (or not advertising AES)."
        Fix   = @(
            "Fix/upgrade client to support AES.",
            "If required as a short-term exception: add RC4 to the service account msDS-SupportedEncryptionTypes (e.g., 28)."
        )
    }
    207 = @{
        Title = "Account lacks AES keys + AES-only msDS-SupportedEncryptionTypes (AUDIT)"
        What  = "Service is configured AES-only but the account appears not to have AES keys yet."
        Fix   = @(
            "Reset/rotate the account password to generate AES keys.",
            "Validate service functionality post-rotation; for keytabs regenerate with AES."
        )
    }
    208 = @{
        Title = "RC4-only client + AES-only msDS-SupportedEncryptionTypes (DENIED in enforcement)"
        What  = "Same as 206, but would be denied under enforcement."
        Fix   = @(
            "Upgrade/fix client to advertise AES.",
            "Or temporarily add RC4 for that service account only (document + timebox)."
        )
    }
    209 = @{
        Title = "Account lacks AES keys + AES-only msDS-SupportedEncryptionTypes (DENIED in enforcement)"
        What  = "Same as 207, but would be denied under enforcement."
        Fix   = @(
            "Reset/rotate the account password (or migrate to gMSA).",
            "Regenerate keytabs including AES where applicable."
        )
    }
}

# =========================
#       MAIN EXECUTION
# =========================
Add-Section "Runtime Preflight"

# Finalize OutputRoot robustly (THIS is the fix)
if ([string]::IsNullOrWhiteSpace($Config.OutputRoot)) {
    $Config.OutputRoot = Get-ScriptDirectory
}

Add-ReportLine ("[+] Script directory detected as: {0}" -f (Get-ScriptDirectory))
Add-ReportLine ("[+] Using OutputRoot: {0}" -f $Config.OutputRoot)

if (-not (Test-IsAdmin)) {
    Add-ReportLine "[!] Not running as Local Administrator. This is usually fine, but remote log/WinRM access may fail depending on policy."
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Add-ReportLine "[+] ActiveDirectory module loaded."
}
catch {
    Add-ReportLine "[X] Failed to load ActiveDirectory module (RSAT). Install RSAT and retry."
    Add-ReportLine "    Windows: Settings -> Optional Features -> Add 'RSAT: Active Directory Domain Services and Lightweight Directory Services Tools'"
    throw
}

$domain = $null
$forest = $null
try {
    $domain = Get-ADDomain -ErrorAction Stop
    $forest = Get-ADForest -ErrorAction Stop
    Add-ReportLine ("[+] Domain detected: {0}" -f $domain.DNSRoot)
    Add-ReportLine ("[+] Forest detected: {0}" -f $forest.Name)
    Add-ReportLine ("[+] Domain Functional Level: {0}" -f $domain.DomainMode)
    Add-ReportLine ("[+] Forest Functional Level: {0}" -f $forest.ForestMode)
}
catch {
    Add-ReportLine "[X] Failed to query domain/forest. Are you joined to the domain, or running with sufficient rights?"
    throw
}

# Create output folder + report file (hard fail if this fails)
$outFolder = New-OutputFolder -Root $Config.OutputRoot -DomainName $domain.DNSRoot
$Global:ReportFile = Join-Path $outFolder "report\FindingsSummary.txt"

Add-ReportLine ("[+] Output folder: {0}" -f $outFolder)
Add-ReportLine ("[+] Report file  : {0}" -f $Global:ReportFile)

# Transcript
if ($Config.UseTranscript) {
    $transcriptPath = Join-Path $outFolder "logs\Transcript.txt"
    try {
        Start-Transcript -Path $transcriptPath -Force | Out-Null
        Add-ReportLine ("[+] Transcript enabled: {0}" -f $transcriptPath)
    }
    catch {
        Add-ReportLine "[!] Failed to start transcript. Continuing without transcript."
        $Config.UseTranscript = $false
    }
}

function Get-TargetDCs {
    param([string[]]$Override)

    if ($Override -and $Override.Count -gt 0) { return $Override }

    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop |
            Sort-Object HostName |
            Select-Object -ExpandProperty HostName
        if ($dcs -and $dcs.Count -gt 0) { return $dcs }
    } catch {}

    if ($Config.PromptForDCsIfNeeded) {
        Add-ReportLine "[!] Could not auto-discover DCs. Prompting for DC hostnames/FQDNs..."
        $input = Read-Host "Enter one or more Domain Controllers (comma-separated FQDNs/hostnames)"
        return ($input.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    return @()
}

$targetDCs = Get-TargetDCs -Override $Config.DomainControllersOverride
if (-not $targetDCs -or $targetDCs.Count -eq 0) {
    Add-ReportLine "[X] No Domain Controllers provided or discovered. Cannot continue."
    if ($Config.UseTranscript) { try { Stop-Transcript | Out-Null } catch {} }
    throw "No DCs"
}
Add-ReportLine ("[+] Target DCs ({0}): {1}" -f $targetDCs.Count, ($targetDCs -join ", "))

# -------------------------
# Check 1 - DC Inventory
# -------------------------
if ($Config.RunDcInventory) {
    Add-Section "Check 1 - Domain Controller Inventory"

    try {
        $dcInventory = Get-ADDomainController -Filter * |
            Select-Object HostName, Site, IPv4Address, OperatingSystem, OperatingSystemVersion, IsGlobalCatalog, Enabled

        $dcCsv = Join-Path $outFolder "csv\DC-Inventory.csv"
        $dcInventory | Export-Csv $dcCsv -NoTypeInformation -Encoding UTF8

        Add-ReportLine ("[+] DC inventory collected: {0}" -f $dcCsv)
        Add-ReportLine "    What to look for:"
        Add-ReportLine "      - DC patch consistency (Jan 2026+ recommended for readiness event visibility)."
        Add-ReportLine "      - Old/unsupported DC OS versions increase risk and reduce feature parity."
    }
    catch {
        Add-ReportLine ("[X] Failed to collect DC inventory: {0}" -f $_.Exception.Message)
    }
}

# -------------------------
# Check 2 - KDC Registry Overrides
# -------------------------
function Get-KdcRegistryConfig {
    param([string[]]$DomainControllers)

    $results = @()
    foreach ($dc in $DomainControllers) {
        try {
            $v = Invoke-Command -ComputerName $dc -ErrorAction Stop -ScriptBlock {
                $p = "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc\Parameters"
                [pscustomobject]@{
                    DefaultDomainSupportedEncTypes = (Get-ItemProperty -Path $p -Name "DefaultDomainSupportedEncTypes" -ErrorAction SilentlyContinue)."DefaultDomainSupportedEncTypes"
                    SupportedEncryptionTypes       = (Get-ItemProperty -Path $p -Name "SupportedEncryptionTypes"       -ErrorAction SilentlyContinue)."SupportedEncryptionTypes"
                }
            }

            $results += [pscustomobject]@{
                DC   = $dc
                DefaultDomainSupportedEncTypes = $v.DefaultDomainSupportedEncTypes
                DDSET_Decoded = Convert-EncTypeMask $v.DefaultDomainSupportedEncTypes
                SupportedEncryptionTypes = $v.SupportedEncryptionTypes
                SET_Decoded  = Convert-EncTypeMask $v.SupportedEncryptionTypes
            }
        }
        catch {
            $results += [pscustomobject]@{
                DC   = $dc
                DefaultDomainSupportedEncTypes = $null
                DDSET_Decoded = "ERROR"
                SupportedEncryptionTypes = $null
                SET_Decoded  = $_.Exception.Message
            }
        }
    }
    $results
}

if ($Config.RunKdcRegistryCheck) {
    Add-Section "Check 2 - KDC Registry Overrides (Visibility / Compatibility Crutches)"

    Add-ReportLine "[i] Reads DC registry keys under:"
    Add-ReportLine "    HKLM:\SYSTEM\CurrentControlSet\Services\Kdc\Parameters"
    Add-ReportLine "      - DefaultDomainSupportedEncTypes (DDSET): assumed enc types when msDS-SupportedEncryptionTypes is not set"
    Add-ReportLine "      - SupportedEncryptionTypes (SET): KDC supported enc types override (rare)"
    Add-ReportLine ""
    Add-ReportLine "[i] If DDSET is explicitly configured to allow RC4 broadly, you may hide readiness problems until enforcement breaks things."

    $kdcCfg = Get-KdcRegistryConfig -DomainControllers $targetDCs
    $kdcCsv = Join-Path $outFolder "csv\DC-KdcRegistryConfig.csv"
    $kdcCfg | Export-Csv $kdcCsv -NoTypeInformation -Encoding UTF8
    Add-ReportLine ("[+] KDC registry config exported: {0}" -f $kdcCsv)

    $overrideFindings = $kdcCfg | Where-Object { $_.DDSET_Decoded -notmatch '^DEFAULT' -and $_.DDSET_Decoded -ne 'ERROR' }
    if ($overrideFindings.Count -gt 0) {
        Add-ReportLine ""
        Add-ReportLine "[!] Findings: One or more DCs have an explicit DefaultDomainSupportedEncTypes configured."
        Add-ReportLine "    Recommended action:"
        Add-ReportLine "      1) Document WHY it exists (legacy compatibility vs troubleshooting artifact)."
        Add-ReportLine "      2) If possible, remove/undo it so your environment aligns with Microsoft defaults."
        Add-ReportLine "      3) If you must keep it temporarily, treat it as technical debt and monitor readiness events aggressively."
        foreach ($f in $overrideFindings) {
            Add-ReportLine ("    - {0}: DDSET={1} ({2})" -f $f.DC, $f.DefaultDomainSupportedEncTypes, $f.DDSET_Decoded)
        }
    } else {
        Add-ReportLine "[+] No explicit DDSET overrides detected on queried DCs (or WinRM access failed)."
    }

    $errors = $kdcCfg | Where-Object { $_.DDSET_Decoded -eq "ERROR" }
    if ($errors.Count -gt 0) {
        Add-ReportLine ""
        Add-ReportLine "[!] Some DC registry checks failed (likely WinRM not enabled / firewall / permissions)."
        Add-ReportLine "    Fix checklist:"
        Add-ReportLine "      - Ensure WinRM is enabled and reachable (TCP 5985/5986) and your account is allowed."
        Add-ReportLine "      - Alternatively, run this script directly on a DC."
    }
}

# -------------------------
# Check 3 - KDC Readiness Events 201-209
# -------------------------
function Get-KdcReadinessEvents {
    param(
        [string[]]$DomainControllers,
        [int[]]$EventIds,
        [int]$DaysBack,
        [int]$MaxPerDc = 0
    )

    $start = (Get-Date).AddDays(-[Math]::Abs($DaysBack))
    $collected = New-Object System.Collections.Generic.List[object]

    foreach ($dc in $DomainControllers) {
        Write-Host ("[i] Reading System events from {0} (last {1} days)..." -f $dc, $DaysBack) -ForegroundColor Cyan
        try {
            $filter = @{ LogName='System'; Id=$EventIds; StartTime=$start }
            $events = Get-WinEvent -ComputerName $dc -FilterHashtable $filter -ErrorAction Stop

            if ($MaxPerDc -gt 0) {
                $events = $events | Sort-Object TimeCreated -Descending | Select-Object -First $MaxPerDc
            }

            foreach ($e in $events) {
                $xml = [xml]$e.ToXml()
                $data = @{}
                foreach ($d in $xml.Event.EventData.Data) {
                    if ($d.Name) { $data[$d.Name] = $d.'#text' }
                }

                # Flexible guesses (field names can differ)
                $guessClient  = $data["ClientName"];      if (-not $guessClient) { $guessClient = $data["Client"] }
                $guessAcct    = $data["AccountName"];     if (-not $guessAcct)   { $guessAcct = $data["TargetUserName"] }
                $guessSpn     = $data["ServiceName"];     if (-not $guessSpn)    { $guessSpn = $data["TargetServerName"] }

                $collected.Add([pscustomobject]@{
                    DC          = $dc
                    TimeCreated = $e.TimeCreated
                    EventId     = $e.Id
                    Level       = $e.LevelDisplayName
                    Client      = $guessClient
                    Account     = $guessAcct
                    Service     = $guessSpn
                    Message     = ($e.Message -replace "\s+"," ").Trim()
                    DataJson    = ($data | ConvertTo-Json -Compress)
                }) | Out-Null
            }
        }
        catch {
            $collected.Add([pscustomobject]@{
                DC          = $dc
                TimeCreated = $null
                EventId     = $null
                Level       = "ERROR"
                Client      = $null
                Account     = $null
                Service     = $null
                Message     = $_.Exception.Message
                DataJson    = $null
            }) | Out-Null
        }
    }

    $collected
}

if ($Config.RunKdcEventCollection) {
    Add-Section "Check 3 - KDC Readiness Events (System Log: IDs 201-209)"

    Add-ReportLine "[i] These events are your best early-warning signals for what may break under enforcement."
    Add-ReportLine "    Focus on:"
    Add-ReportLine "      - 201/206: Clients/devices not advertising AES (legacy clients, appliances, keytabs without AES)"
    Add-ReportLine "      - 202/207: Service accounts missing AES keys (very old passwords or hash-only migrations)"
    Add-ReportLine ""

    $kdcEvents = Get-KdcReadinessEvents -DomainControllers $targetDCs `
        -EventIds $Config.KdcReadinessEventIds -DaysBack $Config.DaysBack -MaxPerDc $Config.MaxEventsPerDC

    $evtCsv = Join-Path $outFolder "csv\KDC-ReadinessEvents.csv"
    $kdcEvents | Export-Csv $evtCsv -NoTypeInformation -Encoding UTF8
    Add-ReportLine ("[+] Events exported: {0}" -f $evtCsv)

    $evtValid = $kdcEvents | Where-Object { $_.EventId -ne $null }
    $evtSummary = $evtValid | Group-Object DC, EventId | Sort-Object Count -Descending | Select-Object Count, Name

    $sumCsv = Join-Path $outFolder "csv\KDC-ReadinessEvents-Summary.csv"
    $evtSummary | Export-Csv $sumCsv -NoTypeInformation -Encoding UTF8
    Add-ReportLine ("[+] Event summary exported: {0}" -f $sumCsv)

    Add-ReportLine ""
    Add-ReportLine "Top event counts (DC, EventId):"
    ($evtSummary | Select-Object -First 12) | ForEach-Object { Add-ReportLine ("  - {0} : {1}" -f $_.Name, $_.Count) }

    $idsFound = $evtValid | Select-Object -ExpandProperty EventId -Unique | Sort-Object
    Add-ReportLine ""
    Add-ReportLine "Event explanations (for IDs seen in your environment):"
    foreach ($id in $idsFound) {
        if ($EventRemediation.ContainsKey($id)) {
            $r = $EventRemediation[$id]
            Add-ReportLine ("  [{0}] {1}" -f $id, $r.Title)
            Add-ReportLine ("       Meaning: {0}" -f $r.What)
            Add-ReportLine ("       Actions:")
            foreach ($a in $r.Fix) { Add-ReportLine ("         - {0}" -f $a) }
            Add-ReportLine ""
        }
    }

    $evtErrors = $kdcEvents | Where-Object { $_.Level -eq "ERROR" }
    if ($evtErrors.Count -gt 0) {
        Add-ReportLine "[!] Some DC event log reads failed."
        Add-ReportLine "    Typical causes: firewall, Remote Event Log access, or permissions."
        Add-ReportLine "    Fix checklist:"
        Add-ReportLine "      - Ensure your account can read DC System log (Domain Admin or Event Log Readers)."
        Add-ReportLine "      - Ensure Remote Event Log access is allowed by firewall/policy."
        Add-ReportLine "      - Alternatively run this script on a DC."
        $errCsv = Join-Path $outFolder "csv\KDC-ReadinessEvents-Errors.csv"
        $evtErrors | Export-Csv $errCsv -NoTypeInformation -Encoding UTF8
        Add-ReportLine ("    Error details exported: {0}" -f $errCsv)
    }

    if ($evtValid.Count -eq 0) {
        Add-ReportLine "[!] No readiness events found in the queried time window."
        Add-ReportLine "    Possible reasons:"
        Add-ReportLine "      - No affected traffic occurred in the last N days, OR"
        Add-ReportLine "      - DCs are not updated to emit these events, OR"
        Add-ReportLine "      - Remote event log access failed."
        Add-ReportLine "    Recommendation: extend -DaysBack, ensure DC patch baseline is current, and keep monitoring."
    }
}

# -------------------------
# Check 4 - SPN Inventory
# -------------------------
function Get-SpnInventory {
    $results = New-Object System.Collections.Generic.List[object]

    if ($Config.IncludeUserSpns) {
        try {
            $users = Get-ADUser -LDAPFilter "(servicePrincipalName=*)" -Properties servicePrincipalName, msDS-SupportedEncryptionTypes, PasswordLastSet, lastLogonTimestamp, Enabled
            foreach ($u in $users) {
                $results.Add([pscustomobject]@{
                    ObjectType         = "User"
                    Name               = $u.SamAccountName
                    DN                 = $u.DistinguishedName
                    Enabled            = $u.Enabled
                    EncMask            = $u.'msDS-SupportedEncryptionTypes'
                    EncTypes           = Convert-EncTypeMask $u.'msDS-SupportedEncryptionTypes'
                    PasswordLastSet    = $u.PasswordLastSet
                    LastLogonTimestamp = if ($u.lastLogonTimestamp) { [DateTime]::FromFileTime($u.lastLogonTimestamp) } else { $null }
                    SPNCount           = @($u.servicePrincipalName).Count
                    SampleSPN          = @($u.servicePrincipalName)[0]
                    OperatingSystem    = $null
                }) | Out-Null
            }
        } catch {
            Add-ReportLine ("[X] SPN user inventory failed: {0}" -f $_.Exception.Message)
        }
    }

    if ($Config.IncludeComputerSpns) {
        try {
            $comps = Get-ADComputer -LDAPFilter "(servicePrincipalName=*)" -Properties servicePrincipalName, msDS-SupportedEncryptionTypes, PasswordLastSet, lastLogonTimestamp, Enabled, OperatingSystem
            foreach ($c in $comps) {
                $results.Add([pscustomobject]@{
                    ObjectType         = "Computer"
                    Name               = $c.SamAccountName
                    DN                 = $c.DistinguishedName
                    Enabled            = $c.Enabled
                    EncMask            = $c.'msDS-SupportedEncryptionTypes'
                    EncTypes           = Convert-EncTypeMask $c.'msDS-SupportedEncryptionTypes'
                    PasswordLastSet    = $c.PasswordLastSet
                    LastLogonTimestamp = if ($c.lastLogonTimestamp) { [DateTime]::FromFileTime($c.lastLogonTimestamp) } else { $null }
                    SPNCount           = @($c.servicePrincipalName).Count
                    SampleSPN          = @($c.servicePrincipalName)[0]
                    OperatingSystem    = $c.OperatingSystem
                }) | Out-Null
            }
        } catch {
            Add-ReportLine ("[X] SPN computer inventory failed: {0}" -f $_.Exception.Message)
        }
    }

    if ($Config.IncludeGmsaSpns) {
        try {
            $gmsas = Get-ADServiceAccount -Filter * -Properties servicePrincipalName, msDS-SupportedEncryptionTypes, PasswordLastSet, lastLogonTimestamp, Enabled
            foreach ($g in $gmsas) {
                if (-not $g.servicePrincipalName) { continue }
                $results.Add([pscustomobject]@{
                    ObjectType         = "gMSA"
                    Name               = $g.SamAccountName
                    DN                 = $g.DistinguishedName
                    Enabled            = $g.Enabled
                    EncMask            = $g.'msDS-SupportedEncryptionTypes'
                    EncTypes           = Convert-EncTypeMask $g.'msDS-SupportedEncryptionTypes'
                    PasswordLastSet    = $g.PasswordLastSet
                    LastLogonTimestamp = if ($g.lastLogonTimestamp) { [DateTime]::FromFileTime($g.lastLogonTimestamp) } else { $null }
                    SPNCount           = @($g.servicePrincipalName).Count
                    SampleSPN          = @($g.servicePrincipalName)[0]
                    OperatingSystem    = $null
                }) | Out-Null
            }
        } catch {
            Add-ReportLine ("[X] gMSA inventory failed (Get-ADServiceAccount): {0}" -f $_.Exception.Message)
        }
    }

    $results
}

if ($Config.RunSpnInventory) {
    Add-Section "Check 4 - SPN-enabled Accounts Inventory (Kerberos Service Targets)"

    Add-ReportLine "[i] This inventory helps you spot:"
    Add-ReportLine "      - Accounts explicitly allowing RC4 (security risk; Kerberoasting-friendly)"
    Add-ReportLine "      - Accounts using DEFAULT (null/0), which will follow KDC default behavior"
    Add-ReportLine "      - Accounts configured AES-only but may still be missing AES keys until password rotation"
    Add-ReportLine ""

    $spnInv = Get-SpnInventory
    $spnCsv = Join-Path $outFolder "csv\SPN-Inventory.csv"
    $spnInv | Export-Csv $spnCsv -NoTypeInformation -Encoding UTF8
    Add-ReportLine ("[+] SPN inventory exported: {0}" -f $spnCsv)

    $spnWithRc4 = $spnInv | Where-Object { $_.EncTypes -match "RC4_HMAC" }
    $spnDefault = $spnInv | Where-Object { $_.EncTypes -match "^DEFAULT" }
    $spnRc4Only = $spnInv | Where-Object { $_.EncMask -eq 4 -or $_.EncTypes -eq "RC4_HMAC" }
    $spnAesOnly = $spnInv | Where-Object { $_.EncMask -eq 24 -or $_.EncTypes -eq "AES128,AES256" }

    $cutoff2008 = Get-Date "2008-01-01"
    $spnPwdPre2008 = $spnInv | Where-Object { $_.PasswordLastSet -and $_.PasswordLastSet -lt $cutoff2008 }

    $review = @(
    @($spnRc4Only)
    @($spnPwdPre2008)
    @($spnDefault)
) | Sort-Object Name -Unique

    $reviewCsv = Join-Path $outFolder "csv\SPN-Inventory-REVIEW.csv"
    $review | Export-Csv $reviewCsv -NoTypeInformation -Encoding UTF8
    Add-ReportLine ("[+] SPN review subset exported: {0}" -f $reviewCsv)

    Add-ReportLine ""
    Add-ReportLine "SPN inventory summary:"
    Add-ReportLine ("  - Total SPN objects      : {0}" -f $spnInv.Count)
    Add-ReportLine ("  - Explicit RC4 allowed   : {0}" -f $spnWithRc4.Count)
    Add-ReportLine ("  - RC4-only (high risk)   : {0}" -f $spnRc4Only.Count)
    Add-ReportLine ("  - DEFAULT (null/0)       : {0}" -f $spnDefault.Count)
    Add-ReportLine ("  - AES-only configured    : {0}" -f $spnAesOnly.Count)
    Add-ReportLine ("  - PasswordLastSet < 2008 : {0}" -f $spnPwdPre2008.Count)

    Add-ReportLine ""
    Add-ReportLine "Top 20 SPN objects to review:"
    $review | Sort-Object PasswordLastSet | Select-Object -First 20 | ForEach-Object {
        Add-ReportLine ("  - [{0}] {1} | Enc={2} ({3}) | PwdLastSet={4} | SPN={5}" -f `
            $_.ObjectType, $_.Name, $_.EncMask, $_.EncTypes, $_.PasswordLastSet, $_.SampleSPN)
    }
}

# -------------------------
# Check 5 - Legacy OS Inventory (Triage)
# -------------------------
if ($Config.RunLegacyOsInventory) {
    Add-Section "Check 5 - Legacy / At-Risk Endpoint Inventory (AD attribute triage)"

    Add-ReportLine "[i] This is triage based on AD 'OperatingSystem' strings."
    Add-ReportLine "    Correlate with readiness events (201/206) for proof."

    try {
        $legacy = Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, lastLogonTimestamp |
            Where-Object { $_.OperatingSystem -match $Config.LegacyOsRegex } |
            Select-Object Name, OperatingSystem, OperatingSystemVersion,
                @{n="LastLogonTimestamp";e={ if ($_.lastLogonTimestamp) { [DateTime]::FromFileTime($_.lastLogonTimestamp) } else { $null } }}

        $legacyCsv = Join-Path $outFolder "csv\Legacy-Computers.csv"
        $legacy | Export-Csv $legacyCsv -NoTypeInformation -Encoding UTF8
        Add-ReportLine ("[+] Legacy endpoint inventory exported: {0}" -f $legacyCsv)

        Add-ReportLine ""
        Add-ReportLine ("Legacy/at-risk candidates found: {0}" -f $legacy.Count)
        Add-ReportLine "Recommended actions:"
        Add-ReportLine "  - Verify these systems/appliances support Kerberos AES (AES128/AES256) and advertise it."
        Add-ReportLine "  - Patch/upgrade where possible."
        Add-ReportLine "  - For non-Windows Kerberos clients using keytabs: regenerate keytabs with AES + validate KVNO."

        $legacy | Sort-Object LastLogonTimestamp -Descending | Select-Object -First 20 | ForEach-Object {
            Add-ReportLine ("  - {0} | {1} | LastLogon={2}" -f $_.Name, $_.OperatingSystem, $_.LastLogonTimestamp)
        }
    }
    catch {
        Add-ReportLine ("[X] Legacy OS inventory failed: {0}" -f $_.Exception.Message)
    }
}

# -------------------------
# Final Playbook
# -------------------------
Add-Section "Operational Playbook - What to Fix First (Minimal Downtime Strategy)"
Add-ReportLine "1) Trust the DC events first (System log IDs 201-209). They are your best 'what will break' signals."
Add-ReportLine "   - 201/206 => client/device/keytab doesn't do AES (or doesn't advertise it)."
Add-ReportLine "   - 202/207 => service account missing AES keys (password rotation / migration issue)."
Add-ReportLine ""
Add-ReportLine "2) Fix root causes, not symptoms:"
Add-ReportLine "   - Upgrade/patch clients and appliances; regenerate keytabs with AES."
Add-ReportLine "   - Rotate service account passwords (and prefer gMSA) to ensure AES keys exist."
Add-ReportLine ""
Add-ReportLine "3) Use msDS-SupportedEncryptionTypes as a SCALPEL:"
Add-ReportLine "   - If legacy support is temporarily required, explicitly include RC4 ONLY on the specific service account that needs it."
Add-ReportLine "   - Avoid domain-wide DefaultDomainSupportedEncTypes overrides unless you fully understand and accept the blast radius."
Add-ReportLine ""
Add-ReportLine "4) Validate changes with evidence:"
Add-ReportLine "   - After remediation, re-run this script and verify readiness events stop appearing for remediated systems."
Add-ReportLine "   - Keep collecting events during the remediation window."

# Markdown report (optional)
if ($Config.WriteMarkdownReport) {
    try {
        $mdPath = Join-Path $outFolder "report\FindingsSummary.md"
        $md = @()
        $md += "# AD April '26 Check0r - Findings Summary"
        $md += ""
        $md += "**Created by:** Benjamin Iheukumere | SafLink IT"
        $md += ""
        $md += "## Output Folder"
        $md += ""
        $md += "````"
        $md += $outFolder
        $md += "````"
        $md += ""
        $md += "## Findings (TXT content)"
        $md += ""
        $md += "````"
        $md += $Global:ReportLines
        $md += "````"
        ($md -join "`r`n") | Set-Content -Path $mdPath -Encoding UTF8
        Add-ReportLine ("[+] Markdown report written: {0}" -f $mdPath)
    }
    catch {
        Add-ReportLine ("[!] Failed to write markdown report: {0}" -f $_.Exception.Message)
    }
}

Add-Section "Exports Created"
Add-ReportLine "CSV exports are located under: .\csv"
Add-ReportLine "Report files are located under: .\report"
Add-ReportLine "Logs are located under: .\logs"
Add-ReportLine ""
Add-ReportLine "Key files to review:"
Add-ReportLine "  - csv\KDC-ReadinessEvents.csv"
Add-ReportLine "  - csv\KDC-ReadinessEvents-Summary.csv"
Add-ReportLine "  - csv\SPN-Inventory-REVIEW.csv"
Add-ReportLine "  - csv\DC-KdcRegistryConfig.csv"
Add-ReportLine "  - csv\Legacy-Computers.csv"
Add-ReportLine "  - report\FindingsSummary.txt"

# Stop transcript last
if ($Config.UseTranscript) {
    try { Stop-Transcript | Out-Null } catch {}
}

Write-Host ""
Write-Host ("Done. Output folder: {0}" -f $outFolder) -ForegroundColor Green
Write-Host "AD April '26 Check0r finished." -ForegroundColor Green
