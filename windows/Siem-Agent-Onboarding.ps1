#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ONE self-contained script: no second file needed. Enables the P1/P2
    (+ extended) Windows log sources from the "SIEM Log Ingestion & Parsing
    SOP" and ships them to the SIEM collector/middleware via Winlogbeat or a
    Wazuh agent, with failover collectors and TLS.

.DESCRIPTION
    Runs two ways:
      1) Interactive — run it with no parameters and it prompts for everything.
      2) Non-interactive — pass parameters for unattended / fleet rollout
         (e.g. a GPO startup script or SCCM/Intune package); anything you
         don't pass is prompted for unless -NonInteractive is set, in which
         case a missing required value is a hard error.

    Log sources enabled:
      - Advanced Audit Policy subcategories (logon/logoff, account mgmt,
        process creation, privilege use, policy change; + Kerberos/DS
        Access on domain controllers for Kerberoasting/AS-REP/DCSync).
      - Command-line auditing on 4688.
      - PowerShell Module Logging + Script Block Logging (4103/4104).
      - Windows Firewall connection logging (allowed + blocked).
      - Task Scheduler, WMI-Activity, and Certificate Services operational
        logs (persistence / lateral-movement / cert-abuse coverage).
      - DNS Server analytical log, on domain controllers running DNS.
      - Optional Sysmon install/update.

.EXAMPLE
    .\Siem-Agent-Onboarding.ps1
    (fully interactive)

.EXAMPLE
    .\Siem-Agent-Onboarding.ps1 -Agent Winlogbeat -Role Server `
        -Collectors "siem-collector-1.internal:5044","siem-collector-2.internal:5044" `
        -Protocol tls -CaCertPath C:\PKI\ca.pem `
        -AgentInstallerPath C:\Staging\winlogbeat-8.14.0-windows-x86_64.zip `
        -IndexPrefix trident-windows -SiteTag kathmandu-dc1 -NonInteractive
#>

[CmdletBinding()]
param(
    [ValidateSet('Winlogbeat', 'Wazuh')][string]$Agent,
    [ValidateSet('DomainController', 'Server', 'Workstation')][string]$Role,
    [string[]]$Collectors,                      # "host:port" entries, first = primary
    [ValidateSet('tcp', 'tls')][string]$Protocol,
    [string]$CaCertPath,
    [string]$ClientCertPath,
    [string]$ClientKeyPath,
    [string]$AgentInstallerPath,
    [string]$IndexPrefix,
    [string]$SiteTag,
    [string]$SysmonInstallerPath,
    [string]$SysmonConfigPath,
    [string]$WazuhAuthPassword,
    [switch]$NonInteractive
)

$ErrorActionPreference = 'Stop'
function Write-Log  { param($msg) Write-Host "[siem-onboard] $msg" }
function Write-Warn2 { param($msg) Write-Warning "[siem-onboard] $msg" }

function Get-OrPrompt {
    param([string]$Value, [string]$Prompt, [string]$Default)
    if (-not [string]::IsNullOrWhiteSpace($Value)) { return $Value }
    if ($NonInteractive) { throw "Missing required value: $Prompt (NonInteractive mode)." }
    if ($Default) {
        $r = Read-Host "$Prompt [default: $Default]"
        if ([string]::IsNullOrWhiteSpace($r)) { return $Default } else { return $r }
    }
    return (Read-Host $Prompt)
}

function Get-OrPromptChoice {
    param([string]$Value, [string]$Prompt, [string[]]$Choices)
    if (-not [string]::IsNullOrWhiteSpace($Value)) { return $Value }
    if ($NonInteractive) { throw "Missing required value: $Prompt (NonInteractive mode)." }
    Write-Host $Prompt
    for ($i = 0; $i -lt $Choices.Count; $i++) { Write-Host "  $($i+1)) $($Choices[$i])" }
    while ($true) {
        $c = Read-Host "Enter choice [1-$($Choices.Count)]"
        if ($c -match '^\d+$' -and [int]$c -ge 1 -and [int]$c -le $Choices.Count) { return $Choices[[int]$c - 1] }
        Write-Host "Invalid choice." -ForegroundColor Yellow
    }
}

Write-Host "=============================================="
Write-Host " SIEM Log Onboarding - Windows (self-contained)"
Write-Host "=============================================="
Write-Host ""

# ===========================================================================
# 1. Collect answers
# ===========================================================================
$Agent = Get-OrPromptChoice -Value $Agent -Prompt "How are logs sent from this host to the SIEM middleware? (Filebeat is Linux-only - not offered here)" -Choices @('Winlogbeat', 'Wazuh')
Write-Log "Agent: $Agent"

$Role = Get-OrPromptChoice -Value $Role -Prompt "Host role?" -Choices @('DomainController', 'Server', 'Workstation')
Write-Log "Role: $Role"

$defaultPort = if ($Agent -eq 'Wazuh') { '1514' } else { '5044' }
if (-not $Collectors -or $Collectors.Count -eq 0) {
    $raw = Get-OrPrompt -Value $null -Prompt "Collector/middleware address(es) - comma-separated host:port for failover (e.g. siem1:$defaultPort,siem2:$defaultPort)"
    $Collectors = $raw -split ',' | ForEach-Object { $_.Trim() }
}
foreach ($c in $Collectors) {
    if ($c -notmatch ':') { throw "Collector '$c' must be host:port." }
}
Write-Log "Collectors: $($Collectors -join ', ')"

if ($Agent -eq 'Winlogbeat') {
    $Protocol = Get-OrPromptChoice -Value $Protocol -Prompt "Transport for Winlogbeat -> collector?" -Choices @('tcp', 'tls')
    if ($Protocol -eq 'tls') {
        $CaCertPath = Get-OrPrompt -Value $CaCertPath -Prompt "Path to CA certificate"
        if (-not (Test-Path $CaCertPath)) { throw "CA cert not found: $CaCertPath" }
        if (-not $NonInteractive -and -not $ClientCertPath) {
            $mtls = Read-Host "Use mutual TLS (client cert/key)? [y/N]"
            if ($mtls -match '^[Yy]') {
                $ClientCertPath = Get-OrPrompt -Value $ClientCertPath -Prompt "Path to client certificate"
                $ClientKeyPath  = Get-OrPrompt -Value $ClientKeyPath  -Prompt "Path to client private key"
            }
        }
    }
} else {
    $Protocol = 'wazuh-native'  # Wazuh's agent<->manager channel is always encrypted/authenticated
    if (-not $NonInteractive -and -not $WazuhAuthPassword) {
        $WazuhAuthPassword = Read-Host "Wazuh enrollment password (leave blank if manager allows unauthenticated auto-enrollment)"
    }
}

$IndexPrefix = Get-OrPrompt -Value $IndexPrefix -Prompt "Index/log-group prefix" -Default "trident-windows"
$SiteTag     = Get-OrPrompt -Value $SiteTag -Prompt "Site/location tag" -Default $env:COMPUTERNAME
$AgentInstallerPath = Get-OrPrompt -Value $AgentInstallerPath -Prompt "Path to the locally staged $Agent installer (.zip/.msi)"
if (-not (Test-Path $AgentInstallerPath)) { throw "Installer not found: $AgentInstallerPath" }

if (-not $NonInteractive -and -not $SysmonInstallerPath) {
    $installSysmon = Read-Host "Install/update Sysmon on this host? [y/N]"
    if ($installSysmon -match '^[Yy]') {
        $SysmonInstallerPath = Get-OrPrompt -Value $null -Prompt "Path to Sysmon64.exe"
        $SysmonConfigPath    = Get-OrPrompt -Value $null -Prompt "Path to Sysmon XML config"
    }
}
if ($SysmonInstallerPath -and -not (Test-Path $SysmonInstallerPath)) { throw "Sysmon installer not found: $SysmonInstallerPath" }
if ($SysmonConfigPath -and -not (Test-Path $SysmonConfigPath)) { throw "Sysmon config not found: $SysmonConfigPath" }

Write-Host ""
Write-Host "=============================================="
Write-Host " Summary"
Write-Host "=============================================="
Write-Host "  Agent:        $Agent"
Write-Host "  Role:         $Role"
Write-Host "  Collectors:   $($Collectors -join ', ')"
Write-Host "  Protocol:     $Protocol"
Write-Host "  Index prefix: $IndexPrefix"
Write-Host "  Site tag:     $SiteTag"
Write-Host "=============================================="
if (-not $NonInteractive) {
    $confirm = Read-Host "Proceed? [y/N]"
    if ($confirm -notmatch '^[Yy]') { Write-Log "Cancelled."; exit 0 }
}

# ===========================================================================
# 2. Advanced Audit Policy — SOP Sections 4.3 / 4.5 / 4.6
# ===========================================================================
Write-Log "Configuring Advanced Audit Policy subcategories for role: $Role ..."

$baseline = @(
    @{ Sub = 'Logon' }, @{ Sub = 'Logoff' }, @{ Sub = 'Account Lockout' }, @{ Sub = 'Special Logon' },
    @{ Sub = 'User Account Management' }, @{ Sub = 'Security Group Management' },
    @{ Sub = 'Process Creation' }, @{ Sub = 'Sensitive Privilege Use' },
    @{ Sub = 'Audit Policy Change' }, @{ Sub = 'Authentication Policy Change' },
    @{ Sub = 'Security State Change' }, @{ Sub = 'Security System Extension' }
)
$dcExtra = @(
    @{ Sub = 'Kerberos Authentication Service' }, @{ Sub = 'Kerberos Service Ticket Operations' },
    @{ Sub = 'Credential Validation' }, @{ Sub = 'Directory Service Access' },
    @{ Sub = 'Directory Service Changes' }, @{ Sub = 'Distribution Group Management' }
)
$subcategories = $baseline
if ($Role -eq 'DomainController') { $subcategories += $dcExtra }
foreach ($item in $subcategories) {
    & auditpol /set /subcategory:"$($item.Sub)" /success:enable /failure:enable | Out-Null
}
Write-Log "Applied $($subcategories.Count) audit subcategories."
if ($Role -eq 'DomainController') {
    Write-Warn2 "On domain controllers, Group Policy usually overrides local auditpol settings on refresh. Mirror this subcategory list into the Default Domain Controllers Policy for a durable baseline."
}

# ===========================================================================
# 3. Command-line auditing (4688) + PowerShell logging (4103/4104)
# ===========================================================================
Write-Log "Enabling command-line auditing and PowerShell logging..."
$auditPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
if (-not (Test-Path $auditPath)) { New-Item -Path $auditPath -Force | Out-Null }
New-ItemProperty -Path $auditPath -Name 'ProcessCreationIncludeCmdLine_Enabled' -PropertyType DWord -Value 1 -Force | Out-Null

$sblPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
if (-not (Test-Path $sblPath)) { New-Item -Path $sblPath -Force | Out-Null }
New-ItemProperty -Path $sblPath -Name 'EnableScriptBlockLogging' -PropertyType DWord -Value 1 -Force | Out-Null

$modPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
if (-not (Test-Path $modPath)) { New-Item -Path $modPath -Force | Out-Null }
New-ItemProperty -Path $modPath -Name 'EnableModuleLogging' -PropertyType DWord -Value 1 -Force | Out-Null
$modNamesPath = "$modPath\ModuleNames"
if (-not (Test-Path $modNamesPath)) { New-Item -Path $modNamesPath -Force | Out-Null }
New-ItemProperty -Path $modNamesPath -Name '*' -PropertyType String -Value '*' -Force | Out-Null

wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:524288000 /rt:false | Out-Null
wevtutil sl "Security" /ms:1073741824 /rt:false | Out-Null

# ===========================================================================
# 4. Extended host-level log sources
# ===========================================================================
Write-Log "Enabling extended log sources (Firewall, Task Scheduler, WMI-Activity, Cert Services)..."

# Windows Firewall connection logging (allowed + blocked)
foreach ($profile in @('Domain', 'Private', 'Public')) {
    Set-NetFirewallProfile -Profile $profile -LogAllowed True -LogBlocked True `
        -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall_$profile.log" `
        -LogMaxSizeKilobytes 16384 -ErrorAction SilentlyContinue
}

# Analytic/debug channels are disabled by default — enable, size, then re-disable
# only if the channel doesn't support live logging while enabled (most do not
# need re-disabling; Task Scheduler and WMI-Activity are Operational, not
# Analytic, so they stay enabled safely).
$extraChannels = @(
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-WMI-Activity/Operational',
    'Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational'
)
foreach ($ch in $extraChannels) {
    try {
        wevtutil sl $ch /e:true /ms:268435456 2>$null | Out-Null
    } catch {
        Write-Warn2 "Could not enable channel '$ch' (may not exist on this SKU) - skipping."
    }
}

# DNS Server analytical log — only meaningful (and only exists) on a DC/DNS server
$eventChannels = @(
    'Security', 'System',
    'Microsoft-Windows-Sysmon/Operational',
    'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-WMI-Activity/Operational'
)
if ($Role -eq 'DomainController') {
    $eventChannels += 'Directory Service'
    if (Get-Service -Name 'DNS' -ErrorAction SilentlyContinue) {
        try {
            wevtutil sl "Microsoft-Windows-DNSServer/Analytical" /e:true /ms:268435456 2>$null | Out-Null
            $eventChannels += 'Microsoft-Windows-DNSServer/Analytical'
            Write-Log "DNS Server analytical logging enabled."
        } catch {
            Write-Warn2 "Could not enable DNS Server analytical log - continuing without it."
        }
    }
}

# ===========================================================================
# 5. Sysmon (optional)
# ===========================================================================
if ($SysmonInstallerPath -and $SysmonConfigPath) {
    $sysmonService = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue
    if ($sysmonService) {
        Write-Log "Sysmon already installed - updating configuration..."
        & $SysmonInstallerPath -c $SysmonConfigPath -accepteula | Out-Null
    } else {
        Write-Log "Installing Sysmon..."
        & $SysmonInstallerPath -accepteula -i $SysmonConfigPath | Out-Null
    }
    wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824 /rt:false | Out-Null
    Write-Log "Sysmon installed/updated."
} else {
    Write-Warn2 "Sysmon not installed (no installer/config given) - recommended for lateral-movement, LSASS-access, and persistence detection."
}

# ===========================================================================
# 6. Agent install + config (Winlogbeat or Wazuh), with failover + TLS
# ===========================================================================
switch ($Agent) {

    'Winlogbeat' {
        Write-Log "Installing Winlogbeat..."
        $installDir = 'C:\Program Files\Winlogbeat'
        if (-not (Test-Path $installDir)) {
            if ($AgentInstallerPath -like '*.zip') {
                Expand-Archive -Path $AgentInstallerPath -DestinationPath 'C:\Program Files\' -Force
                $extracted = Get-ChildItem 'C:\Program Files\' -Directory | Where-Object { $_.Name -like 'winlogbeat-*' } | Select-Object -First 1
                if (-not $extracted) { throw "Could not locate extracted winlogbeat-* directory after unzip." }
                Rename-Item -Path $extracted.FullName -NewName 'Winlogbeat'
            } elseif ($AgentInstallerPath -like '*.msi') {
                Start-Process msiexec.exe -ArgumentList "/i `"$AgentInstallerPath`" /qn" -Wait
            } else {
                throw "AgentInstallerPath must be a .zip or .msi for Winlogbeat."
            }
        }

        $hostsYaml = ($Collectors | ForEach-Object { "`"$_`"" }) -join ', '
        $sslBlock = ""
        if ($Protocol -eq 'tls') {
            $sslBlock = "  ssl.certificate_authorities: [`"$CaCertPath`"]`n  ssl.verification_mode: full"
            if ($ClientCertPath -and $ClientKeyPath) {
                $sslBlock += "`n  ssl.certificate: `"$ClientCertPath`"`n  ssl.key: `"$ClientKeyPath`""
            }
        }

        $eventLogsYaml = ($eventChannels | ForEach-Object { "  - name: `"$_`"`n    ignore_older: 72h" }) -join "`n"

        $winlogbeatYml = Join-Path $installDir 'winlogbeat.yml'
        $winlogbeatConfig = @"
## Managed by Siem-Agent-Onboarding.ps1 — do not hand-edit
## Role: $Role | Site: $SiteTag

winlogbeat.event_logs:
$eventLogsYaml

processors:
  - add_host_metadata: ~
  - add_fields:
      target: ''
      fields:
        log_source_role: '$Role'
        site: '$SiteTag'
        collected_by: 'winlogbeat'
        index_prefix: '$IndexPrefix'

output.logstash:
  hosts: [$hostsYaml]
  loadbalance: true
  worker: 2
$sslBlock

setup.template.name: '$IndexPrefix'
setup.template.pattern: '$IndexPrefix-*'

logging.level: info
logging.to_files: true
logging.files:
  path: C:\ProgramData\winlogbeat\Logs
  name: winlogbeat
  keepfiles: 7
"@
        Set-Content -Path $winlogbeatYml -Value $winlogbeatConfig -Encoding UTF8

        Push-Location $installDir
        try {
            & .\winlogbeat.exe test config -c .\winlogbeat.yml -e
            if (-not (Get-Service -Name 'winlogbeat' -ErrorAction SilentlyContinue)) {
                & .\install-service-winlogbeat.ps1
            }
        } finally {
            Pop-Location
        }
        Set-Service -Name 'winlogbeat' -StartupType Automatic
        Start-Service -Name 'winlogbeat'
        Write-Log "Winlogbeat started -> $($Collectors -join ', ') ($Protocol, loadbalance=true)."
    }

    'Wazuh' {
        Write-Log "Installing Wazuh agent..."
        $primaryHost = ($Collectors[0] -split ':')[0]
        if (-not (Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue)) {
            if ($AgentInstallerPath -notlike '*.msi') { throw "AgentInstallerPath must be a .msi for Wazuh." }
            $msiArgs = "/i `"$AgentInstallerPath`" /q WAZUH_MANAGER=`"$primaryHost`" WAZUH_REGISTRATION_SERVER=`"$primaryHost`""
            Start-Process msiexec.exe -ArgumentList $msiArgs -Wait
        }

        $ossecConf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
        if (-not (Test-Path $ossecConf)) { throw "Wazuh agent installed but $ossecConf not found." }

        [xml]$xml = Get-Content $ossecConf

        # Failover: one <server> node per collector, in order (first = primary)
        $clientNode = $xml.ossec_config.client
        $clientNode.server | ForEach-Object { $clientNode.RemoveChild($_) | Out-Null }
        foreach ($c in $Collectors) {
            $parts = $c -split ':'
            $serverNode = $xml.CreateElement('server')
            $addrNode = $xml.CreateElement('address'); $addrNode.InnerText = $parts[0]
            $portNode = $xml.CreateElement('port');    $portNode.InnerText = $parts[1]
            $protoNode = $xml.CreateElement('protocol'); $protoNode.InnerText = 'tcp'
            $serverNode.AppendChild($addrNode) | Out-Null
            $serverNode.AppendChild($portNode) | Out-Null
            $serverNode.AppendChild($protoNode) | Out-Null
            $clientNode.AppendChild($serverNode) | Out-Null
        }

        $existing = $xml.ossec_config.localfile | Where-Object { $_.InnerText -match 'SIEM-MANAGED' }
        foreach ($node in $existing) { $xml.ossec_config.RemoveChild($node) | Out-Null }
        foreach ($channel in $eventChannels) {
            $lf = $xml.CreateElement('localfile')
            $lfFormat = $xml.CreateElement('log_format'); $lfFormat.InnerText = 'eventchannel'
            $lfLocation = $xml.CreateElement('location'); $lfLocation.InnerText = $channel
            $lf.AppendChild($lfFormat) | Out-Null
            $lf.AppendChild($lfLocation) | Out-Null
            $lf.AppendChild($xml.CreateComment('SIEM-MANAGED')) | Out-Null
            $xml.ossec_config.AppendChild($lf) | Out-Null
        }
        $xml.Save($ossecConf)

        Restart-Service -Name 'WazuhSvc' -Force
        $authArgs = @('-m', $primaryHost)
        if ($WazuhAuthPassword) { $authArgs += @('-P', $WazuhAuthPassword) }
        & 'C:\Program Files (x86)\ossec-agent\agent-auth.exe' @authArgs 2>$null
        Restart-Service -Name 'WazuhSvc' -Force
        Write-Log "Wazuh agent started -> $($Collectors.Count) manager(s), primary $primaryHost."
    }
}

Write-Log "Done. Verify events are arriving at the collector, then mark this host 'live' in the log source inventory (SOP Section 7.1)."
