# SIEM Log Onboarding

Self-contained onboarding scripts that enable the must-have/should-have log
sources defined in [`docs/SIEM_Log_Ingestion_Parsing_SOP.docx`](docs/SIEM_Log_Ingestion_Parsing_SOP.docx)
and ship them to a SIEM collector/middleware via Winlogbeat, Filebeat, or a
Wazuh agent.

## Contents

| Path | Platform | What it does |
| --- | --- | --- |
| `windows/Siem-Agent-Onboarding.ps1` | Windows Server / Domain Controller / Workstation | Enables Advanced Audit Policy subcategories, command-line auditing, PowerShell logging, Windows Firewall/Task Scheduler/WMI-Activity/Cert Services logging, optional Sysmon, then installs & configures Winlogbeat or a Wazuh agent |
| `linux/siem-agent-onboarding-linux.sh` | Linux Server / Workstation | Enables auditd rules (identity, execve, cron, package mgmt, firewall), sshd/firewalld/journald hardening, then installs & configures Filebeat or a Wazuh agent |
| `docs/SIEM_Log_Ingestion_Parsing_SOP.docx` | — | The SOP these scripts implement: must-have/should-have log sources by asset class, SOC/IR use-case mapping, collector sizing, retention, and validation checklists |

## Quick start

### Windows (run as Administrator)

```powershell
# Interactive — prompts for agent, role, collector(s), etc.
.\windows\Siem-Agent-Onboarding.ps1

# Non-interactive / fleet rollout
.\windows\Siem-Agent-Onboarding.ps1 -Agent Winlogbeat -Role Server `
    -Collectors "siem-collector-1.internal:5044","siem-collector-2.internal:5044" `
    -Protocol tls -CaCertPath C:\PKI\ca.pem `
    -AgentInstallerPath C:\Staging\winlogbeat-8.14.0-windows-x86_64.zip `
    -IndexPrefix trident-windows -SiteTag kathmandu-dc1 -NonInteractive
```

If script execution is blocked by policy:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\Siem-Agent-Onboarding.ps1
```

### Linux (run as root)

```bash
# Interactive
sudo ./linux/siem-agent-onboarding-linux.sh

# Non-interactive / fleet rollout
sudo ./linux/siem-agent-onboarding-linux.sh -a filebeat -r server \
    -c "siem-collector-1.internal:5044,siem-collector-2.internal:5044" \
    -P tls --ca /etc/pki/ca.pem --cert /etc/pki/client.pem --key /etc/pki/client-key.pem \
    --index-prefix trident-linux --site kathmandu-dc1 --non-interactive
```

## Notes

- Both scripts support failover across multiple collector addresses and optional (mutual) TLS.
- Agent installers are expected to be staged locally (`-AgentInstallerPath` / `-i`) for restricted-egress environments; a public-repo fallback is included for hosts with internet access.
- Test on a lab host before rolling out to production servers or domain controllers — the Windows script changes Advanced Audit Policy and PowerShell logging registry keys, and the Linux script loads new auditd rules.
- After onboarding a host, verify events are arriving at the collector and mark it "live" in the log source inventory (SOP Section 7.1).

## License

Internal use — Vairav Technology Security / CSOC.
