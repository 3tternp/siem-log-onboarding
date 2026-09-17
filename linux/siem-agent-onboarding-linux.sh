#!/usr/bin/env bash
#
# siem-agent-onboarding.sh  — ONE self-contained script: no second file needed.
#
# Enables the P1/P2 (+ extended) Linux log sources from the "SIEM Log
# Ingestion & Parsing SOP" and ships them to the SIEM collector/middleware
# via Filebeat or a Wazuh agent, with failover collector support and TLS.
#
# Runs two ways:
#   1) Interactive  — run it with no flags and it asks everything.
#   2) Non-interactive — pass flags for unattended / fleet rollout (e.g. via
#      Ansible, cron, or a golden-image build step); anything you don't pass
#      that's required is prompted for, so a partial flag set still works
#      interactively for the rest.
#
# Usage (flags, all optional — omitted ones are prompted for):
#   sudo ./siem-agent-onboarding.sh \
#       -a filebeat|wazuh \
#       -r server|workstation \
#       -c "host1:port1,host2:port2"      # comma-separated for failover/load-balance
#       -P tcp|tls \
#       --ca /path/ca.pem --cert /path/client.pem --key /path/client-key.pem \
#       -i /path/to/agent-installer.deb \
#       --index-prefix trident-linux --site kathmandu-dc1 \
#       --wazuh-password '<enrollment password>' \
#       --non-interactive          # fail instead of prompting if something's missing
#
# Example:
#   sudo ./siem-agent-onboarding.sh -a filebeat -r server \
#       -c "siem-collector-1.internal:5044,siem-collector-2.internal:5044" \
#       -P tls --ca /etc/pki/ca.pem --cert /etc/pki/client.pem --key /etc/pki/client-key.pem \
#       --index-prefix trident-linux --site kathmandu-dc1
#
set -euo pipefail

LOG_TAG="[siem-onboard]"
log()  { echo "${LOG_TAG} $*"; }
warn() { echo "${LOG_TAG} WARNING: $*" >&2; }
die()  { echo "${LOG_TAG} ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 0. Args
# ---------------------------------------------------------------------------
AGENT=""; ROLE=""; COLLECTORS=""; PROTOCOL=""; CA_CERT=""; CLIENT_CERT=""; CLIENT_KEY=""
INSTALLER_PATH=""; INDEX_PREFIX=""; SITE_TAG=""; WAZUH_PASSWORD=""; NON_INTERACTIVE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -a) AGENT="$2"; shift 2 ;;
    -r) ROLE="$2"; shift 2 ;;
    -c) COLLECTORS="$2"; shift 2 ;;
    -P) PROTOCOL="$2"; shift 2 ;;
    --ca) CA_CERT="$2"; shift 2 ;;
    --cert) CLIENT_CERT="$2"; shift 2 ;;
    --key) CLIENT_KEY="$2"; shift 2 ;;
    -i) INSTALLER_PATH="$2"; shift 2 ;;
    --index-prefix) INDEX_PREFIX="$2"; shift 2 ;;
    --site) SITE_TAG="$2"; shift 2 ;;
    --wazuh-password) WAZUH_PASSWORD="$2"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^#//'; exit 0 ;;
    *) die "Unknown argument: $1 (use -h for help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Run as root (sudo)."

ask() {  # ask <varname> <prompt> [default]
  local __var="$1" __prompt="$2" __default="${3:-}" __val
  if [[ -n "${!__var}" ]]; then return; fi
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then die "Missing required value for --${__var,,} (non-interactive mode)."; fi
  if [[ -n "$__default" ]]; then
    read -rp "${__prompt} [default: ${__default}]: " __val
    __val="${__val:-$__default}"
  else
    read -rp "${__prompt}: " __val
  fi
  printf -v "$__var" '%s' "$__val"
}

ask_menu() {  # ask_menu <varname> <prompt> <opt1> <opt2> [...]
  local __var="$1" __prompt="$2"; shift 2
  local -a __opts=("$@")
  if [[ -n "${!__var}" ]]; then return; fi
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then die "Missing required value for ${__var} (non-interactive mode)."; fi
  echo "$__prompt"
  local i=1
  for o in "${__opts[@]}"; do echo "  $i) $o"; i=$((i+1)); done
  local choice
  while true; do
    read -rp "Enter choice [1-${#__opts[@]}]: " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#__opts[@]} )); then
      printf -v "$__var" '%s' "${__opts[$((choice-1))]}"
      return
    fi
    echo "Invalid choice."
  done
}

echo "=============================================="
echo " SIEM Log Onboarding — Linux (self-contained)"
echo "=============================================="
echo

# ---------------------------------------------------------------------------
# 1. Collect answers
# ---------------------------------------------------------------------------
ask_menu AGENT "How are logs sent from this host to the SIEM middleware?
  (Winlogbeat is Windows-only — not offered here)" "filebeat" "wazuh"
log "Agent: $AGENT"

ask_menu ROLE "Host role?" "server" "workstation"
log "Role: $ROLE"

DEFAULT_PORT="5044"; [[ "$AGENT" == "wazuh" ]] && DEFAULT_PORT="1514"
ask COLLECTORS "Collector/middleware address(es) — comma-separated host:port for failover (e.g. siem1:${DEFAULT_PORT},siem2:${DEFAULT_PORT})"
IFS=',' read -ra COLLECTOR_ARR <<< "$COLLECTORS"
[[ ${#COLLECTOR_ARR[@]} -gt 0 ]] || die "No collector addresses given."
for c in "${COLLECTOR_ARR[@]}"; do
  [[ "$c" == *:* ]] || die "Collector '$c' must be host:port."
done

if [[ "$AGENT" == "filebeat" ]]; then
  ask_menu PROTOCOL "Transport for Filebeat -> collector?" "tcp" "tls"
  if [[ "$PROTOCOL" == "tls" ]]; then
    ask CA_CERT "Path to CA certificate"
    [[ -f "$CA_CERT" ]] || die "CA cert not found: $CA_CERT"
    if [[ "$NON_INTERACTIVE" -eq 0 && -z "$CLIENT_CERT" ]]; then
      read -rp "Use mutual TLS (client cert/key)? [y/N]: " mtls
      if [[ "$mtls" =~ ^[Yy]$ ]]; then
        ask CLIENT_CERT "Path to client certificate"
        ask CLIENT_KEY "Path to client private key"
      fi
    fi
  fi
else
  PROTOCOL="wazuh-native"  # Wazuh's agent<->manager channel is always encrypted/authenticated
fi

ask INDEX_PREFIX "Index/log-group prefix (e.g. trident-linux)" "trident-linux"
ask SITE_TAG "Site/location tag (e.g. kathmandu-dc1)" "$(hostname)"
ask INSTALLER_PATH "Path to a locally staged ${AGENT} installer (.deb/.rpm), or leave blank for vendor repo" " "
[[ "$INSTALLER_PATH" == " " ]] && INSTALLER_PATH=""
if [[ -n "$INSTALLER_PATH" && ! -f "$INSTALLER_PATH" ]]; then die "Installer not found: $INSTALLER_PATH"; fi

if [[ "$AGENT" == "wazuh" && "$NON_INTERACTIVE" -eq 0 && -z "$WAZUH_PASSWORD" ]]; then
  read -rp "Wazuh enrollment password (leave blank if manager allows unauthenticated auto-enrollment): " WAZUH_PASSWORD
fi

echo
echo "=============================================="
echo " Summary"
echo "=============================================="
echo "  Agent:        $AGENT"
echo "  Role:         $ROLE"
echo "  Collectors:   $COLLECTORS"
echo "  Protocol:     $PROTOCOL"
echo "  Index prefix: $INDEX_PREFIX"
echo "  Site tag:     $SITE_TAG"
echo "=============================================="
if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
  read -rp "Proceed? [y/N]: " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { log "Cancelled."; exit 0; }
fi

# ---------------------------------------------------------------------------
# 2. Package manager detection
# ---------------------------------------------------------------------------
PKG_MGR=""
if command -v apt-get >/dev/null 2>&1; then PKG_MGR="apt"
elif command -v dnf >/dev/null 2>&1; then PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then PKG_MGR="yum"
else die "Unsupported distro: no apt-get, dnf, or yum found."
fi
log "Package manager: $PKG_MGR"
pkg_install() {
  case "$PKG_MGR" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get install -y "$1" ;;
    dnf) dnf install -y "$1" ;;
    yum) yum install -y "$1" ;;
  esac
}

if [[ -f /etc/os-release ]] && grep -qiE 'debian|ubuntu' /etc/os-release; then
  AUTH_LOG="/var/log/auth.log"
else
  AUTH_LOG="/var/log/secure"
fi

# ===========================================================================
# 3. auditd — install, enable, SOP-aligned + extended rules
# ===========================================================================
log "Ensuring auditd is installed and enabled..."
if ! command -v auditctl >/dev/null 2>&1; then
  case "$PKG_MGR" in
    apt) pkg_install auditd; pkg_install audispd-plugins || true ;;
    dnf|yum) pkg_install audit ;;
  esac
fi
systemctl enable --now auditd

AUDIT_RULES_FILE="/etc/audit/rules.d/90-siem-onboard.rules"
log "Writing audit rules to ${AUDIT_RULES_FILE}..."

if [[ "$(uname -m)" == "x86_64" ]]; then
  ARCH_RULES=$'-a always,exit -F arch=b64 -S execve -k exec\n-a always,exit -F arch=b32 -S execve -k exec'
else
  ARCH_RULES="-a always,exit -F arch=b32 -S execve -k exec"
fi

cat > "$AUDIT_RULES_FILE" <<EOF
## Managed by siem-agent-onboarding.sh — SOP Section 4.4/4.7 + extended sources
## Do not edit by hand; re-run the script to update.

# --- Identity / credential files (P1) ---
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity

# --- SSH configuration (P1) ---
-w /etc/ssh/sshd_config -p wa -k sshd_config

# --- Command execution audit trail (P1) ---
${ARCH_RULES}

# --- Cron / persistence (P2) ---
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# --- systemd timers/units — extended persistence coverage ---
-w /etc/systemd/system/ -p wa -k systemd_persistence
-w /lib/systemd/system/ -p wa -k systemd_persistence

# --- Package manager / software install-remove (P1/P2) ---
-w /usr/bin/dpkg -p x -k software_mgmt
-w /usr/bin/apt -p x -k software_mgmt
-w /usr/bin/apt-get -p x -k software_mgmt
-w /usr/bin/rpm -p x -k software_mgmt
-w /usr/bin/yum -p x -k software_mgmt
-w /usr/bin/dnf -p x -k software_mgmt

# --- Local firewall tampering (P2) ---
-w /etc/firewalld/ -p wa -k firewall
-w /etc/iptables/ -p wa -k firewall
-w /etc/nftables.conf -p wa -k firewall

# --- Network config integrity (P2, extended) ---
-w /etc/hosts -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config
-w /etc/NetworkManager/ -p wa -k network_config

# --- Kernel module load/unload — extended (rootkit/LKM tamper) ---
-w /sbin/insmod -p x -k module_load
-w /sbin/rmmod -p x -k module_load
-w /sbin/modprobe -p x -k module_load

# --- SIEM/agent config tamper watch (P1) ---
-w /etc/filebeat/ -p wa -k siem_tamper
-w /var/ossec/etc/ -p wa -k siem_tamper
-w /etc/audit/ -p wa -k siem_tamper
-w /etc/rsyslog.conf -p wa -k siem_tamper
-w /etc/rsyslog.d/ -p wa -k siem_tamper
EOF

if command -v augenrules >/dev/null 2>&1; then augenrules --load; else auditctl -R "$AUDIT_RULES_FILE"; fi
log "auditd rules loaded ($(auditctl -l | wc -l) rules active)."

# ===========================================================================
# 4. Extended host-level log sources
# ===========================================================================
log "Enabling extended log sources..."

# journald: make sure it forwards to syslog so file-based tailing (Filebeat)
# and Wazuh's syslog localfile both see it even on journald-only distros.
if [[ -f /etc/systemd/journald.conf ]]; then
  sed -i 's/^#\?ForwardToSyslog=.*/ForwardToSyslog=yes/' /etc/systemd/journald.conf
  grep -q '^ForwardToSyslog=' /etc/systemd/journald.conf || echo 'ForwardToSyslog=yes' >> /etc/systemd/journald.conf
  systemctl restart systemd-journald || true
fi

# sshd: verbose logging surfaces key fingerprints and auth method detail
# that plain INFO level omits — useful for credential-access investigations.
if [[ -f /etc/ssh/sshd_config ]]; then
  if grep -q '^LogLevel' /etc/ssh/sshd_config; then
    sed -i 's/^LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
  else
    echo 'LogLevel VERBOSE' >> /etc/ssh/sshd_config
  fi
  systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
fi

# firewalld: log denied (and optionally all) traffic to the journal/syslog
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
  firewall-cmd --set-log-denied=all --permanent || true
  firewall-cmd --reload || true
  log "firewalld log-denied set to 'all'."
fi

# ufw (Debian/Ubuntu alternative firewall)
if command -v ufw >/dev/null 2>&1 && ufw status | grep -qi active; then
  ufw logging on
  log "ufw logging enabled."
fi

# BIND/named DNS query logging, if the host runs it (only relevant on DNS servers)
if command -v rndc >/dev/null 2>&1 && systemctl is-active --quiet named 2>/dev/null; then
  rndc querylog on || true
  log "BIND query logging enabled (rndc querylog on)."
fi

log "Auth log confirmed at ${AUTH_LOG}. rsyslog active: $(systemctl is-active rsyslog 2>/dev/null || echo unknown)"

# ===========================================================================
# 5. Agent install + config (Filebeat or Wazuh), with failover + TLS
# ===========================================================================
case "$AGENT" in

  filebeat)
    log "Installing Filebeat..."
    if ! command -v filebeat >/dev/null 2>&1; then
      if [[ -n "$INSTALLER_PATH" ]]; then
        case "$PKG_MGR" in
          apt) dpkg -i "$INSTALLER_PATH" || apt-get -f install -y ;;
          dnf|yum) rpm -ivh "$INSTALLER_PATH" ;;
        esac
      else
        warn "No installer given — attempting Elastic's public repo (requires internet egress)."
        case "$PKG_MGR" in
          apt)
            pkg_install apt-transport-https
            wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
            echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
              > /etc/apt/sources.list.d/elastic-8.x.list
            apt-get update && pkg_install filebeat
            ;;
          dnf|yum)
            cat > /etc/yum.repos.d/elastic.repo <<'REPO'
[elastic-8.x]
name=Elastic repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
REPO
            pkg_install filebeat
            ;;
        esac
      fi
    fi

    # Build the hosts: [...] YAML list from the comma-separated collectors
    HOSTS_YAML=""
    for c in "${COLLECTOR_ARR[@]}"; do HOSTS_YAML+="\"${c}\", "; done
    HOSTS_YAML="[${HOSTS_YAML%, }]"

    SSL_BLOCK=""
    if [[ "$PROTOCOL" == "tls" ]]; then
      SSL_BLOCK="  ssl.certificate_authorities: [\"${CA_CERT}\"]"$'\n'"  ssl.verification_mode: full"
      if [[ -n "$CLIENT_CERT" && -n "$CLIENT_KEY" ]]; then
        SSL_BLOCK+=$'\n'"  ssl.certificate: \"${CLIENT_CERT}\""$'\n'"  ssl.key: \"${CLIENT_KEY}\""
      fi
    fi

    FILEBEAT_YML="/etc/filebeat/filebeat.yml"
    log "Writing ${FILEBEAT_YML} (failover across ${#COLLECTOR_ARR[@]} collector(s))..."
    cat > "$FILEBEAT_YML" <<EOF
## Managed by siem-agent-onboarding.sh — do not hand-edit
## Role: ${ROLE} | Site: ${SITE_TAG}

filebeat.inputs:
  - type: log
    id: auth-log
    enabled: true
    paths: [${AUTH_LOG}]
    fields: { log_type: auth }
    fields_under_root: false
    tags: ["auth", "linux", "${ROLE}"]

  - type: log
    id: audit-log
    enabled: true
    paths: [/var/log/audit/audit.log]
    fields: { log_type: auditd }
    tags: ["auditd", "linux", "${ROLE}"]

  - type: log
    id: syslog
    enabled: true
    paths: ["/var/log/syslog", "/var/log/messages"]
    fields: { log_type: syslog }
    tags: ["syslog", "linux", "${ROLE}"]

  - type: log
    id: cron-log
    enabled: true
    paths: ["/var/log/cron", "/var/log/cron.log"]
    fields: { log_type: cron }
    tags: ["cron", "linux", "${ROLE}"]

processors:
  - add_host_metadata: ~
  - add_fields:
      target: ""
      fields:
        log_source_role: "${ROLE}"
        site: "${SITE_TAG}"
        collected_by: "filebeat"
        index_prefix: "${INDEX_PREFIX}"

output.logstash:
  hosts: ${HOSTS_YAML}
  loadbalance: true
  worker: 2
${SSL_BLOCK}

setup.ilm.enabled: false
setup.template.name: "${INDEX_PREFIX}"
setup.template.pattern: "${INDEX_PREFIX}-*"

logging.level: info
logging.to_files: true
logging.files: { path: /var/log/filebeat, name: filebeat, keepfiles: 7, permissions: "0640" }
EOF

    filebeat test config -c "$FILEBEAT_YML" || die "Filebeat config failed validation — check ${FILEBEAT_YML}."
    systemctl enable --now filebeat
    log "Filebeat started -> ${COLLECTORS} (${PROTOCOL}, loadbalance=true)."
    ;;

  wazuh)
    log "Installing Wazuh agent..."
    PRIMARY_HOST="${COLLECTOR_ARR[0]%%:*}"
    if [[ ! -x /var/ossec/bin/wazuh-control ]]; then
      if [[ -n "$INSTALLER_PATH" ]]; then
        case "$PKG_MGR" in
          apt) WAZUH_MANAGER="$PRIMARY_HOST" dpkg -i "$INSTALLER_PATH" || apt-get -f install -y ;;
          dnf|yum) WAZUH_MANAGER="$PRIMARY_HOST" rpm -ivh "$INSTALLER_PATH" ;;
        esac
      else
        warn "No installer given — attempting Wazuh's public repo (requires internet egress)."
        case "$PKG_MGR" in
          apt)
            wget -qO - https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
            echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
              > /etc/apt/sources.list.d/wazuh.list
            apt-get update
            WAZUH_MANAGER="$PRIMARY_HOST" pkg_install wazuh-agent
            ;;
          dnf|yum)
            cat > /etc/yum.repos.d/wazuh.repo <<'REPO'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPO
            WAZUH_MANAGER="$PRIMARY_HOST" pkg_install wazuh-agent
            ;;
        esac
      fi
    fi

    OSSEC_CONF="/var/ossec/etc/ossec.conf"
    [[ -f "$OSSEC_CONF" ]] || die "Wazuh agent installed but ${OSSEC_CONF} not found."

    # Build one <server> block per collector for failover, in manager order.
    SERVER_BLOCKS=""
    for c in "${COLLECTOR_ARR[@]}"; do
      h="${c%%:*}"; p="${c##*:}"
      SERVER_BLOCKS+="    <server><address>${h}</address><port>${p}</port><protocol>tcp</protocol></server>"$'\n'
    done

    python3 - "$OSSEC_CONF" "$SERVER_BLOCKS" "$AUTH_LOG" <<'PYEOF'
import sys, re
path, servers, auth_log = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f:
    content = f.read()

# Replace the <client><server>...</server></client> block(s) with our failover set
content = re.sub(
    r"(<client>).*?(</client>)",
    lambda m: m.group(1) + "\n" + servers + "  " + m.group(2),
    content, count=1, flags=re.DOTALL,
)

# Strip any previous SIEM-managed localfile block, then add a fresh one
content = re.sub(r"<!-- SIEM-MANAGED-BEGIN -->.*?<!-- SIEM-MANAGED-END -->", "", content, flags=re.DOTALL)
localfiles = f"""<!-- SIEM-MANAGED-BEGIN -->
  <localfile><log_format>audit</log_format><location>/var/log/audit/audit.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>{auth_log}</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/syslog</location></localfile>
<!-- SIEM-MANAGED-END -->
"""
content = content.replace("</ossec_config>", localfiles + "</ossec_config>")

with open(path, "w") as f:
    f.write(content)
PYEOF

    systemctl enable --now wazuh-agent
    if [[ -n "$WAZUH_PASSWORD" ]]; then
      /var/ossec/bin/agent-auth -m "$PRIMARY_HOST" -P "$WAZUH_PASSWORD" || warn "agent-auth failed — check the enrollment password / manager reachability."
    else
      /var/ossec/bin/agent-auth -m "$PRIMARY_HOST" || warn "agent-auth failed/skipped — the agent may already be registered."
    fi
    systemctl restart wazuh-agent
    log "Wazuh agent started -> ${#COLLECTOR_ARR[@]} manager(s), primary ${PRIMARY_HOST}."
    ;;
esac

log "Done. Verify events are arriving at the collector, then mark this host 'live' in the log source inventory (SOP Section 7.1)."
