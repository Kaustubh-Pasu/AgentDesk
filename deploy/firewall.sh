#!/usr/bin/env bash
# Host firewall for the Agent Desk VPS (Ubuntu/Debian, ufw + iptables DOCKER-USER chain). Run as root, once.
#   ./firewall.sh            apply          ./firewall.sh --dry-run   print only
# Layer 1: only 22 (key-only SSH), 80, 443 are reachable. Database/Redis/app ports are never published by compose.
# Layer 2: the scraper's egress network may reach PUBLIC addresses only — an independent second layer behind the
#          application's own SSRF policy (private, link-local, CGNAT, metadata and multicast ranges are dropped).
set -euo pipefail

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1
SSH_SOURCE="${SSH_SOURCE:-}"                 # optional: restrict SSH to one CIDR, e.g. SSH_SOURCE=198.51.100.4/32
SCRAPER_SUBNET="172.30.3.0/24"               # must match networks.scrape_egress in docker-compose.yml
CONTROL_SUBNET="172.30.2.0/24"               # must match networks.egress
DENIED_V4=(0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24
           192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4)

run() { if (( DRY_RUN )); then printf '+ %s\n' "$*"; else "$@"; fi; }

[[ $EUID -eq 0 || $DRY_RUN -eq 1 ]] || { echo "run as root" >&2; exit 1; }

run ufw --force reset
run ufw default deny incoming
run ufw default allow outgoing
if [[ -n "$SSH_SOURCE" ]]; then run ufw allow from "$SSH_SOURCE" to any port 22 proto tcp; else run ufw limit 22/tcp; fi
run ufw allow 80/tcp
run ufw allow 443/tcp
run ufw allow 443/udp
run ufw --force enable

# Docker bypasses ufw for forwarded traffic, so container egress rules go into DOCKER-USER.
run iptables -N AGENTDESK-EGRESS 2>/dev/null || run iptables -F AGENTDESK-EGRESS
for net in "${DENIED_V4[@]}"; do
  run iptables -A AGENTDESK-EGRESS -d "$net" -j DROP
done
run iptables -A AGENTDESK-EGRESS -p tcp -m multiport --dports 80,443 -j RETURN
run iptables -A AGENTDESK-EGRESS -p udp --dport 53 -j RETURN
run iptables -A AGENTDESK-EGRESS -p tcp --dport 53 -j RETURN
run iptables -A AGENTDESK-EGRESS -j DROP
for subnet in "$SCRAPER_SUBNET" "$CONTROL_SUBNET"; do
  run iptables -C DOCKER-USER -s "$subnet" -j AGENTDESK-EGRESS 2>/dev/null || run iptables -I DOCKER-USER -s "$subnet" -j AGENTDESK-EGRESS
done
# NOTE: the docker embedded DNS (127.0.0.11) is reached inside the container's namespace and is unaffected.

# SSH: keys only.
if [[ -d /etc/ssh/sshd_config.d ]]; then
  if (( DRY_RUN )); then echo "+ write /etc/ssh/sshd_config.d/10-agentdesk.conf (PasswordAuthentication no, PermitRootLogin prohibit-password)";
  else printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n' > /etc/ssh/sshd_config.d/10-agentdesk.conf
       systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true; fi
fi
echo "firewall applied. Verify from OUTSIDE:  nmap -Pn -p 22,80,443,5432,6379,8000 <public-ip>   (only 22/80/443 may be open)"
echo "persist iptables rules with:  apt-get install -y iptables-persistent && netfilter-persistent save"
