#!/bin/bash
set -euo pipefail

# ---------------------------------------------
# AP EcoFlow MQTT DNS Redirect - run.sh
# - Uses hostapd + udhcpd + dnsmasq (DNS-only)
# - DNAT all client DNS:53 -> AP IP:53 (forces our dnsmasq)
# - NAT/forwarding via DOCKER-USER chain on HAOS
# - Debug: tcpdump DNS + MQTT
# ---------------------------------------------

reset_interfaces(){
    ifdown "${INTERFACE:-wlan0}" 2>/dev/null || true
    sleep 1
    ip link set "${INTERFACE:-wlan0}" down 2>/dev/null || true
    ip addr flush dev "${INTERFACE:-wlan0}" 2>/dev/null || true
}

kill_pidfile(){
    local f="$1"
    if [ -f "$f" ]; then
        kill "$(cat "$f")" 2>/dev/null || true
        rm -f "$f"
    fi
}

term_handler(){
    echo "Resetting interfaces"
    reset_interfaces
    kill_pidfile /tmp/dnsmasq.hotspot.pid
    kill_pidfile /tmp/tcpdump.dns.pid
    kill_pidfile /tmp/tcpdump.mqtt.pid
    echo "Stopping..."
    exit 0
}
trap 'term_handler' SIGTERM

echo "Starting..."

CONFIG_PATH=/data/options.json

# ---------- Read options ----------
SSID=$(jq --raw-output ".ssid" "$CONFIG_PATH")
WPA_PASSPHRASE=$(jq --raw-output ".wpa_passphrase" "$CONFIG_PATH")
CHANNEL=$(jq --raw-output ".channel" "$CONFIG_PATH")
ADDRESS=$(jq --raw-output ".address" "$CONFIG_PATH")
NETMASK=$(jq --raw-output ".netmask" "$CONFIG_PATH")
BROADCAST=$(jq --raw-output ".broadcast" "$CONFIG_PATH")
INTERFACE=$(jq --raw-output ".interface" "$CONFIG_PATH")
INTERNET_IF=$(jq --raw-output ".internet_interface" "$CONFIG_PATH")
ALLOW_INTERNET=$(jq --raw-output ".allow_internet" "$CONFIG_PATH")
HIDE_SSID=$(jq --raw-output ".hide_ssid" "$CONFIG_PATH")

DHCP_SERVER=$(jq --raw-output ".dhcp_enable" "$CONFIG_PATH")
DHCP_START=$(jq --raw-output ".dhcp_start" "$CONFIG_PATH")
DHCP_END=$(jq --raw-output ".dhcp_end" "$CONFIG_PATH")
DHCP_DNS=$(jq --raw-output ".dhcp_dns" "$CONFIG_PATH")
DHCP_SUBNET=$(jq --raw-output ".dhcp_subnet" "$CONFIG_PATH")
DHCP_ROUTER=$(jq --raw-output ".dhcp_router" "$CONFIG_PATH")

DNS_OVERRIDE_ENABLED=$(jq --raw-output ".dns_override_enabled" "$CONFIG_PATH")
REDIRECT_MQTT_HOST=$(jq --raw-output ".redirect_mqtt_host" "$CONFIG_PATH")
REDIRECT_TARGET_IP=$(jq --raw-output ".redirect_target_ip" "$CONFIG_PATH")
REDIRECT_TARGET_PORT=$(jq --raw-output ".redirect_target_port" "$CONFIG_PATH")

LEASE_TIME=$(jq --raw-output ".lease_time" "$CONFIG_PATH")
STATIC_LEASES=$(jq -r '.static_leases[] | "\(.mac),\(.ip),\(.name)"' "$CONFIG_PATH" 2>/dev/null || true)

# ---------- Validate ----------
required_vars=(SSID WPA_PASSPHRASE ADDRESS NETMASK BROADCAST INTERFACE INTERNET_IF)
for required_var in "${required_vars[@]}"; do
    if [[ -z "${!required_var}" || "${!required_var}" == "null" ]]; then
        echo >&2 "Error: $required_var not set."
        exit 1
    fi
done

# hostapd requires 8..63 chars for wpa_passphrase
if [[ -z "${WPA_PASSPHRASE}" || "${WPA_PASSPHRASE}" == "null" ]]; then
    echo >&2 "Error: wpa_passphrase is empty/null. Refusing to start an open AP."
    exit 1
fi
if [[ ${#WPA_PASSPHRASE} -lt 8 || ${#WPA_PASSPHRASE} -gt 63 ]]; then
    echo >&2 "Error: wpa_passphrase must be 8..63 characters (got ${#WPA_PASSPHRASE})."
    exit 1
fi

if [[ -z "${CHANNEL}" || "${CHANNEL}" == "null" || "${CHANNEL}" == "0" ]]; then
    echo "Channel is 0/empty -> forcing channel=6"
    CHANNEL=6
fi

echo "Set nmcli managed no"
nmcli dev set "${INTERFACE}" managed no 2>/dev/null || true
echo "Network interface set to ${INTERFACE}"

# ---------- Forwarding ----------
echo "Enabling IPv4 forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
CUR_FWD="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"
echo "ip_forward=${CUR_FWD}"

# ---------- Redirect target IP detection ----------
if [[ -z "${REDIRECT_TARGET_IP}" || "${REDIRECT_TARGET_IP}" == "null" ]]; then
    REDIRECT_TARGET_IP="$(ip -4 addr show dev "${INTERNET_IF}" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
fi
if [[ -z "${REDIRECT_TARGET_IP}" ]]; then
    REDIRECT_TARGET_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
fi
if [[ -z "${REDIRECT_TARGET_IP}" ]]; then
    echo >&2 "Error: redirect_target_ip is empty and could not be auto-detected."
    exit 1
fi

echo "Redirect target: ${REDIRECT_MQTT_HOST} -> ${REDIRECT_TARGET_IP}:${REDIRECT_TARGET_PORT}"

echo "Testing TCP reachability to broker from host namespace..."
nc -zvw3 "${REDIRECT_TARGET_IP}" "${REDIRECT_TARGET_PORT}" \
  && echo "Broker port reachable" \
  || echo "Broker port NOT reachable"

# ---------- Networking values ----------
AP_CIDR="${ADDRESS}/24"

# ---------------------------------------------
# IPTABLES (DOCKER-USER chain)
# ---------------------------------------------
echo "Configuring iptables forwarding/NAT (DOCKER-USER)..."

iptables -N ECOFLOW_AP 2>/dev/null || true
iptables -F ECOFLOW_AP

if iptables -L DOCKER-USER >/dev/null 2>&1; then
  iptables -C DOCKER-USER -j ECOFLOW_AP 2>/dev/null || iptables -I DOCKER-USER 1 -j ECOFLOW_AP
  echo "Using DOCKER-USER -> ECOFLOW_AP"
else
  iptables -C FORWARD -j ECOFLOW_AP 2>/dev/null || iptables -I FORWARD 1 -j ECOFLOW_AP
  echo "DOCKER-USER not present; using FORWARD -> ECOFLOW_AP"
fi

# Allow return traffic (uplink -> AP)
iptables -C ECOFLOW_AP -i "${INTERNET_IF}" -o "${INTERFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -A ECOFLOW_AP -i "${INTERNET_IF}" -o "${INTERFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT

# NAT out uplink
iptables -t nat -C POSTROUTING -s "${AP_CIDR}" -o "${INTERNET_IF}" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s "${AP_CIDR}" -o "${INTERNET_IF}" -j MASQUERADE

if [[ "${ALLOW_INTERNET}" == "true" ]]; then
  echo "Internet access enabled (full NAT like Pi)."
  iptables -C ECOFLOW_AP -i "${INTERFACE}" -o "${INTERNET_IF}" -j ACCEPT 2>/dev/null || \
    iptables -A ECOFLOW_AP -i "${INTERFACE}" -o "${INTERNET_IF}" -j ACCEPT
else
  echo "Internet access disabled; allowing only broker access tcp/${REDIRECT_TARGET_PORT} -> ${REDIRECT_TARGET_IP}"
  iptables -C ECOFLOW_AP -i "${INTERFACE}" -o "${INTERNET_IF}" -p tcp -d "${REDIRECT_TARGET_IP}" --dport "${REDIRECT_TARGET_PORT}" -m state --state NEW,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -A ECOFLOW_AP -i "${INTERFACE}" -o "${INTERNET_IF}" -p tcp -d "${REDIRECT_TARGET_IP}" --dport "${REDIRECT_TARGET_PORT}" -m state --state NEW,ESTABLISHED -j ACCEPT
  iptables -C ECOFLOW_AP -i "${INTERFACE}" -o "${INTERNET_IF}" -j DROP 2>/dev/null || \
    iptables -A ECOFLOW_AP -i "${INTERFACE}" -o "${INTERNET_IF}" -j DROP
fi

echo "iptables (filter/ECOFLOW_AP):"
iptables -vnL ECOFLOW_AP || true

# ---------------------------------------------
# DNS HIJACK (DNAT all client DNS:53 -> AP IP:53)
# IMPORTANT: do this BEFORE starting dnsmasq so clients always hit us.
# Also: clean older rules from previous versions.
# ---------------------------------------------
iptables -t nat -D PREROUTING -i "${INTERFACE}" -p udp --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null || true
iptables -t nat -D PREROUTING -i "${INTERFACE}" -p tcp --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null || true

iptables -t nat -D PREROUTING -i "${INTERFACE}" -p udp --dport 53 -j DNAT --to-destination "${ADDRESS}:53" 2>/dev/null || true
iptables -t nat -D PREROUTING -i "${INTERFACE}" -p tcp --dport 53 -j DNAT --to-destination "${ADDRESS}:53" 2>/dev/null || true

if [[ "${DNS_OVERRIDE_ENABLED}" == "true" ]]; then
  echo "Forcing all AP client DNS -> ${ADDRESS}:53 (DNAT)"
  iptables -t nat -I PREROUTING 1 -i "${INTERFACE}" -p udp --dport 53 -j DNAT --to-destination "${ADDRESS}:53"
  iptables -t nat -I PREROUTING 2 -i "${INTERFACE}" -p tcp --dport 53 -j DNAT --to-destination "${ADDRESS}:53"
fi

# Allow INPUT for dnsmasq + DHCP (AP interface)
iptables -C INPUT -i "${INTERFACE}" -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -A INPUT -i "${INTERFACE}" -p udp --dport 53 -j ACCEPT
iptables -C INPUT -i "${INTERFACE}" -p tcp --dport 53 -j ACCEPT 2>/dev/null || iptables -A INPUT -i "${INTERFACE}" -p tcp --dport 53 -j ACCEPT
iptables -C INPUT -i "${INTERFACE}" -p udp --dport 67 -j ACCEPT 2>/dev/null || iptables -A INPUT -i "${INTERFACE}" -p udp --dport 67 -j ACCEPT
iptables -C INPUT -i "${INTERFACE}" -p udp --dport 68 -j ACCEPT 2>/dev/null || iptables -A INPUT -i "${INTERFACE}" -p udp --dport 68 -j ACCEPT

echo "DNS hijack counters (PREROUTING dpt:53):"
iptables -t nat -vnL PREROUTING | grep -E 'dpt:53|Chain PREROUTING' || true

# ---------------------------------------------
# hostapd runtime config
# - Enables WMM and stability tweaks to match updated hostapd.conf intent
# ---------------------------------------------
HCONFIG="/tmp/hostapd.runtime.conf"
IGNORE_BCAST=0
if [[ "${HIDE_SSID}" == "true" ]]; then IGNORE_BCAST=1; fi

echo "Setup hostapd (runtime config) ..."
cat > "${HCONFIG}" <<EOF
driver=nl80211
interface=${INTERFACE}
ssid=${SSID}
hw_mode=g
channel=${CHANNEL}

ieee80211n=1
ht_capab=[HT20]
wmm_enabled=1

beacon_int=100
dtim_period=2
disassoc_low_ack=0

macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=${IGNORE_BCAST}

ieee80211d=1
country_code=GB

wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=${WPA_PASSPHRASE}

logger_stdout=-1
logger_stdout_level=2
EOF

echo "hostapd config summary:"
grep -E '^(interface=|ssid=|channel=|country_code=|ieee80211n=|wmm_enabled=|dtim_period=|disassoc_low_ack=|ignore_broadcast_ssid=|wpa=|wpa_key_mgmt=|rsn_pairwise=|wpa_passphrase=)' "${HCONFIG}" \
  | sed 's/wpa_passphrase=.*/wpa_passphrase=********/'

# ---------------------------------------------
# Setup interface
# ---------------------------------------------
IFFILE="/etc/network/interfaces"
echo "Setup interface ..."
: > "${IFFILE}"
{
  echo "iface ${INTERFACE} inet static"
  echo "  address ${ADDRESS}"
  echo "  netmask ${NETMASK}"
  echo "  broadcast ${BROADCAST}"
  echo ""
} >> "${IFFILE}"

echo "Resetting interfaces"
reset_interfaces
ifup "${INTERFACE}" 2>/dev/null || true
sleep 1

# ---------------------------------------------
# DHCP server (udhcpd)
# ---------------------------------------------
if [[ "${DHCP_SERVER}" == "true" ]]; then
    mkdir -p /var/lib/udhcpd
    touch /var/lib/udhcpd/udhcpd.leases

    START_IP_LAST_OCTET=$(echo "${DHCP_START}" | cut -d. -f4)
    END_IP_LAST_OCTET=$(echo "${DHCP_END}" | cut -d. -f4)
    MAX_LEASES=$((END_IP_LAST_OCTET - START_IP_LAST_OCTET + 1))

    UCONFIG="/etc/udhcpd.conf"
    echo "Setup udhcpd ..."
    {
      echo "interface    ${INTERFACE}"
      echo "start        ${DHCP_START}"
      echo "end          ${DHCP_END}"
      echo "max_leases   ${MAX_LEASES}"
      # Always point clients at us for DNS (DNAT enforces anyway)
      echo "opt dns      ${ADDRESS}"
      echo "opt subnet   ${DHCP_SUBNET}"
      echo "opt router   ${DHCP_ROUTER}"
      echo "opt lease    ${LEASE_TIME}"
      echo ""
    } > "${UCONFIG}"

    while IFS=, read -r mac ip name; do
        if [[ -n "${mac}" && -n "${ip}" ]]; then
            echo "static_lease ${mac} ${ip}  # ${name}" >> "${UCONFIG}"
        fi
    done <<< "${STATIC_LEASES}"

    echo "Starting DHCP server..."
    udhcpd -f &
fi

sleep 1

# ---------------------------------------------
# Start hostapd
# ---------------------------------------------
echo "Starting HostAP daemon ..."
hostapd "${HCONFIG}" &
sleep 2

# ---------------------------------------------
# DNS override (dnsmasq) on PORT 53 bound only to AP IP
# ---------------------------------------------
if [[ "${DNS_OVERRIDE_ENABLED}" == "true" ]]; then
    echo "Starting dnsmasq (DNS only) AFTER hostapd on ${ADDRESS}:53..."
    echo "DNS override enabled: ${REDIRECT_MQTT_HOST} -> ${REDIRECT_TARGET_IP}"

    kill_pidfile /tmp/dnsmasq.hotspot.pid
    sleep 1

    DNSMASQ_CONF="/tmp/dnsmasq.hotspot.conf"
    cat > "${DNSMASQ_CONF}" <<EOF
port=53
interface=${INTERFACE}
listen-address=${ADDRESS}
bind-interfaces
except-interface=lo

no-resolv
server=${DHCP_DNS}

address=/${REDIRECT_MQTT_HOST}/${REDIRECT_TARGET_IP}

log-queries
log-facility=-

domain-needed
bogus-priv
EOF

    dnsmasq --conf-file="${DNSMASQ_CONF}" --keep-in-foreground --pid-file=/tmp/dnsmasq.hotspot.pid &
    sleep 1

    echo "DNS self-test (should print ${REDIRECT_TARGET_IP}):"
    dig @"${ADDRESS}" "${REDIRECT_MQTT_HOST}" +short || true
fi

# ---------------------------------------------
# Debug tcpdump
# ---------------------------------------------
echo "Starting tcpdump DNS (${INTERFACE} port 53) ..."
tcpdump -i "${INTERFACE}" -n "port 53" >/tmp/tcpdump_dns.log 2>&1 &
echo $! > /tmp/tcpdump.dns.pid

echo "Starting tcpdump MQTT (${INTERFACE} tcp port ${REDIRECT_TARGET_PORT}) ..."
tcpdump -i "${INTERFACE}" -n "tcp port ${REDIRECT_TARGET_PORT}" >/tmp/tcpdump_mqtt.log 2>&1 &
echo $! > /tmp/tcpdump.mqtt.pid

# ---------------------------------------------
# Status loop
# ---------------------------------------------
while true; do
    echo "Interface stats:"
    ifconfig | grep "${INTERFACE}" -A6 || true

    echo "ECOFLOW_AP counters:"
    iptables -vnL ECOFLOW_AP 2>/dev/null || true

    echo "DNS hijack counters (PREROUTING dpt:53):"
    iptables -t nat -vnL PREROUTING | grep -E 'dpt:53|Chain PREROUTING' || true

    echo "Last 20 DNS tcpdump lines:"
    tail -n 20 /tmp/tcpdump_dns.log 2>/dev/null || true

    echo "Last 20 MQTT tcpdump lines:"
    tail -n 20 /tmp/tcpdump_mqtt.log 2>/dev/null || true

    sleep 3600
done
