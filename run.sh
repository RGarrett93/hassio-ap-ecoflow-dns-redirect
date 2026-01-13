#!/bin/bash

reset_interfaces(){
    ifdown "$INTERFACE" 2>/dev/null || true
    sleep 1
    ip link set "$INTERFACE" down 2>/dev/null || true
    ip addr flush dev "$INTERFACE" 2>/dev/null || true
}

term_handler(){
    echo "Resetting interfaces"
    reset_interfaces

    # Stop only the dnsmasq instance we started (avoid pkill in host_network mode)
    if [ -f /tmp/dnsmasq.hotspot.pid ]; then
        kill "$(cat /tmp/dnsmasq.hotspot.pid)" 2>/dev/null || true
        rm -f /tmp/dnsmasq.hotspot.pid
    fi

    echo "Stopping..."
    exit 0
}

trap 'term_handler' SIGTERM

echo "Starting..."

CONFIG_PATH=/data/options.json

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

# Required vars (channel may be 0 in options; we'll normalize it below)
required_vars=(SSID WPA_PASSPHRASE ADDRESS NETMASK BROADCAST INTERFACE)
for required_var in "${required_vars[@]}"; do
    if [[ -z ${!required_var} || ${!required_var} == "null" ]]; then
        echo >&2 "Error: $required_var not set."
        exit 1
    fi
done

# Normalize channel: channel=0 is a common cause of nl80211 "Failed to set beacon parameters"
if [[ -z "${CHANNEL}" || "${CHANNEL}" == "null" || "${CHANNEL}" == "0" ]]; then
    echo "Channel is 0/empty -> forcing channel=6"
    CHANNEL=6
fi

INTERFACES_AVAILABLE="$(ifconfig -a | grep '^wl' | cut -d ':' -f '1')"
UNKNOWN=true

if [[ -z ${INTERFACE} || ${INTERFACE} == "null" ]]; then
    echo >&2 "Network interface not set. Please set one of the available:"
    echo >&2 "${INTERFACES_AVAILABLE}"
    exit 1
fi

for OPTION in ${INTERFACES_AVAILABLE}; do
    if [[ ${INTERFACE} == ${OPTION} ]]; then
        UNKNOWN=false
    fi
done

if [[ ${UNKNOWN} == true ]]; then
    echo >&2 "Unknown network interface ${INTERFACE}. Please set one of the available:"
    echo >&2 "${INTERFACES_AVAILABLE}"
    exit 1
fi

echo "Set nmcli managed no"
nmcli dev set "${INTERFACE}" managed no 2>/dev/null || true

echo "Network interface set to ${INTERFACE}"

# DNS redirect defaults
if [[ -z "${REDIRECT_TARGET_IP}" || "${REDIRECT_TARGET_IP}" == "null" ]]; then
    REDIRECT_TARGET_IP="${ADDRESS}"
fi

if [[ "${DNS_OVERRIDE_ENABLED}" == "true" ]]; then
    echo "Redirect target: ${REDIRECT_MQTT_HOST} -> ${REDIRECT_TARGET_IP}:${REDIRECT_TARGET_PORT}"
fi

# NAT (keep original behaviour)
RULE_3="POSTROUTING -o ${INTERNET_IF} -j MASQUERADE"
RULE_4="FORWARD -i ${INTERNET_IF} -o ${INTERFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT"
RULE_5="FORWARD -i ${INTERFACE} -o ${INTERNET_IF} -j ACCEPT"

echo "Deleting iptables"
iptables -v -t nat -D $(echo ${RULE_3}) 2>/dev/null || true
iptables -v -D $(echo ${RULE_4}) 2>/dev/null || true
iptables -v -D $(echo ${RULE_5}) 2>/dev/null || true

if test ${ALLOW_INTERNET} = true; then
    echo "Configuring iptables for NAT"
    iptables -v -t nat -A $(echo ${RULE_3})
    iptables -v -A $(echo ${RULE_4})
    iptables -v -A $(echo ${RULE_5})
else
    echo "Internet access disabled (no NAT)."
fi

# --- hostapd config: ALWAYS generate a clean file each boot (do not modify /hostapd.conf) ---
HCONFIG="/tmp/hostapd.conf"

echo "Setup hostapd ..."
# Start from the shipped base config (from the image)
cp /hostapd.conf "${HCONFIG}"

{
    echo "ssid=${SSID}"
    echo "wpa_passphrase=${WPA_PASSPHRASE}"
    echo "channel=${CHANNEL}"
    echo "interface=${INTERFACE}"
    echo ""
} >> "${HCONFIG}"

if test ${HIDE_SSID} = true; then
    echo "Hiding SSID"
    echo "ignore_broadcast_ssid=1" >> "${HCONFIG}"
fi

# Setup interface
IFFILE="/etc/network/interfaces"

echo "Setup interface ..."
echo "" > "${IFFILE}"
echo "iface ${INTERFACE} inet static" >> "${IFFILE}"
echo "  address ${ADDRESS}" >> "${IFFILE}"
echo "  netmask ${NETMASK}" >> "${IFFILE}"
echo "  broadcast ${BROADCAST}" >> "${IFFILE}"
echo "" >> "${IFFILE}"

echo "Resetting interfaces"
reset_interfaces
ifup "${INTERFACE}" 2>/dev/null || true
sleep 1

# DHCP server (udhcpd)
if test ${DHCP_SERVER} = true; then
    mkdir -p /var/lib/udhcpd
    touch /var/lib/udhcpd/udhcpd.leases

    START_IP_LAST_OCTET=$(echo "${DHCP_START}" | cut -d. -f4)
    END_IP_LAST_OCTET=$(echo "${DHCP_END}" | cut -d. -f4)
    MAX_LEASES=$((END_IP_LAST_OCTET - START_IP_LAST_OCTET + 1))

    UCONFIG="/etc/udhcpd.conf"

    echo "Setup udhcpd ..."
    echo "interface    ${INTERFACE}"     >  "${UCONFIG}"
    echo "start        ${DHCP_START}"    >> "${UCONFIG}"
    echo "end          ${DHCP_END}"      >> "${UCONFIG}"
    echo "max_leases   ${MAX_LEASES}"    >> "${UCONFIG}"

    # If DNS override is enabled, hand out the hotspot as DNS so clients ask us
    if [[ "${DNS_OVERRIDE_ENABLED}" == "true" ]]; then
        echo "opt dns      ${ADDRESS}" >> "${UCONFIG}"
    else
        echo "opt dns      ${DHCP_DNS}" >> "${UCONFIG}"
    fi

    echo "opt subnet   ${DHCP_SUBNET}"   >> "${UCONFIG}"
    echo "opt router   ${DHCP_ROUTER}"   >> "${UCONFIG}"
    echo "opt lease    ${LEASE_TIME}"    >> "${UCONFIG}"
    echo ""                              >> "${UCONFIG}"

    while IFS=, read -r mac ip name; do
        if [ ! -z "$mac" ] && [ ! -z "$ip" ]; then
            echo "static_lease ${mac} ${ip}  # ${name}" >> "${UCONFIG}"
        fi
    done <<< "${STATIC_LEASES}"

    echo "Starting DHCP server..."
    udhcpd -f &
fi

sleep 1

# Start hostapd
echo "Starting HostAP daemon ..."
hostapd "${HCONFIG}" &
sleep 2

# Start DNS override (DNS-only) AFTER AP is up
if [[ "${DNS_OVERRIDE_ENABLED}" == "true" ]]; then
    echo "Starting dnsmasq (DNS only) AFTER hostapd..."
    echo "DNS override enabled: ${REDIRECT_MQTT_HOST} -> ${REDIRECT_TARGET_IP}"

    # Stop only the dnsmasq instance we started last time
    if [ -f /tmp/dnsmasq.hotspot.pid ]; then
        kill "$(cat /tmp/dnsmasq.hotspot.pid)" 2>/dev/null || true
        rm -f /tmp/dnsmasq.hotspot.pid
        sleep 1
    fi

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
domain-needed
bogus-priv
EOF

    # --pid-file ensures we only kill our own dnsmasq in host_network mode
    dnsmasq --conf-file="${DNSMASQ_CONF}" --keep-in-foreground --pid-file=/tmp/dnsmasq.hotspot.pid &
fi

while true; do
    echo "Interface stats:"
    ifconfig | grep "${INTERFACE}" -A6 || true
    sleep 3600
done
