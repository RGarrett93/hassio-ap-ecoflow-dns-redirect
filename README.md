# AP EcoFlow MQTT DNS Redirect (Home Assistant Add-on)

Create a dedicated Wi-Fi Access Point for EcoFlow devices and transparently redirect EcoFlow’s cloud MQTT hostname (`mqtt-e.ecoflow.com`) to a local target (your Home Assistant host IP on port `8883`).

This lets EcoFlow devices connect as normal, but their MQTT traffic is routed to your local endpoint instead of the public EcoFlow cloud.

> Designed to pair with a local EcoFlow MQTT decoder / bridge add-on (e.g. `hassio-ecoflow-mqtt-decoder`) for protobuf decoding + Home Assistant MQTT Discovery.
https://github.com/RGarrett93/hassio-ecoflow-mqtt-decoder

---

## What this add-on does

- Creates a Wi-Fi hotspot (AP) from your Home Assistant host (Raspberry Pi etc.)  
- Runs DHCP for clients (EcoFlow devices)  
- Runs DNS for clients and overrides:
  - `mqtt-e.ecoflow.com` to `REDIRECT_TARGET_IP`

- Optionally allows internet NAT (disabled by default)  

---

## Typical architecture

EcoFlow devices connect to your Home Assistant hotspot:

1. EcoFlow device joins **your AP SSID**
2. Device receives DHCP config:
   - router: your AP IP (e.g. `192.168.2.1`)
   - DNS: your AP IP (e.g. `192.168.2.1`)
3. When the device tries to resolve `mqtt-e.ecoflow.com`, your DNS replies with `REDIRECT_TARGET_IP`
4. Device connects to MQTT TLS on port `8883` at that local target

---

## Requirements

- Home Assistant OS / Supervised with add-on support
- A supported Wi-Fi interface that can run AP mode (commonly `wlan0`)
- EcoFlow device must be configured to use the hotspot Wi-Fi network

---

## Installation

### Add repository
1. Home Assistant → **Settings** → **Add-ons** → **Add-on Store**
2. (⋮) menu → **Repositories**
3. Add this repository URL:
   - `https://github.com/RGarrett93/hassio-ap-ecoflow-dns-redirect`

### Install the add-on
- Find **AP EcoFlow MQTT DNS Redirect**
- Install
- Configure (see below)
- Ensure **Protection Mode** is disabled 
(otherwise the add-on is unable to use WiFi)
- Start

---

## Configuration

### Required
| Option | Description |
|---|---|
| `ssid` | Wi-Fi name EcoFlow devices will connect to |
| `wpa_passphrase` | WPA2 password |
| `interface` | Wi-Fi device interface (e.g. `wlan0`) |
| `address` | AP gateway IP (default `192.168.2.1`) |

### EcoFlow DNS redirect
| Option | Description |
|---|---|
| `dns_override_enabled` | Enable/disable DNS override |
| `redirect_mqtt_host` | Hostname to override (default `mqtt-e.ecoflow.com`) |
| `redirect_target_ip` | IP to return for that hostname (leave blank to use AP `address`) |
| `redirect_target_port` | Target port (default `8883`) |

> If `redirect_target_ip` is blank, the add-on will use the AP address automatically.

### DHCP options
| Option | Description |
|---|---|
| `dhcp_enable` | Enable DHCP server |
| `dhcp_start` / `dhcp_end` | Address pool |
| `dhcp_dns` | Upstream DNS if override disabled |
| `dhcp_router` | Router offered to clients |

### Example config

```yaml
ssid: "EcoFlowAP"
wpa_passphrase: "supersecretpassword"
channel: 6
address: 192.168.2.1
netmask: 255.255.255.0
broadcast: 192.168.2.254
interface: wlan0

dns_override_enabled: true
redirect_mqtt_host: mqtt-e.ecoflow.com
redirect_target_ip: 192.168.2.1
redirect_target_port: 8883

allow_internet: false
internet_interface: eth0

dhcp_enable: true
dhcp_start: 192.168.2.100
dhcp_end: 192.168.2.200
dhcp_dns: 1.1.1.1
dhcp_subnet: 255.255.255.0
dhcp_router: 192.168.2.1
hide_ssid: false
lease_time: 864000
