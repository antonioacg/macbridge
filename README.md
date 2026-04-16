# macbridge

Userspace Ethernet-to-Wi-Fi bridge for macOS. Makes a device connected via USB Ethernet appear on your Wi-Fi network with its own IP — the same trick Parallels uses for bridged VM networking, but as a standalone CLI tool using BPF.

## Why

macOS cannot bridge Wi-Fi to Ethernet at Layer 2 (802.11 limitation). Internet Sharing gives the device a separate NAT'd subnet. macbridge solves this by rewriting MAC addresses in userspace via BPF, so the remote device gets a real IP on your Wi-Fi network.

## Usage

```bash
# Build
make

# Run (requires root for BPF access)
sudo ./macbridge <wifi-iface> <eth-iface> <remote-ip>

# Example: bridge en10 (USB Ethernet) to en0 (Wi-Fi), remote gets 192.168.0.100
sudo ./macbridge en0 en10 192.168.0.100
```

Find your interfaces with `networksetup -listallhardwareports`.

## What it does

1. Configures the Ethernet interface and starts a DHCP server (dnsmasq)
2. Discovers the remote device and gateway via ARP
3. Proxies ARP for the remote IP on Wi-Fi (other devices can find it)
4. Rewrites MAC addresses on packets flowing between Wi-Fi and Ethernet
5. Cleans up everything on exit (Ctrl+C, signals, crashes)

## Requirements

- macOS (tested on Sequoia/Apple Silicon)
- [dnsmasq](https://formulae.brew.sh/formula/dnsmasq): `brew install dnsmasq`
- A USB Ethernet adapter

## How it works

```
┌─────────┐         ┌───────────┐         ┌────────┐
│  Wi-Fi  │◄──BPF──►│ macbridge │◄──BPF──►│  USB   │
│  (en0)  │         │           │         │ (en10) │
└────┬────┘         └───────────┘         └───┬────┘
     │                                        │
 192.168.0.0/24                          Remote device
 (router, LAN)                         192.168.0.100
```

- **Wi-Fi → Ethernet**: Packets destined for the remote IP arrive with the Mac's Wi-Fi MAC (proxy ARP). macbridge rewrites dst MAC to the remote's real MAC and injects on Ethernet.
- **Ethernet → Wi-Fi**: Packets from the remote are rewritten with the Mac's Wi-Fi MAC as source and injected on Wi-Fi, appearing to come from the Mac.
- **ARP proxy**: macbridge answers ARP requests for the remote IP on Wi-Fi, and answers all ARP requests from the remote on Ethernet (acting as the entire network).

## Cleanup guarantee

macbridge uses a watchdog process pattern:

| Exit cause | Cleanup? |
|---|---|
| Ctrl+C / SIGTERM / SIGHUP | Yes |
| Child crash (SIGSEGV, etc.) | Yes |
| `kill -9` on bridge child | Yes — watchdog catches it |
| `kill -9` on watchdog | No — impossible to catch in any language |

On exit it restores: `net.inet.ip.check_interface`, static ARP entry, and kills dnsmasq.

## License

MIT
