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
                    ┌───────────────────────┐
                    │       macbridge       │
  Mac apps ───utun──►                       ├──BPF──► USB Ethernet ──► remote
                    │                       │
  LAN peers ──BPF──►  (MAC/header rewrite)  ├──BPF──► USB Ethernet ──► remote
    (Wi-Fi)         │                       │
                    │                       ◄──BPF── USB Ethernet ◄── remote
                    └───────────────────────┘
```

Three data paths:

- **Mac → Remote (utun fast path)**: A host route `remote_ip -> utun0` takes priority over Wi-Fi's connected subnet. The kernel hands IP packets to utun; macbridge prepends an Ethernet header and injects on USB. Wi-Fi is never involved.
- **LAN → Remote (proxy ARP path)**: macbridge answers ARP for `remote_ip` on Wi-Fi with the Mac's Wi-Fi MAC. LAN peers send frames to the Mac's Wi-Fi MAC; BPF captures, MACs are rewritten, frame is injected on USB.
- **Remote → anywhere**: BPF on USB captures frames from the remote, rewrites src MAC to the Mac's Wi-Fi MAC, and injects on Wi-Fi to the router or LAN peer. Replies directed at the Mac itself are handled by the kernel (weak host model) without going through the bridge.

## Performance

~300 Mbps bidirectional on the test hardware (MacBook + USB Gigabit + OrangePi 5 Pro). Key optimizations:

- **utun fast path** for Mac → Remote — bypasses the Wi-Fi driver entirely (otherwise every packet gets transmitted over the air too and wastes airtime).
- **Kernel-side cBPF filters** — kernel drops irrelevant frames before they hit the userspace buffer.
- **4 MB BPF buffers** — absorbs bursts without drops.

See [CLAUDE.md](CLAUDE.md) for measured numbers, gotchas (utun byte order, macOS routing quirks), and design notes.

## Resilience

macbridge supervises itself. The parent process forks a bridge child, and when the child exits for *any* reason (interface reset by `configd` after USB re-enumeration, `poll()` errors, crash, etc.), the parent respawns it after a 3-second backoff — including re-applying the Ethernet IP and restarting dnsmasq so it re-binds to the restored address.

Only a termination signal (`SIGINT` / `SIGTERM` / `SIGHUP` / `SIGQUIT`) sent to the parent stops the loop. You can put the Mac to sleep, reboot the remote, swap cables — when everything settles, macbridge is back without intervention.

A heartbeat prints every 5 seconds with per-path packet deltas. On a TTY it overwrites in place; in a pipe/file it appends full lines.

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
