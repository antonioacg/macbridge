# CLAUDE.md

## Architecture

**Watchdog + bridge child** pattern. `main()` is the watchdog — it starts dnsmasq, forks the bridge child, then blocks on `waitpid()`. When the child exits for any reason, the watchdog runs cleanup. The bridge child does all BPF packet processing.

```
main (watchdog)
├── start_dhcp()     → fork/exec dnsmasq
├── fork()
│   └── run_bridge() → BPF packet loop (child)
├── waitpid()        → blocks until child exits
└── do_cleanup()     → kills dnsmasq, restores sysctl, cleans ARP
```

## macOS Networking Gotchas

These are the hard-won lessons from fighting macOS's network stack:

### Same-subnet routing is impossible
macOS won't create a connected route for the same /24 on two interfaces. If en0 owns 192.168.0.0/24, en10 cannot get a connected route for it — no amount of `ifconfig`, `route add`, or bridge interfaces will override this.

### `route add -host X -interface en10` creates bad ARP
The `-interface` flag creates a permanent ARP entry using the interface's **own MAC** (not the remote's). This causes a routing loop — the Mac sends packets to itself. There is no flag combination that fixes this.

### `arp -s` always goes to the connected-route interface
`arp -s 192.168.0.100 <mac>` will create the entry on en0 (the interface that owns the /24), regardless of host routes pointing to en10. `arp -s ... ifscope en10` fails with "No such process" if en10 doesn't own the subnet's connected route.

### pf `route-to` on `lo0` doesn't work
macOS doesn't send locally-generated packets through lo0 for pf evaluation. `pass in on lo0 route-to (en10 ...)` matches zero packets. Use `pass out on en0 route-to ...` instead — but even then, ARP resolution ignores pf's routing override.

### `BIOCSSEESENT` is essential for local traffic
With `see_sent=0` (default), BPF on en0 doesn't see the Mac's own outgoing packets. The bridge needs `see_sent=1` to capture the Mac's traffic destined for the remote. But this floods BPF with all en0 traffic — ARP discovery becomes unreliable due to noise.

**Fix**: Do ARP discovery with a separate `see_sent=0` BPF fd, then reopen with `see_sent=1` for the main loop. Gateway ARP is flaky even then — fallback to reading the system ARP cache via `arp -n`.

### Strong host model (`check_interface=1`)
macOS defaults to strong host model — packets arriving on en10 for an IP owned by en0 (.230) are rejected. The bridge must set `check_interface=0` (weak host model) so ICMP replies from the remote (arriving on en10) are accepted for the Mac's en0 IP. **Must be restored on exit.**

### Wi-Fi BPF injection doesn't loop back
Frames injected via BPF `write()` on en0 go on the air but are NOT delivered to the Mac's own network stack. You cannot use BPF to send the Mac a packet on its own Wi-Fi interface. This means ARP replies for the remote IP can't be self-delivered — use `arp -s` to pre-populate the cache instead.

## Implementation Details

### Packet flow: Mac → Remote
1. Mac has static ARP: `.100 → remote_mac` on en0
2. Mac sends IP packet to `.100`, dst MAC = remote_mac, out en0
3. Wi-Fi AP drops it (unknown dest MAC), but BPF captures outgoing frame
4. Bridge rewrites: src MAC = eth_mac, dst MAC = remote_mac, injects on en10
5. Remote receives, replies to `.230` via gateway `.241`
6. Reply arrives on en10, accepted by weak host model

### Packet flow: LAN → Remote
1. LAN device ARPs for `.100` on Wi-Fi
2. Bridge responds with wifi_mac (proxy ARP)
3. LAN device sends to wifi_mac, Mac receives on en0
4. BPF captures (incoming), bridge rewrites MACs, injects on en10
5. Remote replies, bridge rewrites src MAC to wifi_mac, injects on en0
6. LAN device receives reply

### Packet flow: Remote → Internet
1. Remote sends to gateway `.241` (Mac's en10)
2. Mac's en10 receives, kernel forwards via en0 (IP forwarding enabled)
3. Router NATs to internet, reply comes back to Mac
4. Mac accepts reply (dst = .230, own IP)

Wait — the remote's outgoing traffic uses kernel IP forwarding, NOT the bridge. The bridge handles: (a) traffic TO the remote, (b) ARP proxying, (c) Mac's own traffic to the remote.

### Skip-self logic
With `see_sent=1`, the bridge sees its own injected packets. Skip rules:
- **Injected IP from eth→wifi**: src MAC = wifi_mac AND src IP = remote_ip → skip
- **Injected ARP replies**: operation = REPLY AND sender_ip = remote_ip AND sender_mac = wifi_mac → skip
- **Replies to Mac**: dst IP = wifi_ip → skip (arrives directly on en10, no need to inject on Wi-Fi)

### dnsmasq integration
dnsmasq is fork/exec'd by the watchdog (not the bridge child) so the watchdog can `kill()` it during cleanup. Interface IP uses `.241` in the gateway's /24 subnet. DHCP range is a single IP (the remote's desired address). Gateway points to the `.241` IP so all remote traffic routes through the Mac.

## Troubleshooting

### "cannot discover remote MAC"
- Remote not powered on or Ethernet cable not connected
- Remote's DHCP client hasn't run yet (bridge retries for 60s)
- Wrong eth interface name (check `networksetup -listallhardwareports`)

### "cannot discover gateway MAC"
- Flaky BPF on Wi-Fi (too much traffic). Falls back to system ARP cache automatically.
- If fallback also fails: router not responding to ARP. Check Wi-Fi connection.

### Ping works but SSH doesn't
- Check `remote-exec.sh` uses the right IP
- SSH key might not be set up for this IP

### Duplicate ICMP replies
- `check_interface` not set to 0, or the eth→wifi path isn't skipping replies to wifi_ip
- Should see "no duplicates" in normal operation

### Orphaned dnsmasq after crash
- Only happens if watchdog itself is `kill -9`'d
- Fix: `sudo pkill dnsmasq; sudo sysctl -w net.inet.ip.check_interface=1; sudo arp -d <ip>`

## Performance

### Measured throughput (Mac ↔ OrangePi 5 Pro over USB Gigabit + Wi-Fi)

| Direction | Throughput | Notes |
|---|---|---|
| Remote → Mac | ~310 Mbps, 0 retrans | Bridge bypassed (dst = wifi_ip, kernel handles directly) |
| Mac → Remote (TCP) | ~300 Mbps, some retrans | Via utun, bridge is the ceiling |
| Mac → Remote (UDP 300M) | 300 Mbps, <0.1% loss | Sustainable rate |
| Mac → Remote (UDP 500M) | 313 Mbps delivered, 37% loss | Bridge saturated above ~300 Mbps |

### Evolution
| Version | Mac → Remote | Bottleneck |
|---|---|---|
| Initial (see_sent=1, no filter, 4KB buffer) | 37 Mbps, 2916 retrans | BPF buffer overflow |
| + cBPF filter + 4MB buffer | 63 Mbps, 0 retrans | Wi-Fi uplink |
| + utun fast path (current) | 300 Mbps, some retrans | Bridge syscall overhead |

### Why utun matters — the Wi-Fi detour
Before utun, every Mac → Remote packet was transmitted on Wi-Fi AND on Ethernet:

1. Mac's kernel thinks `.100` lives on en0 (connected /24 subnet)
2. Wi-Fi driver transmits the frame over the air with dst MAC = remote_mac
3. AP drops it (unknown station)
4. BPF (`see_sent=1`) captured the outgoing frame
5. Bridge rewrote MACs, injected on en10 → remote receives

Wasted Wi-Fi airtime on every packet. Wi-Fi is half-duplex and airtime-limited, so the wasted TX saturated the uplink at ~63 Mbps.

### How utun bypasses Wi-Fi
`utun` is a PF_SYSTEM/SYSPROTO_CONTROL virtual interface. We create it with P2P mode (`self=172.16.0.1, peer=192.168.0.100`), which creates a host route `192.168.0.100 -> utun0`. This /32 route wins against en0's /24 connected route (longest-prefix-match).

Now when the Mac sends to `.100`:
1. Kernel routes via utun0 (not en0!)
2. Packet written to utun → userspace reads it
3. Bridge prepends Ethernet header, writes to en10 BPF
4. Remote receives — Wi-Fi never sees the packet

Reply from remote: sent to `172.16.0.1` (Mac's source on utun). Remote's gateway is `eth_mac` on en10, so the reply arrives on en10. Kernel accepts because `172.16.0.1` is a local IP (utun0) — weak host model takes care of the interface mismatch.

### utun gotchas
- **AF prefix is in NETWORK byte order**, not host. Every packet read/written has a 4-byte prefix = `htonl(AF_INET)` = `0x02000000` on the wire. Comments in Apple headers and random SO answers say "host byte order" — they're wrong. Verified empirically.
- **Interface destroyed when fd closes** — no cleanup needed beyond `close()`.
- **No Ethernet header on utun** (it's L3). We prepend one before BPF write.
- **Only IPv4 traffic forwarded** — IPv6 (AF_INET6) would need its own ethertype (0x86DD). Not implemented; easy to add.

### Kernel-side cBPF filter (`BIOCSETF`)
Without a filter, BPF copies every frame on the wire into the userspace buffer — including unrelated Wi-Fi chatter. Userspace then discards 99%. With a filter (`arp || (ip && dst host remote_ip)` on en0, `ether src host remote_mac` on en10), the kernel drops non-matching frames before buffering. Cuts kernel→user copy rate by 10-100x.

### 4 MB BPF buffer (`BIOCSBLEN` before `BIOCSETIF`)
Default is 4 KB — overflows instantly under load. Drops happen in-kernel and are invisible to us. Request 4 MB up front, halve and retry if the kernel rejects. macOS Sequoia accepted 4 MB without complaint.

### Remaining ceiling (~300 Mbps)
The bridge is now syscall-bound. Each Mac → Remote packet costs:
- 1 `read()` from utun (kernel → user copy)
- 1 `write()` to en10 BPF (user → kernel copy)
- Plus `poll()` overhead

At MTU-sized packets, that's ~25k pps × 2 syscalls = ~50k syscalls/sec. Each is 1-3μs → ~50-150ms of wall time per second spent in syscall overhead. The remaining time is the kernel driver path.

### What's NOT available on macOS for further gains
- **Zero-copy BPF** (`BIOCSETBUFMODE` + `BPF_BUFMODE_ZBUF`): FreeBSD has it, Darwin doesn't.
- **AF_PACKET / PF_PACKET sockets**: Linux-only.
- **Native TAP** (L2 virtual interface): Requires a kext. `tuntaposx` is dead.

### If you want more throughput
- Disable `BIOCIMMEDIATE` — kernel batches packets, trades latency for throughput.
- Multi-thread: one thread per fd instead of shared `poll()`. Reduces head-of-line blocking between utun reads and BPF writes.
- Read multiple packets per `read()` from utun when they queue up (check the fd with another poll loop internally).
- Network Extension (`NEPacketTunnelProvider`) for a sanctioned kernel fast-path. Bigger rewrite, needs codesigning + entitlements.

## Build

```bash
make        # builds macbridge
make clean  # removes binary
```

Requires: macOS, clang (Xcode CLI tools), dnsmasq (`brew install dnsmasq`).
