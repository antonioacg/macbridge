/*
 * macbridge - Userspace Ethernet bridge for macOS
 *
 * Bridges an Ethernet adapter (e.g. USB) to Wi-Fi using BPF,
 * rewriting MAC addresses so the remote device appears on the
 * Wi-Fi network with its own IP. Same trick as Parallels bridged
 * networking, but in userspace via BPF.
 *
 * Self-contained: configures the Ethernet interface, runs a DHCP
 * server (dnsmasq), manages ARP and host model, and cleans up
 * everything on exit.
 *
 * Usage: sudo macbridge <wifi-iface> <eth-iface> <remote-ip>
 *   e.g. sudo macbridge en0 en10 192.168.0.100
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/route.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <arpa/inet.h>

#define ETH_ALEN 6
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2
#define MAX_ARP_CACHE 64
#define ETH_BRIDGE_IP "169.254.0.1"  /* link-local, avoids subnet conflicts */

struct arp_packet {
    struct ether_header eth;
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_len;
    uint8_t proto_len;
    uint16_t operation;
    uint8_t sender_mac[ETH_ALEN];
    uint32_t sender_ip;
    uint8_t target_mac[ETH_ALEN];
    uint32_t target_ip;
} __attribute__((packed));

struct arp_entry {
    uint32_t ip;
    uint8_t mac[ETH_ALEN];
};

static struct arp_entry arp_cache[MAX_ARP_CACHE];
static int arp_cache_count = 0;
static volatile int running = 1;

/* Cleanup state — set by bridge, used by watchdog */
static pid_t dnsmasq_pid = 0;
static pid_t bridge_pid = 0;
static char cleanup_remote_ip[32] = {0};
static int check_interface_was = -1;

/*
 * Cleanup runs in the WATCHDOG process (parent), never in signal
 * handlers. The watchdog calls this after waitpid() returns,
 * guaranteeing it runs for any child exit: clean, crash, signal.
 * Only SIGKILL on the watchdog itself can prevent cleanup.
 */
static void do_cleanup(void) {
    if (dnsmasq_pid > 0) {
        kill(dnsmasq_pid, SIGTERM);
        waitpid(dnsmasq_pid, NULL, 0);
        dnsmasq_pid = 0;
        fprintf(stderr, "macbridge: dnsmasq stopped\n");
    }

    if (check_interface_was >= 0) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd),
                 "sysctl -w net.inet.ip.check_interface=%d >/dev/null 2>&1",
                 check_interface_was);
        system(cmd);
        fprintf(stderr, "macbridge: restored check_interface=%d\n",
                check_interface_was);
        check_interface_was = -1;
    }

    if (cleanup_remote_ip[0]) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "arp -d %s 2>/dev/null", cleanup_remote_ip);
        system(cmd);
        fprintf(stderr, "macbridge: cleaned ARP for %s\n", cleanup_remote_ip);
        cleanup_remote_ip[0] = 0;
    }
}

/* Watchdog signal handler: forward to bridge child, then wait */
static void watchdog_signal(int sig) {
    if (bridge_pid > 0)
        kill(bridge_pid, sig);
    /* Don't exit — let the main waitpid() loop collect the child */
}

/* Bridge signal handler: just set flag, no system() calls */
static void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

static void mac_to_str(const uint8_t *mac, char *buf, size_t len) {
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int parse_mac(const char *str, uint8_t *mac) {
    unsigned int m[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
    return 0;
}

static void arp_cache_put(uint32_t ip, const uint8_t *mac) {
    for (int i = 0; i < arp_cache_count; i++) {
        if (arp_cache[i].ip == ip) {
            memcpy(arp_cache[i].mac, mac, ETH_ALEN);
            return;
        }
    }
    if (arp_cache_count < MAX_ARP_CACHE) {
        arp_cache[arp_cache_count].ip = ip;
        memcpy(arp_cache[arp_cache_count].mac, mac, ETH_ALEN);
        arp_cache_count++;
    }
}

static uint8_t *arp_cache_get(uint32_t ip) {
    for (int i = 0; i < arp_cache_count; i++)
        if (arp_cache[i].ip == ip)
            return arp_cache[i].mac;
    return NULL;
}

static int get_mac(const char *ifname, uint8_t *mac) {
    struct ifaddrs *ifap, *ifa;
    if (getifaddrs(&ifap) < 0) return -1;
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, ifname) == 0 &&
            ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
            if (sdl->sdl_alen == ETH_ALEN) {
                memcpy(mac, LLADDR(sdl), ETH_ALEN);
                freeifaddrs(ifap);
                return 0;
            }
        }
    }
    freeifaddrs(ifap);
    return -1;
}

static uint32_t get_default_gateway(void) {
    int mib[] = { CTL_NET, AF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_GATEWAY };
    size_t len = 0;
    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) return 0;

    char *buf = malloc(len);
    if (!buf) return 0;
    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) { free(buf); return 0; }

    uint32_t gw = 0;
    char *p = buf;
    while (p < buf + len) {
        struct rt_msghdr *rtm = (struct rt_msghdr *)p;
        struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
        struct sockaddr_in *dst = (struct sockaddr_in *)sa;
        if (dst->sin_addr.s_addr == 0) {
            sa = (struct sockaddr *)((char *)sa +
                 (sa->sa_len ? sa->sa_len : sizeof(struct sockaddr)));
            struct sockaddr_in *gwsa = (struct sockaddr_in *)sa;
            if (gwsa->sin_family == AF_INET) {
                gw = gwsa->sin_addr.s_addr;
                break;
            }
        }
        p += rtm->rtm_msglen;
    }
    free(buf);
    return gw;
}

static int get_sysctl_int(const char *name) {
    int val = -1;
    size_t len = sizeof(val);
    sysctlbyname(name, &val, &len, NULL, 0);
    return val;
}

/*
 * cBPF filter for the Wi-Fi interface.
 *
 * Accept:
 *   - All ARP (ethertype 0x0806) — small volume, lets us proxy
 *   - IP (0x0800) where dst IP == remote_ip — traffic to the bridged device
 *
 * Drop everything else — kernel filters before buffering.
 *
 * Instruction layout:
 *   [0] ldh  [12]                  ; load ethertype
 *   [1] jeq  0x0806 -> accept      ; if ARP, jump to accept
 *   [2] jeq  0x0800 -> continue    ; if not IP, drop
 *   [3] ld   [30]                  ; load IPv4 dst address (offset 14 + 16)
 *   [4] jeq  remote_ip -> accept   ; else drop
 *   [5] ret  65535                 ; accept (full frame)
 *   [6] ret  0                     ; drop
 */
static struct bpf_insn wifi_filter_prog[7];
static struct bpf_program wifi_filter = { 7, wifi_filter_prog };

static void build_wifi_filter(uint32_t remote_ip) {
    struct bpf_insn p[] = {
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0806, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 30),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ntohl(remote_ip), 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 65535),
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
    memcpy(wifi_filter_prog, p, sizeof(p));
}

/*
 * cBPF filter for the Ethernet interface.
 *
 * Accept only frames with src MAC == remote_mac.
 * Kernel drops DHCP discovers, broadcasts from other devices, etc.
 *
 *   [0] ld   [6]                   ; first 4 bytes of src MAC
 *   [1] jeq  mac[0..3] -> continue
 *   [2] ldh  [10]                  ; last 2 bytes of src MAC
 *   [3] jeq  mac[4..5] -> accept
 *   [4] ret  65535
 *   [5] ret  0
 */
static struct bpf_insn eth_filter_prog[6];
static struct bpf_program eth_filter = { 6, eth_filter_prog };

static void build_eth_filter(const uint8_t *remote_mac) {
    uint32_t mac_hi = ((uint32_t)remote_mac[0] << 24) |
                      ((uint32_t)remote_mac[1] << 16) |
                      ((uint32_t)remote_mac[2] << 8)  |
                       (uint32_t)remote_mac[3];
    uint16_t mac_lo = ((uint16_t)remote_mac[4] << 8) | remote_mac[5];

    struct bpf_insn p[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 6),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, mac_hi, 0, 3),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 10),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, mac_lo, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 65535),
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
    memcpy(eth_filter_prog, p, sizeof(p));
}

/*
 * Open a BPF device and bind it to an interface.
 *
 * Buffer sizing: BIOCSBLEN must be called BEFORE BIOCSETIF.
 * We request 4MB and let the kernel cap it at whatever maximum it allows.
 *
 * see_sent: 0 = only incoming frames, 1 = incoming + locally-generated outgoing
 * filter:   optional cBPF filter program (NULL = accept everything)
 * immediate: 1 = wake up per-packet (low latency), 0 = batch (high throughput)
 */
static int open_bpf(const char *ifname, int *buflen, int see_sent,
                    struct bpf_program *filter, int immediate) {
    char dev[32];
    int fd = -1;

    for (int i = 0; i < 256; i++) {
        snprintf(dev, sizeof(dev), "/dev/bpf%d", i);
        fd = open(dev, O_RDWR);
        if (fd >= 0) break;
        if (errno != EBUSY) break;
    }
    if (fd < 0) {
        perror("open /dev/bpf");
        return -1;
    }

    /* Request large buffer BEFORE BIOCSETIF. Kernel will silently cap it. */
    int want = 4 * 1024 * 1024; /* 4 MB */
    while (want >= 32768) {
        if (ioctl(fd, BIOCSBLEN, &want) == 0) break;
        want /= 2;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
        perror("BIOCSETIF");
        close(fd);
        return -1;
    }

    int enable = 1;
    if (immediate)
        ioctl(fd, BIOCIMMEDIATE, &enable);
    ioctl(fd, BIOCSHDRCMPLT, &enable);
    ioctl(fd, BIOCSSEESENT, &see_sent);

    /* Install kernel-side filter — kernel drops non-matching frames
       before they hit the BPF buffer. Massive throughput win. */
    if (filter && ioctl(fd, BIOCSETF, filter) < 0) {
        perror("BIOCSETF");
        close(fd);
        return -1;
    }

    if (ioctl(fd, BIOCGBLEN, buflen) < 0) {
        perror("BIOCGBLEN");
        close(fd);
        return -1;
    }
    fprintf(stderr, "macbridge: %s BPF buffer = %d bytes\n", ifname, *buflen);

    return fd;
}

static int arp_resolve(int bpf_fd, int buflen, const uint8_t *my_mac,
                       uint32_t my_ip, uint32_t target_ip, uint8_t *out_mac) {
    struct arp_packet req;
    memset(&req, 0, sizeof(req));

    memset(req.eth.ether_dhost, 0xff, ETH_ALEN);
    memcpy(req.eth.ether_shost, my_mac, ETH_ALEN);
    req.eth.ether_type = htons(ETHERTYPE_ARP);
    req.hw_type = htons(1);
    req.proto_type = htons(ETHERTYPE_IP);
    req.hw_len = ETH_ALEN;
    req.proto_len = 4;
    req.operation = htons(ARP_OP_REQUEST);
    memcpy(req.sender_mac, my_mac, ETH_ALEN);
    req.sender_ip = my_ip;
    req.target_ip = target_ip;

    uint8_t *buf = malloc(buflen);
    if (!buf) return -1;

    for (int attempt = 0; attempt < 5; attempt++) {
        write(bpf_fd, &req, sizeof(req));

        struct pollfd pfd = { .fd = bpf_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 1000);
        if (ret <= 0) continue;

        ssize_t n = read(bpf_fd, buf, buflen);
        if (n <= 0) continue;

        uint8_t *p = buf;
        while (p < buf + n) {
            struct bpf_hdr *bh = (struct bpf_hdr *)p;
            uint8_t *frame = p + bh->bh_hdrlen;
            size_t framelen = bh->bh_caplen;

            if (framelen >= sizeof(struct arp_packet)) {
                struct arp_packet *reply = (struct arp_packet *)frame;
                if (ntohs(reply->eth.ether_type) == ETHERTYPE_ARP &&
                    ntohs(reply->operation) == ARP_OP_REPLY &&
                    reply->sender_ip == target_ip) {
                    memcpy(out_mac, reply->sender_mac, ETH_ALEN);
                    free(buf);
                    return 0;
                }
            }
            p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
        }
    }
    free(buf);
    return -1;
}

static void send_arp_reply(int bpf_fd, const uint8_t *my_mac,
                           uint32_t claimed_ip,
                           const uint8_t *target_mac, uint32_t target_ip) {
    struct arp_packet reply;
    memset(&reply, 0, sizeof(reply));

    memcpy(reply.eth.ether_dhost, target_mac, ETH_ALEN);
    memcpy(reply.eth.ether_shost, my_mac, ETH_ALEN);
    reply.eth.ether_type = htons(ETHERTYPE_ARP);
    reply.hw_type = htons(1);
    reply.proto_type = htons(ETHERTYPE_IP);
    reply.hw_len = ETH_ALEN;
    reply.proto_len = 4;
    reply.operation = htons(ARP_OP_REPLY);
    memcpy(reply.sender_mac, my_mac, ETH_ALEN);
    reply.sender_ip = claimed_ip;
    memcpy(reply.target_mac, target_mac, ETH_ALEN);
    reply.target_ip = target_ip;

    write(bpf_fd, &reply, sizeof(reply));
}

/* Configure eth interface and start dnsmasq as child process */
static pid_t start_dhcp(const char *eth_if, const char *remote_ip,
                        uint32_t gw_ip) {
    /* Configure eth interface with link-local IP for dnsmasq binding.
       Use the gateway's /24 subnet for the DHCP range so the remote
       gets an IP on the real network. dnsmasq needs to be on the same
       subnet as the range it serves. */
    char gw_str[32];
    strlcpy(gw_str, inet_ntoa((struct in_addr){.s_addr = gw_ip}), sizeof(gw_str));

    /* Compute a .241 IP in the gateway's subnet for the eth interface */
    struct in_addr eth_addr;
    eth_addr.s_addr = (gw_ip & htonl(0xFFFFFF00)) | htonl(241);
    char eth_ip[32];
    strlcpy(eth_ip, inet_ntoa(eth_addr), sizeof(eth_ip));

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "ifconfig %s %s netmask 255.255.255.0 up", eth_if, eth_ip);
    system(cmd);
    fprintf(stderr, "macbridge: %s configured as %s\n", eth_if, eth_ip);

    /* Fork dnsmasq */
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        /* Child: exec dnsmasq */
        char range[128], opt_gw[64], opt_dns[64];
        snprintf(range, sizeof(range),
                 "--dhcp-range=%s,%s,255.255.255.0,12h", remote_ip, remote_ip);
        snprintf(opt_gw, sizeof(opt_gw), "--dhcp-option=3,%s", eth_ip);
        snprintf(opt_dns, sizeof(opt_dns), "--dhcp-option=6,%s", gw_str);

        char iface_opt[64];
        snprintf(iface_opt, sizeof(iface_opt), "--interface=%s", eth_if);

        execlp("dnsmasq", "dnsmasq",
               iface_opt, "--bind-interfaces",
               range, opt_gw, opt_dns,
               "--no-daemon", "--log-dhcp",
               "--leasefile-ro",    /* don't write lease file */
               NULL);
        perror("execlp dnsmasq");
        _exit(1);
    }

    fprintf(stderr, "macbridge: dnsmasq started (pid %d)\n", pid);

    /* Wait for dnsmasq to be ready */
    usleep(500000);
    return pid;
}

/*
 * Create a utun interface for the Mac -> Remote fast path.
 *
 * The kernel routes packets destined to remote_ip via utun instead of en0,
 * so they never hit the Wi-Fi driver. We read IP packets from utun here,
 * wrap them in an Ethernet header, and inject directly on en10.
 *
 * utun is a PF_SYSTEM/SYSPROTO_CONTROL socket. Each packet read/written
 * is prefixed with a 4-byte address family (host byte order on Darwin).
 *
 * We use P2P mode: self=172.16.0.1, peer=remote_ip. This automatically
 * creates a host route remote_ip -> utun0 that wins over en0's /24
 * (longest-prefix-match). Source IP on the Mac side is 172.16.0.1;
 * the remote replies to that address and its default gateway (eth_mac
 * on en10) delivers the reply back to us via the normal bridge path.
 */
static int create_utun(const char *remote_ip_str, char *ifname_out,
                       size_t ifname_size) {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) { perror("socket PF_SYSTEM"); return -1; }

    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    strlcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
    if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
        perror("CTLIOCGINFO utun");
        close(fd); return -1;
    }

    struct sockaddr_ctl sc;
    memset(&sc, 0, sizeof(sc));
    sc.sc_id = info.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_unit = 0;  /* 0 = auto-pick next free utun unit */

    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
        perror("connect utun");
        close(fd); return -1;
    }

    /* Retrieve the assigned interface name (utunN) */
    socklen_t iflen = ifname_size;
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
                   ifname_out, &iflen) < 0) {
        perror("getsockopt UTUN_OPT_IFNAME");
        close(fd); return -1;
    }

    /* P2P config: self=172.16.0.1, peer=remote_ip (creates host route) */
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "ifconfig %s inet 172.16.0.1 %s netmask 255.255.255.255 up",
             ifname_out, remote_ip_str);
    if (system(cmd) != 0) {
        fprintf(stderr, "macbridge: ifconfig on %s failed\n", ifname_out);
        close(fd); return -1;
    }

    fprintf(stderr, "macbridge: %s up, host route %s -> %s\n",
            ifname_out, remote_ip_str, ifname_out);
    return fd;
}

static int run_bridge(const char *wifi_if, const char *eth_if,
                      const char *remote_ip_str, uint32_t remote_ip,
                      uint32_t gw_ip, uint32_t wifi_ip) {
    uint8_t wifi_mac[ETH_ALEN], eth_mac[ETH_ALEN], remote_mac[ETH_ALEN], gw_mac[ETH_ALEN];
    char macstr[32];

    get_mac(wifi_if, wifi_mac);
    get_mac(eth_if, eth_mac);

    /* Phase 1: ARP discovery with see_sent=0, no filter, immediate mode.
       We need to see all traffic to catch ARP replies. */
    int wifi_buflen, eth_buflen;
    int bpf_wifi = open_bpf(wifi_if, &wifi_buflen, 0, NULL, 1);
    if (bpf_wifi < 0) return 1;

    int bpf_eth = open_bpf(eth_if, &eth_buflen, 0, NULL, 1);
    if (bpf_eth < 0) { close(bpf_wifi); return 1; }

    fprintf(stderr, "macbridge: waiting for remote %s on %s...\n",
            remote_ip_str, eth_if);
    if (arp_resolve(bpf_eth, eth_buflen, eth_mac, 0, remote_ip, remote_mac) < 0) {
        fprintf(stderr, "macbridge: cannot discover remote — is the device up?\n"
                "macbridge: (waiting for DHCP, retrying...)\n");
        /* Retry with longer timeout for boot */
        for (int retry = 0; retry < 30 && running; retry++) {
            sleep(2);
            if (arp_resolve(bpf_eth, eth_buflen, eth_mac, 0,
                            remote_ip, remote_mac) == 0)
                goto found_remote;
        }
        fprintf(stderr, "macbridge: gave up waiting for remote\n");
        close(bpf_wifi); close(bpf_eth);
        return 1;
    }
found_remote:
    mac_to_str(remote_mac, macstr, sizeof(macstr));
    fprintf(stderr, "macbridge: remote = %s @ %s\n", remote_ip_str, macstr);

    /* Discover gateway MAC */
    fprintf(stderr, "macbridge: discovering gateway MAC...\n");
    if (arp_resolve(bpf_wifi, wifi_buflen, wifi_mac, wifi_ip, gw_ip, gw_mac) < 0) {
        /* Fallback: read from system ARP cache */
        fprintf(stderr, "macbridge: BPF ARP failed, using system ARP cache...\n");
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "ping -c 1 -t 1 %s >/dev/null 2>&1",
                 inet_ntoa((struct in_addr){.s_addr = gw_ip}));
        system(cmd);
        snprintf(cmd, sizeof(cmd),
                 "arp -n %s 2>/dev/null | awk '/([0-9a-f]:)/ {print $4}'",
                 inet_ntoa((struct in_addr){.s_addr = gw_ip}));
        FILE *fp = popen(cmd, "r");
        char line[64] = {0};
        if (fp) { fgets(line, sizeof(line), fp); pclose(fp); }
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) > 10 && parse_mac(line, gw_mac) == 0) {
            fprintf(stderr, "macbridge: gateway MAC from system cache\n");
        } else {
            fprintf(stderr, "macbridge: cannot discover gateway MAC\n");
            close(bpf_wifi); close(bpf_eth);
            return 1;
        }
    }
    mac_to_str(gw_mac, macstr, sizeof(macstr));
    fprintf(stderr, "macbridge: gateway = %s @ %s\n",
            inet_ntoa((struct in_addr){.s_addr = gw_ip}), macstr);

    arp_cache_put(gw_ip, gw_mac);

    /* Phase 2: Reopen both BPFs for the main loop with:
         - Kernel-side filters (dramatically reduces kernel->user copies)
         - Large buffers (absorb bursts)
         - see_sent=1 on Wi-Fi so we capture the Mac's own outgoing traffic
       Immediate mode kept ON — low latency matters more than batch efficiency
       for interactive workloads (SSH, ping). Can be disabled for pure throughput. */
    build_wifi_filter(remote_ip);
    build_eth_filter(remote_mac);

    close(bpf_wifi);
    close(bpf_eth);
    /* Wi-Fi BPF: see_sent=0 — Mac's own traffic to remote now goes via utun,
       so we only need incoming from the LAN (external devices reaching the
       remote). Dropping see_sent=1 cuts Wi-Fi noise dramatically. */
    bpf_wifi = open_bpf(wifi_if, &wifi_buflen, 0, &wifi_filter, 1);
    if (bpf_wifi < 0) return 1;
    bpf_eth = open_bpf(eth_if, &eth_buflen, 0, &eth_filter, 1);
    if (bpf_eth < 0) { close(bpf_wifi); return 1; }

    /* Create utun for the Mac -> Remote fast path (bypasses Wi-Fi entirely) */
    char utun_name[16];
    int utun_fd = create_utun(remote_ip_str, utun_name, sizeof(utun_name));
    if (utun_fd < 0) {
        close(bpf_wifi); close(bpf_eth);
        return 1;
    }

    /* Enable weak host model — replies on en10 for utun's IPs still accepted */
    system("sysctl -w net.inet.ip.check_interface=0 >/dev/null 2>&1");

    /* Enable IP forwarding for OrangePi's outgoing traffic */
    system("sysctl -w net.inet.ip.forwarding=1 >/dev/null 2>&1");

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    fprintf(stderr, "\nmacbridge: bridging active — %s <-> %s (%s, via %s)\n",
            wifi_if, remote_ip_str, eth_if, utun_name);
    fprintf(stderr, "macbridge: Ctrl+C to stop\n\n");

    uint8_t *wbuf = malloc(wifi_buflen);
    uint8_t *ebuf = malloc(eth_buflen);
    uint8_t *ubuf = malloc(2048);   /* utun packet buffer (max ~1500 + hdr) */
    if (!wbuf || !ebuf || !ubuf) { perror("malloc"); return 1; }

    uint64_t wifi_to_eth = 0, eth_to_wifi = 0, arp_proxied = 0, utun_to_eth = 0;

    while (running) {
        struct pollfd pfds[3] = {
            { .fd = bpf_wifi, .events = POLLIN },
            { .fd = bpf_eth,  .events = POLLIN },
            { .fd = utun_fd,  .events = POLLIN },
        };
        if (poll(pfds, 3, 500) <= 0) continue;

        /*
         * utun -> Eth: Mac's own traffic to remote_ip.
         * Kernel routes to utun0, we read the IP packet here, wrap it in
         * an Ethernet header addressed to the remote, and inject on en10.
         * This completely bypasses the Wi-Fi driver — no wasted airtime.
         */
        if (pfds[2].revents & POLLIN) {
            ssize_t n = read(utun_fd, ubuf, 2048);
            /* utun prepends 4 bytes of address family in NETWORK byte order */
            if (n > 4) {
                uint32_t af = ntohl(*(uint32_t *)ubuf);
                if (af == AF_INET) {
                    /* Build Ethernet frame: dst=remote_mac, src=eth_mac,
                       type=IPv4. Payload = the IP packet we just read. */
                    uint8_t frame[2048];
                    struct ether_header *eh = (struct ether_header *)frame;
                    memcpy(eh->ether_dhost, remote_mac, ETH_ALEN);
                    memcpy(eh->ether_shost, eth_mac, ETH_ALEN);
                    eh->ether_type = htons(ETHERTYPE_IP);
                    size_t ip_len = n - 4;
                    memcpy(frame + sizeof(*eh), ubuf + 4, ip_len);
                    write(bpf_eth, frame, sizeof(*eh) + ip_len);
                    utun_to_eth++;
                }
            }
        }

        /* Wi-Fi -> Eth */
        if (pfds[0].revents & POLLIN) {
            ssize_t n = read(bpf_wifi, wbuf, wifi_buflen);
            if (n > 0) {
                uint8_t *p = wbuf;
                while (p < wbuf + n) {
                    struct bpf_hdr *bh = (struct bpf_hdr *)p;
                    uint8_t *frame = p + bh->bh_hdrlen;
                    size_t framelen = bh->bh_caplen;
                    p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);

                    if (framelen < sizeof(struct ether_header)) continue;
                    struct ether_header *eh = (struct ether_header *)frame;
                    uint16_t ethertype = ntohs(eh->ether_type);

                    /* ARP: proxy for remote, learn others.
                       With see_sent=0 we no longer capture our own injected
                       replies, so the old skip-self logic is gone. */
                    if (ethertype == ETHERTYPE_ARP && framelen >= sizeof(struct arp_packet)) {
                        struct arp_packet *arp = (struct arp_packet *)frame;
                        if (ntohs(arp->operation) == ARP_OP_REQUEST &&
                            arp->target_ip == remote_ip) {
                            send_arp_reply(bpf_wifi, wifi_mac, remote_ip,
                                           arp->sender_mac, arp->sender_ip);
                            arp_proxied++;
                            arp_cache_put(arp->sender_ip, arp->sender_mac);
                        }
                        if (ntohs(arp->operation) == ARP_OP_REPLY)
                            arp_cache_put(arp->sender_ip, arp->sender_mac);
                        continue;
                    }

                    /* IP to remote? Forward to eth */
                    if (ethertype == ETHERTYPE_IP &&
                        framelen >= sizeof(struct ether_header) + 20) {
                        struct ip *iph = (struct ip *)(frame + sizeof(struct ether_header));
                        if (iph->ip_dst.s_addr == remote_ip) {
                            memcpy(eh->ether_shost, eth_mac, ETH_ALEN);
                            memcpy(eh->ether_dhost, remote_mac, ETH_ALEN);
                            write(bpf_eth, frame, framelen);
                            wifi_to_eth++;
                        }
                    }
                }
            }
        }

        /* Eth -> Wi-Fi */
        if (pfds[1].revents & POLLIN) {
            ssize_t n = read(bpf_eth, ebuf, eth_buflen);
            if (n > 0) {
                uint8_t *p = ebuf;
                while (p < ebuf + n) {
                    struct bpf_hdr *bh = (struct bpf_hdr *)p;
                    uint8_t *frame = p + bh->bh_hdrlen;
                    size_t framelen = bh->bh_caplen;
                    p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);

                    if (framelen < sizeof(struct ether_header)) continue;
                    struct ether_header *eh = (struct ether_header *)frame;
                    uint16_t ethertype = ntohs(eh->ether_type);

                    if (memcmp(eh->ether_shost, remote_mac, ETH_ALEN) != 0)
                        continue;

                    /* ARP from remote: respond to everything */
                    if (ethertype == ETHERTYPE_ARP && framelen >= sizeof(struct arp_packet)) {
                        struct arp_packet *arp = (struct arp_packet *)frame;
                        if (ntohs(arp->operation) == ARP_OP_REQUEST) {
                            send_arp_reply(bpf_eth, eth_mac,
                                           arp->target_ip,
                                           remote_mac, arp->sender_ip);
                            arp_proxied++;
                        }
                        continue;
                    }

                    /* Forward IP to Wi-Fi */
                    if (ethertype == ETHERTYPE_IP &&
                        framelen >= sizeof(struct ether_header) + 20) {
                        struct ip *iph = (struct ip *)(frame + sizeof(struct ether_header));
                        uint32_t dst_ip = iph->ip_dst.s_addr;

                        /* Skip replies to Mac — arrive directly on en10 */
                        if (dst_ip == wifi_ip)
                            continue;

                        uint8_t *dst_mac = arp_cache_get(dst_ip);
                        if (!dst_mac)
                            dst_mac = gw_mac;

                        memcpy(eh->ether_shost, wifi_mac, ETH_ALEN);
                        memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
                        write(bpf_wifi, frame, framelen);
                        eth_to_wifi++;
                    }

                    /* Forward broadcast/multicast */
                    if (eh->ether_dhost[0] & 0x01) {
                        memcpy(eh->ether_shost, wifi_mac, ETH_ALEN);
                        write(bpf_wifi, frame, framelen);
                        eth_to_wifi++;
                    }
                }
            }
        }
    }

    fprintf(stderr,
        "\nmacbridge: stopped. utun->eth=%llu wifi->eth=%llu eth->wifi=%llu arp=%llu\n",
        utun_to_eth, wifi_to_eth, eth_to_wifi, arp_proxied);

    free(wbuf);
    free(ebuf);
    free(ubuf);
    close(bpf_wifi);
    close(bpf_eth);
    close(utun_fd);  /* destroys the utun interface and its host route */
    return 0;
}

/*
 * main() is the WATCHDOG. It:
 *   1. Validates args and saves initial system state
 *   2. Forks the bridge child
 *   3. Waits for the child to exit (for ANY reason)
 *   4. Runs cleanup — guaranteed unless the watchdog itself is SIGKILL'd
 *
 * Signals (SIGINT, SIGTERM, SIGHUP, etc.) are forwarded to the child.
 * The watchdog never calls system() from a signal handler.
 */
int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr,
            "Usage: sudo %s <wifi-iface> <eth-iface> <remote-ip>\n"
            "\n"
            "Bridges <eth-iface> to <wifi-iface> so the remote device\n"
            "appears on the Wi-Fi network at <remote-ip>.\n"
            "\n"
            "Example: sudo %s en0 en10 192.168.0.100\n",
            argv[0], argv[0]);
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "macbridge: must run as root (sudo)\n");
        return 1;
    }

    const char *wifi_if = argv[1];
    const char *eth_if = argv[2];
    const char *remote_ip_str = argv[3];
    uint32_t remote_ip = inet_addr(remote_ip_str);
    if (remote_ip == INADDR_NONE) {
        fprintf(stderr, "Invalid IP: %s\n", remote_ip_str);
        return 1;
    }

    /* Save state BEFORE any modifications */
    strlcpy(cleanup_remote_ip, remote_ip_str, sizeof(cleanup_remote_ip));
    check_interface_was = get_sysctl_int("net.inet.ip.check_interface");
    fprintf(stderr, "macbridge: check_interface was %d\n", check_interface_was);

    /* Discover interfaces and gateway — needed for dnsmasq setup */
    uint8_t wifi_mac[ETH_ALEN], eth_mac[ETH_ALEN];
    char macstr[32];

    if (get_mac(wifi_if, wifi_mac) < 0) {
        fprintf(stderr, "Cannot get MAC for %s\n", wifi_if);
        return 1;
    }
    mac_to_str(wifi_mac, macstr, sizeof(macstr));
    fprintf(stderr, "macbridge: %s MAC = %s\n", wifi_if, macstr);

    if (get_mac(eth_if, eth_mac) < 0) {
        fprintf(stderr, "Cannot get MAC for %s\n", eth_if);
        return 1;
    }
    mac_to_str(eth_mac, macstr, sizeof(macstr));
    fprintf(stderr, "macbridge: %s MAC = %s\n", eth_if, macstr);

    uint32_t gw_ip = get_default_gateway();
    if (gw_ip == 0) {
        fprintf(stderr, "Cannot determine default gateway\n");
        return 1;
    }
    fprintf(stderr, "macbridge: gateway = %s\n",
            inet_ntoa((struct in_addr){.s_addr = gw_ip}));

    uint32_t wifi_ip = 0;
    struct ifaddrs *ifap, *ifa;
    if (getifaddrs(&ifap) == 0) {
        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
            if (strcmp(ifa->ifa_name, wifi_if) == 0 &&
                ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                wifi_ip = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
                break;
            }
        }
        freeifaddrs(ifap);
    }
    fprintf(stderr, "macbridge: %s IP = %s\n", wifi_if,
            inet_ntoa((struct in_addr){.s_addr = wifi_ip}));

    /* Start dnsmasq in the WATCHDOG so it can be cleaned up */
    dnsmasq_pid = start_dhcp(eth_if, remote_ip_str, gw_ip);
    if (dnsmasq_pid < 0) return 1;

    /* Fork the bridge child */
    bridge_pid = fork();
    if (bridge_pid < 0) {
        perror("fork");
        return 1;
    }

    if (bridge_pid == 0) {
        /* === CHILD: run the bridge === */
        signal(SIGINT, handle_signal);
        signal(SIGTERM, handle_signal);
        signal(SIGHUP, handle_signal);
        signal(SIGPIPE, SIG_IGN);
        int rc = run_bridge(wifi_if, eth_if, remote_ip_str, remote_ip, gw_ip, wifi_ip);
        _exit(rc);
    }

    /* === PARENT: watchdog === */
    /* Forward all termination signals to the child */
    signal(SIGINT, watchdog_signal);
    signal(SIGTERM, watchdog_signal);
    signal(SIGHUP, watchdog_signal);
    signal(SIGQUIT, watchdog_signal);
    signal(SIGPIPE, SIG_IGN);

    /* Wait for child to exit — blocks until ANY exit */
    int status;
    waitpid(bridge_pid, &status, 0);
    bridge_pid = 0;

    if (WIFEXITED(status)) {
        fprintf(stderr, "macbridge: bridge exited with code %d\n",
                WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "macbridge: bridge killed by signal %d\n",
                WTERMSIG(status));
    }

    /* Cleanup ALWAYS runs here — safe context, not a signal handler */
    do_cleanup();
    fprintf(stderr, "macbridge: all clean\n");

    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
