/**
 * ebpf_kernel.c — XDP eBPF Kernel Program for High-Speed Packet Filtering
 * 
 * Compiled to eBPF bytecode and loaded into the kernel via libbpf.
 * Runs at XDP hook point (before OS networking stack).
 * 
 * Performance: 100k+ packets/sec with zero-copy to userspace
 * 
 * Maps:
 *   - packet_ring_buffer: Ring buffer for packet events
 *   - blocklist: IP addresses to block
 *   - rate_limiter: Per-IP packet rate tracking
 *   - stats: Performance statistics
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

/* Constants */
#define MAX_ENTRIES 10000
#define RATE_LIMIT_PPS 10000  /* 10k packets/sec per IP */
#define RATE_WINDOW_MS 100    /* 100ms window */

/* Ring buffer for packet events (zero-copy to userspace) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} packet_ring_buffer SEC(".maps");

/* Blocklist: IP -> action (1=block, 0=allow) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);      /* IP address (network byte order) */
    __type(value, __u8);     /* Action: 1=block, 0=allow */
} blocklist SEC(".maps");

/* Rate limiter: IP -> (packet_count, timestamp) */
struct rate_entry {
    __u64 packet_count;
    __u64 last_update_ms;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);           /* IP address */
    __type(value, struct rate_entry);
} rate_limiter SEC(".maps");

/* Statistics */
struct stats {
    __u64 packets_processed;
    __u64 packets_blocked;
    __u64 packets_allowed;
    __u64 rate_limited;
    __u64 parse_errors;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} stats_map SEC(".maps");

/* Packet event for ring buffer */
struct packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 flags;
    __u16 payload_len;
    __u64 timestamp_ns;
    __u8 action;  /* 0=allow, 1=block, 2=rate_limited */
};

/* Helper: Get current time in milliseconds */
static __always_inline __u64 get_time_ms() {
    return bpf_ktime_get_ns() / 1000000;
}

/* Helper: Update statistics */
static __always_inline void update_stats(__u8 action) {
    __u32 key = 0;
    struct stats *s = bpf_map_lookup_elem(&stats_map, &key);
    if (!s) return;
    
    __sync_fetch_and_add(&s->packets_processed, 1);
    
    if (action == 1) {
        __sync_fetch_and_add(&s->packets_blocked, 1);
    } else if (action == 0) {
        __sync_fetch_and_add(&s->packets_allowed, 1);
    } else if (action == 2) {
        __sync_fetch_and_add(&s->rate_limited, 1);
    }
}

/* Helper: Check if IP is in blocklist */
static __always_inline __u8 is_blocked(__u32 ip) {
    __u8 *blocked = bpf_map_lookup_elem(&blocklist, &ip);
    return blocked ? *blocked : 0;
}

/* Helper: Check rate limit for IP */
static __always_inline __u8 check_rate_limit(__u32 ip) {
    struct rate_entry *entry = bpf_map_lookup_elem(&rate_limiter, &ip);
    __u64 now_ms = get_time_ms();
    
    if (!entry) {
        /* First packet from this IP */
        struct rate_entry new_entry = {
            .packet_count = 1,
            .last_update_ms = now_ms,
        };
        bpf_map_update_elem(&rate_limiter, &ip, &new_entry, BPF_ANY);
        return 0;  /* Allow */
    }
    
    /* Check if window expired */
    if (now_ms - entry->last_update_ms > RATE_WINDOW_MS) {
        /* Reset counter */
        entry->packet_count = 1;
        entry->last_update_ms = now_ms;
        return 0;  /* Allow */
    }
    
    /* Increment counter */
    entry->packet_count++;
    
    /* Check if rate exceeded */
    if (entry->packet_count > RATE_LIMIT_PPS / 10) {  /* 10 windows per second */
        return 2;  /* Rate limited */
    }
    
    return 0;  /* Allow */
}

/* Helper: Parse Ethernet header */
static __always_inline int parse_eth_header(void *data, void *data_end,
                                           __u16 *eth_proto) {
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    *eth_proto = eth->h_proto;
    return 0;
}

/* Helper: Parse IPv4 header */
static __always_inline int parse_ipv4_header(void *data, void *data_end,
                                            __u32 *src_ip, __u32 *dst_ip,
                                            __u8 *protocol) {
    struct iphdr *ip = data;
    
    if ((void *)(ip + 1) > data_end)
        return -1;
    
    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *protocol = ip->protocol;
    
    return ip->ihl * 4;  /* Header length */
}

/* Helper: Parse TCP header */
static __always_inline int parse_tcp_header(void *data, void *data_end,
                                           __u16 *src_port, __u16 *dst_port,
                                           __u8 *flags) {
    struct tcphdr *tcp = data;
    
    if ((void *)(tcp + 1) > data_end)
        return -1;
    
    *src_port = tcp->source;
    *dst_port = tcp->dest;
    *flags = tcp->flags;
    
    return tcp->doff * 4;  /* Header length */
}

/* Helper: Parse UDP header */
static __always_inline int parse_udp_header(void *data, void *data_end,
                                           __u16 *src_port, __u16 *dst_port) {
    struct udphdr *udp = data;
    
    if ((void *)(udp + 1) > data_end)
        return -1;
    
    *src_port = udp->source;
    *dst_port = udp->dest;
    
    return sizeof(struct udphdr);
}

/**
 * XDP Program — Main entry point
 * 
 * Called for every packet at XDP hook (before OS stack).
 * Returns: XDP_DROP (block), XDP_PASS (allow), XDP_ABORTED (error)
 */
SEC("xdp")
int xdp_ids_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    __u16 eth_proto = 0;
    __u32 src_ip = 0, dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;
    __u8 protocol = 0, flags = 0;
    __u16 payload_len = 0;
    __u8 action = 0;
    
    /* Parse Ethernet header */
    if (parse_eth_header(data, data_end, &eth_proto) < 0) {
        __u32 key = 0;
        struct stats *s = bpf_map_lookup_elem(&stats_map, &key);
        if (s) __sync_fetch_and_add(&s->parse_errors, 1);
        return XDP_PASS;
    }
    
    /* Only process IPv4 */
    if (eth_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    /* Parse IPv4 header */
    int ip_hdr_len = parse_ipv4_header(data + sizeof(struct ethhdr), data_end,
                                       &src_ip, &dst_ip, &protocol);
    if (ip_hdr_len < 0) {
        __u32 key = 0;
        struct stats *s = bpf_map_lookup_elem(&stats_map, &key);
        if (s) __sync_fetch_and_add(&s->parse_errors, 1);
        return XDP_PASS;
    }
    
    /* Parse transport header (TCP/UDP) */
    void *transport_data = data + sizeof(struct ethhdr) + ip_hdr_len;
    
    if (protocol == IPPROTO_TCP) {
        if (parse_tcp_header(transport_data, data_end, &src_port, &dst_port, &flags) < 0) {
            __u32 key = 0;
            struct stats *s = bpf_map_lookup_elem(&stats_map, &key);
            if (s) __sync_fetch_and_add(&s->parse_errors, 1);
            return XDP_PASS;
        }
    } else if (protocol == IPPROTO_UDP) {
        if (parse_udp_header(transport_data, data_end, &src_port, &dst_port) < 0) {
            __u32 key = 0;
            struct stats *s = bpf_map_lookup_elem(&stats_map, &key);
            if (s) __sync_fetch_and_add(&s->parse_errors, 1);
            return XDP_PASS;
        }
    } else {
        /* Not TCP/UDP, allow */
        update_stats(0);
        return XDP_PASS;
    }
    
    /* Calculate payload length */
    payload_len = (data_end - transport_data) & 0xFFFF;
    
    /* Check blocklist */
    if (is_blocked(src_ip)) {
        action = 1;  /* Block */
        update_stats(1);
        
        /* Send event to userspace */
        struct packet_event *ev = bpf_ringbuf_reserve(&packet_ring_buffer, sizeof(*ev), 0);
        if (ev) {
            ev->src_ip = src_ip;
            ev->dst_ip = dst_ip;
            ev->src_port = src_port;
            ev->dst_port = dst_port;
            ev->protocol = protocol;
            ev->flags = flags;
            ev->payload_len = payload_len;
            ev->timestamp_ns = bpf_ktime_get_ns();
            ev->action = 1;  /* Blocked */
            bpf_ringbuf_submit(ev, 0);
        }
        
        return XDP_DROP;
    }
    
    /* Check rate limit */
    __u8 rate_action = check_rate_limit(src_ip);
    if (rate_action == 2) {
        action = 2;  /* Rate limited */
        update_stats(2);
        return XDP_DROP;
    }
    
    /* Allow packet */
    action = 0;
    update_stats(0);
    
    /* Send event to userspace (sampled: 1 in 100) */
    if ((bpf_get_prandom_u32() % 100) == 0) {
        struct packet_event *ev = bpf_ringbuf_reserve(&packet_ring_buffer, sizeof(*ev), 0);
        if (ev) {
            ev->src_ip = src_ip;
            ev->dst_ip = dst_ip;
            ev->src_port = src_port;
            ev->dst_port = dst_port;
            ev->protocol = protocol;
            ev->flags = flags;
            ev->payload_len = payload_len;
            ev->timestamp_ns = bpf_ktime_get_ns();
            ev->action = 0;  /* Allowed */
            bpf_ringbuf_submit(ev, 0);
        }
    }
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

