typedef unsigned char       __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;

typedef signed char         __s8;
typedef signed short        __s16;
typedef signed int          __s32;
typedef signed long long    __s64;

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>

#define ETH_P_IP      0x0800 
#define IPPROTO_ICMP  1
#define ICMP_ECHO     8

struct ethhdr {
    __u8  h_dest[6];
    __u8  h_source[6];
    __u16 h_proto;
};

struct iphdr {
#if __BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__
    __u8 ihl:4;
    __u8 version:4;
#else
    __u8 version:4;
    __u8 ihl:4;
#endif

    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
};

struct icmphdr {
    __u8 type;
    __u8 code;
    __u16 checksum;
};

#define RATE_LIMIT 3

#define XDP_ABORTED  0
#define XDP_DROP     1
#define XDP_PASS     2
#define XDP_TX       3
#define XDP_REDIRECT 4

struct rate_limit_entry {
    __u64 last_update;
    __u32 packet_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct rate_limit_entry);
} rate_limit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} blacklist_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Apenas IPv4
    if (eth->h_proto != __bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // IP Header
    struct iphdr *ip = data + sizeof(*eth);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Apenas ICMP
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    // ICMP Header
    struct icmphdr *icmp = (void *)ip + sizeof(*ip);

    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    // Apenas ping request
    if (icmp->type != ICMP_ECHO)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // Verifica blacklist
    __u8 *blocked = bpf_map_lookup_elem(&blacklist_map, &src_ip);

    if (blocked)
        return XDP_DROP;

    // Procura entrada
    struct rate_limit_entry *entry;

    entry = bpf_map_lookup_elem(&rate_limit_map, &src_ip);

    if (entry) {

        entry->packet_count++;

        if (entry->packet_count > RATE_LIMIT) {

            __u8 flag = 1;

            bpf_map_update_elem(
                &blacklist_map,
                &src_ip,
                &flag,
                BPF_ANY
            );

             return XDP_DROP;
        }

    } else {

        struct rate_limit_entry new_entry = {
            .last_update = 0,
            .packet_count = 1
        };

        bpf_map_update_elem(
            &rate_limit_map,
            &src_ip,
            &new_entry,
            BPF_ANY
        );
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";