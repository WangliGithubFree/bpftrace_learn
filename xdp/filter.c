#define KBUILD_MODNAME "filter" 
#include <linux/bpf.h> 
#include <linux/if_ether.h> 
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>


int xdp_prog(struct xdp_md *ctx) {
    int mac_addr_index = 0;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    char *h_dest = eth->h_dest;

    if (eth + 1 > (struct ethhdr*)data_end)
        return XDP_ABORTED;

    bpf_trace_printk("mac addr:h_dest begin**********************\n");
    for(mac_addr_index = 0; mac_addr_index < ETH_ALEN; mac_addr_index++) {
        bpf_trace_printk("%x\n", h_dest[mac_addr_index]);
    }
    bpf_trace_printk("mac addr:h_dest end**********************\n");

    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if (ip + 1 > (struct iphdr*)data_end)
            return XDP_ABORTED;
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
            if (udp + 1 > (struct udphdr*)data_end)
                return XDP_ABORTED;
            bpf_trace_printk("UDP packet received: src=%d, dst=%d\n",
                    ntohs(udp->source), ntohs(udp->dest));
        }
    }
    return XDP_PASS;
}
