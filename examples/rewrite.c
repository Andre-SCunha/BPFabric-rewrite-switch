#include <linux/if_ether.h>
#include "ebpf_switch.h"
#include <netinet/ip.h>

#define ARP_PROTOCOL 0x0608
#define IP_PROTOCOL 0x0008
#define ARP_HLEN 8

struct arphdr {
    uint16_t ar_hrd;
    uint16_t ar_pro;
    uint8_t ar_hrdlen;
    uint8_t ar_prolen;
    uint16_t ar_op;
};

struct bpf_map_def SEC("maps") inports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
};

struct bpf_map_def SEC("maps") servers = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 4,
    .value_size = sizeof(uint32_t),
    .max_entries = 3,
};

uint64_t prog(struct packet *pkt)
{	

    #if BYTE_ORDER == LITTLE_ENDIAN
        uint32_t server = 0x0a03000a;
        uint32_t host = 0x0a02000a;
    #endif
    #if BYTE_ORDER == BIG_ENDIAN
        uint32_t server = 0x0a00030a;
        uint32_t host = 0x0a00020a;
    #endif

    //ARP PACK
    if (pkt->eth.h_proto == ARP_PROTOCOL) {
	struct arphdr *arp = (struct arphdr *)(((uint8_t *)&pkt->eth) + ETH_HLEN);
	bpf_notify(1, &arp->ar_hrd, sizeof(uint16_t));
        bpf_notify(1, &arp->ar_pro, sizeof(uint16_t));
        bpf_notify(1, &arp->ar_hrdlen, sizeof(uint8_t));
        bpf_notify(1, &arp->ar_prolen, sizeof(uint8_t));
        bpf_notify(1, &arp->ar_op, sizeof(uint16_t));

	uint8_t *src_eth, *src_ip, *dst_eth, *dst_ip;
        uint16_t len = pkt->metadata.length;
        src_eth = ((uint8_t *)arp + ARP_HLEN);
        src_ip = src_eth + arp->ar_hrdlen;
        dst_eth = src_ip + arp->ar_prolen;
        dst_ip = dst_eth + arp->ar_hrdlen;
	bpf_notify(1, src_eth, arp->ar_hrdlen);
        bpf_notify(1, src_ip, arp->ar_prolen);
        bpf_notify(1, dst_eth, arp->ar_hrdlen);
        bpf_notify(1, dst_ip, arp->ar_prolen);
        bpf_notify(1, &pkt->metadata.length, sizeof(uint16_t));

	if ((*(uint32_t *)dst_ip) == server){
            //bpf_notify(1, dst_ip, arp->ar_prolen);
	    (*(uint32_t *)dst_ip) = host;
            bpf_notify(1, dst_ip, arp->ar_prolen);
        }
        if ((*(uint32_t *)src_ip) == host){
            //bpf_notify(1, src_ip, arp->ar_prolen);
	    (*(uint32_t *)src_ip) = server;
            bpf_notify(1, src_ip, arp->ar_prolen);
        }
        //bpf_notify(1, &arppkg->ar_op + sizeof(uint16_t) + arppkg->ar_hrdlen - 4, arppkg->ar_prolen);
    }
    //IP PACK
    else if (pkt->eth.h_proto == IP_PROTOCOL) {
        struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth) + ETH_HLEN);
	if ((*(uint32_t *)&ipv4->ip_dst.s_addr) == server){
            bpf_notify(1, &ipv4->ip_dst.s_addr, sizeof(struct in_addr));
	    (*(uint32_t *)&ipv4->ip_dst.s_addr) = host;
            (*(uint16_t *)&ipv4->ip_sum) += ((uint16_t)server - (uint16_t)host) + ((uint16_t)(server>>16) - (uint16_t)(host>>16));
            bpf_notify(1, &ipv4->ip_dst.s_addr, sizeof(struct in_addr));
        }
        if ((*(uint32_t *)&ipv4->ip_src.s_addr) == host){
            bpf_notify(1, &ipv4->ip_src.s_addr, sizeof(struct in_addr));
	    (*(uint32_t *)&ipv4->ip_src.s_addr) = server;
            (*(uint16_t *)&ipv4->ip_sum) -= ((uint16_t)server - (uint16_t)host) + ((uint16_t)(server>>16) - (uint16_t)(host>>16));
            bpf_notify(1, &ipv4->ip_src.s_addr, sizeof(struct in_addr));
        }
    }

    
    uint32_t *out_port;

    // if the source is not a broadcast or multicast
    if ((pkt->eth.h_source[0] & 1) == 0) {
        // Update the port associated with the packet
        bpf_map_update_elem(&inports, pkt->eth.h_source, &pkt->metadata.in_port, 0);
    }

    // Flood if the destination is broadcast or multicast
    if (pkt->eth.h_dest[0] & 1) {
        return FLOOD;
    }

    // Lookup the output port
    if (bpf_map_lookup_elem(&inports, pkt->eth.h_dest, &out_port) == -1) {
        // If no entry was found flood
        return FLOOD;
    }

    return *out_port;
}
char _license[] SEC("license") = "GPL";
