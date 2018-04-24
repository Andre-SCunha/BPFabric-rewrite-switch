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

const int serversNumber = 2;
struct bpf_map_def SEC("maps") servers = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 4,
    .value_size = sizeof(uint32_t),
    .max_entries = serversNumber,
};

struct bpf_map_def SEC("maps") conns = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 4,
    .value_size = sizeof(uint64_t),
    .max_entries = 512,
};

int isServer(uint32_t* ip);
int hashIP(uint32_t* ip);
int makeConnKey(uint32_t* src, uint32_t* dst, uint32_t* srv);
uint64_t packIpAddr(uint32_t* src, uint32_t* dst);

uint64_t prog(struct packet *pkt)
{	

    //ARP PACK
    if (pkt->eth.h_proto == ARP_PROTOCOL) {

	struct arphdr *arp = (struct arphdr *)(((uint8_t *)&pkt->eth) + ETH_HLEN);
	/*bpf_notify(1, &arp->ar_hrd, sizeof(uint16_t));
        bpf_notify(1, &arp->ar_pro, sizeof(uint16_t));
        bpf_notify(1, &arp->ar_hrdlen, sizeof(uint8_t));
        bpf_notify(1, &arp->ar_prolen, sizeof(uint8_t));
        bpf_notify(1, &arp->ar_op, sizeof(uint16_t));*/

	uint8_t *src_eth, *src_ip, *dst_eth, *dst_ip;
        uint16_t len = pkt->metadata.length;
        src_eth = ((uint8_t *)arp + ARP_HLEN);
        src_ip = src_eth + arp->ar_hrdlen;
        dst_eth = src_ip + arp->ar_prolen;
        dst_ip = dst_eth + arp->ar_hrdlen;
	/*bpf_notify(1, src_eth, arp->ar_hrdlen);
        bpf_notify(1, src_ip, arp->ar_prolen);
        bpf_notify(1, dst_eth, arp->ar_hrdlen);
        bpf_notify(1, dst_ip, arp->ar_prolen);
        bpf_notify(1, &pkt->metadata.length, sizeof(uint16_t));*/

	if (isServer(dst_ip)){//And src not a server
		//Hash Ip src and get corresponding server
		uint32_t i = hashIP(src_ip);
		uint32_t* p = &i;
		uint32_t* g;
		bpf_map_lookup_elem(&servers, p, &g);
		bpf_notify(1, g, sizeof(uint32_t));
		//make a conection key to store information
		uint32_t key = makeConnKey(src_ip,dst_ip,g);
		uint64_t conval = packIpAddr (src_ip,dst_ip);
		uint64_t* conp;
		//store ip header by key
		bpf_map_update_elem(&conns, &key, &conval, 0);
		bpf_map_lookup_elem(&conns, &key, &conp);
		bpf_notify(1, (uint32_t*)conp, sizeof(uint32_t));//dst
		bpf_notify(1, (uint32_t*)conp + 1, sizeof(uint32_t));//src
	}


	//if ((*(uint32_t *)dst_ip) == server){
            //bpf_notify(1, dst_ip, arp->ar_prolen);
	    //(*(uint32_t *)dst_ip) = host;
            //bpf_notify(1, dst_ip, arp->ar_prolen);
       // }
        //if ((*(uint32_t *)src_ip) == host){
            //bpf_notify(1, src_ip, arp->ar_prolen);
	    //(*(uint32_t *)src_ip) = server;
            //bpf_notify(1, src_ip, arp->ar_prolen);
        //}
        //bpf_notify(1, &arppkg->ar_op + sizeof(uint16_t) + arppkg->ar_hrdlen - 4, arppkg->ar_prolen);
    }
    //IP PACK
    else if (pkt->eth.h_proto == IP_PROTOCOL) {
        struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth) + ETH_HLEN);
	//if ((*(uint32_t *)&ipv4->ip_dst.s_addr) == server){
            //bpf_notify(1, &ipv4->ip_dst.s_addr, sizeof(struct in_addr));
	    //(*(uint32_t *)&ipv4->ip_dst.s_addr) = host;
            //(*(uint16_t *)&ipv4->ip_sum) += ((uint16_t)server - (uint16_t)host) + ((uint16_t)(server>>16) - (uint16_t)(host>>16));
            //bpf_notify(1, &ipv4->ip_dst.s_addr, sizeof(struct in_addr));
        //}
        //if ((*(uint32_t *)&ipv4->ip_src.s_addr) == host){
            //bpf_notify(1, &ipv4->ip_src.s_addr, sizeof(struct in_addr));
	    //(*(uint32_t *)&ipv4->ip_src.s_addr) = server;
            //(*(uint16_t *)&ipv4->ip_sum) -= ((uint16_t)server - (uint16_t)host) + ((uint16_t)(server>>16) - (uint16_t)(host>>16));
            //bpf_notify(1, &ipv4->ip_src.s_addr, sizeof(struct in_addr));
        //}
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

int isServer(uint32_t* ip){

	uint32_t i = 1;
	uint32_t* p = &i;
	uint32_t* g;
	while (bpf_map_lookup_elem(&servers, p, &g) != -1){
		i++;
		//bpf_notify(1, dst_ip, sizeof(uint32_t));
		if ((*g) == (*ip))
			return 1;
	}
	return 0;

}

int hashIP(uint32_t* ip){

	int val = (*ip);
	return (val>>16)%serversNumber +1;

}

int makeConnKey(uint32_t* src, uint32_t* dst, uint32_t* srv){
	int val = (*src);
	int res = (val>>16)*3;
	/*val = (*dst);
	res += (val>>16)*7;*/
	val = (*srv);
	res += (val>>16)*13;
	return res*7;
}

uint64_t packIpAddr(uint32_t* src, uint32_t* dst){
	uint64_t res = (*src) & 0x00000000FFFFFFFF;
	res = (res<<32) + ((*dst) & 0x00000000FFFFFFFF);
	return res;
}

char _license[] SEC("license") = "GPL";
