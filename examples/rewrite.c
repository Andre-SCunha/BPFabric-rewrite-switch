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
	//Get ARP
	struct arphdr *arp = (struct arphdr *)(((uint8_t *)&pkt->eth) + ETH_HLEN);

	//Collecting header info
	uint8_t *src_eth, *src_ip, *dst_eth, *dst_ip;
        src_eth = ((uint8_t *)arp + ARP_HLEN);
        src_ip = src_eth + arp->ar_hrdlen;
        dst_eth = src_ip + arp->ar_prolen;
        dst_ip = dst_eth + arp->ar_hrdlen;
	int isDstServer, isSrcServer;
	isDstServer = isServer((uint32_t*)dst_ip);
	isSrcServer = isServer((uint32_t*)src_ip);

	//In Packet
	if (isDstServer==1 && isSrcServer==0) {
		//Hash Ip src and get corresponding server
		uint32_t key = hashIP((uint32_t*)src_ip);
		uint32_t* server;
		bpf_map_lookup_elem(&servers, &key, &server);
		//Make a conection key and store header information
		uint32_t conkey = makeConnKey((uint32_t*)src_ip, (uint32_t*)dst_ip, server);
		uint64_t conval = packIpAddr ((uint32_t*)src_ip, (uint32_t*)dst_ip);
		bpf_map_update_elem(&conns, &conkey, &conval, 0);
		//Rewrite pkt with connection key as src
		(*(uint32_t *)dst_ip) = (*server);
		(*(uint32_t *)src_ip) = conkey;
	}

	//Out Packet
	if (isDstServer==0 && isSrcServer==1) {
		//Retrieving header info from conkey
		uint64_t* hdrInfo;
		bpf_map_lookup_elem(&conns, dst_ip, &hdrInfo);
		//Rewrite pkt correct info
		(*(uint32_t *)dst_ip) = (*((uint32_t*)hdrInfo + 1));
		(*(uint32_t *)src_ip) = (*(uint32_t*)hdrInfo);
	}
    }

    //IP PACK
    else if (pkt->eth.h_proto == IP_PROTOCOL) {
	//Get IP
        struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth) + ETH_HLEN);

	//Collecting header info
	uint32_t *src_ip, *dst_ip;
        src_ip = (uint32_t*)&ipv4->ip_src.s_addr;
        dst_ip = (uint32_t*)&ipv4->ip_dst.s_addr;
	uint16_t *checksum = (uint16_t *)&ipv4->ip_sum;
	int isDstServer, isSrcServer;
	isDstServer = isServer(dst_ip);
	isSrcServer = isServer(src_ip);

	//In Packet
	if (isDstServer==1 && isSrcServer==0) {
		//Hash Ip src and get corresponding server
		uint32_t key = hashIP(src_ip);
		uint32_t* server;
		bpf_map_lookup_elem(&servers, &key, &server);
		//Make a conection key and store header information
		uint32_t conkey = makeConnKey(src_ip, dst_ip, server);
		uint64_t conval = packIpAddr (src_ip, dst_ip);
		bpf_map_update_elem(&conns, &conkey, &conval, 0);
		//Rewrite pkt with connection key as src
		uint32_t dst_val = (*dst_ip);
		uint32_t src_val = (*src_ip);
		(*dst_ip) = (*server);
		(*src_ip) = conkey;
		//Updating checksum
		uint32_t srv_val = (*server);
		uint32_t new_check = (uint32_t)(*checksum);
		new_check += ((uint16_t)dst_val - (uint16_t)srv_val) + ((uint16_t)(dst_val>>16) - (uint16_t)(srv_val>>16));
		new_check += ((uint16_t)src_val - (uint16_t)conkey ) + ((uint16_t)(src_val>>16) - (uint16_t)(conkey>>16) );
		(*checksum) = (uint16_t)new_check + (uint16_t)(new_check>>16);
	}

	//Out Packet
	if (isDstServer==0 && isSrcServer==1) {
		//Retrieving header info from conkey
		uint64_t* hdrInfo;
		bpf_map_lookup_elem(&conns, dst_ip, &hdrInfo);
		//Rewrite pkt correct info
		uint32_t dst = (*dst_ip);
		uint32_t src = (*src_ip);
		(*dst_ip) = (*((uint32_t*)hdrInfo + 1));
		(*src_ip) = (*(uint32_t*)hdrInfo);
		//Update checksum
		uint32_t new_check = (uint32_t)(*checksum);
		new_check += ((uint16_t)dst - (uint16_t)(*dst_ip)) + ((uint16_t)(dst>>16) - (uint16_t)((*dst_ip)>>16));
		new_check += ((uint16_t)src - (uint16_t)(*src_ip)) + ((uint16_t)(src>>16) - (uint16_t)((*src_ip)>>16));
		(*checksum) = (uint16_t)new_check + (uint16_t)(new_check>>16);
	}
    }

    //Learning Switch    
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
	val = (*dst);
	res += (val>>16)*7;
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
