// Copyright Robert Lica <robertlica21@gimail.com>

#include "./include/skel.h"
#include "./include/router.h"
#include <bits/stdc++.h>

// 0	   1         2     3
// prefix, next_hop, mask, interface

int main(int argc, char *argv[]) {
	packet m;
	int rc;

	// 32 pt ca atatia biti are masca
	std::vector< std::unordered_map< int, std::vector<int>>> tabela_rutare(32);
	load_tabela_rutare(tabela_rutare);
	std::vector< std::pair< __u32, std::vector< uint8_t>>> tabela_arp;
	load_tabela_arp(tabela_arp);

	init();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload +
			sizeof(struct ether_header));

		__u16 check_sum = ip_hdr->check;
		ip_hdr->check = 0;
		// daca nu e check-sum-ul bun, dam drop la pachet
		if (check_sum != not_mine_ip_checksum(ip_hdr, sizeof(struct iphdr))) {
			continue;
		}

		// ttl-ul se termina si dam drop la pachet
		if (ip_hdr->ttl <= 1) {
			error_trimite_icmp(m, TTL_EXC_TYPE, TTL_EXC_CODE, tabela_rutare,
				tabela_arp);
			continue;
		}

		std::vector< int> best_route = look_routing_table(tabela_rutare,
			ip_hdr->daddr);
		if (best_route.size() == 0) {
			error_trimite_icmp(m, DEST_UNREACH, 0, tabela_rutare, tabela_arp);
			continue;
		}

		// recalculam ttl-ul si check-sum-ul
		--ip_hdr->ttl;
		ip_hdr->check = not_mine_ip_checksum(ip_hdr, sizeof(struct iphdr));

		std::pair< __u32, std::vector< uint8_t>> best_arp =
			look_arp_entry(tabela_arp, best_route[1]);
		if (best_arp.first == 0) {
			// nu am gasit in tabela arp
			continue;
		}

		// bagam macul interfetei de iesire in header-ul de ethernet
		get_interface_mac(best_route[3], (uint8_t*) &eth_hdr->ether_shost);
		m.interface = best_route[3];
		
		// bagam mac-ul destinatiei in header-ul de ethernet
		DIE(best_arp.second.size() != 6,
			"MAC-ul din vectorul din arp-ul gasit are marimea diferita de 6\n");
		for (int i = MAC_LEN - 1; i >= 0; --i) {
			eth_hdr->ether_dhost[i] = best_arp.second[i];
		}

		// trimitem pachetul
		send_packet(best_route[3], &m);
	}
}

// ------------------------------------ ICMP ----------------------------------

void error_trimite_icmp(packet &m, char type, char code, 
	std::vector< std::unordered_map< int, std::vector<int>>> &tabela_rutare,
	std::vector< std::pair< __u32, std::vector< uint8_t>>> &tabela_arp) {
	packet pkt;
	memcpy(&pkt, &m, sizeof(packet));

	struct ether_header *eth_hdr = (struct ether_header *)pkt.payload;
	struct iphdr *ip_hdr = (struct iphdr *)(pkt.payload + IP_OFF);
	struct icmphdr *icmp_hdr = (struct icmphdr *)(pkt.payload + ICMP_OFF);

	struct ether_header *m_eth_hdr = (struct ether_header *)m.payload;
	struct iphdr *m_ip_hdr = (struct iphdr *)(m.payload +
		sizeof(struct ether_header));

	// setam icmp headerul
	icmp_hdr->type = type;
	icmp_hdr->code = code;
	icmp_hdr->un.echo.id = htons(getpid());
	icmp_hdr->un.echo.sequence = htons(64);
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = not_mine_ip_checksum(icmp_hdr,
		sizeof(struct icmphdr));

	// setam ip headerul
	ip_hdr->version = 4;
	ip_hdr->ihl = 5;
	ip_hdr->tos = 0;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->id = htons(getpid());	
	ip_hdr->ttl = 64;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->saddr = inet_addr(get_interface_ip(m.interface));
	ip_hdr->daddr = m_ip_hdr->saddr;
	ip_hdr->check = 0;
	ip_hdr->check = not_mine_ip_checksum(ip_hdr, sizeof(struct iphdr));

	// setam ethernet headerul
	get_interface_mac(m.interface, eth_hdr->ether_shost);
	memcpy(&eth_hdr->ether_dhost, &m_eth_hdr->ether_shost, 6 * sizeof(char));

	pkt.len = sizeof(struct ether_header) + sizeof(struct iphdr) +
		sizeof(struct icmphdr);
	pkt.interface = m.interface;
	send_packet(pkt.interface, &pkt);
}


// ---------------------------- TABELA RUTARE ---------------------------------

void load_tabela_rutare(std::vector< std::unordered_map
	< int, std::vector<int>>> &tabela_rutare){
	std::ifstream fin ("rtable.txt");

	while (true) {
		std::string _prefix, _next_hop, _mask, _interface;
		fin >> _prefix;
		if (fin.eof()) {
			break;
		}
		fin >> _next_hop >> _mask >> _interface;

		std::vector<int> temp = get_vector_of_ip(_prefix, _next_hop, _mask,
			_interface);
		tabela_rutare[__builtin_popcount(temp[2]) - 1][temp[0]] = temp;
	}
	fin.close();
}

// 0	   1         2     3
// prefix, next_hop, mask, interface
std::vector<int> get_vector_of_ip(const std::string &_prefix,
	const std::string &_next_hop, const std::string &_mask,
	const std::string &_interface) {
	int prefix, next_hop, mask, interface;
	char* temp;

	temp = from_string_to_char(_prefix);
	inet_pton(AF_INET, temp, &prefix);
	free(temp);

	temp = from_string_to_char(_next_hop);
	inet_pton(AF_INET, temp, &next_hop);
	free(temp);

	temp = from_string_to_char(_mask);
	inet_pton(AF_INET, temp, &mask);
	free(temp);

	temp = from_string_to_char(_interface);
	interface = atoi(temp);
	free(temp);

	return std::vector<int>{prefix, next_hop, mask, interface};
}

std::vector< int> look_routing_table(std::vector< std::unordered_map< int,
	 std::vector<int>>> &tabela_rutare, __u32 &ip_dest) {
	for (int i = 31; i >= 0; --i) {
		// recreem masca
		int mask = 0xffffffff;
		mask <<= (31 - i);

		struct in_addr temp;
		temp.s_addr = ip_dest;

		auto entry = tabela_rutare[i].find(ip_dest & htonl(mask));
		if (entry == tabela_rutare[i].end()) {
			// nu l-am gasit aici
			continue;
		} else {
			return entry->second;
		}
	}

	return std::vector< int>(0);
}

// ------------------------------------- TABELA ARP ---------------------------
void load_tabela_arp(std::vector< std::pair< __u32, std::vector< uint8_t>>>
		&tabela_arp) {
	std::ifstream fin ("arp_table.txt");
	while(true) {
		std::string _ip, _mac;
		__u32 ip;
		std::vector< uint8_t> mac(MAC_LEN);
		uint8_t mac_temp[MAC_LEN];
		fin >> _ip;

		if (fin.eof()) {
			break;
		}
		fin >> _mac;
		char *temp;

		temp = from_string_to_char(_ip);
		inet_pton(AF_INET, temp, &ip);
		free(temp);

		temp = from_string_to_char(_ip);
		hwaddr_aton(temp, mac_temp);
		free(temp);

		for (int i = MAC_LEN - 1; i >= 0; --i) {
			mac[i] = mac_temp[i];
		}
		tabela_arp.push_back(std::pair< __u32,
			std::vector< uint8_t>>(ip, mac));
	}
	fin.close();
}

std::pair< __u32, std::vector< uint8_t>> look_arp_entry(std::vector<
	std::pair< __u32, std::vector< uint8_t>>> &tabela_arp, int &next_hop) {
	for (auto &x : tabela_arp) {
		if (x.first == next_hop) {
			return std::pair< __u32, std::vector< uint8_t>>(x.first, x.second);
		}
	}
	return std::pair< __u32,
		std::vector< uint8_t>>(0, std::vector< uint8_t>(0));
}



char* from_string_to_char(const std::string &s) {
	char *c = (char*)malloc((s.size() + 1) * sizeof(char));
	for (int i = s.size() - 1; i >= 0; --i) {
		c[i] = s[i];
	}
	c[s.size()] = 0;
	return c;
}

void print_char_array(const char *str) {
	int i = 0;
	while (true) {
		char c = str[i];
		if (c == 0) {
			break;
		}
		std::cout << c;
		++i;
	}
	std::cout << std::endl;
}


uint16_t not_mine_ip_checksum(void* vdata,size_t length) {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint64_t acc=0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	// Handle any complete 32-bit blocks.
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}
	// Handle deferred carries.
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}

