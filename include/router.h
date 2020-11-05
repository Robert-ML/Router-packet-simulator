// Copyright Robert Lica <robertlica21@gimail.com>

#ifndef ROUTER_H
#define ROUTER_H

#include <bits/stdc++.h>

#define MAC_LEN 6
#define DEST_UNREACH 3
#define TTL_EXC_CODE 0
#define TTL_EXC_TYPE 11
#define IP_OFF (sizeof(struct ether_header))
#define ICMP_OFF (IP_OFF + sizeof(struct iphdr))

std::vector<int> get_vector_of_ip(const std::string &_prefix,
	const std::string &_next_hop, const std::string &_mask,
	const std::string &_interface);

void load_tabela_rutare(std::vector< std::unordered_map< int,
	std::vector<int>>> &tabela_rutare);
char* from_string_to_char(const std::string &s);
std::vector< int> look_routing_table(std::vector< std::unordered_map< int,
	std::vector<int>>> &tabela_rutare, __u32 &ip_dest);

void load_tabela_arp(std::vector< std::pair< __u32, std::vector< uint8_t>>>
	&tabela_arp);
std::pair< __u32, std::vector< uint8_t>> look_arp_entry(std::vector<
	std::pair< __u32, std::vector< uint8_t>>> &tabela_arp, int &next_hop);

void print_char_array(const char *c);

uint16_t not_mine_ip_checksum(void* vdata,size_t length);

void error_trimite_icmp(packet &m, char type, char code, 
	std::vector< std::unordered_map< int, std::vector<int>>> &tabela_rutare,
	std::vector< std::pair< __u32, std::vector< uint8_t>>> &tabela_arp);

#endif // ROUTER_H