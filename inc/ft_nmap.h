#ifndef FT_NMAP_H
#define FT_NMAP_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>

#define UNUSED(x) (void)x

#define OPT_VERBOSE 0x1
#define OPT_SCAN_SYN 0x2

struct s_nmap
{
    unsigned int options;
};

// TCP pseudo-header for checksum computation (IPv4)
struct pseudo_header_for_tcp_checksum {
	uint32_t ip_src;
	uint32_t ip_dst;
	uint8_t padding;
	uint8_t protocol;
	uint16_t tcp_length; // The length of the TCP header and data (measured in octets).
};

extern struct s_nmap g_nmap;

int ft_nmap();

// utils functions
int todo(char*);
uint16_t calculate_checksum(uint16_t *, int);


#endif
