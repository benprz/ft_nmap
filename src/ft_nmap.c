#include "ft_nmap.h"

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

// Compute checksum for the given buffer and length
unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// Query routing table for source address and port
int get_src_addr_and_port(const char *dest_ip, struct sockaddr_in *src_addr) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket error");
        return -1;
    }

    struct sockaddr_in dest_addr = {0};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip);
    dest_addr.sin_port = htons(9999); // Arbitrary port for routing query

    if (connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Connect error");
        close(sockfd);
        return -1;
    }

    socklen_t src_addr_len = sizeof(struct sockaddr_in);
    if (getsockname(sockfd, (struct sockaddr *)src_addr, &src_addr_len) < 0) {
        perror("Getsockname error");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}

int send_syn_packet(const char *dest_ip, uint16_t dest_port) {
    struct sockaddr_in src_addr;
    if (get_src_addr_and_port(dest_ip, &src_addr) < 0) {
        fprintf(stderr, "Failed to get source address and port\n");
        return -1;
    }

    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_socket < 0) {
        perror("Socket error");
        return -1;
    }

    // Set socket option to include IP header
    int on = 1;
    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("Setsockopt error");
        return -1;
    }

    char packet[1024];
    memset(packet, 0, sizeof(packet));

    // Construct IP header
    struct iphdr *ip = (struct iphdr *)packet;
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = src_addr.sin_addr.s_addr;
    ip->daddr = inet_addr(dest_ip);
    ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr));

    // Construct TCP header
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    tcp->source = src_addr.sin_port;
    tcp->dest = htons(dest_port);
    tcp->seq = htonl(1);
    tcp->ack_seq = 0;
    tcp->doff = 5; // TCP header length (5 * 4 = 20 bytes)
    tcp->syn = 1; // SYN flag
    tcp->window = htons(5840);
    tcp->check = 0; // Calculate later
    tcp->urg_ptr = 0;

    // TCP pseudo header for checksum
    struct pseudo_header {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t tcp_len;
    } psh;

    psh.src = ip->saddr;
    psh.dst = ip->daddr;
    psh.zero = 0;
    psh.proto = IPPROTO_TCP;
    psh.tcp_len = htons(sizeof(struct tcphdr));

    char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));
    tcp->check = checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

    // Destination address for sendto()
    struct sockaddr_in dest_info;
    memset(&dest_info, 0, sizeof(dest_info));
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr.s_addr = ip->daddr;

    // Send packet
    if (sendto(raw_socket, packet, ntohs(ip->tot_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
        perror("Sendto error");
        exit(1);
    }

    printf("Packet sent from %s:%u to %s:%u\n",
           inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port),
           dest_ip, dest_port);

    close(raw_socket);
    return 0;
}

int ft_nmap() {
	char* dest_ip = "127.0.0.1";
	uint16_t dest_port = 9999;
	return send_syn_packet(dest_ip, dest_port);
}

// Use a socket to simulate a connection to the destination IP address.
// This will allow the operating system to determine the appropriate source IP address based on the routing table.
// int query_routing_table_for_src_addr(const struct sockaddr_in* dest_addr, struct sockaddr_in* src_addr) {
//     int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
//     if (sockfd < 0) {
//         perror("query_routing_table_for_src_ip -> socket() :");
//         close(sockfd);
//         return -1;
//     }
// 	if (connect(sockfd, (const struct sockaddr*)dest_addr, sizeof(struct sockaddr)) == -1) {
// 		perror("query_routing_table_for_src_ip -> connect() :");
// 		close(sockfd);
// 		return -1;
// 	}

// 	socklen_t src_addr_len = sizeof(struct sockaddr_in);
// 	if (getsockname(sockfd, (struct sockaddr*)src_addr, &src_addr_len) == -1) {
// 		perror("query_routing_table_for_src_ip -> getsockname() :");
// 		close(sockfd);
// 		return -1;
// 	}
// 	close(sockfd);
// 	return 0;
// }

// void print_hex(unsigned char *ptr, uint16_t size) {
// 	printf("hex dump:\n");
// 	for (uint16_t i = 0; i < size; i++) {
// 		printf("%x ", ptr[i]);
// 	}
// 	printf("\n");
// }



// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>
// #include <sys/socket.h>
// #include <netinet/ip.h>
// #include <netinet/tcp.h>
// #include <arpa/inet.h>

// // Compute checksum for the given buffer and length
// unsigned short checksum(unsigned short *buf, int len) {
//     unsigned long sum = 0;
//     while (len > 1) {
//         sum += *buf++;
//         len -= 2;
//     }
//     if (len == 1) {
//         sum += *(unsigned char *)buf;
//     }
//     sum = (sum >> 16) + (sum & 0xffff);
//     sum += (sum >> 16);
//     return (unsigned short)(~sum);
// }

// int ft_nmap() {
//     int raw_socket;
//     struct sockaddr_in dest_info;
//     char packet[1024];

//     // Create raw socket
//     raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
//     if (raw_socket < 0) {
//         perror("Socket error");
//         exit(1);
//     }

//     // Set socket option to include IP header
//     int on = 1;
//     if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
//         perror("Setsockopt error");
//         exit(1);
//     }

//     // Construct IP header
//     struct iphdr *ip = (struct iphdr *)packet;
//     ip->version = 4;
//     ip->ihl = 5;
//     ip->tos = 0;
//     ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
//     ip->id = htons(54321);
//     ip->frag_off = 0;
//     ip->ttl = 255;
//     ip->protocol = IPPROTO_TCP;
//     ip->check = 0; // Calculate later
//     ip->saddr = inet_addr("127.0.0.1"); // Spoofed source IP
//     ip->daddr = inet_addr("127.0.0.1"); // Destination IP

//     // Calculate IP checksum
//     ip->check = calculate_checksum((unsigned short *)ip, sizeof(struct iphdr));

//     // Construct TCP header
//     struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
//     tcp->source = htons(1234);
//     tcp->dest = htons(9999);
//     tcp->seq = htonl(1);
//     tcp->ack_seq = 0;
//     tcp->doff = 5; // TCP header length (5 * 4 = 20 bytes)
//     tcp->syn = 1; // SYN flag
//     tcp->window = htons(5840);
//     tcp->check = 0; // Calculate later
//     tcp->urg_ptr = 0;

//     // TCP pseudo header for checksum
//     struct pseudo_header {
//         u_int32_t src;
//         u_int32_t dst;
//         u_int8_t zero;
//         u_int8_t proto;
//         u_int16_t tcp_len;
//     } psh;

//     psh.src = ip->saddr;
//     psh.dst = ip->daddr;
//     psh.zero = 0;
//     psh.proto = IPPROTO_TCP;
//     psh.tcp_len = htons(sizeof(struct tcphdr));

//     // Calculate TCP checksum
//     char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
//     memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
//     memcpy(pseudo_packet + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));
//     tcp->check = calculate_checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

//     // Destination address for sendto()
//     memset(&dest_info, 0, sizeof(dest_info));
//     dest_info.sin_family = AF_INET;
//     dest_info.sin_addr.s_addr = ip->daddr;

//     // Send packet
//     if (sendto(raw_socket, packet, ntohs(ip->tot_len), 0,
//                (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
//         perror("Sendto error");
//         exit(1);
//     }

//     close(raw_socket);
//     return 0;
// }

// int ft_nmap() {
// 	// ft_nmap2();
// 	// test_normal_socket();
// 	// return 0;
// 	int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
// 	if (sock_raw < 0) {
// 		perror("ft_nmap -> sockfd = socket()");
// 		return -1;
// 	}

// 	// Set socket option to include IP header
//     int on = 1;
//     if (setsockopt(sock_raw, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
//         perror("Setsockopt error");
//         exit(1);
//     }

// 	// int sockfd_tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
// 	// if (sockfd_tcp < 0) {
// 	// 	perror("ft_nmap -> sockfd_tcp = socket()");
// 	// 	return -1;
// 	// }

// 	printf("Socket file descriptor: %d\n", sock_raw);
// 	// printf("Socket TCP file descriptor: %d\n", sockfd_tcp);

// 	// struct sockaddr_in src_addr, dest_addr = {
// 	// 	.sin_family = AF_INET,
// 	// 	.sin_port = htons(9999), // doesn't matter here
// 	// 	.sin_addr.s_addr = inet_addr("127.0.0.1")
// 	// };

// 	// struct sockaddr_in tcp_socket_addr = {
// 	// 	.sin_family = AF_INET,
// 	// 	.sin_port = 0,
// 	// 	.sin_addr.s_addr = inet_addr("0.0.0.0"),
// 	// 	.sin_zero = 0
// 	// };

// 	// if (bind(sockfd_tcp, (struct sockaddr*)&tcp_socket_addr, sizeof(tcp_socket_addr)) < 0) {
// 	// 	perror("ft_nmap -> bind()");
// 	// 	close(sock_raw);
// 	// 	return -1;
// 	// }
// 	// listen(sockfd_tcp, 10);

// 	// struct sockaddr_in bound_addr;
// 	// socklen_t bound_addr_len = sizeof(bound_addr);
// 	// if (getsockname(sockfd_tcp, (struct sockaddr*)&bound_addr, &bound_addr_len) < 0) {
// 	// 	perror("ft_nmap -> getsockname()");
// 	// 	close(sockfd_tcp);
// 	// 	close(sock_raw);
// 	// 	return -1;
// 	// }

// 	// if (query_routing_table_for_src_addr(&dest_addr, &src_addr) == -1) {
// 	// 	return -1;
// 	// }

// 	// printf("sending to address %s:%u from address %s\n", inet_ntoa(dest_addr.sin_addr), ntohs(dest_addr.sin_port), inet_ntoa(src_addr.sin_addr));

// 	// struct iphdr ip_header = { 0 };
// 	// ip_header.version = 4; // IPv4
// 	// ip_header.ihl = sizeof(ip_header) / 4; // Header length
// 	// ip_header.tos = 0; // Type of service
// 	// ip_header.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr)); // Total length
// 	// ip_header.id = htons(54321); // Identification
// 	// ip_header.frag_off = 0; // Fragment offset
// 	// ip_header.ttl = 255; // Time to live
// 	// ip_header.protocol = IPPROTO_TCP; // Protocol (TCP)
// 	// ip_header.saddr = src_addr.sin_addr.s_addr; // Source address
// 	// ip_header.daddr = dest_addr.sin_addr.s_addr; // Destination address
// 	// ip_header.check = htons(calculate_checksum((uint16_t*)&ip_header, sizeof(struct iphdr)));

// 	char packet[1024] = { 0 };
// 	struct iphdr *ip = (struct iphdr *)packet;
//     ip->version = 4;
//     ip->ihl = 5;
//     ip->tos = 0;
//     ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
//     ip->id = htons(54321);
//     ip->frag_off = 0;
//     ip->ttl = 255;
//     ip->protocol = IPPROTO_TCP;
//     ip->check = 0; // Calculate later
//     ip->saddr = inet_addr("127.0.0.1"); // Spoofed source IP
//     ip->daddr = inet_addr("127.0.0.1"); // Destination IP
//     ip->check = calculate_checksum((unsigned short *)ip, sizeof(struct iphdr));

// 	// printf("IP Header:\n");
// 	// print_hex((unsigned char*)&ip_header, sizeof(ip_header));

// 	// struct tcphdr tcp_header = {
// 	// 	.source = bound_addr.sin_port, // Source port
// 	// 	.dest = htons(9999),   // Destination port
// 	// 	.seq = 0,       // Sequence number
// 	// 	.ack_seq = 0,          // Acknowledgment number
// 	// 	.doff = sizeof(struct tcphdr) / 4, // Data offset
// 	// 	.syn = 1,              // SYN flag
// 	// 	.window = htons(64240), // Window size
// 	// 	.check = 0,            // Checksum (calculated later)
// 	// 	.urg_ptr = 0           // Urgent pointer
// 	// };

// 	// struct tcphdr tcp_header = { 0 };

// 	// tcp_header.source = htons(1234); // Source port
// 	// tcp_header.dest = htons(9999);   // Destination port
// 	// tcp_header.seq = htons(1);       // Sequence number
// 	// tcp_header.ack_seq = 0;          // Acknowledgment number
// 	// tcp_header.doff = sizeof(struct tcphdr) / 4; // Data offset
// 	// tcp_header.syn = 1;              // SYN flag
// 	// tcp_header.window = htons(5840); // Window size
// 	// tcp_header.check = 0;            // Checksum (calculated later)
// 	// tcp_header.urg_ptr = 0;          // Urgent pointer

// 	// printf("TCP Header:\n");
// 	// print_hex((unsigned char*)&tcp_header, sizeof(tcp_header));

// 	// Construct TCP header
//     struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
//     tcp->source = htons(1234);
//     tcp->dest = htons(9999);
//     tcp->seq = htonl(1);
//     tcp->ack_seq = 0;
//     tcp->doff = 5; // TCP header length (5 * 4 = 20 bytes)
//     tcp->syn = 1; // SYN flag
//     tcp->window = htons(5840);
//     tcp->check = 0; // Calculate later
//     tcp->urg_ptr = 0;


//     // TCP pseudo header for checksum
//     struct pseudo_header {
//         uint32_t src;
//         uint32_t dst;
//         uint8_t zero;
//         uint8_t proto;
//         uint16_t tcp_len;
//     } psh;

//     psh.src = ip->saddr;
//     psh.dst = ip->daddr;
//     psh.zero = 0;
//     psh.proto = IPPROTO_TCP;
//     psh.tcp_len = htons(sizeof(struct tcphdr));

//     // Calculate TCP checksum
//     char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
//     memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
//     memcpy(pseudo_packet + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));
//     tcp->check = calculate_checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

// 	// char send_buffer[((sizeof(struct iphdr) + sizeof(struct tcphdr) + 3) & ~3)] = {0}; //rounds-up to 4 bytes words

// 	// memcpy(send_buffer, &ip_header, sizeof(ip_header));

// 	// printf("send_buffer size : %lu | %% 4 = %lu\n", sizeof(send_buffer), sizeof(send_buffer) % 4);
// 	// struct pseudo_header_for_tcp_checksum pseudo_header;

// 	// pseudo_header.ip_src = ip_header.saddr;
// 	// pseudo_header.ip_dst = ip_header.daddr;
// 	// pseudo_header.padding = 0;
// 	// pseudo_header.protocol = IPPROTO_TCP;
// 	// pseudo_header.tcp_length = htons(sizeof(struct tcphdr));

// 	// uint8_t checksum_buffer[((sizeof(pseudo_header) + sizeof(tcp_header)) + 3) & ~3] = {0};
// 	// printf("checksum_buffer size : %lu | %% 4 = %lu\n", sizeof(checksum_buffer), sizeof(checksum_buffer) % 4);
// 	// memcpy(checksum_buffer, &pseudo_header, sizeof(pseudo_header));
// 	// memcpy(checksum_buffer + sizeof(pseudo_header), &tcp_header, sizeof(tcp_header));
// 	// memcpy(send_buffer, &tcp_header, sizeof(struct tcphdr));

// 	// tcp_header.check = htons(calculate_checksum((uint16_t*)checksum_buffer, sizeof(checksum_buffer)));

// 	// printf("TCP Header Checksum: 0x%04x\n", ntohs(tcp_header.check));


// 	// Destination address for sendto()
// 	struct sockaddr_in dest_info;
//     memset(&dest_info, 0, sizeof(dest_info));
//     dest_info.sin_family = AF_INET;
//     dest_info.sin_addr.s_addr = ip->daddr;
// 	// char recv_buffer[1024] = { 0 };
// 	// if (sendto(sock_raw, send_buffer, sizeof(send_buffer), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1) {
// 	// 	perror("ft_nmap -> sendto()");
// 	// 	close(sock_raw);
// 	// 	return -1;
// 	// }

// 	// Send packet
//     if (sendto(sock, packet, ntohs(ip->tot_len), 0,
//                (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
//         perror("Sendto error");
//         exit(1);
//     }
// 	// socklen_t dest_addr_len = sizeof(dest_addr);
// 	// recvfrom(sockfd_tcp, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr*)&dest_addr, &dest_addr_len);
// 	// printf("buffer: `%s`\n", recv_buffer);
// 	close(sock_raw);
// 	return 0;
// }
