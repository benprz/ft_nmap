#include "ft_nmap.h"
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <string.h>
#include <unistd.h>

// Use a socket to simulate a connection to the destination IP address.
// This will allow the operating system to determine the appropriate source IP address based on the routing table.
int query_routing_table_for_src_addr(const struct sockaddr_in* dest_addr, struct sockaddr_in* src_addr) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("query_routing_table_for_src_ip -> socket() :");
        close(sockfd);
        return -1;
    }
	if (connect(sockfd, (const struct sockaddr*)dest_addr, sizeof(struct sockaddr)) == -1) {
		perror("query_routing_table_for_src_ip -> connect() :");
		close(sockfd);
		return -1;
	}

	socklen_t src_addr_len = sizeof(struct sockaddr_in);
	if (getsockname(sockfd, (struct sockaddr*)src_addr, &src_addr_len) == -1) {
		perror("query_routing_table_for_src_ip -> getsockname() :");
		close(sockfd);
		return -1;
	}
	close(sockfd);
	return 0;
}

void test_normal_socket() {
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
	}

	struct sockaddr_in dest_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(80),
		.sin_addr.s_addr = inet_addr("172.67.30.189")
	};

	connect(sockfd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
	// sendto(sockfd, "hello", 5, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

}

int ft_nmap() {
	// test_normal_socket();
	// return 0;
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sockfd < 0) {
		perror("ft_nmap -> socket()");
		return -1;
	}

	int sockfd_tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd_tcp < 0) {
		perror("ft_nmap -> socket()");
		return -1;
	}

	printf("Socket file descriptor: %d\n", sockfd);
	printf("Socket TCP file descriptor: %d\n", sockfd_tcp);

	struct sockaddr_in src_addr, dest_addr = {
		.sin_family = AF_INET,
		.sin_port = 0, // doesn't matter here
		.sin_addr.s_addr = inet_addr("127.0.0.1")
	};

	if (bind(sockfd_tcp, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
		perror("ft_nmap -> bind()");
		close(sockfd);
		return -1;
	}

	struct sockaddr_in bound_addr;
	socklen_t bound_addr_len = sizeof(bound_addr);
	if (getsockname(sockfd_tcp, (struct sockaddr*)&bound_addr, &bound_addr_len) < 0) {
		perror("ft_nmap -> getsockname()");
		close(sockfd_tcp);
		close(sockfd);
		return -1;
	}
	printf("sockfd_tcp is bound to port: %u\n", ntohs(bound_addr.sin_port));

	if (query_routing_table_for_src_addr(&dest_addr, &src_addr) == -1) {
		return -1;
	}

	uint8_t tcp_options[20] = {
		0x02, 0x04, 0x05, 0xb4, // Maximum Segment Size (MSS): 1460 bytes
		0x04,                   // SACK Permitted
		0x01,                   // No-Operation (NOP)
		0x03, 0x03, 0x07,       // Window Scale: 7 (Multiplier: 128)
		0x01,                   // No-Operation (NOP)
		0x08, 0x0a,             // Timestamps
		0xfc, 0x9e, 0x4e, 0x6d, // TSval: 4222642381
		0x00, 0x00, 0x00, 0x00  // TSecr: 0
	};

	struct tcphdr tcp_header = {
		.source = bound_addr.sin_port, // Source port
		.dest = htons(80),   // Destination port
		.seq = htonl(0),       // Sequence number
		.ack_seq = 0,          // Acknowledgment number
		.doff = (sizeof(struct tcphdr) + sizeof(tcp_options)) / 4, // Data offset
		.syn = 1,              // SYN flag
		.window = htons(64240), // Window size
		.check = 0,            // Checksum (calculated later)
		.urg_ptr = 0           // Urgent pointer
	};

	char send_buffer[((sizeof(struct tcphdr) + sizeof(tcp_options) + 3) & ~3)] = {0}; //rounds-up to 4 bytes words
	memcpy(send_buffer, &tcp_header, sizeof(struct tcphdr));
	memcpy(send_buffer + sizeof(struct tcphdr), &tcp_options, sizeof(tcp_options));

	printf("send_buffer size : %lu | %% 4 = %lu\n", sizeof(send_buffer), sizeof(send_buffer) % 4);

	struct pseudo_header_for_tcp_checksum pseudo_header;

	pseudo_header.ip_src = src_addr.sin_addr.s_addr;
	pseudo_header.ip_dst = dest_addr.sin_addr.s_addr;
	pseudo_header.padding = 0;
	pseudo_header.protocol = IPPROTO_TCP;
	pseudo_header.tcp_packet_size = htons(sizeof(struct tcphdr));

	uint8_t checksum_buffer[sizeof(pseudo_header) + sizeof(tcp_header)];
	memcpy(checksum_buffer, &pseudo_header, sizeof(pseudo_header));
	memcpy(checksum_buffer + sizeof(pseudo_header), &tcp_header, sizeof(tcp_header));

	tcp_header.check = htons(calculate_checksum((uint16_t*)checksum_buffer, sizeof(checksum_buffer)));

	char recv_buffer[1024] = { 0 };
	sendto(sockfd, send_buffer, sizeof(send_buffer), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
	socklen_t dest_addr_len = sizeof(dest_addr);
	recvfrom(sockfd_tcp, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr*)&dest_addr, &dest_addr_len);
	printf("buffer: `%s`\n", recv_buffer);
	close(sockfd);
	return 0;
}
