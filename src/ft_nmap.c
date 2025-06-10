#include "ft_nmap.h"

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

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

uint16_t	checksum_for_tcp_header(struct tcphdr tcphdr, struct sockaddr_in local_addr, struct sockaddr_in dest_addr)
{
	size_t			i;
	uint16_t		*words_tcphdr;
	unsigned long	sum;

	sum = 0;

	// TCP pseudo-header for checksum computation (IPv4)
	sum += (uint16_t) htons(sizeof(tcphdr));
	sum += (uint16_t) (local_addr.sin_addr.s_addr & 0xffff);
	sum += (uint16_t) (local_addr.sin_addr.s_addr >> 16 & 0xffff);
	sum += (uint16_t) (dest_addr.sin_addr.s_addr & 0xffff);
	sum += (uint16_t) (dest_addr.sin_addr.s_addr >> 16 & 0xffff);
	sum += htons(IPPROTO_TCP);

	i = 0;
	words_tcphdr = (uint16_t *) &tcphdr;
	fprintf(stdout, "TCP header: ");
	while (i < sizeof(tcphdr) / 2)
	{
		sum += words_tcphdr[i];
		fprintf(stdout, "0x%04x ", words_tcphdr[i]);
		i++;
	}
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (~sum);
}

int send_syn_packet(char *dest_ip, int dest_port)
{
	int sock;
	int	ret;
	struct tcphdr	tcphdr;
	struct addrinfo hints, *infos;
	struct sockaddr_in	src_addr;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	ret = getaddrinfo(dest_ip, NULL, &hints, &infos);
	if (ret)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
		return (1);
	}
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock < 0)
	{
		fprintf(stderr, "socket: %s\n", strerror(errno));
		freeaddrinfo(infos);
		return (2);
	}
	if (get_src_addr_and_port(dest_ip, &src_addr) < 0) {
		close(sock);
		freeaddrinfo(infos);
		return (3);
	}
	memset(&tcphdr, 0, sizeof(tcphdr));
	tcphdr.dest = htons(dest_port);
	tcphdr.source = htons(1111);
	srand(time(NULL));
	tcphdr.seq = htonl(rand());
	tcphdr.doff = 5;
	tcphdr.syn = 1;
	tcphdr.window = htons(5840);
	tcphdr.check = checksum_for_tcp_header(tcphdr, src_addr, * (struct sockaddr_in *) infos->ai_addr);
	fprintf(stdout, "\n0x%04x\n", tcphdr.check);
	ret = sendto(sock, &tcphdr, sizeof(tcphdr), 0, infos->ai_addr, infos->ai_addrlen);
	perror("sendto");
	close(sock);
	freeaddrinfo(infos);
	return 0;
}

int ft_nmap() {
	char* dest_ip = "104.22.45.83";
	uint16_t dest_port = 80;
	return send_syn_packet(dest_ip, dest_port);
}
