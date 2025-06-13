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

uint16_t	checksum(struct tcphdr tcphdr, struct sockaddr_in local_addr, struct sockaddr_in dest_addr)
{
	size_t			i;
	uint16_t		*words_tcphdr;
	unsigned long	sum;

	sum = 0;
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

int main(int argc, char **argv)
{
	int sock;
	int	udp_sock;
	int	ret;
	struct tcphdr	tcphdr;
	struct addrinfo hints, *infos;
	struct sockaddr_in	local_addr;
	socklen_t			local_len;

	if (argc != 3)
	{
		fprintf(stdout, "Fuck off *twists your balls*\n");
		return (1);
	}
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	ret = getaddrinfo(argv[1], argv[2], &hints, &infos);
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
	udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udp_sock < 0)
	{
		fprintf(stderr, "socket: %s\n", strerror(errno));
		close(sock);
		freeaddrinfo(infos);
		return (2);
	}
	if (connect(udp_sock, infos->ai_addr, infos->ai_addrlen))
	{
		fprintf(stderr, "connect: %s\n", strerror(errno));
		close(sock);
		close(udp_sock);
		freeaddrinfo(infos);
		return (2);
	}
	local_len = sizeof(struct sockaddr_in);
	if (getsockname(udp_sock, (struct sockaddr *) &local_addr, &local_len))
	{
		fprintf(stderr, "getsockname: %s\n", strerror(errno));
		close(sock);
		close(udp_sock);
		freeaddrinfo(infos);
		return (2);
	}
	memset(&tcphdr, 0, sizeof(tcphdr));
	tcphdr.dest = htons(atoi(argv[2]));
	tcphdr.source = htons(1111);
	srand(time(NULL));
	tcphdr.seq = htonl(rand());
	tcphdr.doff = 5;
	tcphdr.syn = 1;
	tcphdr.window = htons(5840);
	tcphdr.check = checksum(tcphdr, local_addr, * (struct sockaddr_in *) infos->ai_addr);
	fprintf(stdout, "\n0x%04x\n", tcphdr.check);
	ret = sendto(sock, &tcphdr, sizeof(tcphdr), 0, infos->ai_addr, infos->ai_addrlen);
	perror("sendto");
	close(sock);
	freeaddrinfo(infos);
}
