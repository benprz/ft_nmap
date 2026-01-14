#include <pthread.h>
#include "ft_nmap.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <string.h>

uint16_t	checksum_tcp(struct tcphdr tcphdr, struct sockaddr_in src,
					struct sockaddr_in tgt)
{
	size_t			i;
	uint16_t		*words_tcphdr;
	unsigned long	sum;

	sum = 0;
	sum += (uint16_t) htons(sizeof(tcphdr));
	sum += (uint16_t) (src.sin_addr.s_addr & 0xffff);
	sum += (uint16_t) (src.sin_addr.s_addr >> 16 & 0xffff);
	sum += (uint16_t) (tgt.sin_addr.s_addr & 0xffff);
	sum += (uint16_t) (tgt.sin_addr.s_addr >> 16 & 0xffff);
	sum += htons(IPPROTO_TCP);
	i = 0;
	words_tcphdr = (uint16_t *) &tcphdr;
	while (i < sizeof(tcphdr) / 2)
	{
		sum += words_tcphdr[i];
		i++;
	}
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (~sum);
}

uint16_t	checksum_ip(struct iphdr iphdr)
{
	size_t			i;
	uint16_t		*words_iphdr;
	unsigned long	sum;

	sum = 0;
	i = 0;
	words_iphdr = (uint16_t *) &iphdr;
	while (i < sizeof(iphdr) / 2)
	{
		sum += words_iphdr[i];
		i++;
	}
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (~sum);
}

void	fill_iphdr(struct iphdr *iphdr, struct sockaddr_in src,
					struct sockaddr_in tgt, enum scan_type scan)
{
	uint16_t total_size;

	memset(iphdr, 0, sizeof(struct iphdr));
	iphdr->version = 4;
	iphdr->ihl = 5;
	iphdr->tos = 0;
	total_size = sizeof(struct iphdr);
	total_size += (scan == UDP) ?
		sizeof(struct udphdr) + sizeof(UDP_PAYLOAD) : sizeof(struct tcphdr);
	iphdr->tot_len = htons(total_size);
	// thread safety ?
	srandom(time(NULL));
	iphdr->id = htonl(random());
	iphdr->frag_off = 0;
	iphdr->ttl = 64;
	iphdr->protocol = (scan == UDP) ? IPPROTO_UDP : IPPROTO_TCP;
	iphdr->saddr = src.sin_addr.s_addr;
	iphdr->daddr = tgt.sin_addr.s_addr;
	iphdr->check = checksum_ip(*iphdr);
}

void	fill_udphdr(struct udphdr *udphdr, struct sockaddr_in src,
					struct sockaddr_in tgt)
{
	memset(udphdr, 0, sizeof(struct udphdr));
	udphdr->source = src.sin_port;
	udphdr->dest = tgt.sin_port;
	udphdr->len = htons(sizeof(struct udphdr) + sizeof(UDP_PAYLOAD));
	// no checksum because apparently it's optional ¯\_(ツ)_/¯
}

void	fill_tcphdr(struct tcphdr *tcphdr, struct sockaddr_in src,
					struct sockaddr_in tgt, enum scan_type scan)
{
	memset(tcphdr, 0, sizeof(*tcphdr));
	tcphdr->dest = tgt.sin_port;
	tcphdr->source = src.sin_port;
	// thread safety ?
	srandom(time(NULL));
	tcphdr->seq = htonl(random());
	tcphdr->doff = 5;
	switch (scan)
	{
		case SYN:
			tcphdr->syn = 1;
			break;
		case ACK:
			tcphdr->ack = 1;
			break;
		case FIN:
			tcphdr->fin = 1;
			break;
		case XMAS:
			tcphdr->fin = 1;
			tcphdr->psh = 1;
			tcphdr->urg = 1;
			break;
		default:
			break;
	}
	tcphdr->window = htons(5840);
	tcphdr->check = checksum_tcp(*tcphdr, src, tgt);
}

int	send_probe(struct sockaddr_in src, struct sockaddr_in tgt,
				enum scan_type scan)
{
	// size of iphdr + tcphdr because tcphdr is bigger than udphdr anyway
	char			packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
	struct iphdr	*iphdr;
	struct tcphdr	*tcphdr;
	struct udphdr	*udphdr;
	int				ret;
	int				packet_size;

	iphdr = (struct iphdr *) packet;
	fill_iphdr(iphdr, src, tgt, scan);
	if (scan == UDP)
	{
		udphdr = (struct udphdr *) (packet + sizeof(struct iphdr));
		fill_udphdr(udphdr, src, tgt);
		memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr),
				UDP_PAYLOAD, sizeof(UDP_PAYLOAD));
		packet_size = sizeof(*iphdr) + sizeof(*udphdr) + sizeof(UDP_PAYLOAD);
	}
	else
	{
		tcphdr = (struct tcphdr *) (packet + sizeof(struct iphdr));
		fill_tcphdr(tcphdr, src, tgt, scan);
		packet_size = sizeof(*iphdr) + sizeof(*tcphdr);
	}
	ret = sendto(send_sock, packet, packet_size, 0, (struct sockaddr *) &tgt,
					sizeof(struct sockaddr_in));
	if (ret == -1)
	{
		perror("Couldn't send probe");
		return (1);
	}
	return (0);
}
