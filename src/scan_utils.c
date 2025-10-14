#include "ft_nmap.h"
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int	fill_tcp_filter(struct sockaddr_in src, struct sockaddr_in tgt, char *buff)
{
	int	ret;

	ret = snprintf(buff, TCP_FILTER_SIZE, TCP_FILTER_FORMAT,
					tgt.sin_addr.s_addr & 0xff,
					(tgt.sin_addr.s_addr >> 8) & 0xff,
					(tgt.sin_addr.s_addr >> 16) & 0xff,
					(tgt.sin_addr.s_addr >> 24) & 0xff,
					src.sin_addr.s_addr & 0xff,
					(src.sin_addr.s_addr >> 8) & 0xff,
					(src.sin_addr.s_addr >> 16) & 0xff,
					(src.sin_addr.s_addr >> 24) & 0xff,
					ntohs(tgt.sin_port),
					ntohs(src.sin_port),
					ntohs(src.sin_port),
					ntohs(tgt.sin_port));
	// ret = snprintf(buff, TCP_FILTER_SIZE, TCP_FILTER_FORMAT,
	// 				tgt.sin_addr.s_addr & 0xff,
	// 				(tgt.sin_addr.s_addr >> 8) & 0xff,
	// 				(tgt.sin_addr.s_addr >> 16) & 0xff,
	// 				(tgt.sin_addr.s_addr >> 24) & 0xff,
	// 				src.sin_addr.s_addr & 0xff,
	// 				(src.sin_addr.s_addr >> 8) & 0xff,
	// 				(src.sin_addr.s_addr >> 16) & 0xff,
	// 				(src.sin_addr.s_addr >> 24) & 0xff,
	// 				ntohs(tgt.sin_port),
	// 				ntohs(src.sin_port));
	// fprintf(stdout, "filtre: %s\n", buff);
	return (ret);
}

int	setup_pcap_tcp(pcap_t *handle, struct sockaddr_in src,
					struct sockaddr_in tgt, struct bpf_program *fp)
{
	char				filter[TCP_FILTER_SIZE];

	// can probably remove verification when sure the size is enough
	if (fill_tcp_filter(src, tgt, filter) >= TCP_FILTER_SIZE)
	{
		fprintf(stderr, "printf: filter too small\n");
		return (1);
	}
	if (pcap_compile(handle, fp, filter, true, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR)
	{
		pcap_perror(handle, "compile");
		return (1);
	}
	// est-ce que le problème c'est que fp est plus là quand on return ? probablement pas, il faut surement le free juste après d'ailleurs
	if (pcap_setfilter(handle, fp) != 0)
	{
		pcap_perror(handle, "setfilter");
		return (1);
	}
	return (0);
}

uint16_t	checksum(struct tcphdr tcphdr, struct sockaddr_in src,
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

int send_probe(struct sockaddr_in src, struct sockaddr_in tgt,
				enum scan_type scan)
{
	struct tcphdr	tcphdr;
	struct sockaddr	*tgt_ptr;
	int				ret;

	memset(&tcphdr, 0, sizeof(tcphdr));
	tcphdr.dest = tgt.sin_port;
	tcphdr.source = src.sin_port;
	// thread safety ?
	srandom(time(NULL));
	tcphdr.seq = htonl(random());
	tcphdr.doff = 5;
	switch (scan)
	{
		case SYN:
			tcphdr.syn = 1;
			break;
		case ACK:
			tcphdr.ack = 1;
			break;
		case FIN:
			tcphdr.fin = 1;
			break;
		case XMAS:
			tcphdr.fin = 1;
			tcphdr.psh = 1;
			tcphdr.urg = 1;
			break;
		default:
			break;
	}
	tcphdr.window = htons(5840);
	tcphdr.check = checksum(tcphdr, src, tgt);
	tgt_ptr = (struct sockaddr *) &tgt;
	ret = sendto(sockets.tcp, &tcphdr, sizeof(tcphdr), 0, tgt_ptr, sizeof(tgt));
	if (ret == -1)
	{
		perror("sendto");
		return (1);
	}
	return (0);
}
