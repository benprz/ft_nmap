#include <pthread.h>
#include "ft_nmap.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>

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

int send_udp_probe(struct sockaddr_in tgt)
{
	int	ret;

	ret = sendto(sockets.udp, "knock knock", 11, 0, (struct sockaddr *) &tgt,
					sizeof(tgt));
	if (ret == -1)
	{
		perror("sendto");
		return (1);
	}
	return (0);
}

int send_tcp_probe(struct sockaddr_in src, struct sockaddr_in tgt,
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

int send_probe(struct sockaddr_in src, struct sockaddr_in tgt,
				enum scan_type scan)
{
	if (scan == UDP)
		return(send_udp_probe(tgt));
	else if (scan == ALL)
	{
		fprintf(stderr, "Sending a probe for \"ALL\"??? WTF??\n");
		return (1);
	}
	else
		return(send_tcp_probe(src, tgt, scan));
}
