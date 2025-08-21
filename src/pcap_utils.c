#include "ft_nmap.h"

int	fill_tcp_filter(struct sockaddr_in src, struct sockaddr_in tgt, char *buff)
{
	int	ret;

	ret = snprintf(buff, TCP_FILTER_SIZE, TCP_FILTER_FORMAT,
					src.sin_addr.s_addr & 0xff,
					(src.sin_addr.s_addr >> 8) & 0xff,
					(src.sin_addr.s_addr >> 16) & 0xff,
					(src.sin_addr.s_addr >> 24) & 0xff,
					tgt.sin_addr.s_addr & 0xff,
					(tgt.sin_addr.s_addr >> 8) & 0xff,
					(tgt.sin_addr.s_addr >> 16) & 0xff,
					(tgt.sin_addr.s_addr >> 24) & 0xff,
					ntohs(src.sin_port),
					ntohs(tgt.sin_port),
					ntohs(src.sin_port),
					ntohs(tgt.sin_port));
	return (ret);
}

int	setup_pcap_tcp(pcap_t *handle, struct sockaddr_in src, struct sockaddr_in tgt)
{
	struct bpf_program	fp;
	char				filter[TCP_FILTER_SIZE];

	// can probably remove verification when sure the size is enough
	if (fill_tcp_filter(src, tgt, filter) >= TCP_FILTER_SIZE)
	{
		fprintf(stderr, "printf: filter too small\n");
		return (1);
	}
	if (pcap_compile(handle, &fp, filter, true, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR)
	{
		pcap_perror(handle, "compile");
		return (1);
	}
	if (pcap_setfilter(handle, &fp) == PCAP_ERROR)
	{
		pcap_perror(handle, "setfilter");
		return (1);
	}
	return (0);
}
