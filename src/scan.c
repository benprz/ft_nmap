#include <pthread.h>
#include "ft_nmap.h"
#include <pcap/sll.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

void	breakloop(union sigval arg)
{
	struct timer_data *data;

	data = (struct timer_data *) arg.sival_ptr;
	// fprintf(stdout, "breakloop: %p, %p, %p, %p\n", arg.sival_ptr, (void *) data, (void *) data->handle, (void *) &data->handle_mutex);
	pthread_mutex_lock(&data->handle_mutex);
	if (data->handle)
		pcap_breakloop(data->handle);
	pthread_mutex_unlock(&data->handle_mutex);
}

int	create_timer(timer_t *timerid, struct timer_data *data)
{
	struct sigevent	evp = {0};

	evp.sigev_notify = SIGEV_THREAD;
	evp.sigev_notify_function = &breakloop;
	evp.sigev_value.sival_ptr = data;
	if (timer_create(CLOCK_MONOTONIC, &evp, timerid))
	{
		perror("Couldn't create timer");
		return (1);
	}
	if (timer_settime(*timerid, 0, &default_delay, NULL))
	{
		perror("Couldn't arm timer");
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

int	fill_tcp_filter(struct sockaddr_in src, struct sockaddr_in tgt, char *buff)
{
	int	ret;

	ret = snprintf(buff, FILTER_SIZE, TCP_FILTER_FORMAT,
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
	return (ret);
}

// exactly the same as fill_tcp_filter except it uses UDP_FILTER_FORMAT
int	fill_udp_filter(struct sockaddr_in src, struct sockaddr_in tgt, char *buff)
{
	int	ret;

	ret = snprintf(buff, FILTER_SIZE, UDP_FILTER_FORMAT,
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
	return (ret);
}

int	setup_pcap(pcap_t *handle, enum scan_type scan,  struct sockaddr_in src,
				struct sockaddr_in tgt)
{
	char				filter[FILTER_SIZE];
	struct bpf_program	fp;

	if (scan == UDP)
		fill_udp_filter(src, tgt, filter);
	else
		fill_tcp_filter(src, tgt, filter);
	if (pcap_compile(handle, &fp, filter, true, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR)
	{
		pcap_perror(handle, "compile");
		return (1);
	}
	if (pcap_setfilter(handle, &fp) != 0)
	{
		pcap_perror(handle, "setfilter");
		return (1);
	}
	pcap_freecode(&fp);
	return (0);
}

// timer_data contains the handle too but it felt weird to remove the argument
// 'handle' as timer_data is only needed for the timer breakloop function
void	scan(pcap_t *handle, struct sockaddr_in src, struct sockaddr_in tgt,
			enum scan_type scan, struct timer_data *timer_data)
{
	size_t				sll_hdr_size;
	const u_char		*packet;
	struct pcap_pkthdr	*pcap_hdr;
	struct iphdr		*iphdr;
	int					ret;
	timer_t				timerid;
	struct itimerspec	curr_timer;

	// could be in thread_routine and passed as a parameter
	sll_hdr_size = pcap_datalink(handle) ==
	               DLT_LINUX_SLL ? SLL_HDR_LEN : SLL2_HDR_LEN;
	if (setup_pcap(handle, scan, src, tgt))
		return ;
	if (create_timer(&timerid, timer_data))
		return ;
	do
	{
		if (send_probe(src, tgt, scan))
			return ;
		ret = pcap_next_ex(handle, &pcap_hdr, &packet);
		// if (ret == 0)
		// 	fprintf(stdout, "0\n");
		if (timer_gettime(timerid, &curr_timer))
		{
			perror("Couldn't get current timer");
			return ;
		}
		if (curr_timer.it_value.tv_sec == 0 && curr_timer.it_value.tv_nsec == 0)
			break;
	}
	while (ret == 0);
	if (timer_settime(timerid, 0, &empty_delay, NULL))
	{
		perror("Couldn't disable timer");
		return ;
	}
	// fprintf(stdout, "out of loop. ret = %d\n", ret);
	// IN THEORY, ret can only be 1, 0 or PCAP_ERROR in this situation
	// LMAO it can be PCAP_ERROR_BREAK too ig
	if (ret == PCAP_ERROR)
	{
		pcap_perror(handle, "pcap_next_ex");
		return ;
	}
	else if (ret == 0 || ret == PCAP_ERROR_BREAK)
		return ;
	packet += sll_hdr_size;
	// fprintf(stdout, "PACKET RECEIVED!\n");
	// il faudra virer ça à la fin
	if (pcap_hdr->caplen != pcap_hdr->len)
		fprintf(stdout, "/!\\ LEN (%d) != CAPLEN (%d)\n", pcap_hdr->len, pcap_hdr->caplen);
	// fprintf(stdout, "PACKET (%p) / LEN (%d) / CAPLEN (%d)\n", packet, pcap_hdr->len, pcap_hdr->caplen);
	// fprintf(stdout, "PACKET is an error? %d\n", packet < 0);
	iphdr = (struct iphdr *) packet;
	// print_ip_packet(packet, iphdr->ihl * 4);
	if (iphdr->protocol == IPPROTO_TCP)
	{
		packet += iphdr->ihl * 4;
		fprintf(stdout, "paquet TCP reçu\n");
		// print_tcp_packet(packet, pcap_hdr->caplen - sll_hdr_size - iphdr->ihl * 4);
	}
	else if (iphdr->protocol == IPPROTO_ICMP)
		fprintf(stdout, "paquet ICMP reçu\n");
	else if (iphdr->protocol == IPPROTO_UDP)
		fprintf(stdout, "paquet UDP reçu\n");
	else
		fprintf(stdout, "paquet %d reçu: wtf\n", iphdr->protocol);
}

