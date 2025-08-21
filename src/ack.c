#include "ft_nmap.h"
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pcap/sll.h>
#include <linux/ip.h>

void	ack(pcap_t *handle, struct sockaddr_in src, struct sockaddr_in tgt)
{
	size_t				sll_hdr_size;
	const u_char		*packet;
	struct pcap_pkthdr	pcap_hdr;
	struct iphdr		*iphdr;

	fprintf(stdout, "ack funtion\n");
	// could be in thread_routine and passed as a parameter
	sll_hdr_size = pcap_datalink(handle) ==
	               DLT_LINUX_SLL ? SLL_HDR_LEN : SLL2_HDR_LEN;
	if (setup_pcap_tcp(handle, src, tgt))
		return ;
	packet = pcap_next(handle, &pcap_hdr);
	packet += sll_hdr_size;
	fprintf(stdout, "PACKET RECEIVED!\n");
	if (pcap_hdr.caplen != pcap_hdr.len)
		fprintf(stdout, "/!\\ LEN (%d) != CAPLEN (%d)\n", pcap_hdr.len, pcap_hdr.caplen);
	iphdr = (struct iphdr *) packet;
	if (iphdr->protocol == IPPROTO_TCP)
		fprintf(stdout, "paquet TCP reçu: c'est unfiltered\n");
	else if (iphdr->protocol == IPPROTO_ICMP)
		fprintf(stdout, "paquet ICMP reçu: c'est filtered\n");
	else
		fprintf(stdout, "paquet %d reçu: wtf\n", iphdr->protocol);
}
