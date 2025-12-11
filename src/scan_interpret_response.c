#include <pthread.h>
#include "ft_nmap.h"
#include <pcap/sll.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

enum scan_result	interpret_tcp(const u_char *packet, enum scan_type scan)
{
	struct tcphdr	*tcphdr;

	tcphdr = (struct tcphdr *) packet;
	if (tcphdr->rst)
		return (result_lookup[scan][PR_TCP_RST]);
	else
		return (result_lookup[scan][PR_TCP_SYNACK]);
}

enum scan_result	interpret_icmp(const u_char *packet, enum scan_type scan)
{
	struct icmphdr	*icmphdr;

	icmphdr = (struct icmphdr *) packet;
	if (icmphdr->type == 3 && icmphdr->code == 3)
		return (result_lookup[scan][PR_ICMP_3_3]);
	// je check pas si c'est un 3:1,2,9,10,13 mais on peut surement partir du
	// principe que c'en est un non?
	else
		return (result_lookup[scan][PR_ICMP_OTHER]);
}

enum scan_result	interpret_packet(const u_char *packet, enum scan_type scan)
{
	struct iphdr	*iphdr;

	if (!packet)
		return (result_lookup[scan][PR_NONE]);
	iphdr = (struct iphdr *) packet;
	if (iphdr->protocol == IPPROTO_TCP)
	{
		packet += iphdr->ihl * 4;
		return (interpret_tcp(packet, scan));
	}
	else if (iphdr->protocol == IPPROTO_ICMP)
	{
		packet += iphdr->ihl * 4;
		return (interpret_icmp(packet, scan));
	}
	else if (iphdr->protocol == IPPROTO_UDP)
		return (result_lookup[scan][PR_UDP]);
	// shouldn't happen
	else
	{
		fprintf(stdout, "wtf none?? shouldn't have happened\n");
		return (result_lookup[scan][PR_NONE]);
	}
}
