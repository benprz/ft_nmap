#include "ft_nmap.h"
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pcap/sll.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void print_ip_packet(const u_char* packet, uint32_t length) 
{
    if (packet == NULL || length < sizeof(struct ip)) 
    {
        printf("Paquet IP invalide ou trop court\n");
        return;
    }

    const struct ip* ip_header = (struct ip*)packet;
    uint32_t header_len = ip_header->ip_hl * 4;
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║                ANALYSE DU PAQUET IP              ║\n");
    printf("╠══════════════════════════════════════════════════╣\n");
    
    printf("║ Version: %d  ", ip_header->ip_v);
    printf("Longueur en-tête: %d octets (%d mots)\n", header_len, ip_header->ip_hl);
    printf("║ TOS: 0x%02x  ", ip_header->ip_tos);
    
    switch (ip_header->ip_tos) 
    {
        case 0: printf("(Routine)"); break;
        case 2: printf("(Priorité)"); break;
        case 4: printf("(Immédiat)"); break;
        case 6: printf("(Flash)"); break;
        case 8: printf("(Flash Override)"); break;
        case 10: printf("(Critique)"); break;
        case 12: printf("(Internetwork Control)"); break;
        case 14: printf("(Network Control)"); break;
        default: printf("(Inconnu)");
    }
    
    printf("\n║ Longueur totale: %d octets\n", ntohs(ip_header->ip_len));
    printf("║ Identification: 0x%04x\n", ntohs(ip_header->ip_id));
    printf("║ Flags: 0x%x  ", (ntohs(ip_header->ip_off) & 0xE000) >> 13);
    
    if (ntohs(ip_header->ip_off) & IP_RF) printf("[Réservé] ");
    if (ntohs(ip_header->ip_off) & IP_DF) printf("[Ne pas fragmenter] ");
    if (ntohs(ip_header->ip_off) & IP_MF) printf("[Plus de fragments] ");
    
    printf("\n║ Offset: %d\n", (ntohs(ip_header->ip_off) & 0x1FFF) * 8);
    printf("║ TTL: %d\n", ip_header->ip_ttl);
    printf("║ Protocole: %d (0x%02x)  ", ip_header->ip_p, ip_header->ip_p);
    
    switch (ip_header->ip_p) 
    {
        case IPPROTO_ICMP: printf("ICMP"); break;
        case IPPROTO_TCP:  printf("TCP"); break;
        case IPPROTO_UDP:  printf("UDP"); break;
        default:           printf("Autre");
    }
    
    printf("\n║ Checksum: 0x%04x\n", ntohs(ip_header->ip_sum));
    
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    
    printf("║ Source: %s\n", src_ip);
    printf("║ Destination: %s\n", dst_ip);
    
    if (length > header_len) 
    {
        printf("╠══════════════════════════════════════════════════╣");
        printf("\n║                DONNÉES IP (%d octets)            ║", length - header_len);
        printf("\n╠══════════════════════════════════════════════════╣");
        
        const u_char* data = packet + header_len;
        uint32_t data_len = length - header_len;
        
        for (uint32_t i = 0; i < data_len; i++) 
        {
            if (i % 16 == 0) printf("\n║ %04x: ", i);
            printf("%02x ", data[i]);
            
            if (i % 16 == 15 || i == data_len - 1) 
            {
                for (uint32_t j = 0; j < 15 - (i % 16); j++) printf("   ");
                printf("  ");
                for (uint32_t j = i - (i % 16); j <= i; j++) 
                    printf("%c", (data[j] >= 32 && data[j] <= 126) ? data[j] : '.');
            }
        }
    }
    
    printf("\n╚══════════════════════════════════════════════════╝\n");
}

void print_tcp_packet(const u_char* tcp_segment, uint32_t length)
{
    struct tcphdr *tcp_header = (struct tcphdr*)tcp_segment;
    int tcp_header_len = tcp_header->doff * 4;
    const u_char *payload = tcp_segment + tcp_header_len;
    int payload_len = length - tcp_header_len;

    printf("\n==================== TCP SEGMENT ====================\n");
    printf("Source Port: %u\n", ntohs(tcp_header->source));
    printf("Destination Port: %u\n", ntohs(tcp_header->dest));
    printf("Sequence Number: %u\n", ntohl(tcp_header->seq));
    printf("Ack Number: %u\n", ntohl(tcp_header->ack_seq));
    printf("Header Length: %d bytes\n", tcp_header_len);
    printf("Flags: ");
    if(tcp_header->urg) printf("URG ");
    if(tcp_header->ack) printf("ACK ");
    if(tcp_header->psh) printf("PSH ");
    if(tcp_header->rst) printf("RST ");
    if(tcp_header->syn) printf("SYN ");
    if(tcp_header->fin) printf("FIN ");
    printf("\n");
    printf("Window Size: %u\n", ntohs(tcp_header->window));
    printf("Checksum: 0x%04X\n", ntohs(tcp_header->check));
    printf("Urgent Pointer: %u\n", ntohs(tcp_header->urg_ptr));

    // Affichage hex/ascii du payload
    printf("\nPayload (%d bytes):\n", payload_len);
    printf("Offset   Hexadecimal                           ASCII\n");
    printf("------   ---------------------------------    --------\n");

    for(int offset = 0; offset < payload_len; offset += 16)
    {
        int line_len = (payload_len - offset) > 16 ? 16 : (payload_len - offset);
        
        // Offset
        printf("%05d   ", offset);

        // Hex
        for(int i = 0; i < line_len; i++)
        {
            printf("%02X ", payload[offset + i]);
            if(i == 7) printf(" ");
        }

        // Padding
        for(int i = line_len; i < 16; i++)
        {
            printf("   ");
            if(i == 7) printf(" ");
        }

        printf("   ");

        // ASCII
        for(int i = 0; i < line_len; i++)
        {
            printf("%c", isprint(payload[offset + i]) ? payload[offset + i] : '.');
        }

        printf("\n");
    }
    printf("==================================================\n");
}

void	ack(pcap_t *handle, struct sockaddr_in src, struct sockaddr_in tgt)
{
	size_t				sll_hdr_size;
	const u_char		*packet;
	struct pcap_pkthdr	*pcap_hdr;
	struct iphdr		*iphdr;
	struct bpf_program	fp;
	int					ret;
	timer_t				timerid;
	struct itimerspec	curr_timer;

	// could be in thread_routine and passed as a parameter
	sll_hdr_size = pcap_datalink(handle) ==
	               DLT_LINUX_SLL ? SLL_HDR_LEN : SLL2_HDR_LEN;
	if (setup_pcap_tcp(handle, src, tgt, &fp))
		return ;
	if (create_timer(&timerid, handle))
		return ;
	do
	{
		if (send_probe(src, tgt, ACK))
			return ;
		ret = pcap_next_ex(handle, &pcap_hdr, &packet);
		// if (ret == 0)
		// 	fprintf(stdout, "0\n");
		timer_gettime(timerid, &curr_timer);
		if (curr_timer.it_value.tv_sec == 0 && curr_timer.it_value.tv_nsec == 0)
			break;
	}
	while (ret == 0);
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
	if (pcap_hdr->caplen != pcap_hdr->len)
		fprintf(stdout, "/!\\ LEN (%d) != CAPLEN (%d)\n", pcap_hdr->len, pcap_hdr->caplen);
	// fprintf(stdout, "PACKET (%p) / LEN (%d) / CAPLEN (%d)\n", packet, pcap_hdr->len, pcap_hdr->caplen);
	// fprintf(stdout, "PACKET is an error? %d\n", packet < 0);
	iphdr = (struct iphdr *) packet;
	// print_ip_packet(packet, iphdr->ihl * 4);
	if (iphdr->protocol == IPPROTO_TCP)
	{
		packet += iphdr->ihl * 4;
		fprintf(stdout, "paquet TCP reçu: c'est unfiltered\n");
		// print_tcp_packet(packet, pcap_hdr->caplen - sll_hdr_size - iphdr->ihl * 4);
	}
	else if (iphdr->protocol == IPPROTO_ICMP)
		fprintf(stdout, "paquet ICMP reçu: c'est filtered\n");
	else
		fprintf(stdout, "paquet %d reçu: wtf\n", iphdr->protocol);
}
 
// test juste pour voir ce que renvoie pcap_next
// void	ack(pcap_t *handle, struct sockaddr_in src, struct sockaddr_in tgt)
// {
// 	const u_char		*packet;
// 	struct pcap_pkthdr	pcap_hdr;
// 	struct bpf_program	fp;
// 	// int					ret;

// 	if (setup_pcap_tcp(handle, src, tgt, &fp))
// 		return ;
// 	if (send_probe(src, tgt, ACK))
// 		return ;
// 	packet = pcap_next(handle, &pcap_hdr);
// 	fprintf(stdout, "port %d : packet = %p\n", ntohs(tgt.sin_port), packet);
// }
