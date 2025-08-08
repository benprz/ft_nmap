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
#include <pthread.h>
#include <bits/pthreadtypes.h>
#include <pcap/pcap.h>
#include <sys/select.h>

// Query routing table for source address and port
int get_src_addr_and_port(const struct sockaddr_in *dest_addr, struct sockaddr_in *src_addr) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket error");
        return -1;
    }

    // struct sockaddr_in dest_addr = {0};
    // dest_addr.sin_family = AF_INET;
    // dest_addr.sin_addr.s_addr = inet_addr(dest_ip);
    // dest_addr.sin_port = htons(9999); // Arbitrary port for routing query

    if (connect(sockfd, (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in)) < 0) {
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

int send_syn_packet(const struct sockaddr_in* target)
{
	int sock;
	// int	ret;
	struct tcphdr	tcphdr;
	// struct addrinfo hints, *infos;
	struct sockaddr_in	src_addr;

	// memset(&hints, 0, sizeof(struct addrinfo));
	// hints.ai_family = AF_INET;
	// ret = getaddrinfo(inet_ntoa(*target), NULL, &hints, &infos);
	// if (ret)
	// {
	// 	fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
	// 	return (1);
	// }
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock < 0)
	{
		fprintf(stderr, "socket: %s\n", strerror(errno));
		// freeaddrinfo(infos);
		return (2);
	}
	if (get_src_addr_and_port(target, &src_addr) < 0) {
		close(sock);
		// freeaddrinfo(infos);
		return (3);
	}
	memset(&tcphdr, 0, sizeof(tcphdr));
	tcphdr.dest = target->sin_port;
	tcphdr.source = ports.syn;
	srand(time(NULL));
	tcphdr.seq = htonl(rand());
	tcphdr.doff = 5;
	tcphdr.syn = 1;
	tcphdr.window = htons(5840);
	tcphdr.check = checksum_for_tcp_header(tcphdr, src_addr, *target);
	fprintf(stdout, "\nchecksum:0x%04x\n", tcphdr.check);
	if (sendto(sock, &tcphdr, sizeof(tcphdr), 0, (struct sockaddr *)target, sizeof(struct sockaddr_in)) < 0)
		perror("sendto");
	close(sock);
	// freeaddrinfo(infos);
	return 0;
}

void print_packet_tshark_style(const u_char *pkt, struct pcap_pkthdr *pkt_hdr) {
	// Linux cooked-mode capture v1 (SLL) header is 16 bytes
	// SLL header: [2 bytes packet type][2 bytes address type][2 bytes address len][8 bytes address][2 bytes protocol]
	if (pkt_hdr->caplen < 16) {
		printf("Packet too short for SLL header\n");
		return;
	}
	
	const unsigned char *sll = pkt;
	uint16_t packet_type = (sll[0] << 8) | sll[1];
	uint16_t address_type = (sll[2] << 8) | sll[3];
	uint16_t address_len = (sll[4] << 8) | sll[5];
	uint16_t protocol = (sll[14] << 8) | sll[15];
	
	// Skip SLL header (16 bytes) to get to the actual packet
	const unsigned char *ip = pkt + 16;
	
	// Check if we have enough data for IP header
	if (pkt_hdr->caplen < 16 + 20) {
		printf("Packet too short for IP header after SLL\n");
		return;
	}
	
	uint8_t ip_vhl = ip[0];
	uint8_t ip_version = ip_vhl >> 4;
	uint8_t ip_hlen = (ip_vhl & 0x0F) * 4;
	
	if (ip_version != 4) {
		printf("Not an IPv4 packet (version %d)\n", ip_version);
		return;
	}
	
	if (pkt_hdr->caplen < (bpf_u_int32)(16 + ip_hlen)) {
		printf("Truncated IP header\n");
		return;
	}
	
	char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ip + 12, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, ip + 16, dst_ip, sizeof(dst_ip));
	uint8_t proto = ip[9];
	uint8_t ttl = ip[8];
	
	// SLL packet types
	const char *packet_type_str = "Unknown";
	switch (packet_type) {
		case 0: packet_type_str = "PACKET_HOST"; break;
		case 1: packet_type_str = "PACKET_BROADCAST"; break;
		case 2: packet_type_str = "PACKET_MULTICAST"; break;
		case 3: packet_type_str = "PACKET_OTHERHOST"; break;
		case 4: packet_type_str = "PACKET_OUTGOING"; break;
	}
	
	printf("SLL: type=%u(%s) addr_type=%u addr_len=%u protocol=0x%04x\n", 
		   packet_type, packet_type_str, address_type, address_len, protocol);
	printf("IP: src=%s dst=%s proto=%d ttl=%d\n", src_ip, dst_ip, proto, ttl);

	if (proto == IPPROTO_TCP && pkt_hdr->caplen >= (bpf_u_int32)(16 + ip_hlen + 20)) {
		const unsigned char *tcp = pkt + 16 + ip_hlen;
		uint16_t src_port = (tcp[0] << 8) | tcp[1];
		uint16_t dst_port = (tcp[2] << 8) | tcp[3];
		uint32_t seq = (tcp[4] << 24) | (tcp[5] << 16) | (tcp[6] << 8) | tcp[7];
		uint32_t ack = (tcp[8] << 24) | (tcp[9] << 16) | (tcp[10] << 8) | tcp[11];
		uint8_t flags = tcp[13];
		printf("TCP: src_port=%u dst_port=%u seq=%u ack=%u flags=0x%02x", src_port, dst_port, seq, ack, flags);
		printf(" [");
		if (flags & 0x01) printf("FIN ");
		if (flags & 0x02) printf("SYN ");
		if (flags & 0x04) printf("RST ");
		if (flags & 0x08) printf("PSH ");
		if (flags & 0x10) printf("ACK ");
		if (flags & 0x20) printf("URG ");
		if (flags & 0x40) printf("ECE ");
		if (flags & 0x80) printf("CWR ");
		printf("]\n");
	} else if (proto == IPPROTO_UDP && pkt_hdr->caplen >= (bpf_u_int32)(16 + ip_hlen + 8)) {
		const unsigned char *udp = pkt + 16 + ip_hlen;
		uint16_t src_port = (udp[0] << 8) | udp[1];
		uint16_t dst_port = (udp[2] << 8) | udp[3];
		uint16_t len = (udp[4] << 8) | udp[5];
		printf("UDP: src_port=%u dst_port=%u len=%u\n", src_port, dst_port, len);
	} else if (proto == IPPROTO_ICMP && pkt_hdr->caplen >= (bpf_u_int32)(16 + ip_hlen + 4)) {
		const unsigned char *icmp = pkt + 16 + ip_hlen;
		uint8_t type = icmp[0];
		uint8_t code = icmp[1];
		printf("ICMP: type=%u code=%u\n", type, code);
	}
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
	UNUSED(user_data);
	UNUSED(packet);
    printf("Packet captured: length=%d, timestamp=%ld.%ld\n", header->len, header->ts.tv_sec, header->ts.tv_usec);
    // Process packet data here
}

void *thread_routine(void* arg) {
	UNUSED(arg);
	while (1) {
		pthread_mutex_lock(&task_mutex);
		if (tasks) {
			struct task *task = tasks;
			tasks = tasks->next;
			pthread_mutex_unlock(&task_mutex);
			printf("Processing task: %s %d %d\n", inet_ntoa(task->target.sin_addr), ntohs(task->target.sin_port), task->scan);
			char errbuf[PCAP_ERRBUF_SIZE];
			pcap_t *handle;

		 	// Use pcap_create() for better control over configuration
		 	handle = pcap_create("any", errbuf);
		    if (handle == NULL) {
		        fprintf(stderr, "Error creating pcap handle: %s\n", errbuf);
		        return NULL;
		    }
		    
		    // Set buffer size
		    if (pcap_set_snaplen(handle, BUFSIZ) != 0) {
		        fprintf(stderr, "Error setting snaplen: %s\n", pcap_geterr(handle));
		        pcap_close(handle);
		        return NULL;
		    }
		    
		    // Set timeout for packet capture
		    if (pcap_set_timeout(handle, INITIAL_RTT_TIMEOUT) != 0) {
		        fprintf(stderr, "Error setting timeout: %s\n", pcap_geterr(handle));
		        pcap_close(handle);
		        return NULL;
		    }
		    
		    // Activate the handle
		    if (pcap_activate(handle) != 0) {
		        fprintf(stderr, "Error activating pcap handle: %s\n", pcap_geterr(handle));
		        pcap_close(handle);
		        return NULL;
		    }
		    struct bpf_program filter;
		    char filter_exp[100] = {0};
			printf("FILTER EXP: src host %s && src port %d && dst port %d\n", \
				inet_ntoa(task->target.sin_addr), \
				ntohs(task->target.sin_port), \
				ntohs(ports.syn)
			);
			sprintf(filter_exp, "src host %s && src port %d && dst port %d", \
				inet_ntoa(task->target.sin_addr), \
				ntohs(task->target.sin_port), \
				ntohs(ports.syn)
			);
		    if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
		        pcap_close(handle);
		        return NULL;
		    }
		    if (pcap_setfilter(handle, &filter) == -1) {
		        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
		        pcap_close(handle);
		        return NULL;
		    }

		    printf("Listening for packets...port: %d\n", ntohs(task->target.sin_port));
			send_syn_packet(&task->target);

			// Try to read packet with timeout
			printf("Waiting for packet with timeout: %d seconds\n", INITIAL_RTT_TIMEOUT / 1000);
			
			// Data is available, try to read packet
			struct pcap_pkthdr *pkt_hdr = NULL;
		    const u_char* pkt;
		    int result = pcap_next_ex(handle, &pkt_hdr, &pkt);
			if (result == -1) {
				// Error occurred
				fprintf(stderr, "Error receiving packet: %s\n", pcap_geterr(handle));
				pcap_close(handle);
				free(task);
				return NULL;
			} else if (result == 0) {
				// Timeout occurred
				printf("Timeout: No packet received within %d seconds\n", INITIAL_RTT_TIMEOUT / 1000);
				pcap_close(handle);
				return NULL;
			} else {
				// Packet received successfully
				printf("Received packet: %d bytes\n", pkt_hdr->caplen);
				printf("Packet data: ");
				for (uint32_t i = 0; i < (uint32_t)pkt_hdr->caplen; i++) {
					printf("%02x ", pkt[i]);
				}
				printf("\n");
				print_packet_tshark_style(pkt, pkt_hdr);
			}

			pcap_close(handle);
			free(task);
		} else {
			pthread_mutex_unlock(&task_mutex);
			return NULL;
		}
	}
}

int ft_nmap() {
	pthread_t *threads = malloc(nmap.threads * sizeof(pthread_t));
	if (threads == NULL) {
		perror("threads = malloc()-> ");
		return -1;
	}

	for (int i = 0; i < nmap.threads; i++) {
		if (pthread_create(&threads[i], NULL, thread_routine, NULL) == -1) {
			perror("pthread_create-> ");
			fprintf(stderr, "trying again..\n");
			i--;
			continue;
		}
	}
	for (int i = 0; i < nmap.threads; i++) {
		pthread_join(threads[i], NULL);
	}

	free(threads);
	return 0;
}
