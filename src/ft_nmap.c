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

int send_syn_packet(const struct sockaddr_in* target, const struct sockaddr_in* src_addr)
{
	int sock;
	struct tcphdr	tcphdr;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock < 0)
	{
		fprintf(stderr, "socket: %s\n", strerror(errno));
		return (2);
	}
	memset(&tcphdr, 0, sizeof(tcphdr));
	tcphdr.dest = target->sin_port;
	tcphdr.source = ports.syn;
	srand(time(NULL));
	tcphdr.seq = htonl(rand());
	tcphdr.doff = 5;
	tcphdr.syn = 1;
	tcphdr.window = htons(5840);
	tcphdr.check = checksum_for_tcp_header(tcphdr, *src_addr, *target);
	fprintf(stdout, "\nchecksum:0x%04x\n", tcphdr.check);
	if (sendto(sock, &tcphdr, sizeof(tcphdr), 0, (struct sockaddr *)target, sizeof(struct sockaddr_in)) < 0)
		perror("sendto");
	close(sock);
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
	struct task *task = (struct task *)user_data;
	if (!task) return;
	// Basic decode for SLL + IPv4 + TCP
	if (header->caplen < 16 + 20 + 20) return;
	const unsigned char *ip = packet + 16;
	uint8_t ip_vhl = ip[0];
	uint8_t ip_version = ip_vhl >> 4;
	uint8_t ip_hlen = (ip_vhl & 0x0F) * 4;
	if (ip_version != 4) return;
	if (header->caplen < (bpf_u_int32)(16 + ip_hlen + 20)) return;
	if (ip[9] != IPPROTO_TCP) return;
	const unsigned char *tcp = packet + 16 + ip_hlen;
	uint16_t dst_port = (tcp[2] << 8) | tcp[3];
	uint8_t flags = tcp[13];
	// Expect dst port to be our ephemeral source (ports.syn)
	if (dst_port != ntohs(ports.syn)) return;
	// Interpret SYN/ACK as open, RST as closed; else filtered
	enum scan_result r = SR_FILTERED;
	if ((flags & 0x12) == 0x12) r = SR_OPEN; // SYN+ACK
	else if (flags & 0x04) r = SR_CLOSED;    // RST

    // Debug: print immediate result for this packet
    char target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &task->target.sin_addr, target_ip, sizeof(target_ip));
    printf("[DEBUG] %s scan: packet flags=0x%02x dst_port=%u -> %s:%u => %s\n",
           (task->scan == SYN ? "SYN" : "TCP"),
           flags,
           dst_port,
           target_ip,
           ntohs(task->target.sin_port),
           scan_result_to_str(r));
	add_result(task->target.sin_addr.s_addr, ntohs(task->target.sin_port), task->scan, r);
}

pcap_t *setup_pcap_handle(void) {
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

	// Set immediate mode to ensure packets are delivered as soon as they arrive
	// if not set, we need to wait for the timeout to capture the packet
	if (pcap_set_immediate_mode(handle, 1) != 0) {
		fprintf(stderr, "Error setting immediate mode: %s\n", pcap_geterr(handle));
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

	// Make capture non-blocking so we can enforce our own timeout
	char nb_err[PCAP_ERRBUF_SIZE] = {0};
	if (pcap_setnonblock(handle, 1, nb_err) == -1) {
		fprintf(stderr, "Error setting nonblock: %s\n", nb_err);
		pcap_close(handle);
		return NULL;
	}

	return handle;
}

int setup_pcap_filter(pcap_t *handle, const struct task *task) {
	struct bpf_program filter;
	char filter_exp[TCP_FILTER_SIZE] = {0}; // \0 terminated string
	int ret;
	
    uint32_t dst = task->source.sin_addr.s_addr; // us
    uint32_t src = task->target.sin_addr.s_addr; // them
    printf("FILTER EXP: Using TCP_FILTER_FORMAT macro\n");
    ret = snprintf(filter_exp, TCP_FILTER_SIZE, TCP_FILTER_FORMAT,
					(src) & 0xff,
					(src >> 8) & 0xff,
					(src >> 16) & 0xff,
					(src >> 24) & 0xff,
                    (dst) & 0xff,
                    (dst >> 8) & 0xff,
                    (dst >> 16) & 0xff,
                    (dst >> 24) & 0xff,
                    ntohs(task->target.sin_port),
                    ntohs(ports.syn),
                    ntohs(ports.syn),
                    ntohs(task->target.sin_port));
	if (ret >= TCP_FILTER_SIZE) {
		fprintf(stderr, "Filter expression too long\n");
		return -1;
	}
    printf("Generated filter: %s\n", filter_exp);
	if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
		return -1;
	}
	if (pcap_setfilter(handle, &filter) == -1) {
		fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
		return -1;
	}
	return 0;
}

int capture_packets(pcap_t *handle, struct task *task) {
	printf("Listening for packets...port: %d\n", ntohs(task->target.sin_port));
	send_syn_packet(&task->target, &task->source);

	// Try to read packet with timeout
	printf("Waiting for packet with timeout: %d seconds\n", INITIAL_RTT_TIMEOUT / 1000);
	
	// Non-blocking poll for up to INITIAL_RTT_TIMEOUT milliseconds
	struct pcap_pkthdr *pkt_hdr = NULL;
	const u_char* pkt;
	int elapsed_ms = 0;
	int got_packet = 0;
	
	while (elapsed_ms < INITIAL_RTT_TIMEOUT) {
		printf("Waiting for packet with timeout: %d milliseconds\n", elapsed_ms);
		int result = pcap_next_ex(handle, &pkt_hdr, &pkt);
		if (result == 1) {
			printf("Received packet\n");
			packet_handler((u_char*)task, pkt_hdr, pkt);
			got_packet = 1;
			break;
		} else if (result == -1) {
			fprintf(stderr, "Error receiving packet: %s\n", pcap_geterr(handle));
			break;
		}
		usleep(10 * 1000); // 10ms
		elapsed_ms += 10;
	}
	
	if (!got_packet) {
        char target_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &task->target.sin_addr, target_ip, sizeof(target_ip));
        printf("[DEBUG] Timeout waiting %dms for response -> %s:%u assumed %s\n",
               INITIAL_RTT_TIMEOUT,
               target_ip,
               ntohs(task->target.sin_port),
               scan_result_to_str(SR_FILTERED));
		add_result(task->target.sin_addr.s_addr, ntohs(task->target.sin_port), task->scan, SR_FILTERED);
	}
	
	return got_packet;
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
			
			// Setup pcap handle
			pcap_t *handle = setup_pcap_handle();
			if (handle == NULL) {
				free(task);
				continue;
			}
			
			// Setup pcap filter
			if (setup_pcap_filter(handle, task) < 0) {
				pcap_close(handle);
				free(task);
				continue;
			}
			
			// Capture packets and send SYN
			capture_packets(handle, task);
			
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
	bzero(threads, nmap.threads * sizeof(pthread_t));

	for (int i = 0; i < nmap.threads; i++) {
		if (pthread_create(&threads[i], NULL, thread_routine, NULL) == -1) {
			perror("pthread_create-> ");
			fprintf(stderr, "failed to create one thread..\n");
			continue;
		}
	}
	for (int i = 0; i < nmap.threads; i++) {
		pthread_join(threads[i], NULL);
	}

	free(threads);
	return 0;
}
