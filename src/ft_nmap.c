#include "ft_nmap.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int ft_nmap() {
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sockfd < 0) {
		perror("socket");
		return -1;
	}

	const struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(80),
		.sin_addr.s_addr = inet_addr("127.0.0.1")
	};

	sendto(sockfd, NULL, 0, 0, (struct sockaddr *)&addr, sizeof(addr));
	return 0;
}
