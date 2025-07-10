#include "ft_nmap.h"
#include <unistd.h>
#include <string.h>

int	create_tcp_socket(struct sockaddr_in addr, unsigned short int *port_adr)
{
	int					sock;
	struct sockaddr_in	local;
	socklen_t			len;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1)
	{
		perror("Couldn't create recv socket");
		return (1);
	}
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)))
	{
		close(sock);
		perror("Couldn't bind to port");
		return (1);
	}
	len = sizeof(local);
	if (getsockname(sock, (struct sockaddr *) &local, &len))
	{
		close(sock);
		perror("Couldn't get port");
		return (1);
	}
	*port_adr = local.sin_port;
	return (0);
}

// littéralement la même que pour le tcp sauf pour l'appel de `socket`
int	create_udp_socket(struct sockaddr_in addr, unsigned short int *port_adr)
{
	int					sock;
	struct sockaddr_in	local;
	socklen_t			len;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1)
	{
		perror("Couldn't create recv socket");
		return (1);
	}
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)))
	{
		close(sock);
		perror("Couldn't bind to port");
		return (1);
	}
	len = sizeof(local);
	if (getsockname(sock, (struct sockaddr *) &local, &len))
	{
		close(sock);
		perror("Couldn't get port");
		return (1);
	}
	*port_adr = local.sin_port;
	return (0);
}

int create_recv_sockets(void)
{
	struct sockaddr_in	addr;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = 0;
	if (create_tcp_socket(addr, &ports.syn)
		|| create_tcp_socket(addr, &ports.null)
		|| create_tcp_socket(addr, &ports.ack)
		|| create_tcp_socket(addr, &ports.fin)
		|| create_tcp_socket(addr, &ports.xmas)
		|| create_udp_socket(addr, &ports.udp))
		return (1);
	return (0);
}
