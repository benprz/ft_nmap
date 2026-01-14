#include "ft_nmap.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>

void	free_tasks(struct task *list)
{
	struct task	*next;

	while (list)
	{
		next = list->next;
		free(list);
		list = next;
	}
}

// il faut absolument utiliser cette fonction pour ajouter des task à la liste
void	append_task_to_list(struct task *new_task)
{
	static struct task	*last = NULL;

	if (!last)
	{
		tasks = new_task;
		last = new_task;
	}
	else
	{
		last->next = new_task;
		last = last->next;
	}
}

void	create_task(struct sockaddr_in tgt, struct sockaddr_in src, enum scan_type scan, unsigned short int port)
{
	struct task	*new_task;

	new_task = malloc(sizeof(struct task));
	if (!new_task)
		fprintf(stderr, "Couldn't create task: %s\n", strerror(errno));
	else
	{
		src.sin_port = port;
		*new_task = (struct task) {tgt, src, scan, NULL};
		append_task_to_list(new_task);
	}
}

void	target_create_all_tasks(struct sockaddr_in tgt, struct sockaddr_in src)
{
	for (uint16_t i = nmap.port_start; i <= nmap.port_end; i++)
	{
		tgt.sin_port = htons(i);
		if (nmap.scans[SYN])
			create_task(tgt, src, SYN, ports.syn);
		if (nmap.scans[NUL])
			create_task(tgt, src, NUL, ports.null);
		if (nmap.scans[ACK])
			create_task(tgt, src, ACK, ports.ack);
		if (nmap.scans[FIN])
			create_task(tgt, src, FIN, ports.fin);
		if (nmap.scans[XMAS])
			create_task(tgt, src, XMAS, ports.xmas);
		if (nmap.scans[UDP])
			create_task(tgt, src, UDP, ports.udp);
	}
}

int	get_src_sockaddr(int sock, const struct sockaddr_in *tgt, struct sockaddr_in *src)
{
	struct sockaddr_in	disconnect;
	socklen_t	len;

	if (nmap.spoofed_source.sin_family == AF_INET)
	{
		*src = nmap.spoofed_source;
		return (0);
	}
	if (connect(sock, (struct sockaddr *) tgt, sizeof(struct sockaddr_in)))
	{
		perror("Couldn't connect UDP socket");
		return (1);
	}
	len = sizeof(struct sockaddr_in);
	if (getsockname(sock, (struct sockaddr *) src, &len))
	{
		perror("Couldn't get source IP");
		return (1);
	}
	// ça sert à déconnecter un socket udp connecté
	disconnect.sin_family = AF_UNSPEC;
	connect(sock, (struct sockaddr *) &disconnect, sizeof(disconnect));
	return (0);
}

int add_target(in_addr_t addr, char *name)
{
	struct target *target = targets;
	target = malloc(sizeof(struct target));
	if (!target)
		return (2);
	strcpy(target->name, name);
	target->addr = addr;
	target->next = targets;
	targets = target;

	target = target->next;
	while (target) {
		if (target->addr == addr)
			return (1);
		target = target->next;
	}
	return (0);
}

int	get_tgt_sockaddr(char *target, struct sockaddr_in *addr)
{
	struct addrinfo	*info;
	struct addrinfo	hints;
	int				ret;

	if (!strlen(target))
		return (1);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	ret = getaddrinfo(target, NULL, &hints, &info);
	if (ret || !info)
	{
		fprintf(stderr, "%s: %s\n", target, gai_strerror(ret));
		return (1);
	}
	*addr = * (struct sockaddr_in *) info->ai_addr;
	if ((ret = add_target(addr->sin_addr.s_addr, target)) == 1)
	{
		// target already exists	
		freeaddrinfo(info);
		return (1);
	}
	else if (ret == 2)
	{
		fprintf(stderr, "%s: %s\n", target, strerror(errno));
		freeaddrinfo(info);
		return (2);
	}
	freeaddrinfo(info);
	return (0);
}


int file_create_all_tasks(FILE *file, int src_addr_sock)
{
	char				*next_target;
	char				*clean_target;
	size_t				len;
	struct sockaddr_in	tgt;
	struct sockaddr_in	src;
	int					ret;

	len = 0;
	next_target = NULL;
	ret = 0;
	while ((getline(&next_target, &len, file)) != -1 || ret)
	{
		clean_target = trim_whitespaces(next_target);
		if (strlen(clean_target) > 0
		    && !get_tgt_sockaddr(clean_target, &tgt)
			&& !get_src_sockaddr(src_addr_sock, &tgt, &src))
		{
			target_create_all_tasks(tgt, src);
			ret = create_target_result(tgt.sin_addr.s_addr);
		}
	}
	if (ferror(file))
	{
		fprintf(stderr,
		        "Couldn't read the file: %s\n",
		        strerror(errno));
		return (1);
	}
	free(next_target);
	fclose(file);
	return (ret);
}

int	create_tasks(void)
{
	struct sockaddr_in	tgt;
	struct sockaddr_in	src;
	FILE				*file;
	int					src_addr_sock;

	if (nmap.target_file)
	{
		file = fopen(nmap.target_file, "r");
		if (!file)
		{
			fprintf(stderr, "Error: couldn't open file: %s\n", strerror(errno));
			goto error_no_close;
		}
	}
	// creation du socket udp pour obtenir l'adresse locale
	src_addr_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (src_addr_sock < 0)
	{
		fprintf(stderr, "Error: couldn't create socket: %s\n", strerror(errno));
		goto error;
	}
	if (nmap.target_arg
	    	&& !get_tgt_sockaddr(nmap.target_arg, &tgt)
			&& !get_src_sockaddr(src_addr_sock, &tgt, &src))
	{
		target_create_all_tasks(tgt, src);
		if (create_target_result(tgt.sin_addr.s_addr))
			goto error;
	}
	if (nmap.target_opt
			&& !get_tgt_sockaddr(nmap.target_opt, &tgt)
			&& !get_src_sockaddr(src_addr_sock, &tgt, &src))
	{
		target_create_all_tasks(tgt, src);
		if (create_target_result(tgt.sin_addr.s_addr))
			goto error;
	}
	if (nmap.target_file)
	{
		if (file_create_all_tasks(file, src_addr_sock))
			goto error;
	}
	close(src_addr_sock);
	return (0);
error:
	close(src_addr_sock);
error_no_close:
	free_tasks(tasks);
	tasks = NULL;
	free_results(results);
	results = NULL;
	return (1);
}
