#include "ft_nmap.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void	print_tasks(struct task *task_list)
{
	char	host[1024];
	char	service[20];

	printf("Task list:\n");
	while (task_list)
	{
		getnameinfo((struct sockaddr *) &task_list->target,
		            sizeof(struct sockaddr_in), host, sizeof(host),
		            service, sizeof(service), 0);
		printf("target: %s, service: %s, scan: ", host, service);
		switch (task_list->scan)
		{
			case ALL:
				printf("ALL\n");
				break;
			case SYN:
				printf("SYN\n");
				break;
			case ACK:
				printf("ACK\n");
				break;
			case NUL:
				printf("NUL\n");
				break;
			case FIN:
				printf("FIN\n");
				break;
			case XMAS:
				printf("XMAS\n");
				break;
			case UDP:
				printf("UDP\n");
				break;
		}
		task_list = task_list->next;
	}
}

void	append_task_to_list(struct task *new_task)
{
	struct task	*last;

	if (!tasks)
	{
		tasks = new_task;
		return;
	}
	last = tasks;
	while (last->next)
		last = last->next;
	last->next = new_task;
}

void	create_task(struct sockaddr_in addr, enum scan_type scan)
{
	struct task	*new_task;

	new_task = malloc(sizeof(struct task));
	if (!new_task)
		fprintf(stderr, "Error: couldn't create task: %s\n", strerror(errno));
	else
	{
		*new_task = (struct task) {addr, scan, NULL};
		append_task_to_list(new_task);
	}
}

int	get_target_sockaddr(char *target, struct sockaddr_in *addr)
{
	struct addrinfo	*info;
	struct addrinfo	hints;
	int				ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	ret = getaddrinfo(target, NULL, &hints, &info);
	if (ret || !info)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
		return (1);
	}
	*addr = * (struct sockaddr_in *) info->ai_addr;
	return (0);
}

void	target_create_all_tasks(struct sockaddr_in addr)
{
	for (uint16_t i = nmap.port_start; i <= nmap.port_end; i++)
	{
		addr.sin_port = htons(i);
		if (nmap.scan == ALL)
		{
			create_task(addr, SYN);
			create_task(addr, NUL);
			create_task(addr, ACK);
			create_task(addr, FIN);
			create_task(addr, XMAS);
			create_task(addr, UDP);
		}
		else
			create_task(addr, nmap.scan);
	}
}

void	create_tasks(void)
{
	struct sockaddr_in	addr;

	if (nmap.target_arg && !get_target_sockaddr(nmap.target_arg, &addr))
		target_create_all_tasks(addr);
	if (nmap.target_opt && !get_target_sockaddr(nmap.target_opt, &addr))
		target_create_all_tasks(addr);
}
