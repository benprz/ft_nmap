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

void	free_task_list(struct task *list)
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

void	create_task(struct sockaddr_in addr, enum scan_type scan)
{
	struct task	*new_task;

	new_task = malloc(sizeof(struct task));
	if (!new_task)
		fprintf(stderr, "Couldn't create task: %s\n", strerror(errno));
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
	FILE				*file;
	char				*next_target;
	char				*clean_target;
	size_t				len;
	ssize_t				ret;

	if (nmap.target_file)
	{
		file = fopen(nmap.target_file, "r");
		if (!file)
		{
			fprintf(stderr, "Error: couldn't open file: %s\n", strerror(errno));
			exit(1);
		}
	}
	if (nmap.target_arg && !get_target_sockaddr(nmap.target_arg, &addr))
		target_create_all_tasks(addr);
	if (nmap.target_opt && !get_target_sockaddr(nmap.target_opt, &addr))
		target_create_all_tasks(addr);
	if (!nmap.target_file)
		return;
	len = 0;
	next_target = NULL;
	while ((ret = getline(&next_target, &len, file)) != -1)
	{
		clean_target = trim_whitespaces(next_target);
		if (strlen(clean_target) > 0 && !get_target_sockaddr(clean_target, &addr))
			target_create_all_tasks(addr);
	}
	if (ferror(file))
	{
		fprintf(stderr,
		        "Error: an error occured while trying to read the file: %s\n",
		        strerror(errno));
		free_task_list(tasks);
		exit(2);
	}
	free(next_target);
	fclose(file);
}
