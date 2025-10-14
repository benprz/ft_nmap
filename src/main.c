#include <error.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <argp.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <pthread.h>

#include "ft_nmap.h"

const char args_doc[] = "TARGET";
const char doc[] = "Scan for open ports on one or more machines.";

struct nmap nmap = {
	ALL, // scan type
	10, // number of threads
	1, // port start
	1024, // port end
	NULL, // target_opt (-t argument)
	NULL, // target_file (-t argument)
	NULL // target_arg (non option argument)
};

struct ports	ports;
struct sockets	sockets;
struct task		*tasks = NULL; // liste chaînée
struct result	*results = NULL; // array
size_t			nb_results = 0;
pthread_mutex_t	task_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t	result_mutex = PTHREAD_MUTEX_INITIALIZER;

int parse_host(char *hostname)
{
	struct addrinfo	*hostinfo;
	struct addrinfo	hints;
	int				ret;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	ret = getaddrinfo(hostname, NULL, &hints, &hostinfo);
	if (ret < 0)
	{
		printf("Error: %s\n", gai_strerror(ret));
		return (-1);
	}
	return 0;
}


// lpcap 1.8.0 minimum version (see pcap_compile man page)
int main(int argc, char **argv)
{
	const struct argp_option options[] = {
		{"target", 't', "TARGET", 0, "target (IP or hostname) to scan", 0},
		{"file", 'f', "FILE", 0, "file containing a list of targets to scan", 0},
		{"ports", 'p', "PORT/RANGE", 0, "target ports(s) to scan (single port or range with format (n-m) (max number of ports: 1024)", 0},
		{"threads", 'm', "THREADS", 0, "maximum number of threads to use for the scan (default: 10) (max: 250)", 0},
		{"scan", 's', "TYPE", 0, "type of scan to use, must be one of SYN, NULL, ACK, FIN, XMAS, UDP (all used if not specified)", 0},
		{0}
	};

	struct argp argp = {options, parse_options, args_doc, doc, 0, 0, 0};
	argp_parse(&argp, argc, argv, 0, 0, 0);
	// print_args(nmap);
	if (getuid() != 0)
	{
	    fprintf(stderr, "You must be root to use ft_nmap\n");
	    return (1);
	}
	if (create_recv_sockets()
		|| create_send_sockets()
		|| create_tasks()
		|| ft_nmap())
	{
		free(tasks);
		return (2);
	}
	print_results();
	return (0);
}
