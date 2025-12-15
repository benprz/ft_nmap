#include <error.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stddef.h>
#include <stdio.h>
#include <argp.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

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
	NULL, // target_arg (non option argument)
	{0} // spoofed source
};

struct ports	ports;
int				send_sock;
struct task		*tasks = NULL; // liste chaînée
struct result	*results = NULL; // array of results per target
size_t			nb_results = 0;
pthread_mutex_t	task_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t	result_mutex = PTHREAD_MUTEX_INITIALIZER;
const struct itimerspec	default_delay =
{
	.it_interval = { .tv_sec = 0, .tv_nsec = 0 },
	.it_value = { .tv_sec = INITIAL_RTT_TIMEOUT, .tv_nsec = 0 }
};
const struct itimerspec	empty_delay = {0};
// for impossible replies (not in the official nmap response lookup table) I
// put open most of the time but they shouldn't occur anyway so it dones't matter
// (maybe we should put the same replay as PR_NONE)
const int		result_lookup[6][6] =
{
	{SR_OPEN, SR_CLOSED, SR_OPEN, SR_FILTERED, SR_FILTERED, SR_FILTERED }, // SYN
	{SR_OPEN, SR_CLOSED, SR_OPEN, SR_FILTERED, SR_FILTERED, SR_OPEN_FILTERED}, // NULL
	{SR_OPEN, SR_UNFILTERED, SR_OPEN, SR_FILTERED, SR_FILTERED, SR_FILTERED }, // ACK
	{SR_OPEN, SR_CLOSED, SR_OPEN, SR_FILTERED, SR_FILTERED, SR_OPEN_FILTERED}, // FIN
	{SR_OPEN, SR_CLOSED, SR_OPEN, SR_FILTERED, SR_FILTERED, SR_OPEN_FILTERED}, // XMAS
	{SR_OPEN, SR_CLOSED, SR_OPEN, SR_CLOSED, SR_FILTERED, SR_OPEN_FILTERED}, // UDP
};

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
		{"spoof", 'S', "ADDRESS", 0, "Source IP address to use", 0},
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
		|| create_tasks())
	{
		free(tasks);
		return (2);
	}
	
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
	
	print_scan_config();
	printf("Scanning..\n");
	if (ft_nmap())
	{
		free(tasks);
		return (2);
	}
	
	clock_gettime(CLOCK_MONOTONIC, &end);
	double duration = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
	
	print_results(duration);
	return (0);
}
