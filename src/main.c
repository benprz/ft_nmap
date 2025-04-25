#include <error.h>
#include <netdb.h>
#include <stdio.h>
#include <argp.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "ft_nmap.h"

const char args_doc[] = "[-t TARGET] [-f FILE]";
const char doc[] = "Scan for open ports on one or more machines.";


struct s_nmap g_nmap = {
    0, //options
};

int parse_host(char *hostname)
{
	struct addrinfo *hostinfo;
	struct addrinfo hints;
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
	// ret = socket()
	return 0;
}


int parse_options(int key, char *arg, struct argp_state *state)
{
	UNUSED(arg);
	switch (key)
	{
		case 'v':
			g_nmap.options |= OPT_VERBOSE;
			return todo("OPT_VERBOSE");

		case ARGP_KEY_ARG:
			return todo("ARGP_KEY_ARG");

		case ARGP_KEY_NO_ARGS:
			argp_error(state, "missing host operand");

		/* FALLTHROUGH */
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int main(int argc, char **argv)
{
	//if (getuid() != 0)
	//{
	//    fprintf(stderr, "You must be root to use ft_nmap\n");
	//    return (1);
	//}

	// argp
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

	// check if verbose is set
	return ft_nmap();
}
