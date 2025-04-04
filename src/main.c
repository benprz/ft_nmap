#include <error.h>
#include <netdb.h>
#include <stdio.h>
#include <argp.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "ft_nmap.h"

const char args_doc[] = "HOST ...";
const char doc[] = "Send ICMP ECHO_REQUEST packets to network hosts."
				   "\vOptions marked with (root only) are available only to "
				   "superuser.";


struct s_nmap g_nmap = {
    0, //options
};

enum {
	ARGP_KEY_SYN = 256,
};

#define ARGP_LONG_NAME_SYN "-sS"
#define ARGP_LONG_NAME_SYN_REPLACE "--sS"

int todo(char* msg)
{
    printf("# TODO MESSAGE: %s\n", msg);
    return -1;
}

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

		case ARGP_KEY_SYN:
			g_nmap.options |= OPT_VERBOSE;
			return todo("OPT_SCAN_SYN");

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

void edit_long_name_options(int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], ARGP_LONG_NAME_SYN)) {
			argv[i] = ARGP_LONG_NAME_SYN_REPLACE;
		}
	}
}

int main(int argc, char **argv)
{
 //    if (getuid() != 0)
	// {
	//     fprintf(stderr, "You must be root to use ft_nmap\n");
	//     return (1);
	// }

	// ex: -sS to --sS
	edit_long_name_options(argc, argv);

	// argp
	struct argp_option options[] = {
		{"verbose", 'v', 0, 0, "Produce verbose output", 0},
		{"sS", ARGP_KEY_SYN, 0, 0, "", 0},
		{0}};

	struct argp argp = {options, parse_options, args_doc, doc, 0, 0, 0};
	argp_parse(&argp, argc, argv, 0, 0, 0);

	// check if verbose is set
	return ft_nmap();
}
