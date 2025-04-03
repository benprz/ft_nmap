#include <error.h>
#include <netdb.h>
#include <stdio.h>
#include <argp.h>
#include <unistd.h>

#include "ft_nmap.h"

const char args_doc[] = "HOST ...";
const char doc[] = "Send ICMP ECHO_REQUEST packets to network hosts."
				   "\vOptions marked with (root only) are available only to "
				   "superuser.";


struct s_nmap g_nmap = {
    0, //options
};

int todo(char* msg)
{
    printf("# TODO MESSAGE: %s\n", msg);
    return -1;
}

int parse_host(char *hostname)
{
	struct addrinfo *hostinfo;

	//must free with api function
	if (getaddrinfo(hostname, NULL, NULL, &hostinfo) < 0) {
		return todo("getaddrinfo error");
	}

	return 0;
}

int parse_options(int key, char *arg, struct argp_state *state)
{
	UNUSED(arg);
	switch (key)
	{
	case 'v':
		g_nmap.options |= OPT_VERBOSE;
		break;

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
 //    if (getuid() != 0)
	// {
	//     fprintf(stderr, "You must be root to use ft_nmap\n");
	//     return (1);
	// }

	// argp
	struct argp_option options[] = {
		{"verbose", 'v', 0, 0, "Produce verbose output", 0},
		{0}};

	struct argp argp = {options, parse_options, args_doc, doc, 0, 0, 0};
	argp_parse(&argp, argc, argv, 0, 0, 0);

	// check if verbose is set


	// ft_nmap();
	return 0;
}
