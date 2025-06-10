#include "ft_nmap.h"

#include <argp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void	print_args(struct nmap args)
{
	fprintf(stdout, "scan: %d\n", args.scan);
	fprintf(stdout, "threads: %d\n", args.threads);
	fprintf(stdout, "port start: %d\n", args.port_start);
	fprintf(stdout, "port end: %d\n", args.port_end);
	fprintf(stdout, "target opt: %s\n", args.target_opt);
	fprintf(stdout, "target file name: %s\n", args.target_file);
	fprintf(stdout, "target arg: %s\n", args.target_arg);
}

int parse_scan(char *str)
{
	if (!strcmp(str, "SYN"))
		nmap.scan = SYN;
	else if (!strcmp(str, "NULL"))
		nmap.scan = NUL;
	else if (!strcmp(str, "ACK"))
		nmap.scan = ACK;
	else if (!strcmp(str, "FIN"))
		nmap.scan = FIN;
	else if (!strcmp(str, "XMAS"))
		nmap.scan = XMAS;
	else if (!strcmp(str, "UDP"))
		nmap.scan = UDP;
	else
		return (1);
	return (0);
}

int	parse_port(char *str)
{
	size_t	size;
	int		nb_hyphens;
	char	*after_hyphen;

	size = strlen(str);
	nb_hyphens = 0;
	for (size_t i = 0; i < size; i++)
	{
		if (str[i] == '-')
		{
			if (i == 0 || i == size -1)
				return (1);
			nb_hyphens++;
			if (nb_hyphens > 1)
				return (1);
			after_hyphen = str + i + 1;
			str[i] = 0;
		}
		else if (!isdigit(str[i]))
			return (1);
	}
	if (nb_hyphens)
	{
		nmap.port_start = atoi(str);
		nmap.port_end = atoi(after_hyphen);
	}
	else
	{
		nmap.port_start = atoi(str);
		nmap.port_end = nmap.port_start;
	}
	if (nmap.port_start > nmap.port_end
		|| nmap.port_start <= 0
		|| nmap.port_end <= 0)
		return (1);
	if (nmap.port_end - nmap.port_start > 1023)
		nmap.port_end = nmap.port_start + 1023;
	return (0);
}

int parse_options(int key, char *arg, struct argp_state *state)
{
	UNUSED(arg);
	switch (key)
	{
		case 's':
			if (parse_scan(arg))
				argp_error(state, "bad scan type");
			break;
		case 'm':
			nmap.threads = atoi(arg);
			if (nmap.threads > 250)
				argp_error(state, "max number of threads: 250");
			else if (nmap.threads == 0)
				nmap.threads = 1;
			break;
		case 'p':
			if (parse_port(arg))
				argp_error(state, "bad port range");
			break;
		case 't':
			nmap.target_opt = arg;
			break;
		case 'f':
			nmap.target_file = arg;
			break;
		case ARGP_KEY_ARG:
			if (nmap.target_arg)
				argp_error(state, "too many arguments");
			nmap.target_arg = arg;
			break;
		case ARGP_KEY_END:
			if (!nmap.target_file && !nmap.target_opt && !nmap.target_arg)
				argp_error(state, "no target provided");
		/* FALLTHROUGH */
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
