#include "ft_nmap.h"

#include <argp.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


int parse_scan(char *str)
{
	enum scan_type scan;
	static bool scans_specified = false;

	if (!strcmp(str, "SYN"))
		scan = SYN;
	else if (!strcmp(str, "NULL"))
		scan = NUL;
	else if (!strcmp(str, "ACK"))
		scan = ACK;
	else if (!strcmp(str, "FIN"))
		scan = FIN;
	else if (!strcmp(str, "XMAS"))
		scan = XMAS;
	else if (!strcmp(str, "UDP"))
		scan = UDP;
	else
		return (1);

	// First time -s is seen, clear defaults and mark as user-specified
	if (!scans_specified)
	{
		memset(nmap.scans, 0, sizeof(nmap.scans));
		scans_specified = true;
	}
	nmap.scans[scan] = true;
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

int parse_delay(char *str)
{
	long delay = atoi(str);
	if (delay <= 0)
		return (1);
	timeout_delay.it_value.tv_sec =  delay / 1000;
	timeout_delay.it_value.tv_nsec = (delay % 1000) * 1000000;
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
		case 'S':
			if (inet_pton(AF_INET, arg, &nmap.spoofed_source.sin_addr) != 1)
				argp_error(state, "invalid spoofing address");
			else
				nmap.spoofed_source.sin_family = AF_INET;
			break;
		case 'm':
			nmap.threads = atoi(arg);
			if (nmap.threads > 250)
				argp_error(state, "max number of threads: 250");
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
		case 'T':
			if (parse_delay(arg))
				argp_error(state, "bad delay");
			break;
		case ARGP_KEY_ARG:
			if (nmap.target_arg)
				argp_error(state, "too many arguments");
			nmap.target_arg = arg;
			break;
		case ARGP_KEY_END:
			if (state->argc == 1) {
				argp_help(state->root_argp, state->out_stream, ARGP_HELP_STD_HELP, state->name);
				exit(0);
			}
			else if (!nmap.target_file && !nmap.target_opt && !nmap.target_arg)
				argp_error(state, "no target provided");
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
