#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "ft_nmap.h"

void	free_results(struct result *results)
{
	size_t	i;

	i = 0;
	while (i < nb_results)
	{
		free(results[i].results);
		i++;
	}
	free(results);
}

int	create_target_result(in_addr_t target)
{
	size_t			nb_ports;

	results = reallocarray(results, nb_results + 1, sizeof(struct result));
	if (!results)
	{
		nb_results = 0;
		goto error;
	}
	nb_results++;	// increment nb_results	
	nb_ports = nmap.port_end - nmap.port_start + 1;	
	results[nb_results - 1].results = malloc(sizeof(uint32_t) * nb_ports);
	if (!results[nb_results - 1].results)
		goto error;
	bzero(results[nb_results - 1].results, sizeof(uint32_t) * nb_ports);
	results[nb_results - 1].target = target;
	return (0);

error:
	free_results(results);
	perror("Couldn't allocate results");
	return (1);
}

// port needs to be in host byte order when passed to the function
void	add_result(in_addr_t target, unsigned short port, enum scan_type scan,
					enum scan_result result)
{
	size_t	i;

	i = 0;
	while (i < nb_results && results[i].target != target)
		i++;
	if (i >= nb_results)
		return ; // bruh?
	pthread_mutex_lock(&result_mutex);
	results[i].results[port - nmap.port_start] |= result << (scan * 3);
	pthread_mutex_unlock(&result_mutex);
}

const char *scan_result_to_str(enum scan_result r)
{
    switch (r)
    {
        case SR_OPEN: return "open";
        case SR_CLOSED: return "closed";
        case SR_FILTERED: return "filtered";
        case SR_UNFILTERED: return "unfiltered";
        case SR_OPEN_FILTERED: return "open|filtered";
        default: return "unknown";
    }
}


void    print_results_debug(void)
{
        size_t                  ri;
        struct in_addr  addr;
        size_t                  nb_ports;
        size_t                  p;
        unsigned short  port;
        uint32_t                value;
        enum scan_result        result;

        ri = 0;
        while (ri < nb_results)
        {
                addr.s_addr = results[ri].target;
                printf("target: %s\n", inet_ntoa(addr));
                nb_ports = (size_t)(nmap.port_end - nmap.port_start + 1);
                p = 0;
                while (p < nb_ports)
                {
                        port = (unsigned short)(nmap.port_start + p);
                        value = results[ri].results[p];
                        printf("  port %u:\n", port);
                        if (nmap.scan == SYN || nmap.scan == ALL)
                        {
                                result = (enum scan_result)((value >> (SYN * 3)) & 0x7);
                                printf("    SYN: %s\n", scan_result_to_str(result));
                        }
                        if (nmap.scan == NUL || nmap.scan == ALL)
                        {
                                result = (enum scan_result)((value >> (NUL * 3)) & 0x7);
                                printf("    NUL: %s\n", scan_result_to_str(result));
                        }
                        if (nmap.scan == ACK || nmap.scan == ALL)
                        {
                                result = (enum scan_result)((value >> (ACK * 3)) & 0x7);
                                printf("    ACK: %s\n", scan_result_to_str(result));
                        }
                        if (nmap.scan == FIN || nmap.scan == ALL)
                        {
                                result = (enum scan_result)((value >> (FIN * 3)) & 0x7);
                                printf("    FIN: %s\n", scan_result_to_str(result));
                        }
                        if (nmap.scan == XMAS || nmap.scan == ALL)
                        {
                                result = (enum scan_result)((value >> (XMAS * 3)) & 0x7);
                                printf("    XMAS: %s\n", scan_result_to_str(result));
                        }
                        if (nmap.scan == UDP || nmap.scan == ALL)
                        {
                                result = (enum scan_result)((value >> (UDP * 3)) & 0x7);
                                printf("    UDP: %s\n", scan_result_to_str(result));
                        }
                        p++;
                }
                ri++;
        }
}


