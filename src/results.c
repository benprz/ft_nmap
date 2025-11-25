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

void	print_results(void)
{
    for (size_t ri = 0; ri < nb_results; ri++)
    {
        struct in_addr addr;
        addr.s_addr = results[ri].target;
        printf("Results for %s:\n", inet_ntoa(addr));

        size_t nb_ports = (size_t)(nmap.port_end - nmap.port_start + 1);
        for (size_t p = 0; p < nb_ports; p++)
        {
            unsigned short port = (unsigned short)(nmap.port_start + p);
            uint32_t value = results[ri].results[p];
            enum scan_result syn_res = (enum scan_result)((value >> (SYN * 3)) & 0x7);
            if (nmap.scan == SYN || nmap.scan == ALL)
            {
                printf("  %u/tcp (SYN): %s\n", port, scan_result_to_str(syn_res));
            }
        }
    }
}
