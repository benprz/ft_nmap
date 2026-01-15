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