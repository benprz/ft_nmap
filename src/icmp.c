#include "ft_nmap.h"

void *icmp_thread(void* arg)
{
	UNUSED(arg);
	fprintf(stdout, "I am an ICMP thread :D\n");
	return (NULL);
}
