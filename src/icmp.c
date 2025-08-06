#include "ft_nmap.h"
#include <pthread.h>
#include <unistd.h>

void *icmp_thread(void* arg)
{
	UNUSED(arg);

	fprintf(stdout, "I am an ICMP thread :D\n");
	sleep(3);
	fprintf(stdout, "goodbye ヾ(￣▽￣)\n");
	pthread_mutex_lock(&task_mutex);
	free_task_list(tasks);
	tasks = NULL;
	pthread_mutex_unlock(&task_mutex);
	return (NULL);
}
