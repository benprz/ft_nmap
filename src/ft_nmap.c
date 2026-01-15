#include <pthread.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <bits/pthreadtypes.h>
#include <pcap/pcap.h>
#include <pcap/sll.h>

#include "ft_nmap.h"

void *thread_routine(void* arg) {
	UNUSED(arg);
	pcap_t				*handle;
	char				errbuf[PCAP_ERRBUF_SIZE];
	int					ret;
	struct timer_data	timer_data = { .handle_mutex = PTHREAD_MUTEX_INITIALIZER };

	handle = pcap_create(NULL, errbuf);
	if (!handle)
	{
		fprintf(stderr, "Couldn't open devices: %s\n", errbuf);
		return (NULL);
	}
	pcap_set_snaplen(handle, 65535);
	pcap_set_buffer_size(handle, 1024 * 1024);
	pcap_set_immediate_mode(handle, true);
	ret = pcap_activate(handle);
	if (ret)
	{
		pcap_perror(handle, "pcap_activate");
		pcap_close(handle);
		return (NULL);
	}
	timer_data.handle = handle;
	while (1) {
		pthread_mutex_lock(&task_mutex);
		if (tasks) {
			struct task *task = tasks;
			tasks = tasks->next;
			pthread_mutex_unlock(&task_mutex);
			scan(handle, task->source, task->target, task->scan, &timer_data);
			free(task);
		} else {
			pthread_mutex_unlock(&task_mutex);
			pthread_mutex_lock(&timer_data.handle_mutex);
			pcap_close(handle);
			timer_data.handle = NULL;
			pthread_mutex_unlock(&timer_data.handle_mutex);
			return NULL;
		}
	}
}

int ft_nmap() {
	if (nmap.threads == 0) {
		thread_routine(NULL);
		return 0;
	}

	pthread_t *threads = malloc(nmap.threads * sizeof(pthread_t));

	if (threads == NULL) {
		perror("threads = malloc()-> ");
		return -1;
	}
	bzero(threads, nmap.threads * sizeof(pthread_t));

	for (int i = 0; i < nmap.threads; i++) {
		if (pthread_create(&threads[i], NULL, thread_routine, NULL) == -1) {
			perror("pthread_create-> ");
			fprintf(stderr, "failed to create one thread..\n");
			continue;
		}
	}
	for (int i = 0; i < nmap.threads; i++) {
		pthread_join(threads[i], NULL);
	}

	free(threads);
	return 0;
}
