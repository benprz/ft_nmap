#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <bits/pthreadtypes.h>
#include <stdlib.h>

#include "ft_nmap.h"

pthread_mutex_t task_mutex = PTHREAD_MUTEX_INITIALIZER;

void *thread_routine(void* arg) {
	UNUSED(arg);
	while (1) {
		pthread_mutex_lock(&task_mutex);
		if (tasks) {
			struct task *task = tasks;
			tasks = tasks->next;
			pthread_mutex_unlock(&task_mutex);
			printf("Processing task: %s %d %d\n", inet_ntoa(task->target.sin_addr), ntohs(task->target.sin_port), task->scan);
			free(task);
		} else {
			pthread_mutex_unlock(&task_mutex);
			return NULL;
		}
	}
}

int ft_nmap() {

	pthread_t *threads = malloc(nmap.threads * sizeof(pthread_t));
	if (threads == NULL) {
		perror("threads = malloc()-> ");
		return -1;
	}

	for (int i = 0; i < nmap.threads; i++) {
		if (pthread_create(&threads[i], NULL, thread_routine, NULL) == -1) {
			perror("pthread_create-> ");
			fprintf(stderr, "trying again..\n");
			i--;
			continue;
		}
	}
	for (int i = 0; i < nmap.threads; i++) {
		pthread_join(threads[i], NULL);
	}

	free(threads);
	return 0;
}
