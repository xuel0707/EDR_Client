/*
 * cc busy.c -o busy -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <pthread.h>

pthread_t thread[16];

void *busy(void *ptr)
{
	int i = 0;

	while (1) {
		i++;
	}
}

int main(int argc, char **argv)
{
	int i = 0;

	if (argc == 1) {
		printf("Usage: %s thread_num\n", argv[0]);
		return 0;
	}

	printf("pid: %d\n", getpid());

	memset(&thread[0], 0, 16 * sizeof(pthread_t));

	for (i = 0; i < atoi(argv[1]); i++) {
		pthread_create(&thread[i], NULL, busy, NULL);
	}

	while (1) {
		sleep(1);
	}

	return 0;
}
