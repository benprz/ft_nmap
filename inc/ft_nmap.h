#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <error.h>
#include <math.h>

#define UNUSED(x) (void)x

#define OPT_VERBOSE 0x1

struct s_nmap
{
    unsigned int options;
};

extern struct s_nmap g_nmap;

void signal_handler(int);
void print_stats();

void ft_nmap();
int todo(char*);
