#ifndef FT_NMAP_H
#define FT_NMAP_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>

#define UNUSED(x) (void)x

#define OPT_VERBOSE 0x1
#define OPT_SCAN_SYN 0x2

struct s_nmap
{
    unsigned int options;
};

extern struct s_nmap g_nmap;

int ft_nmap();

// utils functions
int todo(char*);

#endif
