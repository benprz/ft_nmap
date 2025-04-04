#ifndef FT_NMAP_H
#define FT_NMAP_H

#define UNUSED(x) (void)x

#define OPT_VERBOSE 0x1
#define OPT_SCAN_SYN 0x2

struct s_nmap
{
    unsigned int options;
};

extern struct s_nmap g_nmap;

int todo(char*);

int ft_nmap();

#endif
