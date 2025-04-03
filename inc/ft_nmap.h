#ifndef FT_NMAP_H
#define FT_NMAP_H

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

#endif
