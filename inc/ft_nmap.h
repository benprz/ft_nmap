#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <limits.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <sys/socket.h>
#include <argp.h>
#include <netinet/in.h>

#define UNUSED(x) (void)x

enum	scan_type
{
	ALL, SYN, NUL, ACK, FIN, XMAS, UDP
};

struct	nmap
{
	enum scan_type	scan; // type of scan to use
	uint16_t		threads; // number of threads
	uint16_t		port_start;
	uint16_t		port_end;
	char			*target_opt; // argument of -t
	char			*target_file; // argument of -f
	char			*target_arg; // non option argument
};

struct	task
{
	struct sockaddr_in	target;
	struct sockaddr_in	source;
	enum scan_type		scan;
	struct task			*next;
};

// tous les ports sont en network byte order
struct	ports
{
	unsigned short int	syn;
	unsigned short int	null;
	unsigned short int	ack;
	unsigned short int	fin;
	unsigned short int	xmas;
	unsigned short int	udp;
};

struct	sockets
{
	int	tcp;
	int	udp;
};

extern struct nmap		nmap;
extern struct ports		ports;
extern struct sockets	sockets;
extern struct task		*tasks;

int		ft_nmap(void);
int		parse_options(int key, char *arg, struct argp_state *state);
int		create_tasks(void);
void    print_tasks(struct task *task_list);
int		create_recv_sockets(void);

// utils functions
int todo(char*);

uint16_t calculate_checksum(uint16_t *, int);
void    print_args(struct nmap args);
char	*trim_whitespaces(char *str);
void	print_task(struct task task);


#endif
