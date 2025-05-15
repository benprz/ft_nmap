#ifndef FT_NMAP_H
#define FT_NMAP_H

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
	enum scan_type		scan;
	struct task			*next;
};

// TCP pseudo-header for checksum computation (IPv4)
struct pseudo_header_for_tcp_checksum {
	uint32_t ip_src;
	uint32_t ip_dst;
	uint8_t padding;
	uint8_t protocol;
	uint8_t tcp_packet_size; // The length of the TCP header and data (measured in octets).
};

extern struct nmap nmap;
extern struct task *tasks;

int		ft_nmap();
int		parse_options(int key, char *arg, struct argp_state *state);
void	create_tasks(void);
void    print_tasks(struct task *task_list);

// utils functions
int todo(char*);
uint16_t calculate_checksum(uint16_t *, int);
void    print_args(struct nmap args);


#endif
