#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <bits/types/struct_itimerspec.h>
#include <limits.h>
#include <stddef.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <sys/socket.h>
#include <argp.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <pcap/pcap.h>
#include <time.h>

#define UNUSED(x) (void)x
#define TCP_FILTER_SIZE 450
#define TCP_FILTER_FORMAT "ip src %u.%u.%u.%u && dst %u.%u.%u.%u && ((tcp && src port %u && dst port %u) || (icmp && icmp[icmptype] == 3 && (icmp[icmpcode] == 0 || icmp[icmpcode] == 1 || icmp[icmpcode] == 2 || icmp[icmpcode] == 3 || icmp[icmpcode] == 9 || icmp[icmpcode] == 10 || icmp[icmpcode] == 13) && (icmp[8] & 0xf0) == 0x40 && icmp[17] == 6 && icmp[8 + ((icmp[8] & 0xf) * 4):2] == %u && icmp[8 + ((icmp[8] & 0xf) * 4) + 2:2] == %u))"
// #define TCP_FILTER_FORMAT "ip src %u.%u.%u.%u && dst %u.%u.%u.%u && ((tcp && src port %u && dst port %u) || (icmp && icmp[icmptype] == 3 && (icmp[icmpcode] == 0 || icmp[icmpcode] == 1 || icmp[icmpcode] == 2 || icmp[icmpcode] == 3 || icmp[icmpcode] == 9 || icmp[icmpcode] == 10 || icmp[icmpcode] == 13)))"

enum	scan_type
{
	ALL, SYN, NUL, ACK, FIN, XMAS, UDP
};

enum	scan_result
{
	SR_OPEN, SR_CLOSED, SR_FILTERED, SR_UNFILTERED, SR_OPEN_FILTERED
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

struct	result
{
	in_addr_t	target;
	uint32_t	*results; // utilisation: (results[port - nmap.port_start] >> (scan_type * 3)) & 0b111
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

extern struct nmap				nmap;
extern struct ports				ports;
extern struct sockets			sockets;
extern struct task				*tasks;
extern struct result			*results;
extern size_t					nb_results;
extern pthread_mutex_t			task_mutex;
extern pthread_mutex_t			result_mutex;
extern const struct itimerspec	default_delay;
extern const struct itimerspec	empty_delay;

int		ft_nmap(void);
int		parse_options(int key, char *arg, struct argp_state *state);
int		create_tasks(void);
void    print_tasks(struct task *task_list);
int		create_recv_sockets(void);
int		create_send_sockets(void);
void	add_result(in_addr_t target, unsigned short port,  enum scan_type scan,
					enum scan_result result);
int		create_target_result(in_addr_t target);
void	free_results(struct result *results);
void	ack(pcap_t *handle, struct sockaddr_in src, struct sockaddr_in tgt);
int		setup_pcap_tcp(pcap_t *handle, struct sockaddr_in src,
						struct sockaddr_in tgt, struct bpf_program *fp);
int		fill_tcp_filter(struct sockaddr_in src, struct sockaddr_in tgt,
						char *buff);
int		send_probe(struct sockaddr_in src, struct sockaddr_in tgt,
					enum scan_type scan);
int		create_timer(timer_t *timerid, pcap_t *handle);

// utils functions
int todo(char*);

uint16_t calculate_checksum(uint16_t *, int);
void    print_args(struct nmap args);
char	*trim_whitespaces(char *str);
void	print_task(struct task task);

#endif
