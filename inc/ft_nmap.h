#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <bits/pthreadtypes.h>
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
#define UDP_PAYLOAD "knock knock"
// les filtres TCP et UDP ont presque la même longueur (1 char de différence)
#define FILTER_SIZE 451
// #define TCP_FILTER_FORMAT "ip src %u.%u.%u.%u && dst %u.%u.%u.%u && ((tcp && src port %u && dst port %u) || (icmp && icmp[icmptype] == 3 && (icmp[icmpcode] == 0 || icmp[icmpcode] == 1 || icmp[icmpcode] == 2 || icmp[icmpcode] == 3 || icmp[icmpcode] == 9 || icmp[icmpcode] == 10 || icmp[icmpcode] == 13) && (icmp[8] & 0xf0) == 0x40 && icmp[17] == 6 && icmp[8 + ((icmp[8] & 0xf) * 4):2] == %u && icmp[8 + ((icmp[8] & 0xf) * 4) + 2:2] == %u))"
#define UDP_FILTER_FORMAT "ip src %u.%u.%u.%u && dst %u.%u.%u.%u && ((udp && src port %u && dst port %u) || (icmp && icmp[icmptype] == 3 && (icmp[icmpcode] == 0 || icmp[icmpcode] == 1 || icmp[icmpcode] == 2 || icmp[icmpcode] == 3 || icmp[icmpcode] == 9 || icmp[icmpcode] == 10 || icmp[icmpcode] == 13) && (icmp[8] & 0xf0) == 0x40 && icmp[17] == 17 && icmp[8 + ((icmp[8] & 0xf) * 4):2] == %u && icmp[8 + ((icmp[8] & 0xf) * 4) + 2:2] == %u))"

// ALL est à -1 parce que les vrais scans commencent à SYN, comme ça pour
// le tableau de résultat tu peux utiliser scan_type comme indice du tableau
enum	scan_type
{
	ALL = -1, SYN = 0, NUL = 1, ACK = 2, FIN = 3, XMAS = 4, UDP = 5
};

enum	scan_result
{
	SR_OPEN = 0, SR_CLOSED, SR_FILTERED, SR_UNFILTERED, SR_OPEN_FILTERED
};

// toutes les réponses possibles à une probe
enum	probe_response
{
	PR_TCP_SYNACK = 0, PR_TCP_RST, PR_UDP, PR_ICMP_3_3, PR_ICMP_OTHER, PR_NONE
};

// 1 second, which is the default timeout for nmap, you can check it with -Pn option
// -Pn option means that the scan will be performed without pinging the target, 
// so no timeout measurement is done (which is supposed to help to speed up the scan)
#define INITIAL_RTT_TIMEOUT 1 

// BPF filter for capturing relevant packets for port TCP/SYN scan result
// https://nmap.org/book/synscan.html
// - Only allows packets with:
//   * Specific IP source address (%u.%u.%u.%u)
//   * Specific IP destination address (%u.%u.%u.%u)
// - Either:
//     a) TCP packets with given src/dst port
//     b) ICMP packets indicating error about those ports
#define TCP_FILTER_FORMAT \
	/* Match the source and destination IP addresses */ \
	"ip src %u.%u.%u.%u && dst %u.%u.%u.%u && (" \
		/* TCP response: src port %u, dst port %u */ \
		"(tcp && src port %u && dst port %u) || " \
		/* Or, match specific ICMP type/codes indicating filtering or unreachable */ \
		"(icmp && icmp[icmptype] == 3 && " \
			/* ICMP codes: 0,1,2,3,9,10,13 */ \
			"(icmp[icmpcode] == 0 || " \
			"icmp[icmpcode] == 1 || " \
			"icmp[icmpcode] == 2 || " \
			"icmp[icmpcode] == 3 || " \
			"icmp[icmpcode] == 9 || " \
			"icmp[icmpcode] == 10 || " \
			"icmp[icmpcode] == 13) && " \
			/* Inner IP header version must be IPv4 */ \
			"(icmp[8] & 0xf0) == 0x40 && " \
			/* Inner protocol is TCP (protocol number 6) */ \
			"icmp[17] == 6 && " \
			/* Inner TCP src port == %u, dst port == %u */ \
			"icmp[8 + ((icmp[8] & 0xf) * 4):2] == %u && " \
			"icmp[8 + ((icmp[8] & 0xf) * 4) + 2:2] == %u" \
		")" \
	")"

struct	nmap
{
	enum scan_type		scan; // type of scan to use
	uint16_t			threads; // number of threads
	uint16_t			port_start;
	uint16_t			port_end;
	char				*target_opt; // argument of -t
	char				*target_file; // argument of -f
	char				*target_arg; // non option argument
	struct sockaddr_in	spoofed_source;
};

struct	task
{
	struct sockaddr_in	target;
	struct sockaddr_in	source;
	enum scan_type		scan;
	struct task			*next;
};

// per target
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

// the handle in the struct is set to NULL right before being closed so
// pcap_breakloop isn't called on a handle that's been closed
struct	timer_data
{
	pcap_t			*handle;
	pthread_mutex_t	handle_mutex;
};

extern struct nmap				nmap;
extern struct ports				ports;
extern int						send_sock;
extern struct task				*tasks;
extern struct result			*results;
extern size_t					nb_results;
extern pthread_mutex_t			task_mutex;
extern pthread_mutex_t			result_mutex;
extern const struct itimerspec	default_delay;
extern const struct itimerspec	empty_delay;
// usage: result_lookup[scan_type][probe_response] gives you a scan_result
extern const int				result_lookup[6][6];

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
void	scan(pcap_t *handle, struct sockaddr_in src, struct sockaddr_in tgt,
				enum scan_type scan, struct timer_data *timer_data);
enum scan_result	interpret_packet(const u_char *packet, enum scan_type scan);
int 	send_probe(struct sockaddr_in src, struct sockaddr_in tgt,
				enum scan_type scan);

// utils functions
int todo(char*);

uint16_t calculate_checksum(uint16_t *, int);
void    print_args(struct nmap args);
char	*trim_whitespaces(char *str);
void	print_task(struct task task);
const char *scan_result_to_str(enum scan_result r);
void	print_results_debug(void);
void	print_scan_config(void);
void	print_results(double scan_duration);

#endif
