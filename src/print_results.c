#include "ft_nmap.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <stdlib.h>

const char *get_service_name(uint16_t port)
{
	struct servent *serv;

	serv = getservbyport(htons(port), "tcp");
	if (serv)
		return serv->s_name;
	
	serv = getservbyport(htons(port), "udp");
	if (serv)
		return serv->s_name;
	
	return "Unassigned";
}

const char *scan_type_to_str(enum scan_type scan)
{
	switch (scan)
	{
		case SYN: return "SYN";
		case NUL: return "NULL";
		case ACK: return "ACK";
		case FIN: return "FIN";
		case XMAS: return "XMAS";
		case UDP: return "UDP";
		default: return "UNKNOWN";
	}
}

const char *scan_result_to_str(enum scan_result result)
{
	switch (result)
	{
		case SR_OPEN: return "Open";
		case SR_CLOSED: return "Closed";
		case SR_FILTERED: return "Filtered";
		case SR_UNFILTERED: return "Unfiltered";
		case SR_OPEN_FILTERED: return "Open|Filtered";
		default: return "Unknown";
	}
}

// example: "SYN (Open)", "NULL (Closed)"
void format_scan_result(char *buf, size_t buf_size, enum scan_type scan, enum scan_result result)
{
	const char *scan_str = scan_type_to_str(scan);
	const char *result_str = scan_result_to_str(result);
	
	snprintf(buf, buf_size, "%s (%s)", scan_str, result_str);
}

// Determine final conclusion for a port based on all scan results
// Open, Closed, Unfiltered, Filtered, Open|Filtered
enum scan_result determine_final_conclusion(uint32_t port_value)
{
	bool has_open = false;
	bool has_closed = false;
	bool has_unfiltered = false;
	bool has_filtered = false;
	
	for (enum scan_type scan = SYN; scan <= UDP; scan++)
	{
		if (!nmap.scans[scan])
			continue;

		enum scan_result result = (enum scan_result)((port_value >> (scan * 3)) & 0x7);
		
		if (result == SR_OPEN)
			has_open = true;
		else if (result == SR_CLOSED)
			has_closed = true;
		else if (result == SR_UNFILTERED)
			has_unfiltered = true;
		else if (result == SR_FILTERED)
			has_filtered = true;
	}
	
	if (has_open)
		return SR_OPEN;
	if (has_closed)
		return SR_CLOSED;
	if (has_unfiltered)
		return SR_UNFILTERED;
	if (has_filtered)
		return SR_FILTERED;
	
	return SR_OPEN_FILTERED;
}

void print_scan_config(void)
{
	struct in_addr addr;
	char ip_str[INET_ADDRSTRLEN];
	
	printf("\nScan Configurations:\n");
	
	printf("  Targets to scan:\n");
	for (struct target *target = targets; target; target = target->next)
	{	
		addr.s_addr = target->addr;
		if (inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN)) {
			if (strlen(target->name) && strcmp(target->name, ip_str) != 0)
				printf("      %s (%s)\n", target->name, ip_str);
			else
				printf("      %s\n", ip_str);
		}
	}
	
	printf("  No of Ports to scan: %u\n", nmap.port_end - nmap.port_start + 1);
	
	printf("  Scans to be performed: ");
	bool first = true;
	for (enum scan_type s = SYN; s <= UDP; s++)
	{
		if (nmap.scans[s])
		{
			if (!first)
				printf(" ");
			printf("%s", scan_type_to_str(s));
			first = false;
		}
	}
	printf("\n");
	
	printf("  No of threads: %u\n", nmap.threads);
}

void print_scan_duration(double duration_secs)
{
	printf("Scan took %.5f secs\n", duration_secs);
}

void print_table_header(void)
{
	printf("%-8s %-30s %-60s %-15s\n", "Port", "Service Name (if applicable)", "Results", "Conclusion");
	printf("%-8s %-30s %-60s %-15s\n", "----", "----------------------------", "-------", "----------");
}

// Print a single port result row
void print_port_result(uint16_t port, uint32_t port_value)
{
	const char *service = get_service_name(port);
	char results_buf[256] = {0};
	char tmp_buf[64];
	bool first = true;

	// Build results string
	for (enum scan_type scan = SYN; scan <= UDP; scan++)
	{
		if (!nmap.scans[scan])
			continue;

		enum scan_result result = (enum scan_result)((port_value >> (scan * 3)) & 0x7);
		
		if (!first)
			strcat(results_buf, ", ");
		
		format_scan_result(tmp_buf, sizeof(tmp_buf), scan, result);
		strcat(results_buf, tmp_buf);
		first = false;
	}
	
	enum scan_result final = determine_final_conclusion(port_value);
	const char *conclusion = scan_result_to_str(final);
	
	printf("%-8u %-30s %-60s %-15s\n", port, service, results_buf, conclusion);
}

// Print target IP and associated target hostnames (duplicates)
void print_target_ip_and_hostnames(in_addr_t result_addr, const char *ip_str)
{
	printf("\nIP address: %s", ip_str);

	bool found_target = false;
	struct target *target = targets;
	while (target) {
		if (target->addr == result_addr 
			&& strlen(target->name) 
			&& strcmp(target->name, ip_str) != 0)
		{
			if (!found_target) {
				printf(" (");
				found_target = true;
			} else {
				printf(", ");
			}
			printf("%s", target->name);
		}
		target = target->next;
	}
	if (found_target)
		printf(")");
	printf("\n");
}

// Function to print the port results
// For both open and closed/filtered/unfiltered ports categories
// print_open: true for open ports, false for the rest
static void print_ports(size_t i, size_t nb_ports, bool print_open)
{
	for (size_t p = 0; p < nb_ports; p++)
	{
		uint32_t port_value = results[i].results[p];
		enum scan_result final = determine_final_conclusion(port_value);
		
		if ((print_open && final == SR_OPEN) || (!print_open && final != SR_OPEN))
			print_port_result(nmap.port_start + p, port_value);
	}
}

// Main function
// prints all the post-scan output (scan duration, results for each target)
void print_results(double scan_duration)
{	
	print_scan_duration(scan_duration);
	
	// nb_results is the number of targets to scan (since targets also includes duplicates)
	// prints results for each target
	for (size_t i = 0; i < nb_results; i++)
	{
		struct in_addr addr;
		char ip_str[INET_ADDRSTRLEN];
		size_t nb_ports = nmap.port_end - nmap.port_start + 1;
		
		addr.s_addr = results[i].target;
		if (!inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN))
			continue;

		print_target_ip_and_hostnames(results[i].target, ip_str);
		
		printf("\nOpen ports:\n");
		print_table_header();
		print_ports(i, nb_ports, true);
		
		printf("\nClosed/Filtered/Unfiltered ports:\n");
		print_table_header();
		print_ports(i, nb_ports, false);

		if (i < nb_results - 1)
			printf("\n");
		free(results[i].results);
	}
	free(results);
}

