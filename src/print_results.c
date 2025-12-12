#include "ft_nmap.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

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

const char *scan_result_to_str_capitalized(enum scan_result r)
{
	switch (r)
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
	const char *result_str = scan_result_to_str_capitalized(result);
	
	snprintf(buf, buf_size, "%s (%s)", scan_str, result_str);
}

// Determine final conclusion for a port based on all scan results
// Open, Unfiltered, Filtered, Closed
enum scan_result determine_final_conclusion(uint32_t port_value, enum scan_type enabled_scans[])
{
	bool has_open = false;
	bool has_unfiltered = false;
	bool has_filtered = false;
	
	for (int i = 0; enabled_scans[i] != -1 && i < 6; i++)
	{
		enum scan_type scan = enabled_scans[i];
		enum scan_result result = (enum scan_result)((port_value >> (scan * 3)) & 0x7);
		
		if (result == SR_OPEN)
			has_open = true;
		else if (result == SR_UNFILTERED)
			has_unfiltered = true;
		else if (result == SR_FILTERED || result == SR_OPEN_FILTERED)
			has_filtered = true;
	}
	
	if (has_open)
		return SR_OPEN;
	if (has_unfiltered)
		return SR_UNFILTERED;
	if (has_filtered)
		return SR_FILTERED;
	
	return SR_CLOSED;
}

void print_scan_config(void)
{
	struct in_addr addr;
	char ip_str[INET_ADDRSTRLEN];
	
	printf("\nScan Configurations:\n");
	
	for (size_t i = 0; i < nb_results; i++)
	{	
		addr.s_addr = results[i].target;
		if (inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN))
			printf("  Target Ip-Address: %s\n", ip_str);
	}
	
	printf("  No of Ports to scan: %u\n", nmap.port_end - nmap.port_start + 1);
	
	printf("  Scans to be performed: ");
	if (nmap.scan == ALL)
		printf("SYN NULL FIN XMAS ACK UDP\n");
	else
		printf("%s\n", scan_type_to_str(nmap.scan));
	
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
void print_port_result(uint16_t port, uint32_t port_value, enum scan_type enabled_scans[])
{
	const char *service = get_service_name(port);
	char results_buf[256] = {0};
	char temp_buf[64];
	bool first = true;

	// Build results string
	for (int i = 0; enabled_scans[i] != -1 && i < 6; i++)
	{
		enum scan_type scan = enabled_scans[i];
		enum scan_result result = (enum scan_result)((port_value >> (scan * 3)) & 0x7);
		
		if (!first)
			strcat(results_buf, ", ");
		
		format_scan_result(temp_buf, sizeof(temp_buf), scan, result);
		strcat(results_buf, temp_buf);
		first = false;
	}
	
	enum scan_result final = determine_final_conclusion(port_value, enabled_scans);
	const char *conclusion = scan_result_to_str_capitalized(final);
	
	printf("%-8u %-30s %-60s %-15s\n", port, service, results_buf, conclusion);
}

// Main function to print all results
void print_results(double scan_duration)
{
	size_t i;
	enum scan_type enabled_scans[7] = {-1, -1, -1, -1, -1, -1, -1};
	
	// Build list of enabled scan types
	// its either all or only one scan type
	if (nmap.scan == ALL)
	{
		enabled_scans[0] = SYN;
		enabled_scans[1] = NUL;
		enabled_scans[2] = ACK;
		enabled_scans[3] = FIN;
		enabled_scans[4] = XMAS;
		enabled_scans[5] = UDP;
	}
	else
	{
		enabled_scans[0] = nmap.scan;
	}
	
	// Print configuration
	print_scan_config();
	printf("Scanning..\n");
	print_scan_duration(scan_duration);
	
	// Process each target
	for (i = 0; i < nb_results; i++)
	{
		struct in_addr addr;
		char ip_str[INET_ADDRSTRLEN];
		size_t nb_ports = nmap.port_end - nmap.port_start + 1;
		size_t p;
		
		addr.s_addr = results[i].target;
		if (!inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN))
			continue;
		
		printf("\nIP address: %s\n", ip_str);
		
		// Separate open ports from closed/filtered/unfiltered
		printf("\nOpen ports:\n");
		print_table_header();
		
		for (p = 0; p < nb_ports; p++)
		{
			uint16_t port = (uint16_t)(nmap.port_start + p);
			uint32_t port_value = results[i].results[p];
			enum scan_result final = determine_final_conclusion(port_value, enabled_scans);
			
			if (final == SR_OPEN)
				print_port_result(port, port_value, enabled_scans);
		}
		
		printf("\nClosed/Filtered/Unfiltered ports:\n");
		print_table_header();
		
		for (p = 0; p < nb_ports; p++)
		{
			uint16_t port = (uint16_t)(nmap.port_start + p);
			uint32_t port_value = results[i].results[p];
			enum scan_result final = determine_final_conclusion(port_value, enabled_scans);
			
			if (final != SR_OPEN)
				print_port_result(port, port_value, enabled_scans);
		}
	}
}

