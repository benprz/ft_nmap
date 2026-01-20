# ft_nmap

## Description

ft_nmap is a project undertaken at 42 School that involves re-implementing the nmap utility.

## Features

This implementation of nmap is capable of scanning multiple ports on multiple targets simultaneously using
the SYN, NULL, ACK, FIN, XMAS and UDP scan techniques of the original nmap
and uses multi-threading to speed up the scanning process.

## How to Use

You will need `make`, `gcc` and `libpcap`.

1. Clone the repository:

   ```bash
   git clone https://github.com/benprz/ft_nmap.git
   ```

2. Navigate to the project directory:

   ```bash
   cd ft_nmap
   ```

3. Compile the program:

   ```bash
   make
   ```

4. Run the ft_traceroute command as root:

   ```bash
   ./ft_nmap [options] target
   ```

   Example:

   ```bash
   sudo ./ft_nmap -m 100 -s SYN -s XMAS -T 67 fsf.org
   ```

## Usage

- `-f, --file=FILE`            file containing a list of targets to scan
- `-m, --threads=THREADS`      maximum number of threads to use for the scan (default: 0) (max: 250)
- `-p, --ports=PORT/RANGE`     target ports(s) to scan (single port or range with format (n-m) (max number of ports: 1024)
- `-s, --scan=TYPE`            type of scan to use, must be one of SYN, NULL, ACK, FIN, XMAS, UDP (all used if not specified)
- `-S, --spoof=ADDRESS`        Source IP address to use
- `-t, --target=TARGET`        target (IP or hostname) to scan
- `-T, --timeout=TIMEOUT`      timeout in milliseconds for each probe (default: 100)
- `-?, --help`                 Give this help list
- `--usage`                    Give a short usage message
