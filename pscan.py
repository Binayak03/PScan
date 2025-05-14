#!/usr/bin/env python3
"""
PScan - A cross-platform CLI-based network port scanner
Similar to nmap with colorful terminal output
"""

import argparse
import ipaddress
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Optional, Union

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from scanner import scan_port, scan_port_range
from port_service_map import PORT_SERVICE_MAP

console = Console()


def validate_ip(ip: str) -> bool:
    """Validate if the given string is a valid IP address."""
    # Check if it's a CIDR notation (e.g., 192.168.1.0/24)
    if '/' in ip:
        try:
            ipaddress.ip_network(ip, strict=False)
            return True
        except ValueError:
            return False
    
    # Check if it's a range (e.g., 192.168.1.1-192.168.1.10)
    if '-' in ip:
        start_ip, end_ip = ip.split('-')
        try:
            start = ipaddress.ip_address(start_ip.strip())
            end = ipaddress.ip_address(end_ip.strip())
            return int(start) <= int(end)
        except ValueError:
            return False
    
    # Check if it's a single IP
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port: str) -> bool:
    """Validate if the given string is a valid port or port range."""
    if '-' in port:
        start, end = port.split('-')
        if not start.isdigit() or not end.isdigit():
            return False
        start_port, end_port = int(start), int(end)
        return 0 < start_port <= 65535 and 0 < end_port <= 65535 and start_port <= end_port
    else:
        if not port.isdigit():
            return False
        port_num = int(port)
        return 0 < port_num <= 65535


def parse_ports(ports_str: str) -> List[int]:
    """Parse port string into a list of ports."""
    result = []
    port_specs = ports_str.split(',')
    
    for spec in port_specs:
        if '-' in spec:
            start, end = map(int, spec.split('-'))
            result.extend(range(start, end + 1))
        else:
            result.append(int(spec))
    
    return result


def parse_ip_targets(target: str) -> List[str]:
    """
    Parse IP target string into a list of IP addresses.
    Supports single IPs, IP ranges (e.g., 192.168.1.1-192.168.1.10) and CIDR notation.
    """
    result = []
    
    # Handle CIDR notation (e.g., 192.168.1.0/24)
    if '/' in target:
        network = ipaddress.ip_network(target, strict=False)
        result = [str(ip) for ip in network.hosts()]
    
    # Handle IP range (e.g., 192.168.1.1-192.168.1.10)
    elif '-' in target:
        start_ip, end_ip = target.split('-')
        start = ipaddress.ip_address(start_ip.strip())
        end = ipaddress.ip_address(end_ip.strip())
        
        current = int(start)
        while current <= int(end):
            result.append(str(ipaddress.ip_address(current)))
            current += 1
    
    # Handle single IP
    else:
        result.append(target)
    
    return result


def display_header() -> None:
    """Display the PScan header."""
    header = """
    [bold blue]██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗[/bold blue]
    [bold blue]██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║[/bold blue]
    [bold blue]██████╔╝███████╗██║     ███████║██╔██╗ ██║[/bold blue]
    [bold blue]██╔═══╝ ╚════██║██║     ██╔══██║██║╚██╗██║[/bold blue]
    [bold blue]██║     ███████║╚██████╗██║  ██║██║ ╚████║[/bold blue]
    [bold blue]╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝[/bold blue]
    [bold green]A cross-platform port scanner[/bold green]
    [bold yellow]Version 1.0[/bold yellow]
    """
    console.print(Panel(header, border_style="green"))


def display_results(target_ip: str, open_ports: List[Tuple[int, bool, Optional[str]]]) -> None:
    """Display scan results in a nicely formatted table."""
    try:
        hostname = socket.gethostbyaddr(target_ip)[0]
    except socket.herror:
        hostname = "Unknown"

    summary = f"Scan results for [bold cyan]{target_ip}[/bold cyan] ([italic]{hostname}[/italic])"
    console.print(Panel(summary, border_style="blue"))

    if not open_ports:
        console.print("[yellow]No open ports found.[/yellow]")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Port", style="dim", width=8)
    table.add_column("Status", width=10)
    table.add_column("Service", width=30)
    
    for port, is_open, service in open_ports:
        if is_open:
            service_name = service or PORT_SERVICE_MAP.get(port, "unknown")
            table.add_row(
                f"{port}", 
                "[green]Open[/green]", 
                f"[cyan]{service_name}[/cyan]"
            )
    
    console.print(table)


def show_examples() -> None:
    """Display usage examples."""
    examples = """
[bold cyan]PScan - Usage Examples:[/bold cyan]

[green]Basic scan of default ports (1-1000):[/green]
  python pscan.py -t 192.168.1.1

[green]Scan specific ports:[/green]
  python pscan.py -t 192.168.1.1 -p 22,80,443,8080

[green]Scan port range:[/green]
  python pscan.py -t 192.168.1.1 -p 1-1000

[green]Fast scan of common ports:[/green]
  python pscan.py -t 192.168.1.1 -f

[green]Scan multiple IPs with IP range:[/green]
  python pscan.py -t 192.168.1.1-192.168.1.10 -p 22,80,443

[green]Scan network with CIDR notation:[/green]
  python pscan.py -t 192.168.1.0/24 -p 22,80,443 -f

[green]Verbose output with detailed information:[/green]
  python pscan.py -t 192.168.1.1 -p 22,80,443 -v

[green]Adjust thread count for faster scanning:[/green]
  python pscan.py -t 192.168.1.1 -p 1-1000 -T 200
"""
    console.print(Panel(examples, title="PScan Help", border_style="blue"))


def main() -> None:
    """Main function to run the port scanner."""
    parser = argparse.ArgumentParser(
        description="PScan - A cross-platform CLI-based network port scanner",
        epilog="Use --examples to see usage examples"
    )
    
    parser.add_argument("-t", "--target", help="Target IP address to scan")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port(s) to scan (e.g., 80,443,8000-8100)")
    parser.add_argument("-T", "--threads", type=int, default=100, help="Number of threads to use (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds for each port scan (default: 1.0)")
    parser.add_argument("-f", "--fast", action="store_true", help="Perform a fast scan of the most common ports")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show more detailed output during scanning")
    parser.add_argument("--examples", action="store_true", help="Show usage examples")
    
    args = parser.parse_args()
    
    # Show examples if requested
    if args.examples:
        display_header()
        show_examples()
        sys.exit(0)
    
    # Define common ports for fast scan
    COMMON_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
    
    # Check if target is specified
    if not args.target:
        console.print("[bold red]Error: Target IP is required. Use --examples to see usage examples.[/bold red]")
        sys.exit(1)
        
    # Validate the target IP
    if not validate_ip(args.target):
        console.print(f"[bold red]Error: Invalid IP address: {args.target}[/bold red]")
        sys.exit(1)
    
    # Use fast scan if requested
    if args.fast:
        ports_to_scan = COMMON_PORTS
        console.print("[bold yellow]Using fast scan mode - scanning common ports only[/bold yellow]")
    else:
        ports_to_scan = args.ports
    
    # Validate each port specification
    port_specs = ports_to_scan.split(',')
    for spec in port_specs:
        if not validate_port(spec):
            console.print(f"[bold red]Error: Invalid port specification: {spec}[/bold red]")
            sys.exit(1)
    
    display_header()
    
    # Parse the target into a list of IP addresses
    target_ips = parse_ip_targets(args.target)
    ports = parse_ports(ports_to_scan)
    
    # Show more detailed information in verbose mode
    if args.verbose:
        console.print(f"[bold]Target(s):[/bold]")
        for ip in target_ips:
            console.print(f"  [cyan]{ip}[/cyan]")
        
        console.print(f"\n[bold]Port(s):[/bold]")
        if len(ports) > 20:
            # Show only some ports if there are too many
            ports_display = ports[:10] + ["..."] + ports[-10:]
            console.print(f"  [cyan]{', '.join(map(str, ports_display))}[/cyan]")
        else:
            console.print(f"  [cyan]{', '.join(map(str, ports))}[/cyan]")
        
        console.print(f"\n[bold]Scan configuration:[/bold]")
        console.print(f"  [green]Threads:[/green] {args.threads}")
        console.print(f"  [green]Timeout:[/green] {args.timeout} seconds")
        console.print("")
    
    console.print(f"[bold]Scanning [cyan]{len(target_ips)}[/cyan] host(s) for [cyan]{len(ports)}[/cyan] ports...[/bold]")
    
    all_open_ports = {}  # Dictionary to store results for each IP
    closed_count = 0     # Count of closed ports (for verbose mode)
    filtered_count = 0   # Count of filtered ports (for verbose mode)
    
    start_time = time.time()
    total_scans = len(target_ips) * len(ports)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
        console=console
    ) as progress:
        scan_task = progress.add_task("[green]Scanning ports...", total=total_scans)
        
        for target_ip in target_ips:
            if len(target_ips) > 1:
                progress.update(scan_task, description=f"[green]Scanning {target_ip}...")
                
            open_ports = []
            
            with ThreadPoolExecutor(max_workers=min(args.threads, len(ports))) as executor:
                futures = []
                
                for port in ports:
                    futures.append(executor.submit(scan_port, target_ip, port, args.timeout))
                
                for future in futures:
                    result = future.result()
                    port, is_open, service = result
                    if is_open:  # If port is open
                        open_ports.append(result)
                        if args.verbose:
                            console.print(f"  [green]Found open port:[/green] {target_ip}:{port} ({service or PORT_SERVICE_MAP.get(port, 'unknown')})")
                    else:
                        # Count closed ports if verbose
                        if args.verbose and port % 50 == 0:  # Only log some closed ports to avoid spam
                            console.print(f"  [grey]Port {port} is closed on {target_ip}[/grey]")
                        closed_count += 1
                    progress.update(scan_task, advance=1)
            
            if open_ports:
                all_open_ports[target_ip] = open_ports
    
    end_time = time.time()
    scan_duration = end_time - start_time
    
    # Show summary in verbose mode
    if args.verbose:
        console.print("\n[bold]Scan Summary:[/bold]")
        console.print(f"  [green]Total hosts scanned:[/green] {len(target_ips)}")
        console.print(f"  [green]Total ports scanned:[/green] {len(ports)} ports per host")
        console.print(f"  [green]Open ports found:[/green] {sum(len(ports) for ports in all_open_ports.values())}")
        console.print(f"  [green]Closed ports:[/green] {closed_count}")
        console.print(f"  [green]Scan rate:[/green] {total_scans / scan_duration:.2f} ports/second")
    
    console.print(f"\n[bold green]Scan completed in {scan_duration:.2f} seconds[/bold green]")
    
    # Display results for each target
    for target_ip, open_ports in all_open_ports.items():
        display_results(target_ip, open_ports)
        
    # If no open ports were found on any target
    if not all_open_ports:
        console.print("[yellow]No open ports found on any target.[/yellow]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user. Exiting...[/bold red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold red]An error occurred: {str(e)}[/bold red]")
        sys.exit(1)
