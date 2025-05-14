"""
PScan - Network Scanner Module
Contains functions for scanning ports and determining services
"""

import socket
import time
from typing import Tuple, Optional


def scan_port(ip: str, port: int, timeout: float = 1.0) -> Tuple[int, bool, Optional[str]]:
    """
    Scan a specific port on the target IP
    
    Args:
        ip: The target IP address
        port: The port to scan
        timeout: Timeout in seconds
        
    Returns:
        Tuple containing (port, is_open, service_name)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        # TCP connect scan
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            # Port is open, try to identify the service
            service = identify_service(sock, port)
            return port, True, service
        
        return port, False, None
    
    except (socket.timeout, socket.error):
        return port, False, None
    
    finally:
        sock.close()


def scan_port_range(ip: str, start_port: int, end_port: int, timeout: float = 1.0) -> list:
    """
    Scan a range of ports on the target IP
    
    Args:
        ip: The target IP address
        start_port: The starting port
        end_port: The ending port (inclusive)
        timeout: Timeout in seconds
        
    Returns:
        List of tuples (port, is_open, service_name) for open ports
    """
    open_ports = []
    
    for port in range(start_port, end_port + 1):
        port_result = scan_port(ip, port, timeout)
        if port_result[1]:  # If port is open
            open_ports.append(port_result)
    
    return open_ports


def identify_service(sock: socket.socket, port: int) -> Optional[str]:
    """
    Try to identify the service running on an open port
    
    Args:
        sock: An already connected socket
        port: The port number
        
    Returns:
        Service name if identified, None otherwise
    """
    # For common protocols, attempt to get a banner
    common_protocols = {
        21: b"USER anonymous\r\n",    # FTP
        22: b"SSH-2.0-PScan_Client\r\n",  # SSH
        25: b"HELO pscan.local\r\n",  # SMTP
        80: b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",  # HTTP
        110: b"USER anonymous\r\n",   # POP3
        143: b"a1 LOGIN anonymous anonymous\r\n",  # IMAP
        443: b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",  # HTTPS
    }
    
    sock.settimeout(1.0)  # Quick timeout for banner grabbing
    
    try:
        # If it's a common protocol, try to get a banner
        if port in common_protocols:
            sock.send(common_protocols[port])
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Parse the banner to identify the service
            if banner:
                if "SSH" in banner:
                    return f"SSH: {banner}"
                elif "FTP" in banner:
                    return f"FTP: {banner}"
                elif "SMTP" in banner:
                    return f"SMTP: {banner}"
                elif "HTTP" in banner:
                    return f"HTTP: {banner.splitlines()[0] if banner.splitlines() else banner}"
                elif "POP3" in banner:
                    return f"POP3: {banner}"
                elif "IMAP" in banner:
                    return f"IMAP: {banner}"
                else:
                    return banner[:40] + "..." if len(banner) > 40 else banner
    
    except (socket.timeout, socket.error):
        pass
    
    return None
