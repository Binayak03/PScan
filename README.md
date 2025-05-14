# PScan - Cross-Platform Port Scanner

PScan is a powerful, cross-platform command-line port scanner written in Python. It provides colorful terminal output and supports various scanning options similar to nmap.

## Features

- Fast and efficient port scanning
- Colorful terminal output using Rich library
- Support for single IP, IP ranges, and CIDR notation
- Service detection for common ports
- Configurable thread count for faster scanning
- Fast scan mode for common ports
- Detailed scan results with service identification

## Prerequisites

- Python 3.11 or higher
- Required Python packages:
  - rich
  - ipaddress

## Installation

### Windows Installation

1. Clone the repository:
```bash
git clone https://github.com/Binayak03/PScan.git
cd PScan
```

2. Install required dependencies:
```bash
pip install rich ipaddress
```

### Linux Installation

1. Clone the repository:
```bash
git clone https://github.com/Binayak03/PScan.git
cd PScan
```

2. Install virtual environment (if not already installed):
```bash
sudo apt install python3-venv
```

3. Create and activate a virtual environment:
```bash
python3 -m venv pscan_env
source pscan_env/bin/activate
```

4. Install required dependencies:
```bash
pip install rich ipaddress
```

5. Make the script executable:
```bash
chmod +x pscan.py
```

## Usage

### Basic Commands

1. Scan default ports (1-1000):
```bash
# Windows
python pscan.py -t 192.168.1.1

# Linux (with virtual environment activated)
./pscan.py -t 192.168.1.1
```

2. Scan specific ports:
```bash
# Windows
python pscan.py -t 192.168.1.1 -p 22,80,443,8080

# Linux
./pscan.py -t 192.168.1.1 -p 22,80,443,8080
```

3. Scan port range:
```bash
# Windows
python pscan.py -t 192.168.1.1 -p 1-1000

# Linux
./pscan.py -t 192.168.1.1 -p 1-1000
```

4. Fast scan of common ports:
```bash
# Windows
python pscan.py -t 192.168.1.1 -f

# Linux
./pscan.py -t 192.168.1.1 -f
```

5. Scan multiple IPs with IP range:
```bash
# Windows
python pscan.py -t 192.168.1.1-192.168.1.10 -p 22,80,443

# Linux
./pscan.py -t 192.168.1.1-192.168.1.10 -p 22,80,443
```

6. Scan network with CIDR notation:
```bash
# Windows
python pscan.py -t 192.168.1.0/24 -p 22,80,443 -f

# Linux
./pscan.py -t 192.168.1.0/24 -p 22,80,443 -f
```

7. Verbose output with detailed information:
```bash
# Windows
python pscan.py -t 192.168.1.1 -p 22,80,443 -v

# Linux
./pscan.py -t 192.168.1.1 -p 22,80,443 -v
```

8. Adjust thread count for faster scanning:
```bash
# Windows
python pscan.py -t 192.168.1.1 -p 1-1000 -T 200

# Linux
./pscan.py -t 192.168.1.1 -p 1-1000 -T 200
```

### Command Line Options

- `-t, --target`: Target IP address to scan (required)
- `-p, --ports`: Port(s) to scan (default: 1-1000)
- `-T, --threads`: Number of threads to use (default: 100)
- `--timeout`: Timeout in seconds for each port scan (default: 1.0)
- `-f, --fast`: Perform a fast scan of the most common ports
- `-v, --verbose`: Show more detailed output during scanning
- `--examples`: Show usage examples

## Project Structure

- `pscan.py`: Main script containing the CLI interface and core functionality
- `scanner.py`: Contains the port scanning and service detection logic
- `port_service_map.py`: Maps common ports to their service names

## How It Works

1. **Port Scanning**: Uses TCP connect scanning to check if ports are open
2. **Service Detection**: Attempts to identify services running on open ports by:
   - Sending protocol-specific probes
   - Analyzing service banners
   - Using a predefined port-to-service mapping

3. **Multi-threading**: Uses Python's ThreadPoolExecutor for concurrent scanning
4. **Output Formatting**: Uses the Rich library for beautiful terminal output

## Common Ports Scanned in Fast Mode

The fast scan mode (`-f`) checks these common ports:
- 21 (FTP)
- 22 (SSH)
- 23 (Telnet)
- 25 (SMTP)
- 53 (DNS)
- 80 (HTTP)
- 110 (POP3)
- 111 (RPC)
- 135 (Windows RPC)
- 139 (NetBIOS)
- 143 (IMAP)
- 443 (HTTPS)
- 445 (SMB)
- 993 (IMAPS)
- 995 (POP3S)
- 1723 (PPTP)
- 3306 (MySQL)
- 3389 (RDP)
- 5900 (VNC)
- 8080 (HTTP Proxy)

## Security Note

This tool is intended for legitimate network administration and security testing purposes only. Always:
- Obtain proper authorization before scanning any network
- Respect network usage policies
- Use responsibly and ethically

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
