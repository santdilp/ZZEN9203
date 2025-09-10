import subprocess
import re
import requests
import sys
import socket
#import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
#import time
#import json
import ipaddress
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

def get_mac_address_vendor(mac_address):
    """
    Looks up the vendor of a MAC address using maclookup.app API.
    """
    if not mac_address or mac_address == "MAC not found":
        return "Unknown"

    try:
        response = requests.get(f"https://api.maclookup.app/v2/macs/{mac_address}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get('company', 'Unknown')
        elif response.status_code == 404:
            return "Vendor not found"
        elif response.status_code == 429:
            return "Rate limited"
        else:
            return f"API Error ({response.status_code})"
    except requests.exceptions.Timeout:
        return "API Timeout"
    except (requests.exceptions.RequestException, ValueError) as e:
        return "Error fetching vendor"

def get_mac_address_from_ip(ip_address):
    """
    Retrieves the MAC address for a given IP address using the 'arp -a' command.
    """
    try:
        result = subprocess.run(['arp', '-a', ip_address], capture_output=True, text=True, check=True)
        # Regex to find the MAC address in the format xx-xx-xx-xx-xx-xx
        mac_match = re.search(r'\b([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})\b', result.stdout)
        if mac_match:
            # The API accepts either format, so we'll just return it as is
            return mac_match.group(1).replace('-', ':')
    except Exception as e:
        # print(f"Error fetching MAC address for {ip_address}: {e}", file=sys.stderr)
        pass
    return "MAC not found"

def get_arp_table(subnet_filter=None):
    """Get devices from ARP table, optionally filtered by subnet."""
    devices = {}
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, check=True)
        for line in result.stdout.split('\n'):
            match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})', line)
            if match:
                ip, mac = match.groups()
                # Filter by subnet if specified
                if subnet_filter is None or ip.startswith(subnet_filter):
                    devices[ip] = {'mac': mac.replace('-', ':')}
    except Exception:
        pass
    return devices

def grab_banner(ip, port):
    """Grab banner from a specific port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, port))
        
        if port == 80:
            sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 22:
            pass  # SSH sends banner automatically
        elif port == 23:
            pass  # Telnet sends banner automatically
        else:
            sock.send(b"\r\n")
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner[:200]  # Limit banner length
    except Exception:
        return ""

def check_common_ports(ip):
    """Check if device has common IoT ports open and grab banners."""
    ports = [80, 443, 8080, 22, 23, 1883, 8883]  # Common IoT ports
    port_info = {}
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(ip, port)
                port_info[port] = banner
            sock.close()
        except Exception:
            pass
    return port_info

def nmap_scan_hosts(ip_range):
    """Use nmap to discover active hosts with multiple discovery methods."""
    if not NMAP_AVAILABLE:
        print("[1/3] Python nmap library not available, will use ping sweep...")
        return []
    
    try:
        print(f"[1/3] Running nmap host discovery on {ip_range}...")
        nm = nmap.PortScanner()
        # Use multiple discovery methods: ping, ARP, SYN to common ports
        nm.scan(hosts=ip_range, arguments='-sn -PS22,80,443,8080 -PA80,443,8080 -PE -PP')
        hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up']
        print(f"[1/3] Nmap discovered {len(hosts)} active hosts")
        return hosts
    except Exception as e:
        if 'nmap program was not found' in str(e):
            print("[1/3] Nmap not installed. Install from: https://nmap.org/download.html")
            print("[1/3] For better results, install nmap and restart. Using ping sweep...")
        else:
            print(f"[1/3] Nmap scan failed: {e}")
        return []

def nmap_scan_detailed(ip):
    """Use nmap for detailed host scanning with OS detection."""
    if not NMAP_AVAILABLE:
        return None
    
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-sS -O -sV -A --top-ports 2000 --osscan-guess --fuzzy')
        
        if ip in nm.all_hosts():
            host_info = nm[ip]
            
            # Get open ports and detailed services
            ports = []
            services = {}
            scripts = {}
            
            for proto in host_info.all_protocols():
                ports_list = host_info[proto].keys()
                for port in ports_list:
                    port_info = host_info[proto][port]
                    if port_info['state'] == 'open':
                        ports.append(port)
                        
                        # Enhanced service detection
                        service = port_info.get('name', '')
                        version = port_info.get('version', '')
                        product = port_info.get('product', '')
                        extrainfo = port_info.get('extrainfo', '')
                        
                        service_str = ' '.join(filter(None, [service, product, version, extrainfo]))
                        services[port] = service_str.strip() or 'unknown'
                        
                        # Extract script scan results
                        if 'script' in port_info:
                            scripts[port] = port_info['script']
            
            # Enhanced OS detection
            os_info = ""
            os_accuracy = 0
            if 'osmatch' in host_info and host_info['osmatch']:
                best_match = host_info['osmatch'][0]
                os_info = best_match['name']
                os_accuracy = int(best_match.get('accuracy', 0))
            
            # Get additional host information
            result = {
                'ports': ports,
                'services': services,
                'os': os_info,
                'os_accuracy': os_accuracy,
                'scripts': scripts,
                'state': host_info.state(),
                'hostname': host_info.hostname(),
                'uptime': host_info.get('uptime', {}).get('seconds', '') if 'uptime' in host_info else '',
                'distance': host_info.get('distance', {}).get('value', '') if 'distance' in host_info else ''
            }
            
            # Add OS fingerprint if available
            if 'fingerprint' in host_info:
                result['fingerprint'] = host_info['fingerprint']
            
            return result
    except Exception:
        pass
    
    return None

def scan_single_ip(ip):
    """Scan a single IP with nmap or fallback to ping."""
    device_info = None
    
    # Try nmap detailed scan first
    if NMAP_AVAILABLE:
        nmap_info = nmap_scan_detailed(ip)
        if nmap_info:
            mac = get_mac_address_from_ip(ip)
            device_info = {
                'mac': mac,
                'ports': nmap_info['ports'],
                'services': nmap_info['services'],
                'os': nmap_info['os'],
                'os_accuracy': nmap_info.get('os_accuracy', 0),
                'scripts': nmap_info.get('scripts', {}),
                'hostname': nmap_info.get('hostname', ''),
                'uptime': nmap_info.get('uptime', ''),
                'fingerprint': nmap_info.get('fingerprint', '')
            }
    
    # Fallback to ping + basic port scan
    if not device_info:
        try:
            subprocess.run(['ping', '-n', '1', '-w', '2000', ip], capture_output=True, check=True, text=True)
            mac = get_mac_address_from_ip(ip)
            port_info = check_common_ports(ip)
            device_info = {
                'mac': mac,
                'ports': list(port_info.keys()),
                'banners': port_info,
                'services': {},
                'os': ''
            }
        except subprocess.CalledProcessError:
            pass
    
    return ip, device_info

def is_likely_iot(vendor, ports=None, banners=None, services=None, os_info=None):
    """Enhanced IoT detection using vendor, port, banner, service, and OS analysis."""
    iot_vendors = [
        "Amazon", "Apple", "Arlo", "Bosch", "Ecobee", "Eero", "Google", "Huawei", 
        "LIFX", "Ring", "Samsung", "Sensibo", "Sonos", "TP-Link", "Wyze", "Xiaomi",
        "TP-LINK", "D-Link", "Netgear", "Logitech", "Philips", "Hue", "Nest",
        "Belkin", "Linksys", "ASUS", "Ubiquiti", "Hikvision", "Dahua", "Axis",
        "Honeywell", "Schlage", "Yale", "August", "Chamberlain", "Roku", "Chromecast",
        "Tesla", "Fitbit", "Garmin", "Withings", "Netatmo", "Tado", "Rachio",
        "iRobot", "Shark", "Dyson", "LG", "Whirlpool", "GE", "Frigidaire"
    ]
    
    # Check vendor name
    for iot_vendor in iot_vendors:
        if iot_vendor.lower() in vendor.lower():
            return True
    
    # Check OS fingerprint
    if os_info:
        iot_os_keywords = ['embedded', 'linux', 'busybox', 'router', 'camera', 'iot']
        if any(keyword in os_info.lower() for keyword in iot_os_keywords):
            return True
    
    # Check for IoT-specific ports
    if ports:
        iot_ports = [8080, 1883, 8883, 554, 8554]  # Common IoT ports
        if any(port in ports for port in iot_ports):
            return True
    
    # Check services
    if services:
        iot_services = ['rtsp', 'mqtt', 'upnp', 'http-alt']
        for service in services.values():
            if any(iot_service in service.lower() for iot_service in iot_services):
                return True
    
    # Check banners for IoT indicators
    if banners:
        iot_keywords = ['camera', 'router', 'access point', 'smart', 'iot', 'embedded', 
                       'lighttpd', 'busybox', 'dropbear', 'telnet', 'admin', 'login']
        for banner in banners.values():
            if banner and any(keyword in banner.lower() for keyword in iot_keywords):
                return True
    
    return False

def scan_network_comprehensive(ip_range):
    """Comprehensive network scan without relying on ARP table."""
    print(f"[1/3] Discovering active hosts on {ip_range}...")
    
    # First, discover all active hosts using nmap
    active_hosts = nmap_scan_hosts(ip_range)
    
    if not active_hosts:
        print("[1/3] No active hosts found with nmap, falling back to ping sweep...")
        # Fallback: manual ping sweep for the range
        active_hosts = ping_sweep(ip_range)
    
    print(f"[2/3] Found {len(active_hosts)} active hosts, performing detailed scans...")
    
    # Scan each active host in parallel
    devices = {}
    completed = 0
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_ip = {executor.submit(scan_single_ip, ip): ip for ip in active_hosts}
        
        for future in as_completed(future_to_ip):
            ip, device_info = future.result()
            completed += 1
            
            if device_info:
                devices[ip] = device_info
                print(f"[2/3] Scanned {ip} - Device found ({completed}/{len(active_hosts)})")
            else:
                print(f"[2/3] Scanned {ip} - No response ({completed}/{len(active_hosts)})")
    
    print(f"[3/3] Scan complete! Found {len(devices)} devices with detailed information")
    return devices

def ping_sweep(ip_range):
    """Fallback ping sweep when nmap is not available."""
    active_hosts = []
    try:
        # Parse the IP range to get list of IPs
        ips = parse_ip_range(ip_range)
        if not ips:
            print(f"[1/3] Could not parse IP range: {ip_range}")
            return []
        
        print(f"[1/3] Ping sweeping {len(ips)} addresses...")
        
        # Ping sweep with threading
        completed = 0
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {executor.submit(ping_host, ip): ip for ip in ips}
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                completed += 1
                
                if future.result():
                    active_hosts.append(ip)
                    print(f"[1/3] Found active host: {ip} ({completed}/{len(ips)})")
                elif completed % 50 == 0:  # Progress update every 50 pings
                    print(f"[1/3] Ping progress: {completed}/{len(ips)} ({len(active_hosts)} active)")
    except Exception as e:
        print(f"[1/3] Ping sweep error: {e}")
    
    return active_hosts

def ping_host(ip):
    """Ping a single host to check if it's alive."""
    try:
        result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                              capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False

def parse_ip_range(ip_input):
    """Parse different IP input formats and return list of IPs to scan."""
    # CIDR notation (e.g., 192.168.4.0/22)
    if '/' in ip_input:
        try:
            network = ipaddress.IPv4Network(ip_input, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return []
    
    # Range notation (e.g., 192.168.4.0-252)
    elif '-' in ip_input:
        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})', ip_input)
        if match:
            base_ip = match.group(1)
            start = int(match.group(2))
            end = int(match.group(3))
            return [f"{base_ip}.{i}" for i in range(start, end + 1)]
        return []
    
    # Single IP
    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_input):
        return [ip_input]
    
    return []

def main():
    """
    Main function to run the network scan and print device information.
    """
    if len(sys.argv) != 2:
        print("Usage: python getdevices.py <IP_ADDRESS_RANGE>")
        print("Example: python getdevices.py 192.168.4.0/22 (CIDR notation)")
        print("Example: python getdevices.py 192.168.4.0-252 (range notation)")
        print("Example: python getdevices.py 192.168.4.5 (single host)")
        sys.exit(1)
    
    ip_input = sys.argv[1]
    
    # Parse IP range
    ip_list = parse_ip_range(ip_input)
    if not ip_list:
        print("Invalid IP address or range format.")
        sys.exit(1)
    
    # Use comprehensive network scanning instead of ARP table
    devices = scan_network_comprehensive(ip_input)

    if not devices:
        print("No active devices found in the specified range.")
        return

    print("\nNetwork Scan Results:")
    print("-" * 140)
    print(f"{'IP Address':<15} | {'MAC Address':<20} | {'Vendor':<20} | {'Ports':<15} | {'OS Info':<25} | {'Category':<15} | {'Services'}")
    print("-" * 140)
    
    for ip, info in devices.items():
        mac = info['mac']
        ports = info.get('ports', [])
        services = info.get('services', {})
        os_info = info.get('os', '')
        banners = info.get('banners', {})
        
        vendor_info = get_mac_address_vendor(mac)
        category = "Likely IoT Device" if is_likely_iot(vendor_info, ports, banners, services, os_info) else "Standard Device"
        ports_str = ','.join(map(str, ports[:5])) if ports else 'None'  # Show first 5 ports
        if len(ports) > 5:
            ports_str += '...'
        
        # Get most interesting service info
        service_info = ""
        if services:
            service_list = [f"{port}:{service}" for port, service in list(services.items())[:2]]
            service_info = ', '.join(service_list)
        elif banners:
            for port, banner in banners.items():
                if banner and len(banner) > 10:
                    service_info = banner[:25] + "..." if len(banner) > 25 else banner
                    break
        
        os_display = os_info[:25] + "..." if len(os_info) > 25 else os_info
        
        print(f"{ip:<15} | {mac:<20} | {vendor_info:<20} | {ports_str:<15} | {os_display:<25} | {category:<15} | {service_info}")

if __name__ == "__main__":
    main()