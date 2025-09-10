import subprocess
import re
import requests
import sys
import socket
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import time

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from manuf import manuf
    MANUF_AVAILABLE = True
    mac_parser = manuf.MacParser()
except ImportError:
    MANUF_AVAILABLE = False
    mac_parser = None

# Cache for MAC vendor lookups
mac_vendor_cache = {}

def get_mac_address_vendor(mac_address):
    """Lookup MAC address vendor using manuf library (offline) with API fallback."""
    if not mac_address or mac_address == "MAC not found":
        return "Unknown"
    
    # Check cache first
    if mac_address in mac_vendor_cache:
        return mac_vendor_cache[mac_address]
    
    # Try manuf library first (offline, no rate limits)
    if MANUF_AVAILABLE and mac_parser:
        try:
            vendor = mac_parser.get_manuf(mac_address)
            if vendor:
                mac_vendor_cache[mac_address] = vendor
                debug_print(f"[DEBUG] MAC {mac_address} -> {vendor} (manuf library)")
                return vendor
        except Exception as e:
            debug_print(f"[DEBUG] Manuf library failed for {mac_address}: {e}")
    
    # Fallback to API with rate limiting
    debug_print(f"[DEBUG] Using API fallback for MAC {mac_address}")
    time.sleep(0.5)  # Rate limiting
    
    try:
        response = requests.get(f"https://api.maclookup.app/v2/macs/{mac_address}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            vendor = data.get('company', 'Unknown')
            mac_vendor_cache[mac_address] = vendor
            return vendor
        elif response.status_code == 404:
            mac_vendor_cache[mac_address] = "Vendor not found"
            return "Vendor not found"
        elif response.status_code == 429:
            debug_print(f"[DEBUG] Rate limited for MAC {mac_address}")
            return "Rate limited"
        else:
            return f"API Error ({response.status_code})"
    except requests.exceptions.Timeout:
        return "API Timeout"
    except (requests.exceptions.RequestException, ValueError):
        return "Error fetching vendor"

def get_mac_address_from_ip(ip_address):
    """Get MAC address from ARP table."""
    try:
        result = subprocess.run(['arp', '-a', ip_address], capture_output=True, text=True, check=True)
        mac_match = re.search(r'\b([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})\b', result.stdout)
        if mac_match:
            return mac_match.group(1).replace('-', ':')
    except Exception:
        pass
    return "MAC not found"

def ping_host(ip):
    """Ping a single host to check if alive."""
    try:
        result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                              capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False

def ping_sweep(ip_range):
    """Discover active hosts using ping sweep."""
    print(f"[1/4] Starting ping sweep on {ip_range}...")
    
    # Parse IP range
    ips = parse_ip_range(ip_range)
    if not ips:
        print(f"Could not parse IP range: {ip_range}")
        return []
    
    print(f"[1/4] Pinging {len(ips)} addresses...")
    
    active_hosts = []
    completed = 0
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {executor.submit(ping_host, ip): ip for ip in ips}
        
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            completed += 1
            
            if future.result():
                active_hosts.append(ip)
                print(f"[1/4] Active: {ip} ({len(active_hosts)} found, {completed}/{len(ips)})")
            elif completed % 50 == 0:
                print(f"[1/4] Progress: {completed}/{len(ips)} ({len(active_hosts)} active)")
    
    print(f"[1/4] Ping sweep complete: {len(active_hosts)} active hosts found")
    return active_hosts

def nmap_scan_detailed(ip):
    """Detailed nmap scan for single host with debugging."""
    if not NMAP_AVAILABLE:
        debug_print(f"[DEBUG] Nmap not available for {ip}")
        return None
    
    try:
        debug_print(f"[DEBUG] Starting nmap scan for {ip}...")
        nm = nmap.PortScanner()
        
        # Show the exact nmap command being run
        nmap_args = '-sS -O -sV -A --top-ports 1000 --osscan-guess'
        debug_print(f"[DEBUG] Nmap command: nmap {nmap_args} {ip}")
        
        nm.scan(ip, arguments=nmap_args)
        debug_print(f"[DEBUG] Nmap scan completed for {ip}")
        
        if ip in nm.all_hosts():
            host_info = nm[ip]
            debug_print(f"[DEBUG] Host {ip} state: {host_info.state()}")
            
            ports = []
            services = {}
            
            debug_print(f"[DEBUG] Protocols found: {host_info.all_protocols()}")
            
            for proto in host_info.all_protocols():
                proto_ports = list(host_info[proto].keys())
                debug_print(f"[DEBUG] {proto.upper()} ports scanned: {len(proto_ports)}")
                
                for port in proto_ports:
                    port_info = host_info[proto][port]
                    state = port_info['state']
                    debug_print(f"[DEBUG] Port {port}/{proto}: {state}")
                    
                    if state == 'open':
                        ports.append(port)
                        
                        service = port_info.get('name', '')
                        version = port_info.get('version', '')
                        product = port_info.get('product', '')
                        extrainfo = port_info.get('extrainfo', '')
                        
                        service_str = ' '.join(filter(None, [service, product, version, extrainfo]))
                        services[port] = service_str.strip() or 'unknown'
                        
                        debug_print(f"[DEBUG] Port {port} service: {services[port]}")
            
            # OS detection results
            os_info = ""
            if 'osmatch' in host_info and host_info['osmatch']:
                os_matches = host_info['osmatch']
                debug_print(f"[DEBUG] OS matches found: {len(os_matches)}")
                for i, match in enumerate(os_matches[:3]):  # Show top 3
                    debug_print(f"[DEBUG] OS match {i+1}: {match['name']} (accuracy: {match.get('accuracy', 'unknown')}%)")
                os_info = os_matches[0]['name']
            else:
                debug_print(f"[DEBUG] No OS matches found for {ip}")
            
            result = {
                'ports': ports,
                'services': services,
                'os': os_info,
                'hostname': host_info.hostname()
            }
            
            debug_print(f"[DEBUG] Nmap results for {ip}: {len(ports)} open ports, OS: {os_info[:30]}")
            return result
        else:
            debug_print(f"[DEBUG] Host {ip} not found in nmap results")
            
    except Exception as e:
        debug_print(f"[DEBUG] Nmap scan failed for {ip}: {e}")
    
    return None

def is_likely_iot(vendor, ports=None, services=None, os_info=None):
    """Determine if device is likely IoT based on vendor, ports, services, OS."""
    iot_vendors = [
        "Amazon", "Apple", "Arlo", "Bosch", "Ecobee", "Google", "Huawei", 
        "LIFX", "Ring", "Samsung", "Sonos", "TP-Link", "Wyze", "Xiaomi",
        "D-Link", "Netgear", "Logitech", "Philips", "Nest", "Belkin", 
        "Linksys", "ASUS", "Ubiquiti", "Hikvision", "Roku", "Chromecast"
    ]
    
    # Check vendor
    for iot_vendor in iot_vendors:
        if iot_vendor.lower() in vendor.lower():
            return True
    
    # Check OS
    if os_info:
        iot_keywords = ['embedded', 'linux', 'busybox', 'router', 'camera']
        if any(keyword in os_info.lower() for keyword in iot_keywords):
            return True
    
    # Check ports
    if ports:
        iot_ports = [8080, 1883, 8883, 554, 8554, 5000]
        if any(port in ports for port in iot_ports):
            return True
    
    # Check services
    if services:
        iot_services = ['rtsp', 'mqtt', 'upnp', 'http-alt', 'lighttpd']
        for service in services.values():
            if any(iot_service in service.lower() for iot_service in iot_services):
                return True
    
    return False

def discover_upnp_device(ip):
    """Discover UPnP device information with debugging."""
    debug_print(f"[DEBUG] Trying UPnP discovery for {ip}")
    
    try:
        # Try multicast SSDP first
        upnp_info = try_ssdp_multicast(ip)
        if upnp_info:
            debug_print(f"[DEBUG] UPnP found via multicast: {upnp_info}")
            return upnp_info
        
        # Try direct HTTP on common UPnP ports
        upnp_info = try_direct_upnp(ip)
        if upnp_info:
            debug_print(f"[DEBUG] UPnP found via direct HTTP: {upnp_info}")
            return upnp_info
        
        debug_print(f"[DEBUG] No UPnP info found for {ip}")
    except Exception as e:
        debug_print(f"[DEBUG] UPnP discovery error for {ip}: {e}")
    
    return None

def try_ssdp_multicast(ip):
    """Try SSDP multicast discovery with multiple search targets."""
    search_targets = [
        'upnp:rootdevice',
        'ssdp:all',
        'urn:schemas-upnp-org:device:MediaRenderer:1',
        'urn:schemas-upnp-org:device:MediaServer:1',
        'urn:schemas-upnp-org:device:InternetGatewayDevice:1'
    ]
    
    for st in search_targets:
        try:
            ssdp_request = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                f"ST: {st}\r\n"
                "MX: 2\r\n\r\n"
            )
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            # Enable broadcast
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # Try multicast first
            sock.sendto(ssdp_request.encode(), ('239.255.255.250', 1900))
            
            # Also try direct unicast to the device
            try:
                sock.sendto(ssdp_request.encode(), (ip, 1900))
            except Exception:
                pass
            
            start_time = time.time()
            while time.time() - start_time < 2:
                try:
                    response, addr = sock.recvfrom(2048)
                    if addr[0] == ip:  # Response from target IP
                        response_str = response.decode('utf-8', errors='ignore')
                        debug_print(f"[DEBUG] SSDP response from {ip} (ST={st}): {response_str[:150]}...")
                        
                        location_match = re.search(r'LOCATION:\s*(.+)', response_str, re.IGNORECASE)
                        if location_match:
                            location_url = location_match.group(1).strip()
                            sock.close()
                            return fetch_upnp_xml(location_url)
                except socket.timeout:
                    break
            
            sock.close()
        except Exception as e:
            debug_print(f"[DEBUG] SSDP search failed for ST={st}: {e}")
    
    return None

def try_direct_upnp(ip):
    """Try direct HTTP requests to common UPnP ports and paths."""
    # Common UPnP ports and paths
    upnp_configs = [
        (1900, '/description.xml'),
        (1900, '/rootDesc.xml'), 
        (1900, '/device.xml'),
        (1900, '/upnp/desc.xml'),
        (49152, '/description.xml'),  # Common alternative port
        (49153, '/description.xml'),
        (49154, '/description.xml'),
        (8080, '/description.xml'),   # Ring and other IoT devices
        (80, '/description.xml'),     # Some devices use port 80
        (80, '/upnp/desc.xml'),
        (8557, '/description.xml'),   # Ring specific
    ]
    
    for port, path in upnp_configs:
        try:
            url = f"http://{ip}:{port}{path}"
            debug_print(f"[DEBUG] Trying direct UPnP: {url}")
            response = requests.get(url, timeout=2)
            if response.status_code == 200 and 'xml' in response.text.lower():
                debug_print(f"[DEBUG] Found UPnP XML at {url}")
                return parse_upnp_xml(response.text)
        except Exception:
            continue
    
    return None

def fetch_upnp_xml(location_url):
    """Fetch and parse UPnP device description XML."""
    try:
        debug_print(f"[DEBUG] Fetching UPnP XML from: {location_url}")
        xml_response = requests.get(location_url, timeout=5)
        if xml_response.status_code == 200:
            debug_print(f"[DEBUG] UPnP XML received: {xml_response.text[:200]}...")
            return parse_upnp_xml(xml_response.text)
    except Exception as e:
        debug_print(f"[DEBUG] Failed to fetch UPnP XML: {e}")
    
    return None

def parse_upnp_xml(xml_content):
    """Parse UPnP device description XML with better error handling."""
    try:
        # Clean up XML content
        xml_content = xml_content.strip()
        if not xml_content.startswith('<?xml'):
            # Some devices return HTML, skip those
            if '<html' in xml_content.lower():
                return None
        
        root = ET.fromstring(xml_content)
        debug_print(f"[DEBUG] Parsing UPnP XML root tag: {root.tag}")
        
        # Try multiple ways to find device info
        device_paths = [
            './/{urn:schemas-upnp-org:device-1-0}device',
            './/device',
            './/{http://schemas.xmlsoap.org/soap/envelope/}device',
            './/root/device'
        ]
        
        device = None
        for path in device_paths:
            device = root.find(path)
            if device is not None:
                debug_print(f"[DEBUG] Found device element using path: {path}")
                break
        
        if device is not None:
            # Try multiple field names and namespaces
            fields = {
                'manufacturer': ['manufacturer', 'Manufacturer'],
                'model_name': ['modelName', 'ModelName', 'friendlyName', 'FriendlyName'],
                'model_number': ['modelNumber', 'ModelNumber'],
                'serial_number': ['serialNumber', 'SerialNumber', 'UDN']
            }
            
            result = {}
            for key, field_names in fields.items():
                value = ''
                for field_name in field_names:
                    # Try with namespace
                    elem = device.find(f'.//{{{root.tag.split("}")[0][1:] if "}" in root.tag else "urn:schemas-upnp-org:device-1-0"}}}{field_name}')
                    if elem is None:
                        # Try without namespace
                        elem = device.find(f'.//{field_name}')
                    if elem is not None and elem.text:
                        value = elem.text.strip()
                        break
                result[key] = value
            
            debug_print(f"[DEBUG] Parsed UPnP info: {result}")
            return result if any(result.values()) else None
            
    except Exception as e:
        debug_print(f"[DEBUG] XML parsing error: {e}")
    
    return None

def scan_device_comprehensive(ip):
    """Comprehensive scan of single device: nmap → MAC → UPnP if IoT."""
    debug_print(f"[2/4] Scanning {ip}...")
    
    device_info = {
        'ip': ip,
        'mac': 'Unknown',
        'vendor': 'Unknown',
        'ports': [],
        'services': {},
        'os': '',
        'hostname': '',
        'is_iot': False,
        'upnp_info': None
    }
    
    # Get MAC address and vendor
    mac = get_mac_address_from_ip(ip)
    if mac != "MAC not found":
        device_info['mac'] = mac
        device_info['vendor'] = get_mac_address_vendor(mac)
    
    # Nmap scan
    nmap_info = nmap_scan_detailed(ip)
    if nmap_info:
        device_info.update(nmap_info)
    
    # Check if IoT device
    device_info['is_iot'] = is_likely_iot(
        device_info['vendor'], 
        device_info['ports'], 
        device_info['services'], 
        device_info['os']
    )
    
    # UPnP discovery for IoT devices
    if device_info['is_iot']:
        print(f"[3/4] IoT device detected at {ip}, trying UPnP discovery...")
        upnp_info = discover_upnp_device(ip)
        if upnp_info:
            device_info['upnp_info'] = upnp_info
            print(f"[3/4] UPnP info found: {upnp_info.get('manufacturer', 'Unknown')} {upnp_info.get('model_name', '')}")
    
    return device_info

def parse_ip_range(ip_input):
    """Parse IP range input (CIDR, range, or single IP)."""
    if '/' in ip_input:
        try:
            network = ipaddress.IPv4Network(ip_input, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return []
    elif '-' in ip_input:
        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})', ip_input)
        if match:
            base_ip = match.group(1)
            start = int(match.group(2))
            end = int(match.group(3))
            return [f"{base_ip}.{i}" for i in range(start, end + 1)]
        return []
    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_input):
        return [ip_input]
    return []

# Global debug flag
DEBUG = False

def debug_print(message):
    """Print debug message if debug mode enabled."""
    if DEBUG:
        print(message)

def main():
    """Main function with layered discovery approach."""
    global DEBUG
    
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python getdevice-week3.py <IP_RANGE> [--debug]")
        print("Example: python getdevice-week3.py 192.168.1.0/24")
        print("Example: python getdevice-week3.py 192.168.1.1-254 --debug")
        sys.exit(1)
    
    ip_range = sys.argv[1]
    
    if len(sys.argv) == 3 and sys.argv[2] == '--debug':
        DEBUG = True
        print("Debug mode enabled")
    
    print("=== IoT Device Discovery with Layered Approach ===")
    print(f"MAC Vendor Lookup: {'manuf library (offline)' if MANUF_AVAILABLE else 'API only (rate limited)'}")
    print(f"Nmap Available: {'Yes' if NMAP_AVAILABLE else 'No'}")
    print()
    
    # Step 1: Ping sweep to find active hosts
    active_hosts = ping_sweep(ip_range)
    
    if not active_hosts:
        print("No active hosts found.")
        return
    
    # Step 2-4: Detailed scanning of active hosts
    print(f"[2/4] Starting detailed scans of {len(active_hosts)} active hosts...")
    
    devices = []
    completed = 0
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(scan_device_comprehensive, ip): ip for ip in active_hosts}
        
        for future in as_completed(future_to_ip):
            device_info = future.result()
            completed += 1
            
            if device_info:
                devices.append(device_info)
                status = "IoT" if device_info['is_iot'] else "Standard"
                ports_found = len(device_info.get('ports', []))
                services_found = len(device_info.get('services', {}))
                print(f"[2/4] Completed {device_info['ip']} - {status} device, {ports_found} ports, {services_found} services ({completed}/{len(active_hosts)})")
    
    # Results summary
    print(f"\n[4/4] Scan complete! Found {len(devices)} devices")
    
    iot_devices = [d for d in devices if d['is_iot']]
    print(f"IoT devices identified: {len(iot_devices)}")
    
    # Display detailed results for vulnerability assessment
    print("\n" + "="*150)
    print("DEVICE DISCOVERY RESULTS (For Vulnerability Assessment)")
    print("="*150)
    
    for device in devices:
        ip = device['ip']
        mac = device['mac']
        vendor = device['vendor']
        ports = device['ports']
        services = device['services']
        os_info = device['os']
        device_type = "IoT" if device['is_iot'] else "Standard"
        
        print(f"\n[{device_type.upper()}] {ip} ({vendor})")
        print(f"  MAC: {mac}")
        if os_info:
            print(f"  OS:  {os_info}")
        
        if ports:
            print(f"  Open Ports ({len(ports)}): {', '.join(map(str, ports))}")
            
            # Show detailed service information for vulnerability assessment
            if services:
                print("  Services (for CVE lookup):")
                for port, service in services.items():
                    print(f"    Port {port}: {service}")
        else:
            print("  No open ports detected")
        
        # UPnP info
        if device['upnp_info']:
            upnp = device['upnp_info']
            print(f"  UPnP: {upnp.get('manufacturer', '')} {upnp.get('model_name', '')}")
            if upnp.get('model_number'):
                print(f"        Model: {upnp.get('model_number')}")
        
        print("-" * 80)

if __name__ == "__main__":
    main()