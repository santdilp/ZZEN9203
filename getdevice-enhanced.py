import subprocess
import re
import requests
import sys
import socket
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import time
import argparse
import json

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

def nmap_scan_detailed(ip, force=False):
    """Detailed nmap scan for single host with force option."""
    if not NMAP_AVAILABLE:
        debug_print(f"[DEBUG] Nmap not available for {ip}")
        return None
    
    try:
        debug_print(f"[DEBUG] Starting nmap scan for {ip} (force={force})...")
        nm = nmap.PortScanner()
        
        # Force mode: more aggressive scanning
        if force:
            nmap_args = '-sS -O -sV -A --top-ports 1000 --osscan-guess -Pn --host-timeout 30m'
            debug_print(f"[DEBUG] Force mode: Using aggressive scan")
        else:
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
            os_accuracy = 0
            if 'osmatch' in host_info and host_info['osmatch']:
                os_matches = host_info['osmatch']
                debug_print(f"[DEBUG] OS matches found: {len(os_matches)}")
                for i, match in enumerate(os_matches[:3]):  # Show top 3
                    debug_print(f"[DEBUG] OS match {i+1}: {match['name']} (accuracy: {match.get('accuracy', 'unknown')}%)")
                os_info = os_matches[0]['name']
                os_accuracy = int(os_matches[0].get('accuracy', 0))
            else:
                debug_print(f"[DEBUG] No OS matches found for {ip}")
            
            result = {
                'ports': ports,
                'services': services,
                'os': os_info,
                'os_accuracy': os_accuracy,
                'hostname': host_info.hostname()
            }
            
            debug_print(f"[DEBUG] Nmap results for {ip}: {len(ports)} open ports, OS: {os_info[:30]}")
            return result
        else:
            debug_print(f"[DEBUG] Host {ip} not found in nmap results")
            
    except Exception as e:
        debug_print(f"[DEBUG] Nmap scan failed for {ip}: {e}")
    
    return None

def is_likely_iot(vendor, ports=None, services=None, os_info=None, force_iot=False):
    """Determine if device is likely IoT based on vendor, ports, services, OS."""
    if force_iot:
        return True
        
    iot_vendors = [
        "Amazon", "Apple", "Arlo", "Bosch", "Ecobee", "Google", "Huawei", 
        "LIFX", "Ring", "Samsung", "Sonos", "TP-Link", "Wyze", "Xiaomi",
        "D-Link", "Netgear", "Logitech", "Philips", "Nest", "Belkin", 
        "Linksys", "ASUS", "Ubiquiti", "Hikvision", "Roku", "Chromecast",
        "Meross"  # Added for smart light bulb
    ]
    
    # Check vendor
    for iot_vendor in iot_vendors:
        if iot_vendor.lower() in vendor.lower():
            return True
    
    # Check OS
    if os_info:
        iot_keywords = ['embedded', 'linux', 'busybox', 'router', 'camera', 'smart', 'iot']
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

def query_local_llm(device_info):
    """Query local LLM for IoT device analysis."""
    try:
        # Example using Ollama (install with: ollama pull llama2)
        prompt = f"""Analyze device: IP {device_info['ip']}, Vendor {device_info['vendor']}, OS {device_info['os']}, Ports {device_info['ports']}. 
Provide: 1) Device type 2) Security risk (Low/Medium/High) 3) Main vulnerabilities. Keep brief."""
        
        # Try Ollama API
        response = requests.post('http://localhost:11434/api/generate', 
                               json={
                                   'model': 'gemma3:1b',
                                   'prompt': prompt,
                                   'stream': False
                               }, 
                               timeout=60)
        
        if response.status_code == 200:
            return response.json().get('response', 'No response from LLM')
        else:
            return f"LLM API Error: {response.status_code}"
            
    except requests.exceptions.ConnectionError:
        return "Local LLM not available (install Ollama and run: ollama pull llama2)"
    except Exception as e:
        return f"LLM Error: {e}"

def scan_device_comprehensive(ip, force=False, use_llm=False):
    """Comprehensive scan of single device with force and LLM options."""
    debug_print(f"Scanning {ip} (force={force}, llm={use_llm})...")
    
    device_info = {
        'ip': ip,
        'mac': 'Unknown',
        'vendor': 'Unknown',
        'ports': [],
        'services': {},
        'os': '',
        'hostname': '',
        'is_iot': False,
        'llm_analysis': None
    }
    
    # Get MAC address and vendor
    mac = get_mac_address_from_ip(ip)
    if mac != "MAC not found":
        device_info['mac'] = mac
        device_info['vendor'] = get_mac_address_vendor(mac)
    
    # Nmap scan with force option
    nmap_info = nmap_scan_detailed(ip, force=force)
    if nmap_info:
        device_info.update(nmap_info)
    
    # Check if IoT device (force mode ignores IoT check)
    device_info['is_iot'] = is_likely_iot(
        device_info['vendor'], 
        device_info['ports'], 
        device_info['services'], 
        device_info['os'],
        force_iot=force
    )
    
    # LLM analysis if requested
    if use_llm and (device_info['is_iot'] or force):
        print(f"Querying local LLM for {ip}...")
        device_info['llm_analysis'] = query_local_llm(device_info)
    
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
    """Main function with enhanced options."""
    global DEBUG
    
    parser = argparse.ArgumentParser(description='IoT Device Discovery and CVE Scanner')
    parser.add_argument('target', help='IP address, range, or CIDR (e.g., 192.168.1.100, 192.168.1.0/24)')
    parser.add_argument('--force', action='store_true', 
                       help='Force scan even if ping fails, ignore IoT detection')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--llm', action='store_true', help='Use local LLM for device analysis')
    
    args = parser.parse_args()
    
    if args.debug:
        DEBUG = True
        print("Debug mode enabled")
    
    print("=== Enhanced IoT Device Scanner ===")
    print(f"MAC Vendor Lookup: {'manuf library (offline)' if MANUF_AVAILABLE else 'API only (rate limited)'}")
    print(f"Nmap Available: {'Yes' if NMAP_AVAILABLE else 'No'}")
    print(f"Force Mode: {'Enabled' if args.force else 'Disabled'}")
    print(f"LLM Analysis: {'Enabled' if args.llm else 'Disabled'}")
    print()
    
    # Parse target
    ips = parse_ip_range(args.target)
    if not ips:
        print(f"Invalid IP format: {args.target}")
        sys.exit(1)
    
    if args.force:
        print(f"Force mode: Scanning {len(ips)} target(s) without ping check")
        active_hosts = ips
    else:
        # Ping sweep for active hosts
        print(f"Ping sweep on {len(ips)} addresses...")
        active_hosts = []
        for ip in ips:
            if ping_host(ip):
                active_hosts.append(ip)
                print(f"Active: {ip}")
        
        if not active_hosts:
            print("No active hosts found. Use --force to scan anyway.")
            return
    
    print(f"\nScanning {len(active_hosts)} host(s)...")
    
    # Scan devices
    devices = []
    for i, ip in enumerate(active_hosts, 1):
        print(f"[{i}/{len(active_hosts)}] Scanning {ip}...")
        device = scan_device_comprehensive(ip, force=args.force, use_llm=args.llm)
        if device:
            devices.append(device)
    
    # Display results
    print(f"\n{'='*100}")
    print("SCAN RESULTS")
    print(f"{'='*100}")
    
    for device in devices:
        ip = device['ip']
        vendor = device['vendor']
        os_info = device['os']
        ports = device['ports']
        device_type = "IoT" if device['is_iot'] else "Standard"
        
        print(f"\n[{device_type}] {ip}")
        print(f"  Vendor: {vendor}")
        if os_info:
            print(f"  OS: {os_info}")
        if ports:
            print(f"  Ports: {', '.join(map(str, ports))}")
            for port, service in device['services'].items():
                print(f"    {port}: {service}")
        
        # LLM analysis
        if device.get('llm_analysis'):
            print(f"  LLM Analysis:")
            for line in device['llm_analysis'].split('\n'):
                if line.strip():
                    print(f"    {line.strip()}")
        
        print("-" * 80)

if __name__ == "__main__":
    main()