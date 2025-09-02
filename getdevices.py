import subprocess
import re
import requests
import sys

def get_mac_address_vendor(mac_address):
    """
    Looks up the vendor of a MAC address using a public API.
    
    This function uses the macvendors.com API which does not require an API key
    for up to 1000 requests per day.
    """
    if not mac_address or mac_address == "MAC not found":
        return "Unknown"

    api_url = f"https://api.macvendors.com/api/{mac_address}"
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            vendor_info = response.json()
            return vendor_info.get('result', {}).get('company', 'Unknown')
        else:
            return "Vendor not found"
    except (requests.exceptions.RequestException, ValueError) as e:
        print(f"Error during API request for MAC {mac_address}: {e}", file=sys.stderr)
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

def is_likely_iot(vendor):
    """
    Determines if a device is likely an IoT device based on its vendor name.
    
    This is a simple heuristic based on a list of common IoT brands.
    """
    iot_vendors = [
        "Amazon", "Apple", "Arlo", "Bosch", "Ecobee", "Eero", "Google", "Huawei", 
        "LIFX", "Ring", "Samsung", "Sensibo", "Sonos", "TP-Link", "Wyze", "Xiaomi",
        "TP-LINK", "D-Link", "Netgear", "Logitech", "Philips", "Hue", "Nest"
    ]
    # Check if any part of the vendor name contains one of the listed keywords (case-insensitive)
    for iot_vendor in iot_vendors:
        if iot_vendor.lower() in vendor.lower():
            return True
    return False

def main():
    """
    Main function to run the network scan and print device information.
    """
    if len(sys.argv) != 2:
        print("Usage: python network_scanner_win.py <IP_ADDRESS_RANGE>")
        print("Example: python network_scanner_win.py 192.168.1.1/24 (CIDR notation is not supported with this script)")
        print("Example: python network_scanner_win.py 192.168.1.1-254 (scan range)")
        print("Example: python network_scanner_win.py 192.168.1.5 (single host)")
        sys.exit(1)
    
    ip_input = sys.argv[1]
    
    devices = {}
    
    # Check for IP range format (e.g., 192.168.1.1-254)
    if '-' in ip_input:
        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})', ip_input)
        if match:
            base_ip = match.group(1)
            start = int(match.group(2))
            end = int(match.group(3))
            
            print(f"Scanning the network range {ip_input}...")
            for i in range(start, end + 1):
                ip_address = f"{base_ip}.{i}"
                try:
                    # Ping the IP address
                    subprocess.run(['ping', '-n', '1', '-w', '100', ip_address], capture_output=True, check=True, text=True)
                    # If ping is successful, try to get the MAC address
                    mac = get_mac_address_from_ip(ip_address)
                    if mac != "MAC not found":
                        devices[ip_address] = {'mac': mac}
                except subprocess.CalledProcessError:
                    # Ping failed, device is not active
                    pass
        else:
            print("Invalid IP range format. Use a format like '192.168.1.1-254'.")
            sys.exit(1)
    
    # Check for single IP address
    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_input):
        ip_address = ip_input
        print(f"Scanning single host {ip_address}...")
        mac = get_mac_address_from_ip(ip_address)
        if mac != "MAC not found":
            devices[ip_address] = {'mac': mac}
    else:
        print("Invalid IP address or range format.")
        sys.exit(1)

    if not devices:
        print("No active devices found in the specified range.")
        return

    print("\nNetwork Scan Results:")
    print("-" * 70)
    print(f"{'IP Address':<15} | {'MAC Address':<20} | {'Vendor':<15} | {'Category'}")
    print("-" * 70)
    
    for ip, info in devices.items():
        mac = info['mac']
        vendor_info = get_mac_address_vendor(mac)
        category = "Likely IoT Device" if is_likely_iot(vendor_info) else "Standard Device"
        print(f"{ip:<15} | {mac:<20} | {vendor_info:<15} | {category}")

if __name__ == "__main__":
    main()
