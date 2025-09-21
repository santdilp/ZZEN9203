#!/usr/bin/env python3
"""getdevice-week3-optimized.py

Optimised, cleaned and better-reporting version of user's script.
- Reduced noisy debug prints; uses logging module with --debug flag
- Consolidated imports and removed unused blocks
- Improved CLI flags and non-interactive options (--no-interactive)
- Adds JSON/CSV output (--output-json / --output-csv)
- Tries to enrich nmap script CVE findings with nvdlib (if installed)
- Keeps manuf offline vendor lookup when available with simple cache
- ThreadPoolExecutor usage preserved with safer exception handling

Note: This script still relies on nmap python bindings for scanning when available.
If nmap or manuf or nvdlib are not installed, the script gracefully degrades.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional

# Optional dependencies
try:
    import nmap
    NMAP_AVAILABLE = True
except Exception:
    nmap = None
    NMAP_AVAILABLE = False

try:
    from manuf import manuf
    mac_parser = manuf.MacParser()
    MANUF_AVAILABLE = True
except Exception:
    mac_parser = None
    MANUF_AVAILABLE = False

try:
    import nvdlib
    NVDLIB_AVAILABLE = True
except Exception:
    nvdlib = None
    NVDLIB_AVAILABLE = False

# Simple in-memory cache for MAC vendor lookups
MAC_VENDOR_CACHE: Dict[str, str] = {}

# Logging setup
logger = logging.getLogger("getdevice")


def setup_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)-5s: %(message)s")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="IoT device discovery + vulnerability scanning")
    parser.add_argument("ip_range", help="IP range: CIDR, single IP or A.B.C.1-254")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--cve-only", action="store_true", help="Skip discovery and run CVE scan on provided IPs")
    parser.add_argument("--no-interactive", action="store_true", help="Non-interactive (auto select all detected devices for CVE scan)")
    parser.add_argument("--output-json", help="Write full results to JSON file")
    parser.add_argument("--output-csv", help="Write summary to CSV file")
    return parser.parse_args()


def parse_ip_range(ip_input: str) -> List[str]:
    """Support CIDR, range like 192.168.1.1-254 or single IP."""
    ip_input = ip_input.strip()
    if "/" in ip_input:
        try:
            network = ipaddress.IPv4Network(ip_input, strict=False)
            return [str(ip) for ip in network.hosts()]
        except Exception:
            return []
    if "-" in ip_input:
        # Accept formats like 192.168.1.1-254 or 192.168.1.100-192.168.1.110
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}-\d{1,3}$", ip_input):
            base, end = ip_input.rsplit('.', 1)
            start = int(base.split('.')[-1])
            prefix = '.'.join(base.split('.')[:-1])
            start = int(start)
            end = int(end)
            return [f"{prefix}.{i}" for i in range(start, end + 1)]
        m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$", ip_input)
        if m:
            start_ip = ipaddress.IPv4Address(m.group(1))
            end_ip = ipaddress.IPv4Address(m.group(2))
            return [str(ipaddress.IPv4Address(i)) for i in range(int(start_ip), int(end_ip) + 1)]
        return []
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip_input):
        return [ip_input]
    return []


def ping_host(ip: str, timeout_ms: int = 1000) -> bool:
    """Platform-aware single ping. Returns True if host responded."""
    try:
        if sys.platform.startswith("win"):
            # Windows
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        else:
            # Unix-like: -c 1, -W timeout (seconds) -> convert ms to seconds
            cmd = ["ping", "-c", "1", "-W", str(max(1, int((timeout_ms + 999) / 1000))), ip]
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc.returncode == 0
    except Exception as e:
        logger.debug("ping_host exception: %s", e)
        return False


def ping_sweep(ip_range: str, max_workers: int = 50) -> List[str]:
    ips = parse_ip_range(ip_range)
    if not ips:
        logger.error("Invalid IP range: %s", ip_range)
        return []
    logger.info("Pinging %d addresses...", len(ips))
    alive: List[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(ping_host, ip): ip for ip in ips}
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            try:
                if fut.result():
                    alive.append(ip)
                    logger.debug("Host alive: %s", ip)
            except Exception as e:
                logger.debug("ping task error for %s: %s", ip, e)
    logger.info("Ping sweep complete: %d active hosts", len(alive))
    return alive


def get_mac_from_arp(ip: str) -> Optional[str]:
    """Try to extract MAC from system arp table."""
    try:
        if sys.platform.startswith("win"):
            res = subprocess.run(["arp", "-a", ip], capture_output=True, text=True)
            out = res.stdout
            m = re.search(r"([0-9a-fA-F]{2}(-[0-9a-fA-F]{2}){5})", out)
            if m:
                return m.group(1).replace('-', ':')
        else:
            res = subprocess.run(["arp", "-n", ip], capture_output=True, text=True)
            out = res.stdout
            m = re.search(r"([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})", out)
            if m:
                return m.group(1)
    except Exception as e:
        logger.debug("get_mac_from_arp exception: %s", e)
    return None


def lookup_mac_vendor(mac: str) -> str:
    if not mac:
        return "Unknown"
    if mac in MAC_VENDOR_CACHE:
        return MAC_VENDOR_CACHE[mac]
    vendor = "Unknown"
    if MANUF_AVAILABLE and mac_parser:
        try:
            v = mac_parser.get_manuf(mac)
            if v:
                vendor = v
        except Exception:
            pass
    # If still unknown, do not call external API automatically (avoid rate limits).
    MAC_VENDOR_CACHE[mac] = vendor
    return vendor


# --------------- Nmap scanning helpers ---------------

def nmap_scan_detailed(ip: str) -> Optional[Dict[str, Any]]:
    if not NMAP_AVAILABLE:
        logger.debug("nmap not available")
        return None
    try:
        nm = nmap.PortScanner()
        args = "-sS -sV -O --top-ports 1000 --osscan-guess"
        logger.debug("Running nmap: %s %s", args, ip)
        nm.scan(ip, arguments=args)
        if ip not in nm.all_hosts():
            return None
        host = nm[ip]
        ports = []
        services = {}
        for proto in host.all_protocols():
            for port in host[proto].keys():
                info = host[proto][port]
                if info.get('state') == 'open':
                    ports.append(port)
                    service = ' '.join(filter(None, [info.get('name',''), info.get('product',''), info.get('version',''), info.get('extrainfo','')])).strip()
                    services[port] = service or 'unknown'
        os_info = ''
        os_accuracy = 0
        if 'osmatch' in host and host['osmatch']:
            os_info = host['osmatch'][0].get('name','')
            try:
                os_accuracy = int(host['osmatch'][0].get('accuracy', 0))
            except Exception:
                os_accuracy = 0
        hostname = host.hostname() if hasattr(host, 'hostname') else ''
        return {'ports': ports, 'services': services, 'os': os_info, 'os_accuracy': os_accuracy, 'hostname': hostname}
    except Exception as e:
        logger.debug("nmap_scan_detailed exception for %s: %s", ip, e)
        return None


def nmap_cve_scan(ip: str) -> Optional[List[Dict[str, Any]]]:
    if not NMAP_AVAILABLE:
        return None
    try:
        nm = nmap.PortScanner()
        args = '--script "vuln and safe" -sV --script-timeout=30s'
        logger.debug("Running nmap vuln scan: %s %s", args, ip)
        nm.scan(ip, arguments=args)
        if ip not in nm.all_hosts():
            return None
        host = nm[ip]
        vulns: List[Dict[str, Any]] = []
        for proto in host.all_protocols():
            for port in host[proto].keys():
                info = host[proto][port]
                if info.get('state') != 'open':
                    continue
                scripts = info.get('script', {})
                for script_name, output in scripts.items():
                    parsed = parse_vulnerability_output(script_name, output, port)
                    if parsed:
                        # Try to enrich with NVD if available
                        if NVDLIB_AVAILABLE and parsed.get('cve'):
                            parsed = enrich_with_nvd(parsed)
                        vulns.append(parsed)
        return vulns
    except Exception as e:
        logger.debug("nmap_cve_scan exception for %s: %s", ip, e)
        return None


def parse_vulnerability_output(script_name: str, output: str, port: int) -> Optional[Dict[str, Any]]:
    if not output or len(output.strip()) < 10:
        return None
    # Deduplicate CVEs by converting to set then back to sorted list
    cves = sorted(list(set(re.findall(r"CVE-\d{4}-\d{4,}", output))))
    indicators = ['vulnerable', 'exploit', 'weakness', 'insecure', 'default', 'unauthenticated', 'disclosure', 'bypass']
    has_vuln = any(x in output.lower() for x in indicators) or bool(cves)
    if not has_vuln:
        return None
    # Severity heuristics
    severity = 'Unknown'
    low = ['low', 'minor', 'info']
    med = ['medium', 'moderate']
    high = ['high', 'dangerous']
    crit = ['critical', 'severe']
    lo = output.lower()
    if any(w in lo for w in crit):
        severity = 'Critical'
    elif any(w in lo for w in high):
        severity = 'High'
    elif any(w in lo for w in med):
        severity = 'Medium'
    elif any(w in lo for w in low):
        severity = 'Low'
    elif cves:
        severity = 'Medium'
    title = script_name.replace('_', ' ').replace('-', ' ').title()
    desc = ' '.join(output.split())
    return {'title': title, 'port': port, 'cve': cves, 'severity': severity, 'description': desc[:800], 'script': script_name}


def enrich_with_nvd(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """If nvdlib available, fetch CVE details and attach CVSS scores/summary."""
    if not NVDLIB_AVAILABLE:
        return vuln
    cve_list = vuln.get('cve', [])
    if not cve_list:
        return vuln
    details = []
    for cve in cve_list:
        if not cve:
            continue
        try:
            res = nvdlib.searchCVE(cveId=cve)
            if res and isinstance(res, list):
                # nvdlib returns list; take first
                entry = res[0]
                score_v3 = entry.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore') if entry.get('impact') else None
                score_v2 = entry.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore') if entry.get('impact') else None
                details.append({'cve': cve, 'summary': entry.get('summary'), 'cvss_v3': score_v3, 'cvss_v2': score_v2})
        except Exception as e:
            logger.debug("nvdlib lookup failed for %s: %s", cve, e)
    if details:
        vuln['nvd'] = details
    return vuln


# UPnP helpers (kept but simplified)

def parse_upnp_xml(xml_content: str) -> Optional[Dict[str, str]]:
    try:
        root = ET.fromstring(xml_content)
        # best-effort extraction
        manuf = root.find('.//manufacturer')
        model = root.find('.//modelName') or root.find('.//friendlyName')
        serial = root.find('.//serialNumber') or root.find('.//UDN')
        return {
            'manufacturer': manuf.text.strip() if manuf is not None and manuf.text else '',
            'model_name': model.text.strip() if model is not None and model.text else '',
            'serial_number': serial.text.strip() if serial is not None and serial.text else ''
        }
    except Exception:
        return None


def try_direct_upnp(ip: str) -> Optional[Dict[str, str]]:
    import requests
    candidates = [(1900, '/description.xml'), (80, '/description.xml'), (8080, '/description.xml')]
    for port, path in candidates:
        url = f"http://{ip}:{port}{path}"
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200 and '<' in r.text:
                parsed = parse_upnp_xml(r.text)
                if parsed:
                    return parsed
        except Exception:
            continue
    return None


def is_likely_iot(vendor: str, ports: List[int], services: Dict[int, str], os_info: str) -> bool:
    iot_keywords = ['camera', 'iot', 'embedded', 'busybox', 'rtsp', 'mqtt', 'upnp']
    if vendor and any(k.lower() in vendor.lower() for k in ['ring', 'wyze', 'hikvision', 'arlo', 'tp-link', 'sonos', 'xiaomi', 'google', 'amazon']):
        return True
    if os_info and any(k in os_info.lower() for k in iot_keywords):
        return True
    if any(p in ports for p in [554, 1883, 8080, 5000, 8554]):
        return True
    for s in services.values():
        if any(k in s.lower() for k in iot_keywords):
            return True
    return False


# High-level device scan

def scan_device(ip: str) -> Dict[str, Any]:
    dev = {'ip': ip, 'mac': None, 'vendor': 'Unknown', 'ports': [], 'services': {}, 'os': '', 'os_accuracy': 0, 'hostname': '', 'is_iot': False, 'upnp': None}
    mac = get_mac_from_arp(ip)
    if mac:
        dev['mac'] = mac
        dev['vendor'] = lookup_mac_vendor(mac)
    nmap_info = nmap_scan_detailed(ip)
    if nmap_info:
        dev.update(nmap_info)
    dev['is_iot'] = is_likely_iot(dev.get('vendor',''), dev.get('ports', []), dev.get('services', {}), dev.get('os',''))
    if dev['is_iot']:
        upnp = try_direct_upnp(ip)
        if upnp:
            dev['upnp'] = upnp
    return dev


def summarize_devices(devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(devices)
    iot = [d for d in devices if d.get('is_iot')]
    summary = {'total_devices': total, 'iot_devices': len(iot), 'devices': []}
    for d in devices:
        summary['devices'].append({'ip': d['ip'], 'vendor': d.get('vendor'), 'is_iot': d.get('is_iot'), 'ports': len(d.get('ports', [])), 'os': d.get('os','')})
    return summary


def write_json(path: str, data: Any) -> None:
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        logger.info("Wrote JSON output: %s", path)
    except Exception as e:
        logger.error("Failed to write JSON: %s", e)


def write_csv(path: str, devices: List[Dict[str, Any]]) -> None:
    try:
        import csv
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['ip', 'vendor', 'is_iot', 'ports_count', 'os'])
            for d in devices:
                w.writerow([d['ip'], d.get('vendor',''), d.get('is_iot', False), len(d.get('ports', [])), d.get('os','')])
        logger.info("Wrote CSV output: %s", path)
    except Exception as e:
        logger.error("Failed to write CSV: %s", e)


def perform_cve_scanning(devices: List[Dict[str, Any]], no_interactive: bool = False) -> None:
    if not NMAP_AVAILABLE:
        logger.error("Nmap python bindings not available; cannot perform CVE scanning")
        return
    candidates = [d for d in devices if d.get('is_iot') and d.get('os_accuracy', 0) >= 80 and d.get('ports')]
    if not candidates:
        logger.info("No suitable devices for CVE scanning (needs IoT + open ports + some OS accuracy)")
        return
    if no_interactive:
        selected = candidates
    else:
        # default interactive: select all
        selected = candidates
    for i, dev in enumerate(selected, 1):
        logger.info("CVE scanning %s (%d/%d)", dev['ip'], i, len(selected))
        vulns = nmap_cve_scan(dev['ip'])
        if vulns:
            logger.warning("Vulnerabilities found for %s: %d", dev['ip'], len(vulns))
            for v in vulns:
                title = v.get('title', 'Unknown')
                severity = v.get('severity', 'Unknown')
                cves = v.get('cve', [])
                if cves:
                    for cve in cves:
                        # Try to get description from NVD data if available
                        desc = "No description available"
                        if v.get('nvd'):
                            nvd_entry = next((entry for entry in v['nvd'] if entry['cve'] == cve), None)
                            if nvd_entry and nvd_entry.get('summary'):
                                desc = nvd_entry['summary'][:100] + "..." if len(nvd_entry['summary']) > 100 else nvd_entry['summary']
                        logger.info(" - %s: %s [%s] - %s", title, cve, severity, desc)
                else:
                    logger.info(" - %s [%s]", title, severity)
        else:
            logger.info("No known vulnerabilities found for %s", dev['ip'])


def main():
    args = parse_args()
    setup_logging(args.debug)
    logger.info("Starting discovery for %s", args.ip_range)
    logger.info("Manuf available: %s | Nmap available: %s | nvdlib available: %s", MANUF_AVAILABLE, NMAP_AVAILABLE, NVDLIB_AVAILABLE)

    if args.cve_only:
        ips = parse_ip_range(args.ip_range)
        if not ips:
            logger.error("Invalid IPs for cve-only mode")
            sys.exit(1)
        devices = [{'ip': ip, 'vendor': 'Unknown', 'os': 'Unknown', 'os_accuracy': 100, 'ports': [80,443,22], 'is_iot': True} for ip in ips[:10]]
        perform_cve_scanning(devices, no_interactive=args.no_interactive)
        return

    active = ping_sweep(args.ip_range)
    if not active:
        logger.info("No active hosts discovered")
        return

    devices: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(scan_device, ip): ip for ip in active}
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            try:
                d = fut.result()
                devices.append(d)
                logger.info("Scanned %s: IoT=%s ports=%d", ip, d.get('is_iot'), len(d.get('ports', [])))
            except Exception as e:
                logger.error("scan failed for %s: %s", ip, e)

    summary = summarize_devices(devices)
    logger.info("Discovery complete: %d devices (%d IoT)", summary['total_devices'], summary['iot_devices'])

    if args.output_json:
        write_json(args.output_json, {'summary': summary, 'devices': devices})
    if args.output_csv:
        write_csv(args.output_csv, devices)

    # Auto-run CVE scanning on high confidence IoT devices if non-interactive
    perform_cve_scanning(devices, no_interactive=args.no_interactive)


if __name__ == '__main__':
    main()
