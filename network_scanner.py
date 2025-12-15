import argparse
import ipaddress
import socket
import subprocess
import concurrent.futures
import json
import os
import sys

def check_port_80(ip):
    """Checks if port 80 is open on the given IP."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((str(ip), 80))
            return result == 0
    except Exception:
        return False

def check_ping(ip):
    """Checks if the IP responds to ICMP ping."""
    # Option '-c' for count (1 packet), '-W' for timeout (1000ms) on Mac/Linux
    try:
        # Check platform to adjust ping arguments slightly if needed, but -c and -W are fairly standard on *nix/mac
        # Using -W 1 for 1 second timeout.
        output = subprocess.run(
            ['ping', '-c', '1', '-W', '1000', str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return output.returncode == 0
    except Exception:
        return False

import urllib.request
import urllib.error
import threading
import time

# Global lock for rate limiting vendor API (1 req/sec)
vendor_lock = threading.Lock()

def get_mac_address(ip):
    """Retrieves the MAC address for an IP using the ARP table."""
    try:
        # distinct command for MacOS/Linux vs Windows could be needed, but 'arp -n <ip>' usually works on *nix
        output = subprocess.check_output(['arp', '-n', str(ip)], timeout=2).decode()
        # Parse standard arp output: "? (192.168.1.1) at 00:00:00:00:00:00 on ..."
        if "at" in output:
            parts = output.split("at")
            if len(parts) > 1:
                mac_part = parts[1].strip().split()[0]
                # specific check for incomplete arp entries
                if "incomplete" in mac_part or "no entry" in output.lower():
                    return None
                
                # Normalize MAC: Ensure 01 instead of 1 in segments
                # macOS arp might return 1:2:3:4:5:6, we want 01:02:03:04:05:06
                normalized_mac = ":".join(f"{int(part, 16):02x}" for part in mac_part.split(":"))
                return normalized_mac
        return None
    except Exception:
        return None

def is_private_mac(mac):
    """Checks if a MAC address is locally administered (randomized)."""
    try:
        first_byte = int(mac.split(":")[0], 16)
        # Check 2nd least significant bit of 1st byte (x2, x6, xA, xE)
        return (first_byte & 0x02) != 0
    except:
        return False

def get_vendor(mac):
    """Retrieves device vendor using macvendors.com API with rate limiting."""
    if not mac:
        return "Unknown"
    
    # Check for Private/Randomized MAC
    if is_private_mac(mac):
        return "Private/Randomized Device"

    with vendor_lock:
        try:
            time.sleep(1.1) # Strict 1 request/sec limit
            
            # API expects XX:XX:XX:XX:XX:XX
            url = f"https://api.macvendors.com/{mac}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Python Scanner'})
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.read().decode()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return "Vendor Not Found"
            return "API Error"
        except Exception:
            return "Unknown"

def get_hostname(ip):
    """Resolves hostname for an IP address."""
    try:
        # 1-second timeout for resolution
        hostname, _, _ = socket.gethostbyaddr(str(ip))
        return hostname
    except Exception:
        return "Unknown"

def scan_ip(ip):
    """Scans a single IP for Port 80 and Ping."""
    is_active = False
    port_80_open = check_port_80(ip)
    ping_responsive = check_ping(ip)
    
    if port_80_open or ping_responsive:
        # We found a host. Let's try to get more details.
        # Note: ARP requires the OS to have communicated with the IP recently.
        # Ping usually refreshes the ARP cache.
        mac = get_mac_address(ip)
        vendor = get_vendor(mac) if mac else "Unknown"
        
        return {
            "ip": str(ip),
            "hostname": get_hostname(ip),
            "mac": mac if mac else "Unknown",
            "vendor": vendor,
            "port_80": port_80_open,
            "ping": ping_responsive
        }
    return None

def scan_network(cidr, threads=50, status_callback=None, progress_callback=None):
    """
    Scans a CIDR block for active hosts.
    Returns a tuple: (active_hosts_list, statistics_dict)
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        if status_callback:
            status_callback(f"Error: Invalid CIDR - {e}")
        return [], {}

    # Skip network and broadcast addresses for /24 and larger
    if network.num_addresses > 2:
        hosts = list(network.hosts())
    else:
        hosts = list(network)

    total_hosts = len(hosts)
    active_hosts = []
    
    # Stats tracking
    start_time = time.time()
    timeouts = 0
    errors = 0
    
    if status_callback:
        status_callback(f"Starting scan of {cidr} ({total_hosts} IPs) with {threads} threads...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_ip = {executor.submit(scan_ip, ip): ip for ip in hosts}
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_ip), 1):
            ip = future_to_ip[future]
            try:
                result = future.result()
                if result:
                    active_hosts.append(result)
            except Exception as e:
                errors += 1
                if status_callback:
                    status_callback(f"Error scanning {ip}: {e}")
            
            # Progress update
            if progress_callback:
                progress_callback(i, total_hosts)
            elif status_callback and i % 10 == 0:
                # Fallback to old behavior if no progress_callback
                status_callback(f"Progress: {i}/{total_hosts}")

    duration = time.time() - start_time
    
    stats = {
        "total_scanned": total_hosts,
        "active_count": len(active_hosts),
        "duration": duration,
        "threads": threads,
        "timeouts": timeouts, # Note: explicit timeouts hard to catch with high-level futures unless handled in scan_ip
        "errors": errors
    }
    
    if status_callback:
        status_callback(f"Scan complete. Found {len(active_hosts)} active hosts in {duration:.2f}s.")
        
    return active_hosts, stats

def main():
    parser = argparse.ArgumentParser(description="Scan a CIDR block for active IPs (Port 80/Ping).")
    parser.add_argument("cidr", help="CIDR block to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--output", default="scan_results.json", help="Output JSON file name")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads (default: 50)")

    args = parser.parse_args()

    active_hosts = scan_network(args.cidr, args.threads)
    
    try:
        with open(args.output, 'w') as f:
            json.dump(active_hosts, f, indent=4)
        print(f"Results saved to {args.output}")
    except IOError as e:
        print(f"Error writing output file: {e}")

if __name__ == "__main__":
    main()
