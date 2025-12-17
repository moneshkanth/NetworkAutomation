import requests
import socket
import time
from urllib.parse import urlparse

def analyze_latency(url):
    """
    Analyzes the latency components of a URL request.
    
    Args:
        url (str): The URL to analyze (e.g., "https://google.com").
        
    Returns:
        dict: A dictionary containing timing metrics (in seconds) or error details.
    """
    metrics = {
        "DNS Lookup": 0,
        "TCP Connection": 0,
        "TTFB": 0,
        "Content Download": 0,
        "Total Time": 0,
        "Status Code": None,
        "Error": None
    }
    
    try:
        # Ensure URL has schema
        if not url.startswith("http"):
            url = f"https://{url}"
            
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        # 1. DNS Lookup Time
        start_dns = time.time()
        ip_address = socket.gethostbyname(hostname)
        metrics["DNS Lookup"] = time.time() - start_dns
        
        # 2. TCP Connection Time
        start_conn = time.time()
        sock = socket.create_connection((ip_address, port), timeout=5)
        metrics["TCP Connection"] = time.time() - start_conn
        sock.close() # Close immediate socket, requests will make its own
        
        # 3. Request (TTFB + Download)
        # Using requests to measure the full cycle
        start_req = time.time()
        response = requests.get(url, timeout=10)
        total_req_time = time.time() - start_req
        
        metrics["Status Code"] = response.status_code
        metrics["TTFB"] = response.elapsed.total_seconds()
        
        # Content Download is roughly Total Request Time - TTFB
        # Note: requests.get() downloads body by default.
        metrics["Content Download"] = max(0, total_req_time - metrics["TTFB"])
        
        # Calculate Total directly to be the sum of phases for the chart consistency
        # although technically requests made a SECOND connection, so exact sum might differ 
        # from a single session. For visualization, we sum our measured phases.
        metrics["Total Time"] = (
            metrics["DNS Lookup"] + 
            metrics["TCP Connection"] + 
            metrics["TTFB"] + 
            metrics["Content Download"]
        )

        return metrics

    except socket.gaierror:
        metrics["Error"] = "DNS Lookup Failed"
        return metrics
    except requests.exceptions.Timeout:
        metrics["Error"] = "Request Timed Out"
        return metrics
    except requests.exceptions.RequestException as e:
        metrics["Error"] = f"Request Failed: {str(e)}"
        return metrics
    except Exception as e:
        metrics["Error"] = f"An unexpected error occurred: {str(e)}"
        return metrics
