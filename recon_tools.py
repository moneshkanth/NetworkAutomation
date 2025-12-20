import requests
import streamlit as st
import time

# --- Tool 1: Shodan Public Attack Surface Scanner ---
@st.cache_data(ttl=3600) 
def get_shodan_data(ip_address):
    """
    Fetches open ports and vulnerabilities from Shodan's InternetDB (Free API).
    """
    url = f"https://internetdb.shodan.io/{ip_address}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 404:
            return {"error": "IP not found in Shodan database (No open ports visible)."}
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}

# --- Tool 2: CRT.sh Subdomain Finder ---
@st.cache_data(ttl=3600*24)
def get_crt_subdomains(domain):
    """
    Fetches subdomains from Certificate Transparency Logs via crt.sh.
    Includes retry logic because crt.sh is often overloaded.
    """
    # Force json output
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'}
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            # Increased timeout to 45s
            response = requests.get(url, headers=headers, timeout=45)
            
            # Explicitly check for 5xx errors to retry
            if response.status_code in [500, 502, 503, 504]:
                if attempt < max_retries - 1:
                    time.sleep(3)
                    continue
                else:
                    # Exhausted retries, break to fallback
                    break

            response.raise_for_status()
            
            data = response.json()
            
            # Filter duplicates and extract unique logic
            subdomains = set()
            for entry in data:
                names = entry.get('name_value', '').split('\n')
                for name in names:
                    if name.strip():
                        subdomains.add(name.strip().lower())
            
            return sorted(list(subdomains))
            
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            if attempt < max_retries - 1:
                time.sleep(3) # Wait 3 seconds before retry
                continue
            break # Go to fallback
            
        except Exception as e:
            # If 5xx error, retry. Else break to fallback
            if attempt < max_retries - 1:
                time.sleep(3)
                continue
            break

    # --- FALLBACK: HackerTarget API ---
    # If crt.sh fails (common), we try HackerTarget (free tier).
    # URL: https://api.hackertarget.com/hostsearch/?q={domain}
    try:
        ht_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(ht_url, timeout=20)
        
        if response.status_code == 200:
            lines = response.text.split('\n')
            subdomains = set()
            for line in lines:
                if "," in line:
                    host = line.split(',')[0]
                    if host:
                        subdomains.add(host.strip().lower())
            
            if subdomains:
                return sorted(list(subdomains))
    except:
        pass # If fallback fails, we return the original error logic below
        
    return {"error": "All Sources Failed (crt.sh & HackerTarget). Please try again later."}
