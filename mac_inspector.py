import requests
import re
import time

def get_mac_vendor(mac_address):
    """
    Queries macvendors.com API to get the vendor of a MAC address.
    """
    # 1. Sanitize Input
    # Remove common delimiters to get raw hex
    clean_mac = re.sub(r'[:\-\.]', '', mac_address)
    
    # Basic validation
    if not clean_mac or len(clean_mac) < 6:
        return {"error": "Invalid MAC Address format. Please provide at least the first 6 characters (OUI)."}
        
    # 2. Format with Colons (API prefers XX:XX:XX:XX:XX:XX)
    # properly formatting chunks of 2
    formatted_mac = ":".join(clean_mac[i:i+2] for i in range(0, len(clean_mac), 2))
        
    try:
        # 3. Query API
        url = f"https://api.macvendors.com/{formatted_mac}"
        response = requests.get(url, timeout=5)
        
        # 4. Handle Responses
        if response.status_code == 200:
            return {"vendor": response.text.strip()}
        elif response.status_code == 404:
            return {"error": f"Vendor Not Found for {formatted_mac}"}
        elif response.status_code == 429:
             return {"error": "Rate Limit Exceeded. Please wait a moment."}
        else:
            return {"error": f"API Error: {response.status_code}"}
            
    except requests.exceptions.RequestException as e:
        return {"error": f"Network Error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected Error: {str(e)}"}
