import requests
import streamlit as st
import json

# Using a community mirror for "Latest" because Microsoft URLs have dynamic GUIDs.
# Source: https://github.com/maciejporebski/azure-ips
AZURE_IP_RANGES_URL = "https://raw.githubusercontent.com/maciejporebski/azure-ips/master/ServiceTags_Public_Latest.json"

@st.cache_data(ttl=3600*24) # Cache for 24 hours
def fetch_azure_data_v2():
    """
    Fetches the official Azure Service Tags JSON.
    """
    try:
        response = requests.get(AZURE_IP_RANGES_URL, timeout=15)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def get_unique_regions(data):
    """Extracts unique regions for the dropdown."""
    if "values" not in data:
        return []
    regions = set()
    for item in data['values']:
        r = item.get('properties', {}).get('region', '')
        if r:
            regions.add(r)
    return sorted(list(regions))

def filter_azure_ranges(data, service_search, region_filter):
    """
    Filters the JSON for matching IPs.
    """
    if "values" not in data:
        return []

    results = []
    search_term = service_search.lower().strip()
    
    for item in data['values']:
        # Properties
        props = item.get('properties', {})
        system_service = props.get('systemService', '').lower()
        item_name = item.get('name', '').lower() # Fallback
        item_region = props.get('region', '').lower()
        
        # Check Region
        if region_filter and region_filter != "All":
            if item_region != region_filter.lower():
                continue
                
        # Check Service Name
        # We match against 'systemService' OR 'name' (e.g. AzureCloud.EastUS)
        if search_term:
            if (search_term not in system_service) and (search_term not in item_name):
                continue
        
        # If match, collect IPs
        prefixes = props.get('addressPrefixes', [])
        # Filter for IPv4 only
        ipv4 = [p for p in prefixes if ":" not in p]
        results.extend(ipv4)
        
    # Deduplicate and sort
    # Sorting IPs properly requires ipaddress module, but string sort is "okay" for simple list
    # Let's simple string sort for now to keep it fast
    return sorted(list(set(results)))

def generate_cisco_acl(prefixes):
    """
    Formats the list as Cisco ACL entries.
    """
    lines = []
    lines.append("! Azure Allowed Ranges")
    for p in prefixes:
        # Assuming modern Cisco syntax (accepts CIDR) or Object Groups
        # standard ACL: access-list 100 permit ip <net> <wildcard> any
        # Simplest distinct output for Engineers:
        lines.append(f"permit ip {p} any")
    return "\n".join(lines)
