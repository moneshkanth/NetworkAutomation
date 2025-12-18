import requests
import pandas as pd

# Using RIPE Stat API (More robust than bgpview)
API_BASE = "https://stat.ripe.net/data"

def get_asn_details(asn):
    """
    Fetches ASN metadata (Owner, Country).
    Endpoint: as-overview
    """
    try:
        url = f"{API_BASE}/as-overview/data.json?resource=AS{asn}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                "owner": data.get("holder", "Unknown"),
                "country": "Unknown", # RIPE doesn't always return country in overview easily, but let's try
                "description": f"Allocated: {data.get('type', 'Unknown')}",
                "rer": data.get("block", {}).get("resource", "Unknown") # Approximate
            }
    except Exception as e:
        return {"error": str(e)}
    return {"error": "API Request Failed"}

def get_asn_peers(asn):
    """
    Fetches Peers.
    Endpoint: asn-neighbours
    """
    try:
        url = f"{API_BASE}/asn-neighbours/data.json?resource=AS{asn}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json().get('data', {})
            neighbours = data.get('neighbours', [])
            
            # RIPE returns { 'asn': ..., 'type': 'left'/'right', 'power': ... }
            # We filter for 'left' (upstream/provider usually) or just take all.
            # RIPE's 'left'/'right' is about transitive power, roughly 'left' is upstream.
            
            peers_list = []
            for peer in neighbours:
                peers_list.append({
                    "asn": peer.get("asn"),
                    "name": f"AS{peer.get('asn')}", # RIPE doesn't give names here, would need separate lookup
                    "relationship": peer.get('type') 
                })
            # Limit to top 20 by 'power' if available, otherwise just list
            return peers_list[:20]
    except:
        pass
    return []

def get_asn_prefixes(asn):
    """
    Fetches advertised prefixes (IPv4).
    Endpoint: announced-prefixes
    """
    try:
        url = f"{API_BASE}/announced-prefixes/data.json?resource=AS{asn}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json().get('data', {})
            prefixes = data.get('prefixes', [])
            
            # Filter IPv4
            v4 = [p for p in prefixes if "." in p.get("prefix", "")]
            
            return [{"prefix": p.get("prefix"), "name": p.get("timelines", [{}])[0].get("starttime", "N/A"), "description": ""} for p in v4]
    except:
        pass
    return []

def generate_bgp_graph(asn, peers):
    """
    Generates DOT for BGP Topology.
    """
    dot = ['graph "BGP Topology" {']
    dot.append('  layout="neato";') 
    dot.append('  overlap=false;')
    dot.append('  splines=true;')
    dot.append('  node [shape=box, style=filled, fontname="Helvetica"];')
    
    # Center Node
    dot.append(f'  "ASN{asn}" [fillcolor="#FFCDD2", label="AS{asn}", shape=doubleoctagon, width=1.5];')
    
    for peer in peers:
        p_asn = peer['asn']
        # Color peers
        dot.append(f'  "AS{p_asn}" [fillcolor="#BBDEFB", label="AS{p_asn}"];')
        dot.append(f'  "AS{p_asn}" -- "ASN{asn}" [penwidth=1, color="#90CAF9"];')
        
    dot.append('}')
    return "\n".join(dot)
