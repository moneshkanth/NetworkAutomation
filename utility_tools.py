import math
import ipaddress
import pandas as pd

def calculate_azure_egress(amount_gb):
    """
    Calculates estimated Azure Egress cost based on tiered pricing.
    
    Tiers (Approximate Standard Egress):
    - First 100 GB: Free
    - Next 10 TB (100GB - 10,100GB): $0.087 / GB
    - Next 40 TB (10TB - 50TB): $0.083 / GB
    - Over 50 TB: $0.07 / GB
    
    Args:
        amount_gb (float): Total data transfer in GB.
        
    Returns:
        dict: Breakdown of costs and total.
    """
    remaining = amount_gb
    total_cost = 0.0
    breakdown = []
    
    # Tier 1: First 100GB Free
    tier1_limit = 100
    if remaining > 0:
        chunk = min(remaining, tier1_limit)
        cost = 0.0
        breakdown.append({"Tier": "First 100 GB (Free)", "GB": chunk, "Rate": "$0.00", "Cost": f"${cost:.2f}"})
        remaining -= chunk
        
    # Tier 2: Next 10 TB (10,240 GB) @ $0.087
    tier2_limit = 10 * 1024 # 10 TB in GB
    if remaining > 0:
        chunk = min(remaining, tier2_limit)
        cost = chunk * 0.087
        total_cost += cost
        breakdown.append({"Tier": "Next 10 TB", "GB": chunk, "Rate": "$0.087", "Cost": f"${cost:.2f}"})
        remaining -= chunk
        
    # Tier 3: Next 40 TB (40,960 GB) @ $0.083
    tier3_limit = 40 * 1024
    if remaining > 0:
        chunk = min(remaining, tier3_limit)
        cost = chunk * 0.083
        total_cost += cost
        breakdown.append({"Tier": "Next 40 TB", "GB": chunk, "Rate": "$0.083", "Cost": f"${cost:.2f}"})
        remaining -= chunk
        
    # Tier 4: Over 50 TB @ $0.07
    if remaining > 0:
        chunk = remaining
        cost = chunk * 0.07
        total_cost += cost
        breakdown.append({"Tier": "Over 50 TB", "GB": chunk, "Rate": "$0.070", "Cost": f"${cost:.2f}"})
        
    return {
        "total_cost": round(total_cost, 2),
        "breakdown": breakdown
    }

def convert_optical_power(value, unit):
    """
    Converts between dBm and mW.
    
    Args:
        value (float): The signal strength.
        unit (str): The unit of input ('dBm' or 'mW').
        
    Returns:
        dict: Resulting value and unit.
    """
    try:
        if unit == 'dBm':
            # dBm to mW: P(mW) = 10 ^ (P(dBm) / 10)
            mw = 10 ** (value / 10)
            return {"input": f"{value} dBm", "output_val": mw, "output_unit": "mW"}
        elif unit == 'mW':
            # mW to dBm: P(dBm) = 10 * log10(P(mW))
            if value <= 0:
                return {"error": "mW must be > 0"}
            dbm = 10 * math.log10(value)
            return {"input": f"{value} mW", "output_val": dbm, "output_unit": "dBm"}
    except Exception as e:
        return {"error": str(e)}

def exclude_subnets(supernet_cidr, exclude_cidr):
    """
    Subtracts a subnet from a supernet using ipaddress.address_exclude.
    
    Args:
        supernet_cidr (str): The containing network (e.g. 10.0.0.0/8).
        exclude_cidr (str): The network to remove (e.g. 10.1.0.0/16).
        
    Returns:
        list: CIDR strings of remaining subnets.
        str: Error message if any.
    """
    try:
        s_net = ipaddress.ip_network(supernet_cidr, strict=False)
        e_net = ipaddress.ip_network(exclude_cidr, strict=False)
        
        if not e_net.subnet_of(s_net):
            return [], f"Error: {exclude_cidr} is not inside {supernet_cidr}."
            
        # Perform exclusion
        remaining = parse_exclusion_generator(s_net.address_exclude(e_net))
        return remaining, None
        
    except ValueError as e:
        return [], f"Invalid CIDR: {e}"
    except Exception as e:
        return [], str(e)

def parse_exclusion_generator(gen):
    """Helper to consume generator and return strings."""
    return [str(n) for n in gen]

def calculate_mtu_overhead(phys_mtu, protocol_overhead):
    """
    Calculates Safe Tunnel MTU and TCP MSS.
    
    Args:
        phys_mtu (int): The Physical Interface MTU (default 1500).
        protocol_overhead (int): Bytes added by the tunnel header.
        
    Returns:
        dict: Safe MTU, Recommended MSS, and breakdown.
    """
    safe_mtu = phys_mtu - protocol_overhead
    # TCP/IP Headers = 40 bytes (20 IP + 20 TCP)
    tcp_ip_headers = 40
    mss = safe_mtu - tcp_ip_headers
    
    return {
        "safe_mtu": safe_mtu,
        "mss": mss,
        "breakdown": {
            "Physical MTU": phys_mtu,
            "Tunnel Overhead": protocol_overhead,
            "TCP/IP Headers": tcp_ip_headers,
            "Payload (MSS)": mss
        }
    }
