import ipaddress
import math
import pandas as pd

def calculate_vlsm(root_network_cidr, requirements):
    """
    Calculates VLSM allocations for a given root network and list of requirements.
    
    Args:
        root_network_cidr (str): The root CIDR (e.g. '192.168.0.0/24')
        requirements (list[dict]): List of dicts, e.g. [{'name': 'VLAN1', 'hosts': 50}]
        
    Returns:
        pd.DataFrame: DataFrame containing allocation details.
        str: Error message if any, else None.
    """
    try:
        root = ipaddress.ip_network(root_network_cidr, strict=False)
    except ValueError:
        return None, "Invalid Root Network CIDR."

    # 1. Sort requirements from Largest to Smallest (Critical for VLSM)
    # We create a copy to avoid mutating the original input if that matters
    reqs = sorted(requirements, key=lambda x: x['hosts'], reverse=True)
    
    allocations = []
    current_ip = root.network_address
    
    for req in reqs:
        name = req.get('name', 'Unnamed')
        hosts_needed = int(req.get('hosts', 0))
        
        if hosts_needed <= 0:
            allocations.append({
                "Subnet Name": name,
                "Hosts Needed": hosts_needed,
                "Error": "Hosts must be > 0"
            })
            continue

        # 2. Calculate Prefix
        # Needs hosts + 2 (Network + Broadcast)
        needed_total = hosts_needed + 2
        
        # Calculate power of 2 (k)
        # 2^k >= needed_total
        # k = ceil(log2(needed_total))
        k = math.ceil(math.log2(needed_total))
        
        # Prefix = 32 - k (for IPv4)
        prefix = 32 - k
        
        # Edge case: if k is very small (e.g. need 1 host -> total 3 -> k=2 -> /30).
        # /31 is usually for ptp links but strict VLSM often assumes /30 min for hosts.
        # Let's assume standard /30 is min for general LANs. 
        if prefix > 30:
            prefix = 30 # Smallest standard subnet
            
        # 3. Create Subnet
        try:
            # Construct candidate network
            candidate_str = f"{current_ip}/{prefix}"
            subnet = ipaddress.ip_network(candidate_str, strict=False)
            
            # 4. Check Collision / Bounds
            # Is this subnet actually inside the root?
            # And does it overlap with what we've already used? (Logic guarantees no overlap if moving fwd)
            if not subnet.subnet_of(root):
                allocations.append({
                    "Subnet Name": name,
                    "Hosts Needed": hosts_needed,
                    "Error": "Insufficient Space in Root Network"
                })
                # We can't proceed linearly if we ran out of space
                break
                
            # 5. Success - Record Data
            usable_hosts = subnet.num_addresses - 2
            efficiency = (hosts_needed / usable_hosts) * 100 if usable_hosts > 0 else 0
            
            allocations.append({
                "Subnet Name": name,
                "CIDR": str(subnet),
                "Network Address": str(subnet.network_address),
                "Broadcast Address": str(subnet.broadcast_address),
                "Range": f"{subnet.network_address + 1} - {subnet.broadcast_address - 1}",
                "Hosts Needed": hosts_needed,
                "Usable Hosts": usable_hosts,
                "Utilization %": round(efficiency, 1),
                "Status": "Allocated"
            })
            
            # 6. Move Pointer
            # Next IP is broadcast + 1
            current_ip = subnet.broadcast_address + 1
            
        except Exception as e:
            allocations.append({
                "Subnet Name": name,
                "Error": str(e)
            })
            
    # Calculate Free Space (Optional bonus logic)
    # We could find what's left between current_ip and root.broadcast_address
    # But for now let's just return the allocations.
    
    df = pd.DataFrame(allocations)
    return df, None

def get_free_space_summary(root_network_cidr, allocated_df):
    """
    Returns a simple summary of used vs free ips.
    """
    try:
        root = ipaddress.ip_network(root_network_cidr, strict=False)
        total_ips = root.num_addresses
        
        used_ips = 0
        if not allocated_df.empty and 'CIDR' in allocated_df.columns:
            for cidr in allocated_df['CIDR'].dropna():
                used_ips += ipaddress.ip_network(cidr).num_addresses
                
        free_ips = total_ips - used_ips
        
        return {
            "Total IPs": total_ips,
            "Used IPs": used_ips,
            "Free IPs": free_ips,
            "Usage %": round((used_ips/total_ips)*100, 1)
        }
    except:
        return {}
