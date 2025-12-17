import ipaddress

def calculate_subnet_details(cidr):
    """
    Calculates network details for a given CIDR block.
    
    Args:
        cidr (str): The CIDR block (e.g., "192.168.1.0/24").
        
    Returns:
        dict: A dictionary containing subnet details, or None if invalid.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        
        # Calculate details
        netmask = str(network.netmask)
        network_address = str(network.network_address)
        broadcast_address = str(network.broadcast_address)
        num_hosts = network.num_addresses - 2 if network.num_addresses > 2 else 0
        
        # Calculate First and Last IP
        if network.num_addresses > 2:
            first_ip = str(list(network.hosts())[0])
            last_ip = str(list(network.hosts())[-1])
        else:
            first_ip = "N/A"
            last_ip = "N/A"

        # Calculate Wildcard Mask (inverse of netmask)
        # Convert netmask to int, invert bits, mask to 32 bits, convert back to IPv4
        netmask_int = int(network.netmask)
        wildcard_int = netmask_int ^ 0xFFFFFFFF
        wildcard_mask = str(ipaddress.IPv4Address(wildcard_int))

        return {
            "CIDR": str(network),
            "Netmask": netmask,
            "Wildcard Mask": wildcard_mask,
            "Network Address": network_address,
            "Broadcast Address": broadcast_address,
            "First Usable IP": first_ip,
            "Last Usable IP": last_ip,
            "Total Usable Hosts": f"{num_hosts:,}"
        }
    except ValueError:
        return None
    except Exception as e:
        return {"Error": str(e)}
