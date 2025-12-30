import ipaddress

def analyze_ipv6(address_str):
    """
    Analyzes an IPv6 address string.

    Args:
        address_str (str): The IPv6 address to analyze.

    Returns:
        dict: A dictionary containing details about the address, or an error message.
    """
    try:
        # Strict mode ensures we only accept valid IPv6
        ipv6 = ipaddress.IPv6Address(address_str)
    except ValueError:
        return {"error": "Invalid IPv6 Address format."}
    except Exception as e:
        return {"error": str(e)}

    # Determine Address Type/Scope
    addr_type = "Unknown"
    description = "Standard Unicast Address"
    
    if ipv6.is_multicast:
        addr_type = "Multicast"
        description = "Used for one-to-many communication."
    elif ipv6.is_private:
        # Logic for Unique Local (fc00::/7)
        addr_type = "Unique Local (Private)"
        description = "Similar to IPv4 Private (RFC1918). Not routable on the internet."
    elif ipv6.is_global:
        addr_type = "Global Unicast"
        description = "Publicly routable on the commercial internet."
    elif ipv6.is_link_local:
        addr_type = "Link-Local"
        description = "Valid only on the local physical link (network segment). Starts with fe80::"
    elif ipv6.is_loopback:
        addr_type = "Loopback"
        description = "The localhost address (::1)."
    elif ipv6.is_unspecified:
        addr_type = "Unspecified"
        description = "The address :: (all zeros), used when no address is assigned."
    elif ipv6.is_reserved:
        addr_type = "Reserved"
        description = "Reserved by IETF."
        
    return {
        "original": address_str,
        "compressed": ipv6.compressed,
        "exploded": ipv6.exploded,
        "type": addr_type,
        "description": description,
        "is_multicast": ipv6.is_multicast,
        "is_private": ipv6.is_private,
        "is_global": ipv6.is_global,
        "is_link_local": ipv6.is_link_local,
        "is_loopback": ipv6.is_loopback,
        "version": ipv6.version
    }
