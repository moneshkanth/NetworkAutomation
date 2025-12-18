import ipaddress

def optimize_routes(raw_text):
    """
    Parses a list of IP addresses/CIDRs and optimizes them into the minimal set of CIDRs.
    
    Args:
        raw_text (str): Input text containing one IP/subnet per line.
        
    Returns:
        dict: {
            'optimized_cidrs': list of str,
            'original_count': int,
            'optimized_count': int,
            'reduction_percentage': float,
            'errors': list of str (lines that couldn't be parsed)
        }
    """
    networks = []
    errors = []
    
    # Process input lines
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    original_count = len(lines)
    
    for line in lines:
        try:
            # strict=False allows matching "192.168.1.1/24" without erroring that host bits are set
            net = ipaddress.ip_network(line, strict=False)
            networks.append(net)
        except ValueError:
            errors.append(line)
            
    # Key Logic: Collapse Addresses
    # ipaddress.collapse_addresses returns an iterator of minimal CIDRs
    try:
        optimized_networks = list(ipaddress.collapse_addresses(networks))
    except Exception as e:
        # Fallback if list is empty or other issue
        optimized_networks = []

    optimized_cidrs = [str(n) for n in optimized_networks]
    optimized_count = len(optimized_cidrs)
    
    # Calculate reduction efficiency
    if original_count > 0:
        reduction = ((original_count - optimized_count) / original_count) * 100.0
    else:
        reduction = 0.0
        
    return {
        'optimized_cidrs': optimized_cidrs,
        'original_count': original_count,
        'optimized_count': optimized_count,
        'reduction_percentage': round(reduction, 1),
        'errors': errors
    }
