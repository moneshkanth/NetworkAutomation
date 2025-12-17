import dns.resolver
import concurrent.futures

# Resolver IPs
RESOLVERS = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222"
}

def query_resolver(provider, resolver_ip, domain, record_type):
    """
    Queries a specific DNS resolver for a record.
    
    Args:
        provider (str): Name of the provider (e.g., "Google").
        resolver_ip (str): IP address of the resolver.
        domain (str): Domain to query.
        record_type (str): Type of record (A, AAAA, MX, CNAME).
        
    Returns:
        dict: Result containing provider, ip, status, and records.
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [resolver_ip]
    resolver.lifetime = 2.0 # 2 second timeout
    
    try:
        answers = resolver.resolve(domain, record_type)
        records = [str(r) for r in answers]
        return {
            "Provider": provider,
            "Resolver IP": resolver_ip,
            "Status": "✅",
            "Result": ", ".join(records)
        }
    except dns.resolver.NoAnswer:
        return {
            "Provider": provider,
            "Resolver IP": resolver_ip,
            "Status": "⚠️",
            "Result": "No Record Found"
        }
    except dns.resolver.NXDOMAIN:
        return {
            "Provider": provider,
            "Resolver IP": resolver_ip,
            "Status": "❌",
            "Result": "Domain Not Found"
        }
    except dns.resolver.Timeout:
        return {
            "Provider": provider,
            "Resolver IP": resolver_ip,
            "Status": "⏱️",
            "Result": "Timeout"
        }
    except Exception as e:
        return {
            "Provider": provider,
            "Resolver IP": resolver_ip,
            "Status": "⚠️",
            "Result": str(e)
        }

def check_dns_propagation(domain, record_type):
    """
    Checks DNS propagation across multiple global providers.
    
    Args:
        domain (str): Domain name to check.
        record_type (str): DNS record type.
        
    Returns:
        list: List of result dictionaries.
    """
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(RESOLVERS)) as executor:
        future_to_provider = {
            executor.submit(query_resolver, name, ip, domain, record_type): name 
            for name, ip in RESOLVERS.items()
        }
        
        for future in concurrent.futures.as_completed(future_to_provider):
            results.append(future.result())
            
    return results
