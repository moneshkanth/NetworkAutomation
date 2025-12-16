import ssl
import socket
import datetime

def get_ssl_expiry(hostname):
    """
    Connects to the host and retrieves SSL certificate expiry date.
    Returns a dictionary with status and details.
    """
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    # 3 second timeout
    conn.settimeout(3.0)

    try:
        conn.connect((hostname, 443))
        ssl_info = conn.getpeercert()
        
        # Parse expiration date
        not_after_str = ssl_info['notAfter']
        expires = datetime.datetime.strptime(not_after_str, ssl_date_fmt)
        remaining = expires - datetime.datetime.utcnow()
        
        return {
            "host": hostname,
            "status": "Valid", 
            "days_remaining": remaining.days,
            "expires_on": expires.strftime("%Y-%m-%d"),
            "issuer": dict(x[0] for x in ssl_info['issuer'])['commonName']
        }
    except ssl.CertificateError:
        return {"host": hostname, "status": "Certificate Error", "days_remaining": -1}
    except socket.timeout:
        return {"host": hostname, "status": "Timeout", "days_remaining": -1}
    except Exception as e:
        return {"host": hostname, "status": f"Error: {str(e)}", "days_remaining": -1}
    finally:
        conn.close()

def check_bulk_ssl(hosts):
    """Checks a list of hosts."""
    results = []
    for host in hosts:
        host = host.strip()
        if host:
            results.append(get_ssl_expiry(host))
    return results
