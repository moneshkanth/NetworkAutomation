import re
import ipaddress

def sanitize_config(text, options):
    """
    Sanitizes configuration text based on selected options.

    Args:
        text (str): The raw configuration text.
        options (dict): Dictionary of boolean flags for what to redact.
            {
                "passwords": bool,
                "public_ips": bool,
                "mac_addresses": bool,
                "snmp": bool
            }

    Returns:
        str: The sanitized text.
    """
    sanitized_text = text

    if options.get("passwords", True):
        sanitized_text = redact_passwords(sanitized_text)
    
    if options.get("public_ips", False):
        sanitized_text = redact_public_ips(sanitized_text)

    if options.get("mac_addresses", False):
        sanitized_text = redact_mac_addresses(sanitized_text)

    if options.get("snmp", False):
        sanitized_text = redact_snmp(sanitized_text)

    return sanitized_text

def redact_passwords(text):
    """
    Redacts passwords and secrets.
    Looks for:
    - password 7 <string>
    - secret 5 <string>
    - key <string>
    - auth <string>
    """
    # Regex for common Cisco/Network password patterns
    # (password|secret|key|auth) followed by optional type (5|7) and then the secret string
    # We match until end of line or next space, but typically these are one token or rest of line.
    # Let's assume rest of line for things like 'password 7' but 'key' might be in a chain.
    # User requirement: "password 7, secret 5, key, auth and replace the string following them"
    
    # Pattern 1: password 7 <hash> or secret 5 <hash>
    # Replaces the hash with [REDACTED]
    text = re.sub(r'(password\s+7\s+)(\S+)', r'\1[REDACTED]', text, flags=re.IGNORECASE)
    text = re.sub(r'(secret\s+5\s+)(\S+)', r'\1[REDACTED]', text, flags=re.IGNORECASE)
    
    # Pattern 2: key <string> or auth <string> (simpler approach, replace next token)
    # Careful not to redact keywords themselves if they appear in other contexts, but user specified "key" and "auth"
    text = re.sub(r'(key\s+)(\S+)', r'\1[REDACTED]', text, flags=re.IGNORECASE)
    text = re.sub(r'(auth\s+)(\S+)', r'\1[REDACTED]', text, flags=re.IGNORECASE)
    
    # Generic "password <string>" (plaintext or other types if not 7)
    text = re.sub(r'(password\s+)(\S+)', lambda m: m.group(1) + "[REDACTED]" if m.group(2) != "7" else m.group(0), text, flags=re.IGNORECASE)

    return text

def redact_public_ips(text):
    """
    Redacts Public IPv4 addresses.
    Preserves Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    """
    # Find all potential IP strings
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    def replace_ip(match):
        ip_str = match.group(0)
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_global and not ip.is_private: # is_global is usually opposite of private but there are reserved ranges. User asked to keep "Private IPs like 10.x...". is_private handles 10/8, 172.16/12, 192.168/16.
                 # Double check loopback/link-local if needed, but "Public IPs" usually implies internet routable. 
                 # is_private catches the standard RFC1918.
                 return "X.X.X.X"
            return ip_str
        except ValueError:
            return ip_str

    return re.sub(ip_pattern, replace_ip, text)

def redact_mac_addresses(text):
    """
    Redacts MAC addresses.
    Formats: aa:bb:cc:dd:ee:ff, aabb.ccdd.eeff, aa-bb-cc-dd-ee-ff
    """
    # Pattern 1: Colon separated
    text = re.sub(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', 'XX:XX:XX:XX:XX:XX', text)
    
    # Pattern 2: Dash separated
    text = re.sub(r'([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}', 'XX-XX-XX-XX-XX-XX', text)
    
    # Pattern 3: Dot separated (Cisco style aabb.ccdd.eeff)
    text = re.sub(r'[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}', 'XXXX.XXXX.XXXX', text)
    
    return text

def redact_snmp(text):
    """
    Redacts lines containing 'snmp-server community'.
    """
    # Replace the value after community
    # snmp-server community <string> <ro/rw>
    # Match specific pattern first
    text = re.sub(r'(snmp-server\s+community\s+)(\S+)', r'\1[REDACTED]', text, flags=re.IGNORECASE)
    
    return text
