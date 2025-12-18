import re

def lint_config(config_text):
    """
    Analyzes a network configuration for policy violations.
    
    Args:
        config_text (str): The raw configuration text.
        
    Returns:
        list: A list of result dictionaries: 
              {'severity': 'Error'|'Warning'|'Pass', 'rule': '...', 'message': '...'}
    """
    results = []
    
    # Rule 1: Security - No Telnet
    # Check for "feature telnet" (NX-OS) or "transport input telnet" (IOS)
    if re.search(r"feature\s+telnet", config_text, re.IGNORECASE) or \
       re.search(r"transport\s+input\s+.*telnet", config_text, re.IGNORECASE):
        results.append({
            "severity": "Error",
            "rule": "Security Compliance",
            "message": "❌ Telnet is enabled. This is a critical security risk. Use SSH instead."
        })
    else:
        results.append({
            "severity": "Pass",
            "rule": "Security Compliance",
            "message": "✅ No Telnet configuration found."
        })
        
    # Rule 2: Performance - MTU 9000 (Jumbo Frames)
    # We look for "mtu 9000" or simple check if it's missing entirely from likely interface blocks
    # For a simple linter, we'll check if "mtu 9000" exists at least once if "interface" is present.
    if "interface" in config_text.lower():
        if not re.search(r"mtu\s+9000", config_text, re.IGNORECASE):
            results.append({
                "severity": "Warning",
                "rule": "Datacenter Performance",
                "message": "⚠️ Jumbo Frames (MTU 9000) not detected. Ensure critical links support 9000 bytes."
            })
        else:
             results.append({
                "severity": "Pass",
                "rule": "Datacenter Performance",
                "message": "✅ MTU 9000 detected."
            })
            
    # Rule 3: Availability - Interface Shutdown
    # Check if any interface is strictly "shutdown" (without "no")
    # This is tricky with regex because "no shutdown" contains "shutdown".
    # We look for lines that are exactly "  shutdown" or "shutdown" without a preceding "no".
    
    # Find all occurrences of shutdown
    shutdowns = re.findall(r"(^\s*|^\s*no\s+)shutdown", config_text, re.MULTILINE | re.IGNORECASE)
    
    # Count strict shutdowns (lines that DO NOT start with "no")
    # shutdown_matches will contain tuples or strings depending on capture groups.
    # The regex r"(^\s*|^\s*no\s+)shutdown" captures the prefix.
    # If prefix contains "no", it's good. If it's just whitespace, it's bad.
    
    active_shutdown_count = 0
    for prefix in shutdowns:
        if "no" not in prefix.lower():
            active_shutdown_count += 1
            
    if active_shutdown_count > 0:
        results.append({
            "severity": "Warning",
            "rule": "Interface Availability",
            "message": f"⚠️ Found {active_shutdown_count} interface(s) in 'shutdown' state. Verify this is intentional."
        })
    else:
        results.append({
            "severity": "Pass",
            "rule": "Interface Availability",
            "message": "✅ No disabled interfaces found (all are 'no shutdown' or implied up)."
        })
        
    return results
